import { ProviderRequestError } from '../errors';
import {
  buildProviderUrl,
  httpOptions,
  isUnderOrigin,
  providerRequest,
  type ProviderHttpSettings,
} from '../http/provider-http';
import { withProviderRetry, type RetryPolicy } from '../http/retry';
import type { AccessTokenProvider } from '../tokens/token-service';
import type { GrantRef } from '../types';

export interface GraphRequestOptions {
  /** `$select` fields. */
  select?: readonly string[];
  query?: Record<string, string | number | undefined>;
  /** Statuses returned as `null` instead of thrown (e.g. `404` for lookups). */
  nullOn?: readonly number[];
}

export interface GraphListOptions extends GraphRequestOptions {
  /** Maximum pages followed (default 20); more is `bad_response`. */
  maxPages?: number;
}

export interface MicrosoftGraphClientOptions {
  /** `PROVIDER_M365_GRAPH_URL`. */
  graphUrl: URL;
  tokens: AccessTokenProvider;
  http?: ProviderHttpSettings;
  retry?: RetryPolicy;
  /** API version path segment (default `v1.0`). */
  version?: 'v1.0' | 'beta';
}

/**
 * Read-only Microsoft Graph client (D6): `get` and `list` with `@odata.nextLink` paging followed
 * only on the configured Graph origin and base path (D17), `$select`, bounded retries of
 * throttling. 8.2 uses only `GET`.
 */
export class MicrosoftGraphClient {
  private readonly version: string;

  constructor(private readonly options: MicrosoftGraphClientOptions) {
    this.version = options.version ?? 'v1.0';
  }

  async get<T = unknown>(
    grant: GrantRef,
    path: string,
    signal: AbortSignal,
    options: GraphRequestOptions = {},
  ): Promise<T | null> {
    const url = buildProviderUrl(
      this.options.graphUrl,
      `/${this.version}${path}`,
      this.query(options),
    );
    return (await this.fetchUrl(grant, url, signal, options.nullOn)) as T | null;
  }

  /** Every `value` item across pages. */
  async list<T = unknown>(
    grant: GrantRef,
    path: string,
    signal: AbortSignal,
    options: GraphListOptions = {},
  ): Promise<T[] | null> {
    const maxPages = options.maxPages ?? 20;
    let url: URL = buildProviderUrl(
      this.options.graphUrl,
      `/${this.version}${path}`,
      this.query(options),
    );
    const items: T[] = [];
    for (let page = 0; ; page += 1) {
      if (page >= maxPages) throw new ProviderRequestError('bad_response');
      const body = await this.fetchUrl(grant, url, signal, options.nullOn);
      if (body === null) return page === 0 ? null : items;
      if (
        !body ||
        typeof body !== 'object' ||
        !Array.isArray((body as { value?: unknown }).value)
      ) {
        throw new ProviderRequestError('bad_response');
      }
      items.push(...(body as { value: T[] }).value);
      const next = (body as Record<string, unknown>)['@odata.nextLink'];
      if (next === undefined || next === null) return items;
      if (typeof next !== 'string' || !isUnderOrigin(this.options.graphUrl, next)) {
        // A paging link to any other origin or path is never followed (D17).
        throw new ProviderRequestError('bad_response');
      }
      url = new URL(next);
    }
  }

  private query(options: GraphRequestOptions): Record<string, string | number | undefined> {
    return {
      ...(options.select && options.select.length > 0 ? { $select: options.select.join(',') } : {}),
      ...options.query,
    };
  }

  private async fetchUrl(
    grant: GrantRef,
    url: URL,
    signal: AbortSignal,
    nullOn: readonly number[] = [],
  ): Promise<unknown> {
    const base = new URL(this.options.graphUrl.href);
    const basePath = base.pathname.replace(/\/+$/, '');
    const relative = url.pathname.slice(basePath.length);
    const query = Object.fromEntries(url.searchParams.entries());
    return withProviderRetry(
      async () => {
        const { token } = await this.options.tokens.getAccessToken(grant, signal);
        const response = await providerRequest({
          ...httpOptions(this.options.http),
          origin: this.options.graphUrl,
          method: 'GET',
          path: relative,
          query,
          headers: { authorization: `Bearer ${token}` },
          acceptStatuses: nullOn,
          signal,
          api: 'graph',
        });
        return nullOn.includes(response.status) ? null : response.json;
      },
      signal,
      this.options.retry,
    );
  }
}

import { ProviderRequestError } from '../errors';
import { httpOptions, providerRequest, type ProviderHttpSettings } from '../http/provider-http';
import { withProviderRetry, type RetryPolicy } from '../http/retry';
import type { AccessTokenProvider } from '../tokens/token-service';
import type { GrantRef } from '../types';

export interface GoogleRequestOptions {
  query?: Record<string, string | number | undefined>;
  /** Statuses returned as `null` instead of thrown. */
  nullOn?: readonly number[];
}

export interface GoogleListOptions extends GoogleRequestOptions {
  /** The response field holding the items (e.g. `domains`). */
  itemsField: string;
  /** Maximum pages followed (default 20). */
  maxPages?: number;
}

export interface GoogleAdminClientOptions {
  /** `PROVIDER_GOOGLE_ADMIN_URL`. */
  adminUrl: URL;
  tokens: AccessTokenProvider;
  http?: ProviderHttpSettings;
  retry?: RetryPolicy;
}

const PAGE_TOKEN = /^[A-Za-z0-9_\-.~+/=]{1,1024}$/;

/**
 * Read-only Google Admin SDK client (D6): `get` and `list` with `pageToken` paging (the token is
 * an opaque query value on the same configured endpoint), bounded retries of throttling.
 */
export class GoogleAdminClient {
  constructor(private readonly options: GoogleAdminClientOptions) {}

  async get<T = unknown>(
    grant: GrantRef,
    path: string,
    signal: AbortSignal,
    options: GoogleRequestOptions = {},
  ): Promise<T | null> {
    return (await this.request(
      grant,
      path,
      options.query ?? {},
      signal,
      options.nullOn,
    )) as T | null;
  }

  async list<T = unknown>(
    grant: GrantRef,
    path: string,
    signal: AbortSignal,
    options: GoogleListOptions,
  ): Promise<T[] | null> {
    const maxPages = options.maxPages ?? 20;
    const items: T[] = [];
    let pageToken: string | undefined;
    for (let page = 0; ; page += 1) {
      if (page >= maxPages) throw new ProviderRequestError('bad_response');
      const body = await this.request(
        grant,
        path,
        { ...options.query, ...(pageToken ? { pageToken } : {}) },
        signal,
        options.nullOn,
      );
      if (body === null) return page === 0 ? null : items;
      if (!body || typeof body !== 'object') throw new ProviderRequestError('bad_response');
      const record = body as Record<string, unknown>;
      const pageItems = record[options.itemsField];
      if (pageItems !== undefined && !Array.isArray(pageItems)) {
        throw new ProviderRequestError('bad_response');
      }
      items.push(...((pageItems as T[] | undefined) ?? []));
      const next = record.nextPageToken;
      if (next === undefined || next === null || next === '') return items;
      if (typeof next !== 'string' || !PAGE_TOKEN.test(next))
        throw new ProviderRequestError('bad_response');
      pageToken = next;
    }
  }

  private async request(
    grant: GrantRef,
    path: string,
    query: Record<string, string | number | undefined>,
    signal: AbortSignal,
    nullOn: readonly number[] = [],
  ): Promise<unknown> {
    return withProviderRetry(
      async () => {
        const { token } = await this.options.tokens.getAccessToken(grant, signal);
        const response = await providerRequest({
          ...httpOptions(this.options.http),
          origin: this.options.adminUrl,
          method: 'GET',
          path,
          query,
          headers: { authorization: `Bearer ${token}` },
          acceptStatuses: nullOn,
          signal,
          api: 'google.admin',
        });
        return nullOn.includes(response.status) ? null : response.json;
      },
      signal,
      this.options.retry,
    );
  }
}

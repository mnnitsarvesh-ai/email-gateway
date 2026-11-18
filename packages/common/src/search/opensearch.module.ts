import { type DynamicModule, Global, Inject, Injectable, Module } from '@nestjs/common';
import type { HealthDetails } from '@email-gateway/shared-types';
import type { HealthIndicator } from '../health/health-indicator';
import { OpenSearchError, openSearchErrorType } from './opensearch.errors';

/**
 * The OpenSearch client of the archive search index (step 8.1 A16, ADR-0068): plain `fetch`
 * with a per-request `AbortSignal.timeout`, optional basic auth, JSON and NDJSON bodies and
 * custom routing. No client library (no new supply-chain dependency); SigV4 is deferred (10.1).
 * Errors expose the HTTP status and OpenSearch error type only (`OpenSearchError`).
 *
 * Services register `OpenSearchService` as a health indicator only where search is required
 * (the worker's `index`/`ediscovery` roles); the api treats it as optional.
 */

export const OPENSEARCH_OPTIONS = Symbol('OPENSEARCH_OPTIONS');

export interface OpenSearchOptions {
  /** `ARCHIVE_SEARCH_URL`, e.g. `http://localhost:9200`. */
  url: string;
  /** `ARCHIVE_SEARCH_USERNAME` / `ARCHIVE_SEARCH_PASSWORD` (set together). */
  username?: string | undefined;
  password?: string | undefined;
  /** `ARCHIVE_SEARCH_TIMEOUT_MS`. */
  timeoutMs: number;
}

export type OpenSearchQueryValue = string | number | boolean | undefined;

export interface OpenSearchRequestOptions {
  /** JSON body. */
  body?: unknown;
  /** NDJSON body (`_bulk`): one JSON value per line, newline-terminated. */
  ndjson?: readonly unknown[];
  /** Custom routing (the organization id of archive documents). */
  routing?: string;
  query?: Record<string, OpenSearchQueryValue>;
  /** Statuses that are returned instead of thrown (e.g. 404 for a missing document). */
  allowStatuses?: readonly number[];
}

export interface OpenSearchResponse<T> {
  status: number;
  body: T;
}

export type OpenSearchBulkOperation =
  | { action: 'index'; index: string; id: string; routing?: string; document: unknown }
  | { action: 'delete'; index: string; id: string; routing?: string };

export interface OpenSearchBulkItemResult {
  action: 'index' | 'delete';
  index: string | null;
  id: string | null;
  status: number;
  /** `error.type` of a failed item (never its reason). */
  errorType: string | null;
  ok: boolean;
}

export interface OpenSearchBulkResult {
  errors: boolean;
  items: OpenSearchBulkItemResult[];
}

export interface OpenSearchHit<S> {
  _index: string;
  _id: string;
  _source?: S;
  sort?: unknown[];
}

export interface OpenSearchSearchResponse<S> {
  timedOut: boolean;
  hits: OpenSearchHit<S>[];
}

const SEGMENT = (value: string): string => {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512) {
    throw new OpenSearchError('http', 400, 'invalid_name');
  }
  return encodeURIComponent(value);
};

@Injectable()
export class OpenSearchService implements HealthIndicator {
  readonly healthName = 'opensearch';
  private readonly baseUrl: string;
  private readonly authorization: string | null;

  constructor(@Inject(OPENSEARCH_OPTIONS) private readonly options: OpenSearchOptions) {
    let url: URL;
    try {
      url = new URL(options.url);
    } catch {
      throw new Error('ARCHIVE_SEARCH_URL must be an http(s) URL');
    }
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password) {
      throw new Error('ARCHIVE_SEARCH_URL must be an http(s) URL without credentials');
    }
    this.baseUrl = url.toString().replace(/\/+$/, '');
    if (Boolean(options.username) !== Boolean(options.password)) {
      throw new Error('ARCHIVE_SEARCH_USERNAME and ARCHIVE_SEARCH_PASSWORD must be set together');
    }
    this.authorization =
      options.username && options.password
        ? `Basic ${Buffer.from(`${options.username}:${options.password}`, 'utf8').toString('base64')}`
        : null;
  }

  /** One HTTP call; throws `OpenSearchError` for any status outside 2xx and `allowStatuses`. */
  async request<T = unknown>(
    method: 'GET' | 'PUT' | 'POST' | 'DELETE' | 'HEAD',
    path: string,
    options: OpenSearchRequestOptions = {},
  ): Promise<OpenSearchResponse<T>> {
    if (!path.startsWith('/') || path.includes('..')) {
      throw new OpenSearchError('http', 400, 'invalid_path');
    }
    const url = new URL(this.baseUrl + path);
    for (const [key, value] of Object.entries(options.query ?? {})) {
      if (value !== undefined) url.searchParams.set(key, String(value));
    }
    if (options.routing !== undefined) url.searchParams.set('routing', options.routing);
    const headers: Record<string, string> = { accept: 'application/json' };
    if (this.authorization) headers.authorization = this.authorization;
    let body: string | undefined;
    if (options.ndjson !== undefined) {
      headers['content-type'] = 'application/x-ndjson';
      body = options.ndjson.map((line) => JSON.stringify(line)).join('\n') + '\n';
    } else if (options.body !== undefined) {
      headers['content-type'] = 'application/json';
      body = JSON.stringify(options.body);
    }
    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body,
        signal: AbortSignal.timeout(this.options.timeoutMs),
      });
    } catch (error) {
      const name = (error as { name?: unknown } | null)?.name;
      throw new OpenSearchError(
        name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'unavailable',
      );
    }
    let text: string;
    try {
      text = method === 'HEAD' ? '' : await response.text();
    } catch {
      throw new OpenSearchError('timeout', response.status);
    }
    let parsed: unknown = null;
    if (text !== '') {
      try {
        parsed = JSON.parse(text);
      } catch {
        if (response.ok) throw new OpenSearchError('invalid_response', response.status);
      }
    }
    const allowed = options.allowStatuses?.includes(response.status) ?? false;
    if (!response.ok && !allowed) {
      throw new OpenSearchError('http', response.status, openSearchErrorType(parsed));
    }
    return { status: response.status, body: parsed as T };
  }

  /** `PUT _index_template/<name>` (composable template). */
  async putIndexTemplate(name: string, body: unknown): Promise<void> {
    await this.request('PUT', `/_index_template/${SEGMENT(name)}`, { body });
  }

  /** `PUT /<index>`; an existing index is not an error (`created: false`). */
  async createIndex(index: string, body: unknown = {}): Promise<{ created: boolean }> {
    const res = await this.request('PUT', `/${SEGMENT(index)}`, { body, allowStatuses: [400] });
    if (res.status === 400) {
      const type = openSearchErrorType(res.body);
      if (type === 'resource_already_exists_exception') return { created: false };
      throw new OpenSearchError('http', 400, type);
    }
    return { created: true };
  }

  /** `HEAD /<index>`. */
  async indexExists(index: string): Promise<boolean> {
    const res = await this.request('HEAD', `/${SEGMENT(index)}`, { allowStatuses: [404] });
    return res.status === 200;
  }

  /** `POST /_aliases` (atomic alias actions). */
  async updateAliases(body: { actions: unknown[] }): Promise<void> {
    if (body.actions.length === 0) return;
    await this.request('POST', '/_aliases', { body });
  }

  /** `POST /_bulk`: per-item results in request order; the call fails only on a request error. */
  async bulk(
    operations: readonly OpenSearchBulkOperation[],
    options: { refresh?: boolean | 'wait_for' } = {},
  ): Promise<OpenSearchBulkResult> {
    if (operations.length === 0) return { errors: false, items: [] };
    const lines: unknown[] = [];
    for (const op of operations) {
      const meta = {
        _index: op.index,
        _id: op.id,
        ...(op.routing !== undefined ? { routing: op.routing } : {}),
      };
      lines.push({ [op.action]: meta });
      if (op.action === 'index') lines.push(op.document);
    }
    const res = await this.request<{ errors?: boolean; items?: unknown[] }>('POST', '/_bulk', {
      ndjson: lines,
      query: { refresh: options.refresh === undefined ? undefined : String(options.refresh) },
    });
    const raw = Array.isArray(res.body?.items) ? res.body.items : [];
    if (raw.length !== operations.length) {
      throw new OpenSearchError('invalid_response', res.status);
    }
    const items = raw.map((entry, i): OpenSearchBulkItemResult => {
      const action = operations[i]!.action;
      const item = ((entry as Record<string, unknown> | null)?.[action] ?? {}) as {
        _index?: unknown;
        _id?: unknown;
        status?: unknown;
        error?: unknown;
      };
      const status = typeof item.status === 'number' ? item.status : 0;
      const errorType =
        item.error === undefined ? null : openSearchErrorType({ error: item.error });
      // Deleting a document that is already gone is the desired end state.
      const ok =
        item.error === undefined &&
        ((status >= 200 && status < 300) || (action === 'delete' && status === 404));
      return {
        action,
        index: typeof item._index === 'string' ? item._index : null,
        id: typeof item._id === 'string' ? item._id : null,
        status,
        errorType,
        ok,
      };
    });
    return { errors: items.some((i) => !i.ok), items };
  }

  /** `POST /<index or alias>/_search`. */
  async search<S = Record<string, unknown>>(
    index: string,
    body: unknown,
    options: { routing?: string } = {},
  ): Promise<OpenSearchSearchResponse<S>> {
    const res = await this.request<{ timed_out?: boolean; hits?: { hits?: OpenSearchHit<S>[] } }>(
      'POST',
      `/${SEGMENT(index)}/_search`,
      { body, routing: options.routing },
    );
    return { timedOut: res.body?.timed_out === true, hits: res.body?.hits?.hits ?? [] };
  }

  /** `POST /<index or alias>/_count`; a missing index or alias counts 0. */
  async count(index: string, body: unknown, options: { routing?: string } = {}): Promise<number> {
    const res = await this.request<{ count?: number }>('POST', `/${SEGMENT(index)}/_count`, {
      body,
      routing: options.routing,
      allowStatuses: [404],
    });
    if (res.status === 404) return 0;
    if (typeof res.body?.count !== 'number')
      throw new OpenSearchError('invalid_response', res.status);
    return res.body.count;
  }

  /** `GET /<index>/_doc/<id>`; null when the document (or index) does not exist. */
  async getDoc<S = Record<string, unknown>>(
    index: string,
    id: string,
    options: { routing?: string } = {},
  ): Promise<{ index: string; source: S | null } | null> {
    const res = await this.request<{ found?: boolean; _index?: string; _source?: S }>(
      'GET',
      `/${SEGMENT(index)}/_doc/${SEGMENT(id)}`,
      { routing: options.routing, allowStatuses: [404] },
    );
    if (res.status === 404 || res.body?.found !== true) return null;
    return { index: res.body._index ?? index, source: res.body._source ?? null };
  }

  /** `POST /<index>/_delete_by_query` (organization purge, reconciliation). */
  async deleteByQuery(
    index: string,
    body: unknown,
    options: { routing?: string; refresh?: boolean; conflicts?: 'abort' | 'proceed' } = {},
  ): Promise<{ deleted: number }> {
    const res = await this.request<{ deleted?: number }>(
      'POST',
      `/${SEGMENT(index)}/_delete_by_query`,
      {
        body,
        routing: options.routing,
        query: {
          refresh: options.refresh,
          conflicts: options.conflicts ?? 'proceed',
        },
        allowStatuses: [404],
      },
    );
    return { deleted: res.status === 404 ? 0 : (res.body?.deleted ?? 0) };
  }

  /** `GET /_cluster/health`. */
  async clusterHealth(): Promise<{
    status: 'green' | 'yellow' | 'red';
    numberOfNodes: number | null;
  }> {
    const res = await this.request<{ status?: unknown; number_of_nodes?: unknown }>(
      'GET',
      '/_cluster/health',
    );
    const status = res.body?.status;
    if (status !== 'green' && status !== 'yellow' && status !== 'red') {
      throw new OpenSearchError('invalid_response', res.status);
    }
    return {
      status,
      numberOfNodes:
        typeof res.body?.number_of_nodes === 'number' ? res.body.number_of_nodes : null,
    };
  }

  /** Readiness: the cluster answers and is not red (a single local node is yellow or green). */
  async checkHealth(): Promise<HealthDetails> {
    const health = await this.clusterHealth();
    if (health.status === 'red') throw new Error('OpenSearch cluster status is red');
    return { clusterStatus: health.status };
  }
}

@Global()
@Module({})
export class OpenSearchModule {
  static forRoot(options: OpenSearchOptions): DynamicModule {
    return {
      module: OpenSearchModule,
      providers: [{ provide: OPENSEARCH_OPTIONS, useValue: options }, OpenSearchService],
      exports: [OpenSearchService],
    };
  }
}

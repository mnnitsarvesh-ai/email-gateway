/**
 * Office 365 Management Activity API simulator (design note D12): subscription start, content
 * listing with `NextPageUri` paging and window validation (≤ 24 h, ≥ now − 7 days), audit blobs.
 * Error `AF20022` while no `Audit.Exchange` subscription exists.
 */
import { json, type SimRequest, type SimResponse, type Simulator } from './server';
import type { SimScript } from './script';
import { hasPermission } from './tokens';
import type { MsDirectory } from './types';

const CONTENT_TYPE = 'Audit.Exchange';
const DAY_MS = 24 * 60 * 60 * 1000;

export class O365ManagementSimulator implements Simulator {
  readonly name = 'o365';

  constructor(
    private readonly script: SimScript,
    readonly prefix = '/o365',
  ) {}

  errorBody(_status: number, code: string): unknown {
    return { error: { code, message: 'Simulated error.' } };
  }

  private error(status: number, code: string): SimResponse {
    return json(status, this.errorBody(status, code));
  }

  handle(request: SimRequest): SimResponse {
    const match =
      /^\/api\/v1\.0\/([^/]+)\/activity\/feed\/(subscriptions\/start|subscriptions\/content|audit\/([^/]+))$/.exec(
        request.path,
      );
    if (!match) return this.error(404, 'AF10000');
    const tenantId = decodeURIComponent(match[1] as string);
    const header = request.headers.authorization;
    const token = this.script.tokens.resolve(
      typeof header === 'string' ? header : undefined,
      tenantId,
    );
    if (!token || (token.resource !== null && token.resource !== 'o365_management')) {
      return this.error(401, 'AF10001');
    }
    if (token.directoryId !== tenantId) return this.error(401, 'AF10001');
    if (!hasPermission(token, ['ActivityFeed.Read'])) return this.error(403, 'AF10002');
    const directory = (this.script.dataset.microsoft?.directories ?? []).find(
      (d) => d.tenantId === tenantId,
    );
    if (!directory) return this.error(400, 'AF20010');
    if (!directory.licenses.unifiedAudit) return this.error(403, 'AF20023');
    const operation = match[2] as string;
    if (operation === 'subscriptions/start') {
      if (request.method !== 'POST') return this.error(405, 'AF10000');
      if (request.query.get('contentType') !== CONTENT_TYPE) return this.error(400, 'AF20021');
      directory.exchange.subscribed = true;
      return json(200, { contentType: CONTENT_TYPE, status: 'enabled', webhook: null });
    }
    if (request.method !== 'GET') return this.error(405, 'AF10000');
    if (!directory.exchange.subscribed) return this.error(400, 'AF20022');
    if (operation === 'subscriptions/content')
      return this.listContent(request, directory, tenantId);
    const blob = directory.exchange.blobs.find((b) => b.contentId === match[3]);
    return blob ? json(200, blob.records) : this.error(404, 'AF20051');
  }

  private listContent(request: SimRequest, directory: MsDirectory, tenantId: string): SimResponse {
    if (request.query.get('contentType') !== CONTENT_TYPE) return this.error(400, 'AF20021');
    const start = Date.parse(request.query.get('startTime') ?? '');
    const end = Date.parse(request.query.get('endTime') ?? '');
    const now = this.script.now();
    if (Number.isNaN(start) || Number.isNaN(end) || end <= start) return this.error(400, 'AF20055');
    if (end - start > DAY_MS || start < now - 7 * DAY_MS) return this.error(400, 'AF20055');
    const all = directory.exchange.blobs
      .filter((b) => {
        const created = Date.parse(b.contentCreated);
        return created >= start && created < end;
      })
      .sort((a, b) => Date.parse(a.contentCreated) - Date.parse(b.contentCreated));
    const pageSize = directory.exchange.listingPageSize ?? 3;
    const offset = Number(request.query.get('nextPage') ?? '0');
    if (!Number.isInteger(offset) || offset < 0) return this.error(400, 'AF20055');
    const slice = all.slice(offset, offset + pageSize);
    const base = `${request.publicBase}/api/v1.0/${encodeURIComponent(tenantId)}/activity/feed`;
    const body = slice.map((b) => ({
      contentType: CONTENT_TYPE,
      contentId: b.contentId,
      contentUri: `${base}/audit/${encodeURIComponent(b.contentId)}`,
      contentCreated: b.contentCreated,
      contentExpiration: new Date(Date.parse(b.contentCreated) + 7 * DAY_MS).toISOString(),
    }));
    const headers: Record<string, string> = {};
    if (offset + pageSize < all.length) {
      const params = new URLSearchParams(request.query);
      params.set('nextPage', String(offset + pageSize));
      headers.NextPageUri = `${base}/subscriptions/content?${params.toString()}`;
    }
    return json(200, body, headers);
  }
}

export const createO365Simulator = (script: SimScript): Simulator =>
  new O365ManagementSimulator(script);

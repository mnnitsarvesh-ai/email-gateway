import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { Principal } from '../../auth-contracts/principal';
import { systemScope } from '../../auth-contracts/tenant-scope';
import type { ApiConventionMetrics } from '../../http/api-metrics';
import { CursorCodec } from '../../http/cursor/cursor-codec';
import type { MessageDataRepository } from '../messages/repositories/message-data.repository';
import type { MessageDataService } from '../messages/services/message-data.service';
import type { MessagesRepository } from '../tenant-data/messages.repository';
import type {
  ClickRow,
  MessageUrlFullRow,
  UrlProtectionRepository,
} from './url-protection.repository';
import { MessageUrlsQuerySchema, UrlClicksQuerySchema } from './url-protection.schemas';
import {
  clickSummaries,
  latestUrlResults,
  toClickItem,
  toUrlItem,
  UrlProtectionService,
} from './url-protection.service';

const scope = systemScope(7n);
const principal: Principal = {
  kind: 'api_key',
  apiKeyId: 1n,
  apiKeyPublicId: randomUUID(),
  organizationId: 7n,
  organizationPublicId: randomUUID(),
  permissions: new Set(['message:read']),
};
const ref = {
  id: 5n,
  publicId: 'pub',
  receivedAt: new Date('2026-11-12T08:00:00Z'),
  organizationId: 7n,
};

const url = (seq: number, sha = 'a'.repeat(64)): MessageUrlFullRow =>
  ({
    urlSeq: seq,
    url: `https://x.example/${seq}`,
    urlSha256: sha,
    host: 'x.example',
    unicodeHost: null,
    registrableDomain: 'x.example',
    hostKind: 'domain',
    flags: ['url.userinfo', 'bogus'],
    sources: { html_href: 2, nonsense: 1 },
    organizationId: 7n,
    messageId: 5n,
  }) as unknown as MessageUrlFullRow;

const click = (id: number, at: string, over: Partial<ClickRow> = {}): ClickRow => ({
  id: BigInt(id),
  clickedAt: new Date(at),
  publicId: randomUUID(),
  organizationId: 7n,
  messageId: 5n,
  messageReceivedAt: ref.receivedAt,
  urlSeq: 0,
  decision: 'blocked',
  verdict: 'malicious',
  reasonCodes: ['url.feed_malicious', 'junk'],
  clientNetwork: '203.0.113.0/24',
  ...over,
});

function setup() {
  const codec = new CursorCodec({
    API_CURSOR_KEY: randomBytes(32).toString('hex'),
    API_CURSOR_KEY_PREVIOUS: undefined,
    API_CURSOR_TTL_SECONDS: 86_400,
  });
  const repo = {
    messageUrls: vi.fn<UrlProtectionRepository['messageUrls']>(),
    results: vi.fn<UrlProtectionRepository['results']>(() => Promise.resolve([])),
    latestRewrite: vi.fn<UrlProtectionRepository['latestRewrite']>(() => Promise.resolve(null)),
    clickCounts: vi.fn<UrlProtectionRepository['clickCounts']>(() => Promise.resolve([])),
    clicks: vi.fn<UrlProtectionRepository['clicks']>(),
    clicksBoundary: vi.fn<UrlProtectionRepository['clicksBoundary']>(),
    clickHosts: vi.fn<UrlProtectionRepository['clickHosts']>(() =>
      Promise.resolve(new Map([['5:0', { host: 'x.example', registrableDomain: 'x.example' }]])),
    ),
  };
  const messages = { messageRef: vi.fn(() => Promise.resolve(ref)) };
  const data = { scanRounds: vi.fn(() => Promise.resolve(new Map([[30n, 1]]))) };
  const identities = { publicIdMap: vi.fn(() => Promise.resolve(new Map([[5n, 'pub']]))) };
  const metrics = { scanBudgetExhausted: { inc: vi.fn() } };
  const service = new UrlProtectionService(
    { API_LIST_SCAN_BUDGET_ROWS: 1000 },
    repo as unknown as UrlProtectionRepository,
    messages as unknown as MessageDataService,
    data as unknown as MessageDataRepository,
    identities as unknown as MessagesRepository,
    codec,
    metrics as unknown as ApiConventionMetrics,
  );
  service.now = () => new Date('2026-11-12T12:00:00Z');
  return { service, repo, messages, metrics };
}

describe('URL protection (step 6.1 WP2)', () => {
  it('maps a URL: tenant view fields, latest result of the same URL, rewrite, clicks', () => {
    const latest = latestUrlResults([
      {
        scanId: 10n,
        urlSeq: 0,
        urlSha256: 'a'.repeat(64),
        verdict: 'clean',
        reasonCodes: [],
        rewritten: false,
      },
      {
        scanId: 30n,
        urlSeq: 0,
        urlSha256: 'a'.repeat(64),
        verdict: 'malicious',
        reasonCodes: ['url.feed_malicious'],
        rewritten: true,
      },
    ]);
    const clicks = clickSummaries([
      { urlSeq: 0, decision: 'blocked', count: 2 },
      { urlSeq: 0, decision: 'continued', count: 1 },
    ]);
    const rewrite = { round: 1, status: 'rewritten' as const, skipReason: null };
    const item = toUrlItem(url(0), latest.get(0), 1, rewrite, clicks.get(0));
    expect(item).toEqual({
      urlSeq: 0,
      url: 'https://x.example/0',
      host: 'x.example',
      unicodeHost: null,
      registrableDomain: 'x.example',
      hostKind: 'domain',
      sources: { html_href: 2 },
      flags: ['url.userinfo'],
      latest: {
        round: 1,
        verdict: 'malicious',
        reasonCodes: ['url.feed_malicious'],
        rewritten: true,
      },
      rewrite,
      clicks: { total: 3, byDecision: { blocked: 2, continued: 1 } },
    });
    // A result naming another URL (hash mismatch) is not shown, as in the scans view.
    expect(toUrlItem(url(0, 'b'.repeat(64)), latest.get(0), 1, null, undefined)).toMatchObject({
      latest: null,
      clicks: { total: 0, byDecision: {} },
    });
  });

  it('maps a click without token material', () => {
    const item = toClickItem(click(1, '2026-11-12T10:00:00.000Z'), 'pub', {
      host: 'x.example',
      registrableDomain: 'x.example',
    });
    expect(item).toMatchObject({
      decision: 'blocked',
      reasonCodes: ['url.feed_malicious'],
      messageId: 'pub',
      host: 'x.example',
    });
    expect(item).not.toHaveProperty('tokenKid');
  });

  it('URLs of a message: keyset urlSeq bound to the message', async () => {
    const t = setup();
    t.repo.messageUrls.mockResolvedValueOnce([url(0), url(1)]);
    const page = await t.service.ofMessage(
      principal,
      scope,
      'pub',
      MessageUrlsQuerySchema.parse({ limit: '1' }),
    );
    expect(page.data.map((u) => u.urlSeq)).toEqual([0]);
    expect(t.repo.clickCounts.mock.calls[0]![2]).toEqual([0]);
    t.repo.messageUrls.mockResolvedValueOnce([]);
    await t.service.ofMessage(
      principal,
      scope,
      'pub',
      MessageUrlsQuerySchema.parse({ cursor: page.nextCursor! }),
    );
    expect(t.repo.messageUrls.mock.calls[1]![2]).toMatchObject({ afterSeq: 0 });
  });

  it('clicks: unfiltered keyset; filtered scan-bounded with the boundary and the metric', async () => {
    const t = setup();
    t.repo.clicks.mockResolvedValueOnce([
      click(2, '2026-11-12T10:00:00.000Z'),
      click(1, '2026-11-12T09:00:00.000Z'),
    ]);
    const page = await t.service.clicks(
      principal,
      scope,
      UrlClicksQuerySchema.parse({ limit: '1' }),
    );
    expect(t.repo.clicksBoundary).not.toHaveBeenCalled();
    expect(t.repo.clicks.mock.calls[0]![1]).toMatchObject({
      range: { from: new Date('2026-11-11T12:00:00Z'), to: new Date('2026-11-12T12:00:00Z') },
      take: 2,
    });
    expect(page.nextCursor).toEqual(expect.any(String));

    t.repo.clicksBoundary.mockResolvedValueOnce({ at: new Date('2026-11-12T01:00:00Z'), id: 7n });
    t.repo.clicks.mockResolvedValueOnce([]);
    const filtered = await t.service.clicks(
      principal,
      scope,
      UrlClicksQuerySchema.parse({ decision: 'blocked,warned', messageId: randomUUID() }),
    );
    expect(t.repo.clicks.mock.calls[1]![1]).toMatchObject({
      boundary: { id: 7n },
      filters: {
        decisions: ['blocked', 'warned'],
        message: { id: 5n, receivedAt: ref.receivedAt },
      },
    });
    expect(filtered).toEqual({ data: [], nextCursor: expect.any(String) });
    expect(t.metrics.scanBudgetExhausted.inc).toHaveBeenCalledWith({ resource: 'url_clicks' });
  });

  it('clicks: a foreign messageId is 404 message_not_found; ranges over 31 days are 400', async () => {
    const t = setup();
    t.messages.messageRef.mockRejectedValueOnce(
      Object.assign(new Error('nf'), { code: 'message_not_found' }),
    );
    await expect(
      t.service.clicks(principal, scope, UrlClicksQuerySchema.parse({ messageId: randomUUID() })),
    ).rejects.toMatchObject({ code: 'message_not_found' });
    await expect(
      t.service.clicks(
        principal,
        scope,
        UrlClicksQuerySchema.parse({ from: '2026-10-01T00:00:00Z', to: '2026-11-12T00:00:00Z' }),
      ),
    ).rejects.toThrow('Bad Request');
  });
});

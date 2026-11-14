import { randomBytes, randomUUID } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import { MetricsService } from '@email-gateway/common';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConventionMetrics } from '../../../http/api-metrics';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import type { DomainsRepository } from '../../tenant-data/domains.repository';
import { sha256Hex } from '../domain/v1-list';
import { MessageListQuerySchema, MessageRecipientsQuerySchema } from '../dto/message-data.schemas';
import { messageSearchTimeout } from '../messages.errors';
import type {
  DeliveryRow,
  MessageDataRepository,
  MessageDetailRow,
  MessageListRow,
  RecipientKeyRow,
  RecipientRow,
} from '../repositories/message-data.repository';
import {
  driverKeyOf,
  latestDeliveries,
  MessageDataService,
  residualsOf,
  searchValuesOf,
  toMessageItem,
} from './message-data.service';

const ORG = randomUUID();
const scope = systemScope(7n);
const ALL_SEARCH = ['message:read', 'message:reveal', 'delivery:read', 'quarantine:read'];
const principal: Principal = {
  kind: 'api_key',
  apiKeyId: 1n,
  apiKeyPublicId: randomUUID(),
  organizationId: 7n,
  organizationPublicId: ORG,
  permissions: new Set(ALL_SEARCH),
};
const withPermissions = (permissions: string[]): Principal => ({
  ...principal,
  permissions: new Set(permissions),
});
const NOW = new Date('2026-11-12T12:00:00.000Z');

function row(id: number, at: string, over: Partial<MessageListRow> = {}): MessageListRow {
  return {
    id: BigInt(id),
    receivedAt: new Date(at),
    organizationId: 7n,
    domainId: null,
    direction: 'inbound',
    status: 'delivered',
    statusChangedAt: new Date(at),
    subject: 'Hello',
    envelopeFrom: 's@x.example',
    headerFrom: null,
    recipientCount: 1,
    attachmentCount: 0,
    sizeBytes: 100,
    finalVerdict: 'clean',
    finalAction: 'deliver',
    riskScore: 10,
    ...over,
  };
}

function setup(budget = 1000, cap = 500) {
  const codec = new CursorCodec({
    API_CURSOR_KEY: randomBytes(32).toString('hex'),
    API_CURSOR_KEY_PREVIOUS: undefined,
    API_CURSOR_TTL_SECONDS: 86_400,
  });
  const repo = {
    messagesPage: vi.fn<MessageDataRepository['messagesPage']>(),
    messagesBoundary: vi.fn<MessageDataRepository['messagesBoundary']>(),
    recipientRows: vi.fn<MessageDataRepository['recipientRows']>(),
    recipientBoundary: vi.fn<MessageDataRepository['recipientBoundary']>(),
    recipientPage: vi.fn<MessageDataRepository['recipientPage']>(),
    foreignKeys: vi.fn<MessageDataRepository['foreignKeys']>(),
    foreignBoundary: vi.fn<MessageDataRepository['foreignBoundary']>(),
    foreignPage: vi.fn<MessageDataRepository['foreignPage']>(),
    messagesByKeys: vi.fn<MessageDataRepository['messagesByKeys']>(),
    prefixProbe: vi.fn<MessageDataRepository['prefixProbe']>(),
    prefixPage: vi.fn<MessageDataRepository['prefixPage']>(),
    publicIds: vi.fn((_s: unknown, ids: readonly bigint[]) =>
      Promise.resolve(new Map(ids.map((id) => [id, `pub-${id}`]))),
    ),
    domainPublicIds: vi.fn((_s: unknown, ids: readonly bigint[]) =>
      Promise.resolve(new Map(ids.map((id) => [id, `dom-${id}`]))),
    ),
    findDetail: vi.fn<MessageDataRepository['findDetail']>(),
    findRef: vi.fn<MessageDataRepository['findRef']>(),
    recipients: vi.fn<MessageDataRepository['recipients']>(),
    deliveries: vi.fn<MessageDataRepository['deliveries']>(),
    userPublicIds: vi.fn((_s: unknown, ids: readonly bigint[]) =>
      Promise.resolve(new Map(ids.map((id) => [id, `user-${id}`]))),
    ),
  };
  const domains = { findByPublicId: vi.fn() };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'api_key', id: 'k' })),
  };
  const metrics = { scanBudgetExhausted: { inc: vi.fn() } };
  const registry = new MetricsService({ service: 'api-test' });
  const service = new MessageDataService(
    {
      API_MESSAGES_MAX_RANGE_DAYS: 31,
      API_LIST_SCAN_BUDGET_ROWS: budget,
      API_MESSAGES_SEARCH_MAX_MATCHES: cap,
      API_MESSAGES_SEARCH_TIMEOUT_MS: 2000,
    },
    repo as unknown as MessageDataRepository,
    domains as unknown as DomainsRepository,
    codec,
    audit as unknown as AuditService,
    metrics as unknown as ApiConventionMetrics,
    registry,
  );
  let now = NOW;
  service.now = () => now;
  const series = async (name: string) =>
    (await registry.metrics()).split('\n').filter((line) => line.startsWith(name));
  return { service, repo, domains, audit, metrics, series, setNow: (d: Date) => (now = d) };
}

const q = (query: Record<string, string>) => MessageListQuerySchema.parse(query);
const at = (iso: string) => new Date(iso);

describe('MessageDataService.list (step 6.1 D3–D6, D11; step 7.2 §2 E1, E2)', () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => {
    t = setup();
  });

  it('driver none: default 24 h window, full page continues after the last row, window pinned', async () => {
    t.repo.messagesPage.mockResolvedValueOnce([
      row(3, '2026-11-12T11:00:00.000Z'),
      row(2, '2026-11-12T10:00:00.000Z'),
      row(1, '2026-11-12T09:00:00.000Z'),
    ]);
    const first = await t.service.list(principal, scope, q({ limit: '2' }));
    expect(first.data.map((d) => d.id)).toEqual(['pub-3', 'pub-2']);
    expect(t.repo.messagesPage.mock.calls[0]![1]).toMatchObject({
      driver: 'none',
      key: undefined,
      range: { from: at('2026-11-11T12:00:00.000Z'), to: NOW },
      direction: 'desc',
      take: 3,
    });
    expect(t.repo.messagesPage.mock.calls[0]![1]).not.toHaveProperty('boundary');
    expect(first.nextCursor).toEqual(expect.any(String));

    // Later page: "now" moved, the window stays the first page's; the keyset is the last row.
    t.setNow(at('2026-11-12T13:00:00.000Z'));
    t.repo.messagesPage.mockResolvedValueOnce([row(1, '2026-11-12T09:00:00.000Z')]);
    const second = await t.service.list(
      principal,
      scope,
      q({ limit: '2', cursor: first.nextCursor! }),
    );
    expect(t.repo.messagesPage.mock.calls[1]![1]).toMatchObject({
      range: { from: at('2026-11-11T12:00:00.000Z'), to: NOW },
      after: { at: at('2026-11-12T10:00:00.000Z'), id: 2n },
    });
    expect(second).toEqual({ data: [expect.objectContaining({ id: 'pub-1' })], nextCursor: null });
    expect(await t.series('api_message_list_plan_total{')).toEqual([
      'api_message_list_plan_total{driver="none",budgeted="false",service="api-test"} 2',
    ]);
  });

  it('a cursor under other filters, sort or with another explicit window is cursor_invalid', async () => {
    t.repo.messagesPage.mockResolvedValue([
      row(2, '2026-11-12T10:00:00.000Z'),
      row(1, '2026-11-12T09:00:00.000Z'),
    ]);
    const { nextCursor } = await t.service.list(principal, scope, q({ limit: '1' }));
    for (const query of [
      { limit: '1', cursor: nextCursor!, direction: 'inbound' } as Record<string, string>,
      { limit: '1', cursor: nextCursor!, sort: 'receivedAt' },
      { limit: '1', cursor: nextCursor!, to: '2026-11-12T11:00:00Z' },
    ]) {
      await expect(t.service.list(principal, scope, q(query))).rejects.toMatchObject({
        code: 'cursor_invalid',
      });
    }
    // Another organization presenting the cursor.
    await expect(
      t.service.list(
        { ...principal, organizationPublicId: randomUUID() },
        scope,
        q({ cursor: nextCursor! }),
      ),
    ).rejects.toMatchObject({ code: 'cursor_invalid' });
  });

  it('a range longer than API_MESSAGES_MAX_RANGE_DAYS or reversed is 400', async () => {
    await expect(
      t.service.list(
        principal,
        scope,
        q({ from: '2026-10-01T00:00:00Z', to: '2026-11-12T00:00:00Z' }),
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      t.service.list(
        principal,
        scope,
        q({ from: '2026-11-12T00:00:00Z', to: '2026-11-11T00:00:00Z' }),
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(t.repo.messagesPage).not.toHaveBeenCalled();
  });

  it.each([
    [{ internetMessageId: ' <ID@MX.example> ' }, 'internetMessageId', 'ID@MX.example'],
    [{ sender: 'Boss@Corp.example' }, 'sender', 'boss@corp.example'],
    [{ headerFrom: 'Boss <boss@corp.example>' }, 'headerFrom', 'Boss <boss@corp.example>'],
    [{ subject: 'RE: Fwd:  Quarterly\treport ' }, 'subject', 'Quarterly report'],
    [{ senderDomain: '@Corp.Example' }, 'senderDomain', 'corp.example'],
    [{ verdict: 'spam', sort: 'receivedAt' }, 'verdict', 'spam'],
  ])('an email_messages driver reads its index exactly: %o', async (query, driver, key) => {
    t.repo.messagesPage.mockResolvedValue([row(1, '2026-11-12T09:00:00.000Z')]);
    const page = await t.service.list(principal, scope, q(query));
    expect(t.repo.messagesPage).toHaveBeenCalledTimes(1);
    expect(t.repo.messagesPage.mock.calls[0]![1]).toMatchObject({ driver, key });
    expect(t.repo.messagesBoundary).not.toHaveBeenCalled();
    expect(page.nextCursor).toBeNull();
  });

  it('a driver with residuals is budgeted over its index; a short page continues at the boundary', async () => {
    t.repo.messagesBoundary.mockResolvedValue({ at: at('2026-11-12T01:00:00.000Z'), id: 5n });
    t.repo.messagesPage.mockResolvedValue([row(9, '2026-11-12T10:00:00.000Z')]);
    const page = await t.service.list(
      principal,
      scope,
      q({ sender: 'a@b.example', direction: 'outbound', 'riskScore.gte': '500', limit: '10' }),
    );
    expect(t.repo.messagesBoundary.mock.calls[0]![1]).toMatchObject({
      driver: 'sender',
      key: 'a@b.example',
      budget: 1000,
    });
    expect(t.repo.messagesPage.mock.calls[0]![1]).toMatchObject({
      driver: 'sender',
      key: 'a@b.example',
      boundary: { at: at('2026-11-12T01:00:00.000Z'), id: 5n },
      residuals: { direction: ['outbound'], riskScore: { gte: 500 } },
    });
    expect(page.data).toHaveLength(1);
    expect(t.metrics.scanBudgetExhausted.inc).toHaveBeenCalledWith({ resource: 'messages' });
    t.repo.messagesBoundary.mockResolvedValue(null);
    t.repo.messagesPage.mockResolvedValue([]);
    await t.service.list(
      principal,
      scope,
      q({
        sender: 'a@b.example',
        direction: 'outbound',
        'riskScore.gte': '500',
        limit: '10',
        cursor: page.nextCursor!,
      }),
    );
    expect(t.repo.messagesBoundary.mock.calls[1]![1].after).toEqual({
      at: at('2026-11-12T01:00:00.000Z'),
      id: 5n,
    });
    expect(await t.series('api_message_list_plan_total{')).toEqual([
      'api_message_list_plan_total{driver="sender",budgeted="true",service="api-test"} 2',
    ]);
  });

  it('scan (residuals only): an empty page with a boundary has a nextCursor; a filled page continues after its last row', async () => {
    t.repo.messagesBoundary.mockResolvedValueOnce({ at: at('2026-11-12T01:00:00.000Z'), id: 5n });
    t.repo.messagesPage.mockResolvedValueOnce([]);
    const empty = await t.service.list(principal, scope, q({ hasAttachments: 'true' }));
    expect(t.repo.messagesPage.mock.calls[0]![1]).toMatchObject({
      driver: 'scan',
      residuals: { hasAttachments: true },
    });
    expect(empty.data).toEqual([]);
    expect(empty.nextCursor).toEqual(expect.any(String));
    t.repo.messagesBoundary.mockResolvedValueOnce(null);
    t.repo.messagesPage.mockResolvedValueOnce([row(1, '2026-11-12T09:00:00.000Z')]);
    expect(
      (await t.service.list(principal, scope, q({ hasAttachments: 'true' }))).nextCursor,
    ).toBeNull();

    t.repo.messagesBoundary.mockResolvedValue({ at: at('2026-11-12T01:00:00.000Z'), id: 5n });
    t.repo.messagesPage.mockResolvedValue([
      row(9, '2026-11-12T10:00:00.000Z'),
      row(8, '2026-11-12T09:00:00.000Z'),
    ]);
    t.metrics.scanBudgetExhausted.inc.mockClear();
    const page = await t.service.list(principal, scope, q({ status: 'delivered', limit: '1' }));
    expect(t.metrics.scanBudgetExhausted.inc).not.toHaveBeenCalled();
    t.repo.messagesPage.mockResolvedValue([]);
    await t.service.list(
      principal,
      scope,
      q({ status: 'delivered', limit: '1', cursor: page.nextCursor! }),
    );
    expect(t.repo.messagesBoundary.mock.calls.at(-1)![1].after).toEqual({
      at: at('2026-11-12T10:00:00.000Z'),
      id: 9n,
    });
  });

  it('several verdicts are residual (scan); one verdict with other filters is budgeted', async () => {
    t.repo.messagesBoundary.mockResolvedValue(null);
    t.repo.messagesPage.mockResolvedValue([]);
    await t.service.list(principal, scope, q({ verdict: 'spam,phishing' }));
    expect(t.repo.messagesPage.mock.calls[0]![1]).toMatchObject({
      driver: 'scan',
      residuals: { verdict: ['spam', 'phishing'] },
    });
    await t.service.list(principal, scope, q({ verdict: 'spam', direction: 'inbound' }));
    expect(t.repo.messagesPage.mock.calls[1]![1]).toMatchObject({
      driver: 'verdict',
      key: 'spam',
      residuals: { direction: ['inbound'] },
    });
  });

  it('recipient driver (exact) collapses a message listed twice and continues after the recipient row', async () => {
    const r = (id: number, messageId: number, iso: string): RecipientKeyRow => ({
      id: BigInt(id),
      messageId: BigInt(messageId),
      receivedAt: at(iso),
      organizationId: 7n,
    });
    t.repo.recipientRows.mockResolvedValue([
      r(30, 3, '2026-11-12T11:00:00.000Z'),
      r(29, 3, '2026-11-12T11:00:00.000Z'),
      r(20, 2, '2026-11-12T10:00:00.000Z'),
      r(10, 1, '2026-11-12T09:00:00.000Z'),
    ]);
    t.repo.messagesByKeys.mockResolvedValue([
      row(2, '2026-11-12T10:00:00.000Z'),
      row(3, '2026-11-12T11:00:00.000Z'),
    ]);
    const page = await t.service.list(
      principal,
      scope,
      q({ recipient: 'A@X.example', limit: '3' }),
    );
    expect(t.repo.recipientRows.mock.calls[0]![1]).toMatchObject({
      address: 'a@x.example',
      take: 4,
    });
    expect(t.repo.messagesByKeys.mock.calls[0]![2]).toEqual([
      { id: 3n, receivedAt: at('2026-11-12T11:00:00.000Z') },
      { id: 2n, receivedAt: at('2026-11-12T10:00:00.000Z') },
    ]);
    expect(page.data.map((d) => d.id)).toEqual(['pub-3', 'pub-2']);
    t.repo.recipientRows.mockResolvedValue([]);
    await t.service.list(
      principal,
      scope,
      q({ recipient: 'a@x.example', limit: '3', cursor: page.nextCursor! }),
    );
    expect(t.repo.recipientRows.mock.calls[1]![1].after).toEqual({
      at: at('2026-11-12T10:00:00.000Z'),
      id: 20n,
    });
  });

  it('recipient driver (budgeted) keeps the recipient keyset and collapses repeats', async () => {
    t.repo.recipientBoundary.mockResolvedValue({ at: at('2026-11-12T01:00:00.000Z'), id: 7n });
    t.repo.recipientPage.mockResolvedValue([
      { ...row(3, '2026-11-12T11:00:00.000Z'), rid: 30n },
      { ...row(3, '2026-11-12T11:00:00.000Z'), rid: 29n },
      { ...row(2, '2026-11-12T10:00:00.000Z'), rid: 20n },
    ]);
    const page = await t.service.list(
      principal,
      scope,
      q({ recipient: 'a@x.example', verdict: 'spam,phishing', limit: '2' }),
    );
    expect(t.repo.recipientPage.mock.calls[0]![1]).toMatchObject({
      address: 'a@x.example',
      boundary: { at: at('2026-11-12T01:00:00.000Z'), id: 7n },
      residuals: { verdict: ['spam', 'phishing'] },
    });
    // Two recipient rows fill the page (limit 2); both are message 3: one item; next = rid 29.
    expect(page.data.map((d) => d.id)).toEqual(['pub-3']);
    t.repo.recipientPage.mockResolvedValue([]);
    await t.service.list(
      principal,
      scope,
      q({
        recipient: 'a@x.example',
        verdict: 'spam,phishing',
        limit: '2',
        cursor: page.nextCursor!,
      }),
    );
    expect(t.repo.recipientBoundary.mock.calls[1]![1].after).toEqual({
      at: at('2026-11-12T11:00:00.000Z'),
      id: 29n,
    });
  });

  it.each([
    [{ recipientDomain: 'Partner.example' }, 'recipientDomain', 'partner.example'],
    [{ deliveryStatus: 'bounced' }, 'deliveryStatus', 'bounced'],
    [{ quarantineStatus: 'held' }, 'quarantineStatus', 'held'],
  ])(
    'a foreign driver reads grouped keys then the messages by key: %o',
    async (query, driver, key) => {
      t.repo.foreignKeys.mockResolvedValue([
        { receivedAt: at('2026-11-12T11:00:00.000Z'), id: 3n },
        { receivedAt: at('2026-11-12T10:00:00.000Z'), id: 2n },
        { receivedAt: at('2026-11-12T09:00:00.000Z'), id: 1n },
      ]);
      t.repo.messagesByKeys.mockResolvedValue([
        row(2, '2026-11-12T10:00:00.000Z'),
        row(3, '2026-11-12T11:00:00.000Z'),
      ]);
      const page = await t.service.list(principal, scope, q({ ...query, limit: '2' }));
      expect(t.repo.foreignKeys.mock.calls[0]![1]).toMatchObject({ driver, key, take: 3 });
      expect(page.data.map((d) => d.id)).toEqual(['pub-3', 'pub-2']);
      t.repo.foreignKeys.mockResolvedValue([]);
      await t.service.list(principal, scope, q({ ...query, limit: '2', cursor: page.nextCursor! }));
      expect(t.repo.foreignKeys.mock.calls[1]![1].after).toEqual({
        at: at('2026-11-12T10:00:00.000Z'),
        id: 2n,
      });
    },
  );

  it('a foreign driver with residuals is budgeted (boundary over raw entries)', async () => {
    t.repo.foreignBoundary.mockResolvedValue(null);
    t.repo.foreignPage.mockResolvedValue([row(4, '2026-11-12T08:00:00.000Z')]);
    const page = await t.service.list(
      principal,
      scope,
      q({ deliveryStatus: 'deferred', quarantineStatus: 'held', hasAttachments: 'false' }),
    );
    // quarantineStatus outranks deliveryStatus.
    expect(t.repo.foreignBoundary.mock.calls[0]![1]).toMatchObject({
      driver: 'quarantineStatus',
      key: 'held',
      budget: 1000,
    });
    expect(t.repo.foreignPage.mock.calls[0]![1]).toMatchObject({
      driver: 'quarantineStatus',
      boundary: null,
      residuals: { deliveryStatus: 'deferred', hasAttachments: false },
    });
    expect(page).toMatchObject({ data: [{ id: 'pub-4' }], nextCursor: null });
  });

  it('subject prefix: probe within the cap, then the sorted page with residuals', async () => {
    t.repo.prefixProbe.mockResolvedValue(false);
    t.repo.prefixPage.mockResolvedValue([row(5, '2026-11-12T09:00:00.000Z')]);
    const page = await t.service.list(
      principal,
      scope,
      q({ subjectPrefix: 'Re: Invoice 100%', direction: 'inbound' }),
    );
    expect(t.repo.prefixProbe.mock.calls[0]![1]).toMatchObject({
      pattern: 'Invoice 100!%%',
      cap: 500,
      timeoutMs: 2000,
    });
    expect(t.repo.prefixPage.mock.calls[0]![1]).toMatchObject({
      pattern: 'Invoice 100!%%',
      residuals: { direction: ['inbound'] },
    });
    expect(page.nextCursor).toBeNull();
    expect(await t.series('api_message_list_plan_total{')).toEqual([
      'api_message_list_plan_total{driver="subjectPrefix",budgeted="false",service="api-test"} 1',
    ]);
  });

  it('subject prefix: more than the cap is 422 message_search_too_broad (no page read)', async () => {
    t.repo.prefixProbe.mockResolvedValue(true);
    await expect(
      t.service.list(principal, scope, q({ subjectPrefix: 'Invoice' })),
    ).rejects.toMatchObject({ code: 'message_search_too_broad', status: 422 });
    expect(t.repo.prefixPage).not.toHaveBeenCalled();
    expect(await t.series('api_message_search_refused_total{')).toEqual([
      'api_message_search_refused_total{reason="too_broad",service="api-test"} 1',
    ]);
  });

  it('subject prefix: a MAX_EXECUTION_TIME timeout is 503 message_search_timeout (counted)', async () => {
    t.repo.prefixProbe.mockResolvedValue(false);
    t.repo.prefixPage.mockRejectedValue(messageSearchTimeout());
    await expect(
      t.service.list(principal, scope, q({ subjectPrefix: 'Invoice' })),
    ).rejects.toMatchObject({ code: 'message_search_timeout', status: 503 });
    expect(await t.series('api_message_search_refused_total{')).toEqual([
      'api_message_search_refused_total{reason="timeout",service="api-test"} 1',
    ]);
  });

  it.each([
    [{ recipient: 'alice@acme.example' }, 'recipient', 'message:reveal'],
    [{ subject: 'Hello' }, 'subject', 'message:reveal'],
    [{ subjectPrefix: 'Hello' }, 'subjectPrefix', 'message:reveal'],
    [{ deliveryStatus: 'bounced' }, 'deliveryStatus', 'delivery:read'],
    [{ quarantineStatus: 'held' }, 'quarantineStatus', 'quarantine:read'],
  ])(
    'filter-level permission %o → 403 message_filter_forbidden before any read',
    async (query, filter, permission) => {
      const lacking = withPermissions(ALL_SEARCH.filter((p) => p !== permission));
      await expect(
        t.service.list(lacking, scope, q({ ...query, domainId: randomUUID() })),
      ).rejects.toMatchObject({
        code: 'message_filter_forbidden',
        status: 403,
        details: { filter, permission },
      });
      for (const fn of Object.values(t.repo)) expect(fn).not.toHaveBeenCalled();
      expect(t.domains.findByPublicId).not.toHaveBeenCalled();
      expect(t.audit.record).not.toHaveBeenCalled();
    },
  );

  it('message:read alone still lists with the ungated filters', async () => {
    t.repo.messagesPage.mockResolvedValue([]);
    const page = await t.service.list(
      withPermissions(['message:read']),
      scope,
      q({ senderDomain: 'a.example' }),
    );
    expect(page.data).toEqual([]);
    // The recipient domain stays open: the masked address keeps its domain in clear.
    t.repo.foreignKeys.mockResolvedValue([]);
    t.repo.messagesByKeys.mockResolvedValue([]);
    const byDomain = await t.service.list(
      withPermissions(['message:read']),
      scope,
      q({ recipientDomain: 'acme.example' }),
    );
    expect(byDomain.data).toEqual([]);
  });

  it('domainId is resolved in the scope; unknown or foreign → 404 domain_not_found', async () => {
    const domainId = randomUUID();
    t.domains.findByPublicId.mockResolvedValueOnce(null);
    await expect(t.service.list(principal, scope, q({ domainId }))).rejects.toMatchObject({
      code: 'domain_not_found',
    });
    expect(t.domains.findByPublicId).toHaveBeenCalledWith(scope, domainId);
    t.domains.findByPublicId.mockResolvedValueOnce({ id: 44n });
    t.repo.messagesBoundary.mockResolvedValue(null);
    t.repo.messagesPage.mockResolvedValue([row(1, '2026-11-12T09:00:00.000Z', { domainId: 44n })]);
    const page = await t.service.list(principal, scope, q({ domainId }));
    expect(t.repo.messagesPage.mock.calls[0]![1].residuals).toEqual({ domainId: 44n });
    expect(page.data[0]!.domainId).toBe('dom-44');
  });

  it('audits identifying searches on the first page only, hashing the (normalized) values', async () => {
    t.repo.messagesBoundary.mockResolvedValue({ at: at('2026-11-12T01:00:00.000Z'), id: 5n });
    t.repo.messagesPage.mockResolvedValue([row(1, '2026-11-12T09:00:00.000Z')]);
    const page = await t.service.list(
      principal,
      scope,
      q({ sender: 'Boss@Corp.example', direction: 'inbound', subject: 'Re:  Pay  now' }),
      '10.0.0.1',
    );
    expect(t.audit.record).toHaveBeenCalledTimes(1);
    const entry = (t.audit.record.mock.calls[0] as unknown[])[0] as Record<string, unknown>;
    expect(entry).toMatchObject({
      organizationId: 7n,
      action: 'message.searched',
      resourceType: 'message',
      sourceIp: '10.0.0.1',
      metadata: {
        filters: ['direction', 'sender', 'subject'],
        plan: 'sender',
        budgeted: true,
        resultCount: 1,
        valueSha256: {
          sender: sha256Hex('boss@corp.example'),
          subject: sha256Hex('Pay now'),
        },
      },
    });
    expect(JSON.stringify(entry.metadata)).not.toMatch(/boss@corp\.example|Pay now/);
    await t.service.list(
      principal,
      scope,
      q({
        sender: 'boss@corp.example',
        direction: 'inbound',
        subject: 'Re:  Pay  now',
        cursor: page.nextCursor!,
      }),
    );
    expect(t.audit.record).toHaveBeenCalledTimes(1);
    t.repo.messagesPage.mockResolvedValue([]);
    await t.service.list(principal, scope, q({ senderDomain: 'corp.example' }));
    expect(t.audit.record).toHaveBeenCalledTimes(1);
  });

  it('never serves a row without a registry public id', async () => {
    t.repo.messagesPage.mockResolvedValue([
      row(2, '2026-11-12T10:00:00.000Z'),
      row(1, '2026-11-12T09:00:00.000Z'),
    ]);
    t.repo.publicIds.mockResolvedValueOnce(new Map([[1n, 'pub-1']]));
    const page = await t.service.list(principal, scope, q({}));
    expect(page.data.map((d) => d.id)).toEqual(['pub-1']);
  });
});

describe('search values and residuals (step 7.2 §3.2)', () => {
  it('normalizes every search value the SQL compares', () => {
    const filters = q({
      internetMessageId: '<a@b>',
      subject: 'AW: Hi',
      subjectPrefix: 'Fwd: 50%_off',
      sender: 'A@B.example',
      senderDomain: '@B.example',
      recipientDomain: 'C.example',
      verdict: 'spam,bulk',
    }).filters;
    expect(searchValuesOf(filters)).toEqual({
      internetMessageId: 'a@b',
      subject: 'Hi',
      subjectPrefix: '50!%!_off%',
      sender: 'a@b.example',
      senderDomain: 'b.example',
      recipientDomain: 'c.example',
      verdict: ['spam', 'bulk'],
    });
  });

  it('maps every residual filter to its resolved predicate value', () => {
    const filters = q({
      direction: 'inbound,outbound',
      status: 'delivered',
      verdict: 'spam,bulk',
      action: 'deliver',
      domainId: randomUUID(),
      sender: 'a@b.example',
      headerFrom: 'A <a@b.example>',
      recipient: 'r@c.example',
      'riskScore.gte': '10',
      hasAttachments: 'false',
      internetMessageId: '<i@d>',
      subject: 'Re: S',
      subjectPrefix: 'Pre',
      senderDomain: 'b.example',
      recipientDomain: 'c.example',
      deliveryStatus: 'bounced',
      quarantineStatus: 'released',
    }).filters;
    const values = searchValuesOf(filters);
    const names = Object.keys(filters) as Parameters<typeof residualsOf>[0];
    expect(residualsOf(names, filters, values, 9n)).toEqual({
      direction: ['inbound', 'outbound'],
      status: ['delivered'],
      verdict: ['spam', 'bulk'],
      action: ['deliver'],
      domainId: 9n,
      sender: 'a@b.example',
      headerFrom: 'A <a@b.example>',
      recipient: 'r@c.example',
      riskScore: { gte: 10 },
      hasAttachments: false,
      messageIdKey: 'i@d',
      subjectKey: 'S',
      subjectPrefixPattern: 'Pre%',
      senderDomain: 'b.example',
      recipientDomain: 'c.example',
      deliveryStatus: 'bounced',
      quarantineStatus: 'released',
    });
    expect(driverKeyOf({ driver: 'none', residuals: [], budgeted: false }, values)).toBeUndefined();
    expect(
      driverKeyOf({ driver: 'verdict', residuals: [], budgeted: false }, { verdict: ['x'] }),
    ).toBe('x');
  });
});

describe('message detail and recipients', () => {
  it('maps the detail and answers 404 message_not_found', async () => {
    const t = setup();
    t.repo.findDetail.mockResolvedValueOnce(null);
    await expect(t.service.detail(scope, randomUUID())).rejects.toMatchObject({
      code: 'message_not_found',
    });
    const detail = {
      ...row(5, '2026-11-12T09:00:00.000Z', { domainId: 3n }),
      publicId: 'pub',
      internetMessageId: '<a@b>',
      lifecycleRound: 1,
      version: 4,
      statusReason: 'delivered',
      clientIp: '192.0.2.1',
      clientHelo: 'helo',
      mtaQueueId: 'Q1',
    } as unknown as MessageDetailRow;
    t.repo.findDetail.mockResolvedValueOnce(detail);
    const view = await t.service.detail(scope, 'pub');
    expect(view).toMatchObject({ id: 'pub', domainId: 'dom-3', version: 4, mtaQueueId: 'Q1' });
    expect(view).not.toHaveProperty('emlObjectKey');
    // Step 7.2 (§2 E5): the subject is withheld for every caller.
    expect(view).toMatchObject({ subject: null, subjectMasked: true });
    expect(JSON.stringify(view)).not.toContain('Hello');
  });

  it('recipients: keyset rcptSeq, latest delivery, masked addresses, user ids withheld (7.2)', async () => {
    const t = setup();
    const ref = { id: 5n, publicId: 'pub', receivedAt: new Date(), organizationId: 7n };
    t.repo.findRef.mockResolvedValue(ref);
    const rcpt = (id: number, seq: number, userId: bigint | null): RecipientRow => ({
      id: BigInt(id),
      organizationId: 7n,
      messageId: 5n,
      receivedAt: ref.receivedAt,
      rcptSeq: seq,
      address: `r${seq}@x.example`,
      status: 'delivered',
      finalAction: 'deliver',
      direction: 'inbound',
      userId,
    });
    t.repo.recipients.mockResolvedValueOnce([
      rcpt(11, 0, 9n),
      rcpt(12, 1, null),
      rcpt(13, 2, null),
    ]);
    const delivery = (recipientId: number, seq: number, status: string): DeliveryRow =>
      ({
        organizationId: 7n,
        messageId: 5n,
        recipientId: BigInt(recipientId),
        deliverySeq: seq,
        status,
        finalSmtpCode: 250,
        deliveredAt: null,
      }) as DeliveryRow;
    t.repo.deliveries.mockResolvedValueOnce([
      delivery(11, 0, 'deferred'),
      delivery(11, 1, 'delivered'),
    ]);
    const query = MessageRecipientsQuerySchema.parse({ limit: '2' });
    const page = await t.service.recipients(principal, scope, 'pub', query);
    expect(page.data).toEqual([
      expect.objectContaining({
        rcptSeq: 0,
        address: 'r***@x.example',
        addressMasked: true,
        userId: null,
        latestDelivery: {
          deliverySeq: 1,
          status: 'delivered',
          finalSmtpCode: 250,
          deliveredAt: null,
        },
      }),
      expect.objectContaining({
        rcptSeq: 1,
        address: 'r***@x.example',
        addressMasked: true,
        userId: null,
        latestDelivery: null,
      }),
    ]);
    expect(JSON.stringify(page)).not.toMatch(/r0@|r1@|user-9/);
    // The matched user is never looked up (withheld).
    expect(t.repo.userPublicIds).not.toHaveBeenCalled();
    t.repo.recipients.mockResolvedValueOnce([]);
    t.repo.deliveries.mockResolvedValueOnce([]);
    await t.service.recipients(
      principal,
      scope,
      'pub',
      MessageRecipientsQuerySchema.parse({ cursor: page.nextCursor! }),
    );
    expect(t.repo.recipients.mock.calls[1]![2]).toMatchObject({ afterSeq: 1 });
    // A cursor of another message is refused.
    await expect(
      t.service.recipients(
        principal,
        scope,
        'other',
        MessageRecipientsQuerySchema.parse({ cursor: page.nextCursor! }),
      ),
    ).rejects.toMatchObject({ code: 'cursor_invalid' });
    t.repo.findRef.mockResolvedValueOnce(null);
    await expect(
      t.service.recipients(principal, scope, 'x', MessageRecipientsQuerySchema.parse({})),
    ).rejects.toMatchObject({ code: 'message_not_found' });
  });

  it('latestDeliveries keeps the highest delivery_seq', () => {
    const rows = [
      { recipientId: 1n, deliverySeq: 0 },
      { recipientId: 1n, deliverySeq: 2 },
      { recipientId: 1n, deliverySeq: 1 },
      { recipientId: 2n, deliverySeq: 0 },
    ] as DeliveryRow[];
    const latest = latestDeliveries(rows);
    expect(latest.get(1n)?.deliverySeq).toBe(2);
    expect(latest.get(2n)?.deliverySeq).toBe(0);
  });

  it('toMessageItem never exposes internal ids', () => {
    const item = toMessageItem(row(5, '2026-11-12T09:00:00.000Z', { domainId: 3n }), 'pub', 'dom');
    expect(item.id).toBe('pub');
    expect(item.domainId).toBe('dom');
    expect(JSON.stringify(item)).not.toMatch(/"5"|organizationId/);
  });

  it('toMessageItem withholds the subject: subjectMasked only when one exists (7.2 §2 E5)', () => {
    const at = '2026-11-12T09:00:00.000Z';
    expect(toMessageItem(row(5, at, { subject: 'Pay now' }), 'p', null)).toMatchObject({
      subject: null,
      subjectMasked: true,
    });
    expect(toMessageItem(row(5, at, { subject: null }), 'p', null)).toMatchObject({
      subject: null,
      subjectMasked: false,
    });
    // Sender addresses stay clear (triage needs them, §1.5).
    expect(toMessageItem(row(5, at), 'p', null).envelopeFrom).toBe(row(5, at).envelopeFrom);
  });
});

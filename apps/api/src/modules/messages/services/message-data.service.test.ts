import { randomBytes, randomUUID } from 'node:crypto';
import { BadRequestException } from '@nestjs/common';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConventionMetrics } from '../../../http/api-metrics';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import type { DomainsRepository } from '../../tenant-data/domains.repository';
import { MessageListQuerySchema, MessageRecipientsQuerySchema } from '../dto/message-data.schemas';
import type {
  DeliveryRow,
  MessageDataRepository,
  MessageDetailRow,
  MessageListRow,
  RecipientKeyRow,
  RecipientRow,
} from '../repositories/message-data.repository';
import { latestDeliveries, MessageDataService, toMessageItem } from './message-data.service';

const ORG = randomUUID();
const scope = systemScope(7n);
const principal: Principal = {
  kind: 'api_key',
  apiKeyId: 1n,
  apiKeyPublicId: randomUUID(),
  organizationId: 7n,
  organizationPublicId: ORG,
  permissions: new Set(['message:read']),
};
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

function setup(budget = 1000) {
  const codec = new CursorCodec({
    API_CURSOR_KEY: randomBytes(32).toString('hex'),
    API_CURSOR_KEY_PREVIOUS: undefined,
    API_CURSOR_TTL_SECONDS: 86_400,
  });
  const repo = {
    indexPlan: vi.fn<MessageDataRepository['indexPlan']>(),
    verdictPlan: vi.fn<MessageDataRepository['verdictPlan']>(),
    recipientRows: vi.fn<MessageDataRepository['recipientRows']>(),
    messagesByKeys: vi.fn<MessageDataRepository['messagesByKeys']>(),
    scanBoundary: vi.fn<MessageDataRepository['scanBoundary']>(),
    scanPage: vi.fn<MessageDataRepository['scanPage']>(),
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
  const service = new MessageDataService(
    { API_MESSAGES_MAX_RANGE_DAYS: 31, API_LIST_SCAN_BUDGET_ROWS: budget },
    repo as unknown as MessageDataRepository,
    domains as unknown as DomainsRepository,
    codec,
    audit as unknown as AuditService,
    metrics as unknown as ApiConventionMetrics,
  );
  let now = NOW;
  service.now = () => now;
  return { service, repo, domains, audit, metrics, setNow: (d: Date) => (now = d) };
}

const q = (query: Record<string, string>) => MessageListQuerySchema.parse(query);

describe('MessageDataService.list (step 6.1 D3–D6, D11)', () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => {
    t = setup();
  });

  it('index plan: default 24 h window, full page continues after the last row, window pinned', async () => {
    t.repo.indexPlan.mockResolvedValueOnce([
      row(3, '2026-11-12T11:00:00.000Z'),
      row(2, '2026-11-12T10:00:00.000Z'),
      row(1, '2026-11-12T09:00:00.000Z'),
    ]);
    const first = await t.service.list(principal, scope, q({ limit: '2' }));
    expect(first.data.map((d) => d.id)).toEqual(['pub-3', 'pub-2']);
    expect(t.repo.indexPlan.mock.calls[0]![1]).toMatchObject({
      range: { from: new Date('2026-11-11T12:00:00.000Z'), to: NOW },
      direction: 'desc',
      take: 3,
    });
    expect(first.nextCursor).toEqual(expect.any(String));

    // Later page: "now" moved, the window stays the first page's; the keyset is the last row.
    t.setNow(new Date('2026-11-12T13:00:00.000Z'));
    t.repo.indexPlan.mockResolvedValueOnce([row(1, '2026-11-12T09:00:00.000Z')]);
    const second = await t.service.list(
      principal,
      scope,
      q({ limit: '2', cursor: first.nextCursor! }),
    );
    expect(t.repo.indexPlan.mock.calls[1]![1]).toMatchObject({
      range: { from: new Date('2026-11-11T12:00:00.000Z'), to: NOW },
      after: { at: new Date('2026-11-12T10:00:00.000Z'), id: 2n },
    });
    expect(second).toEqual({ data: [expect.objectContaining({ id: 'pub-1' })], nextCursor: null });
  });

  it('a cursor under other filters, sort or with another explicit window is cursor_invalid', async () => {
    t.repo.indexPlan.mockResolvedValue([
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
    expect(t.repo.indexPlan).not.toHaveBeenCalled();
  });

  it('verdict plan with one verdict, ascending sort', async () => {
    t.repo.verdictPlan.mockResolvedValue([
      row(1, '2026-11-12T09:00:00.000Z', { finalVerdict: 'spam' }),
    ]);
    const page = await t.service.list(principal, scope, q({ verdict: 'spam', sort: 'receivedAt' }));
    expect(t.repo.verdictPlan.mock.calls[0]![1]).toMatchObject({
      verdict: 'spam',
      direction: 'asc',
    });
    expect(page.data[0]).toMatchObject({ finalVerdict: 'spam' });
    expect(t.audit.record).not.toHaveBeenCalled();
  });

  it('recipient plan collapses a message listed twice and continues after the recipient row', async () => {
    const r = (id: number, messageId: number, at: string): RecipientKeyRow => ({
      id: BigInt(id),
      messageId: BigInt(messageId),
      receivedAt: new Date(at),
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
      { id: 3n, receivedAt: new Date('2026-11-12T11:00:00.000Z') },
      { id: 2n, receivedAt: new Date('2026-11-12T10:00:00.000Z') },
    ]);
    expect(page.data.map((d) => d.id)).toEqual(['pub-3', 'pub-2']);
    t.repo.recipientRows.mockResolvedValue([]);
    await t.service.list(
      principal,
      scope,
      q({ recipient: 'a@x.example', limit: '3', cursor: page.nextCursor! }),
    );
    expect(t.repo.recipientRows.mock.calls[1]![1].after).toEqual({
      at: new Date('2026-11-12T10:00:00.000Z'),
      id: 20n,
    });
  });

  it('scan plan: a short page within the budget window continues at the boundary (metric)', async () => {
    t.repo.scanBoundary.mockResolvedValue({ at: new Date('2026-11-12T01:00:00.000Z'), id: 5n });
    t.repo.scanPage.mockResolvedValue([
      row(9, '2026-11-12T10:00:00.000Z', { direction: 'outbound' }),
    ]);
    const page = await t.service.list(principal, scope, q({ direction: 'outbound', limit: '10' }));
    expect(t.repo.scanBoundary.mock.calls[0]![1]).toMatchObject({ budget: 1000 });
    expect(t.repo.scanPage.mock.calls[0]![1]).toMatchObject({
      boundary: { at: new Date('2026-11-12T01:00:00.000Z'), id: 5n },
      filters: { direction: { values: ['outbound'] } },
    });
    expect(page.data).toHaveLength(1);
    expect(t.metrics.scanBudgetExhausted.inc).toHaveBeenCalledWith({ resource: 'messages' });
    t.repo.scanBoundary.mockResolvedValue(null);
    t.repo.scanPage.mockResolvedValue([]);
    await t.service.list(
      principal,
      scope,
      q({ direction: 'outbound', limit: '10', cursor: page.nextCursor! }),
    );
    expect(t.repo.scanBoundary.mock.calls[1]![1].after).toEqual({
      at: new Date('2026-11-12T01:00:00.000Z'),
      id: 5n,
    });
  });

  it('scan plan: an empty page with a boundary still has a nextCursor; without one it ends', async () => {
    t.repo.scanBoundary.mockResolvedValueOnce({ at: new Date('2026-11-12T01:00:00.000Z'), id: 5n });
    t.repo.scanPage.mockResolvedValueOnce([]);
    const empty = await t.service.list(principal, scope, q({ hasAttachments: 'true' }));
    expect(empty.data).toEqual([]);
    expect(empty.nextCursor).toEqual(expect.any(String));
    t.repo.scanBoundary.mockResolvedValueOnce(null);
    t.repo.scanPage.mockResolvedValueOnce([row(1, '2026-11-12T09:00:00.000Z')]);
    const last = await t.service.list(principal, scope, q({ hasAttachments: 'true' }));
    expect(last.nextCursor).toBeNull();
  });

  it('scan plan: a filled page continues after its last row (not the boundary)', async () => {
    t.repo.scanBoundary.mockResolvedValue({ at: new Date('2026-11-12T01:00:00.000Z'), id: 5n });
    t.repo.scanPage.mockResolvedValue([
      row(9, '2026-11-12T10:00:00.000Z'),
      row(8, '2026-11-12T09:00:00.000Z'),
    ]);
    const page = await t.service.list(principal, scope, q({ status: 'delivered', limit: '1' }));
    expect(t.metrics.scanBudgetExhausted.inc).not.toHaveBeenCalled();
    t.repo.scanPage.mockResolvedValue([]);
    await t.service.list(
      principal,
      scope,
      q({ status: 'delivered', limit: '1', cursor: page.nextCursor! }),
    );
    expect(t.repo.scanBoundary.mock.calls[1]![1].after).toEqual({
      at: new Date('2026-11-12T10:00:00.000Z'),
      id: 9n,
    });
  });

  it('domainId is resolved in the scope; unknown or foreign → 404 domain_not_found', async () => {
    const domainId = randomUUID();
    t.domains.findByPublicId.mockResolvedValueOnce(null);
    await expect(t.service.list(principal, scope, q({ domainId }))).rejects.toMatchObject({
      code: 'domain_not_found',
    });
    expect(t.domains.findByPublicId).toHaveBeenCalledWith(scope, domainId);
    t.domains.findByPublicId.mockResolvedValueOnce({ id: 44n });
    t.repo.scanBoundary.mockResolvedValue(null);
    t.repo.scanPage.mockResolvedValue([row(1, '2026-11-12T09:00:00.000Z', { domainId: 44n })]);
    const page = await t.service.list(principal, scope, q({ domainId }));
    expect(t.repo.scanPage.mock.calls[0]![1].filters).toEqual({ domainId: 44n });
    expect(page.data[0]!.domainId).toBe('dom-44');
  });

  it('audits identifying searches on the first page only, hashing the values', async () => {
    t.repo.scanBoundary.mockResolvedValue({ at: new Date('2026-11-12T01:00:00.000Z'), id: 5n });
    t.repo.scanPage.mockResolvedValue([row(1, '2026-11-12T09:00:00.000Z')]);
    const page = await t.service.list(
      principal,
      scope,
      q({ sender: 'Boss@Corp.example', direction: 'inbound' }),
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
        filters: ['direction', 'sender'],
        plan: 'scan',
        resultCount: 1,
        valueSha256: { sender: expect.stringMatching(/^[0-9a-f]{64}$/) },
      },
    });
    expect(JSON.stringify(entry.metadata)).not.toContain('boss@corp.example');
    await t.service.list(
      principal,
      scope,
      q({ sender: 'boss@corp.example', direction: 'inbound', cursor: page.nextCursor! }),
    );
    expect(t.audit.record).toHaveBeenCalledTimes(1);
  });

  it('never serves a row without a registry public id', async () => {
    t.repo.indexPlan.mockResolvedValue([
      row(2, '2026-11-12T10:00:00.000Z'),
      row(1, '2026-11-12T09:00:00.000Z'),
    ]);
    t.repo.publicIds.mockResolvedValueOnce(new Map([[1n, 'pub-1']]));
    const page = await t.service.list(principal, scope, q({}));
    expect(page.data.map((d) => d.id)).toEqual(['pub-1']);
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
  });

  it('recipients: keyset rcptSeq, latest delivery per recipient, user public ids', async () => {
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
        userId: 'user-9',
        latestDelivery: {
          deliverySeq: 1,
          status: 'delivered',
          finalSmtpCode: 250,
          deliveredAt: null,
        },
      }),
      expect.objectContaining({ rcptSeq: 1, userId: null, latestDelivery: null }),
    ]);
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
});

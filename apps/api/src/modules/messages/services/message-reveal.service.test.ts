import { randomBytes } from 'node:crypto';
import { MetricsService } from '@email-gateway/common';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditEntry, AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import { RevealBodySchema, RevealManyBodySchema } from '../dto/message-sensitive.schemas';
import type {
  MessageDataRepository,
  MessageDetailRow,
  MessageRef,
  RecipientRow,
} from '../repositories/message-data.repository';
import type { MessageHeadersRepository } from '../repositories/message-headers.repository';
import type { MessageRevealRepository } from '../repositories/message-reveal.repository';
import { MessageRevealService, revealMetadata } from './message-reveal.service';

const scope = systemScope(7n);
const principal: Principal = {
  kind: 'api_key',
  apiKeyId: 1n,
  apiKeyPublicId: '01930000-0000-7000-8000-00000000000a',
  organizationId: 7n,
  organizationPublicId: '01930000-0000-7000-8000-0000000000aa',
  permissions: new Set(['message:reveal']),
};
const otherOrgPrincipal: Principal = {
  ...principal,
  organizationId: 8n,
  organizationPublicId: '01930000-0000-7000-8000-0000000000bb',
};
const NOW = new Date('2026-11-14T12:00:00.000Z');
/** JSON of audit entries (bigint organization ids as strings) to check no value leaks. */
const json = (value: unknown) =>
  JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));
const id = (n: number) => `01930000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const ref = (n: number): MessageRef => ({
  id: BigInt(n),
  publicId: id(n),
  receivedAt: new Date(`2026-11-1${n % 3}T08:00:00.000Z`),
  organizationId: 7n,
});

function setup() {
  const events: string[] = [];
  const reveals = {
    refs: vi.fn((_s: unknown, ids: readonly string[]) => {
      events.push('read:refs');
      return Promise.resolve(
        ids.flatMap((pid) => [1, 2, 3].map(ref).filter((r) => r.publicId === pid)),
      );
    }),
    subjects: vi.fn((_s: unknown, refs: readonly MessageRef[]) => {
      events.push('read:subjects');
      return Promise.resolve(
        refs
          .filter((r) => r.id !== 3n) // message 3: its email_messages row is gone
          .map((r) => ({ ref: r, subject: r.id === 2n ? null : `Subject ${r.id}` })),
      );
    }),
  };
  const recipient = (seq: number, userId: bigint | null): RecipientRow => ({
    id: BigInt(100 + seq),
    organizationId: 7n,
    messageId: 1n,
    receivedAt: ref(1).receivedAt,
    rcptSeq: seq,
    address: `r${seq}@acme.example`,
    status: 'delivered',
    finalAction: 'deliver',
    direction: 'inbound',
    userId,
  });
  const allRecipients = [recipient(0, 9n), recipient(1, null), recipient(2, null)];
  const data = {
    findDetail: vi.fn((_s: unknown, publicId: string) => {
      events.push('read:detail');
      return Promise.resolve(
        publicId === id(1)
          ? ({ ...ref(1), subject: 'Pay now', publicId: id(1) } as unknown as MessageDetailRow)
          : null,
      );
    }),
    recipients: vi.fn(
      (_s: unknown, _m: MessageRef, page: { take: number; afterSeq?: number | undefined }) => {
        events.push('read:recipients');
        return Promise.resolve(
          allRecipients
            .filter((r) => page.afterSeq === undefined || r.rcptSeq > page.afterSeq)
            .slice(0, page.take),
        );
      },
    ),
    userPublicIds: vi.fn((_s: unknown, ids: readonly bigint[]) =>
      Promise.resolve(new Map(ids.map((u) => [u, `user-${u}`]))),
    ),
  };
  const headers = {
    headers: vi.fn(() => {
      events.push('read:headers');
      return Promise.resolve([
        { seq: 1, name: 'To', value: 'Alice <alice@acme.example>' },
        { seq: 2, name: 'Subject', value: 'Pay now' },
        // Never returned even if the collation matched it (defence in depth).
        { seq: 3, name: 'From', value: 'x@y.example' },
      ]);
    }),
  };
  const recorded: AuditEntry[] = [];
  let failAudit = false;
  const audit = {
    actorFrom: vi.fn(() => ({ type: 'api_key', id: principal.kind === 'api_key' ? 'k' : 'u' })),
    record: vi.fn((entry: AuditEntry, tx: unknown) => {
      expect(tx).toBe('tx');
      if (failAudit) return Promise.reject(new Error('writer down'));
      events.push('audit');
      recorded.push(entry);
      return Promise.resolve();
    }),
  };
  const transactions = {
    run: vi.fn(async <T>(fn: (tx: never) => Promise<T>) => {
      events.push('tx:begin');
      const out = await fn('tx' as never);
      events.push('tx:commit');
      return out;
    }),
  };
  const codec = new CursorCodec({
    API_CURSOR_KEY: randomBytes(32).toString('hex'),
    API_CURSOR_KEY_PREVIOUS: undefined,
    API_CURSOR_TTL_SECONDS: 86_400,
  });
  const registry = new MetricsService({ service: 'api-test' });
  const service = new MessageRevealService(
    reveals as unknown as MessageRevealRepository,
    data as unknown as MessageDataRepository,
    headers as unknown as MessageHeadersRepository,
    codec,
    audit as unknown as AuditService,
    transactions as unknown as TransactionRunner,
    registry,
  );
  service.now = () => NOW;
  const series = async (name: string) =>
    (await registry.metrics()).split('\n').filter((line) => line.startsWith(name));
  return {
    service,
    reveals,
    data,
    headers,
    audit,
    transactions,
    recorded,
    events,
    series,
    failAudit: () => (failAudit = true),
  };
}

describe('revealMetadata', () => {
  it('holds fields and counts only', () => {
    expect(revealMetadata({ fields: ['subject'], bulk: true })).toEqual({
      fields: ['subject'],
      bulk: true,
    });
    expect(
      revealMetadata({
        fields: ['headers', 'recipients'],
        headerCount: 2,
        recipients: { count: 0, firstRcptSeq: null, lastRcptSeq: null },
      }),
    ).toEqual({
      fields: ['headers', 'recipients'],
      headerCount: 2,
      recipients: { count: 0, firstRcptSeq: null, lastRcptSeq: null },
    });
  });
});

describe('MessageRevealService.revealMany (§2 E6)', () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => {
    t = setup();
  });

  it('returns the found subjects in request order, omitting unknown, foreign and gone ids', async () => {
    const body = RevealManyBodySchema.parse({
      messageIds: [id(2), id(9), id(1).toUpperCase(), id(3)],
    });
    const out = await t.service.revealMany(principal, scope, body, '198.51.100.7');
    expect(out).toEqual({
      revealedAt: NOW.toISOString(),
      data: [
        { id: id(2), subject: null },
        { id: id(1), subject: 'Subject 1' },
      ],
    });
    // Lower-cased ids are looked up within the scope.
    expect(t.reveals.refs).toHaveBeenCalledWith(scope, [id(2), id(9), id(1), id(3)]);
  });

  it('commits one audit row per revealed message before answering (fields only, no value)', async () => {
    const body = RevealManyBodySchema.parse({ messageIds: [id(1), id(2)] });
    await t.service.revealMany(principal, scope, body, '198.51.100.7');
    expect(t.events).toEqual([
      'read:refs',
      'read:subjects',
      'tx:begin',
      'audit',
      'audit',
      'tx:commit',
    ]);
    expect(t.transactions.run).toHaveBeenCalledTimes(1);
    expect(t.recorded).toEqual([
      expect.objectContaining({
        organizationId: 7n,
        action: 'message.revealed',
        resourceType: 'message',
        resourceId: id(1),
        sourceIp: '198.51.100.7',
        metadata: { fields: ['subject'], bulk: true },
      }),
      expect.objectContaining({ resourceId: id(2), metadata: { fields: ['subject'], bulk: true } }),
    ]);
    expect(json(t.recorded)).not.toContain('Subject 1');
    expect(await t.series('api_message_reveal_total')).toEqual([
      'api_message_reveal_total{kind="bulk",service="api-test"} 1',
    ]);
    expect(await t.series('api_message_reveal_values_total')).toEqual([
      'api_message_reveal_values_total{field="subject",service="api-test"} 2',
    ]);
  });

  it('nothing found: no audit row, an empty page', async () => {
    const body = RevealManyBodySchema.parse({ messageIds: [id(9)] });
    expect(await t.service.revealMany(principal, scope, body, null)).toEqual({
      revealedAt: NOW.toISOString(),
      data: [],
    });
    expect(t.transactions.run).not.toHaveBeenCalled();
  });

  it('an audit failure is 503 service_unavailable and returns no value', async () => {
    t.failAudit();
    const body = RevealManyBodySchema.parse({ messageIds: [id(1)] });
    await expect(t.service.revealMany(principal, scope, body, null)).rejects.toMatchObject({
      code: 'service_unavailable',
      status: 503,
    });
    expect(await t.series('api_message_reveal_total')).toEqual([]);
  });
});

describe('MessageRevealService.reveal (§2 E6)', () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => {
    t = setup();
  });

  it('reveals subject, To/Cc/Subject rows and recipients after the audit commit', async () => {
    const body = RevealBodySchema.parse({ fields: ['subject', 'headers', 'recipients'] });
    const out = await t.service.reveal(principal, scope, id(1), body, '198.51.100.7');
    expect(out).toEqual({
      messageId: id(1),
      revealedAt: NOW.toISOString(),
      subject: 'Pay now',
      headers: [
        { seq: 1, name: 'To', value: 'Alice <alice@acme.example>' },
        { seq: 2, name: 'Subject', value: 'Pay now' },
      ],
      recipients: {
        data: [
          { rcptSeq: 0, address: 'r0@acme.example', userId: 'user-9' },
          { rcptSeq: 1, address: 'r1@acme.example', userId: null },
          { rcptSeq: 2, address: 'r2@acme.example', userId: null },
        ],
        nextCursor: null,
      },
    });
    expect(t.events.indexOf('tx:commit')).toBe(t.events.length - 1);
    expect(t.events.filter((e) => e.startsWith('read:'))).toHaveLength(3);
    expect(t.recorded).toEqual([
      expect.objectContaining({
        action: 'message.revealed',
        resourceType: 'message',
        resourceId: id(1),
        metadata: {
          fields: ['subject', 'headers', 'recipients'],
          headerCount: 2,
          recipients: { count: 3, firstRcptSeq: 0, lastRcptSeq: 2 },
        },
      }),
    ]);
    expect(json(t.recorded)).not.toMatch(/alice|r0@|Pay now/);
    expect(await t.series('api_message_reveal_values_total')).toEqual([
      'api_message_reveal_values_total{field="subject",service="api-test"} 1',
      'api_message_reveal_values_total{field="headers",service="api-test"} 2',
      'api_message_reveal_values_total{field="recipients",service="api-test"} 3',
    ]);
  });

  it('only the requested fields are read and returned', async () => {
    const out = await t.service.reveal(
      principal,
      scope,
      id(1),
      RevealBodySchema.parse({ fields: ['subject'] }),
      null,
    );
    expect(out).toEqual({ messageId: id(1), revealedAt: NOW.toISOString(), subject: 'Pay now' });
    expect(t.headers.headers).not.toHaveBeenCalled();
    expect(t.data.recipients).not.toHaveBeenCalled();
    expect(t.recorded[0]!.metadata).toEqual({ fields: ['subject'] });
  });

  it('pages recipients with a cursor bound to the message and the organization', async () => {
    const first = await t.service.reveal(
      principal,
      scope,
      id(1),
      RevealBodySchema.parse({ fields: ['recipients'], recipientsLimit: 2 }),
      null,
    );
    expect(first.recipients!.data.map((r) => r.rcptSeq)).toEqual([0, 1]);
    const cursor = first.recipients!.nextCursor!;
    expect(cursor).toEqual(expect.any(String));
    expect(t.recorded[0]!.metadata).toEqual({
      fields: ['recipients'],
      recipients: { count: 2, firstRcptSeq: 0, lastRcptSeq: 1 },
    });
    const second = await t.service.reveal(
      principal,
      scope,
      id(1),
      RevealBodySchema.parse({
        fields: ['recipients'],
        recipientsCursor: cursor,
        recipientsLimit: 2,
      }),
      null,
    );
    expect(second.recipients).toEqual({
      data: [{ rcptSeq: 2, address: 'r2@acme.example', userId: null }],
      nextCursor: null,
    });
    // Another message, another organization or a tampered cursor: 400 before any read.
    const reads = t.data.findDetail.mock.calls.length;
    for (const [who, messageId, c] of [
      [principal, id(2), cursor],
      [otherOrgPrincipal, id(1), cursor],
      [principal, id(1), `${cursor.startsWith('e') ? 'f' : 'e'}${cursor.slice(1)}`],
    ] as const) {
      await expect(
        t.service.reveal(
          who,
          scope,
          messageId,
          RevealBodySchema.parse({ fields: ['recipients'], recipientsCursor: c }),
          null,
        ),
      ).rejects.toMatchObject({ code: 'cursor_invalid' });
    }
    expect(t.data.findDetail.mock.calls.length).toBe(reads);
  });

  it('404 message_not_found for unknown and foreign ids, nothing audited', async () => {
    await expect(
      t.service.reveal(
        principal,
        scope,
        id(9),
        RevealBodySchema.parse({ fields: ['subject'] }),
        null,
      ),
    ).rejects.toMatchObject({ code: 'message_not_found' });
    expect(t.transactions.run).not.toHaveBeenCalled();
  });

  it('an audit failure is 503 service_unavailable and returns no value', async () => {
    t.failAudit();
    await expect(
      t.service.reveal(
        principal,
        scope,
        id(1),
        RevealBodySchema.parse({ fields: ['subject', 'recipients'] }),
        null,
      ),
    ).rejects.toMatchObject({ code: 'service_unavailable' });
    expect(await t.series('api_message_reveal_values_total')).toEqual([]);
  });
});

describe('reveal request bodies (strict)', () => {
  it.each([
    [{}, 'messageIds'],
    [{ messageIds: [] }, 'messageIds'],
    [{ messageIds: ['not-a-uuid'] }, 'messageIds'],
    [{ messageIds: [id(1), id(1).toUpperCase()] }, 'twice'],
    [{ messageIds: Array.from({ length: 101 }, (_, i) => id(i + 1)) }, 'messageIds'],
    [{ messageIds: [id(1)], extra: true }, 'extra'],
  ])('bulk refuses %j', (body, text) => {
    const parsed = RevealManyBodySchema.safeParse(body);
    expect(parsed.success).toBe(false);
    expect(JSON.stringify(parsed.error)).toContain(text);
  });

  it.each([
    [{}, 'fields'],
    [{ fields: [] }, 'fields'],
    [{ fields: ['body'] }, 'fields'],
    [{ fields: ['subject', 'subject'] }, 'twice'],
    [{ fields: ['subject', 'headers', 'recipients', 'subject'] }, 'fields'],
    [{ fields: ['subject'], recipientsCursor: 'x' }, 'recipientsCursor'],
    [{ fields: ['headers'], recipientsLimit: 5 }, 'recipientsLimit'],
    [{ fields: ['recipients'], recipientsLimit: 0 }, 'recipientsLimit'],
    [{ fields: ['recipients'], recipientsLimit: 101 }, 'recipientsLimit'],
    [{ fields: ['recipients'], recipientsLimit: '5' }, 'recipientsLimit'],
    [{ fields: ['recipients'], recipientsCursor: '' }, 'recipientsCursor'],
    [{ fields: ['subject'], messageIds: [] }, 'messageIds'],
  ])('single refuses %j', (body, text) => {
    const parsed = RevealBodySchema.safeParse(body);
    expect(parsed.success).toBe(false);
    expect(JSON.stringify(parsed.error)).toContain(text);
  });

  it('accepts the documented shapes', () => {
    expect(RevealBodySchema.parse({ fields: ['recipients'], recipientsLimit: 100 })).toEqual({
      fields: ['recipients'],
      recipientsLimit: 100,
    });
    expect(RevealManyBodySchema.parse({ messageIds: [id(1).toUpperCase()] })).toEqual({
      messageIds: [id(1)],
    });
  });
});

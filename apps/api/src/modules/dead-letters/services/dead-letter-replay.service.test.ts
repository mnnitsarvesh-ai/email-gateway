import { ConflictException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import {
  encodeEvent,
  HEADERS,
  MetricsService,
  PublishFailedError,
  uuidv7,
} from '@email-gateway/common';
import { EXAMPLE_EVENT_PAYLOADS, type EventEnvelope } from '@email-gateway/event-contracts';
import { beforeEach, describe, expect, it } from 'vitest';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import type { AuditEntry, AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { ApiConfig } from '../../../config';
import type { DeadLetterBroker, DeadLetterSession } from '../broker/dead-letter-broker';
import type { DeadLettersRepository } from '../dead-letters.repository';
import { type DeadLetterMessage, REPLAY_LOCK_KEY } from '../domain/dead-letter-replay';
import { ReplayRequestSchema } from '../dto/dead-letters.schemas';
import {
  DeadLetterReplayService,
  REPLAY_AUDIT_ACTION,
  REPLAY_IN_PROGRESS,
} from './dead-letter-replay.service';

const ORG_A = { id: '42', publicId: '0190f0f0-0000-7000-8000-0000000000aa' };
const ORG_B = { id: '43', publicId: '0190f0f0-0000-7000-8000-0000000000bb' };

const principal = {
  kind: 'user',
  userId: 1n,
  userPublicId: '0190f0f0-0000-7000-8000-000000000001',
  organizationId: 1n,
  organizationPublicId: '0190f0f0-0000-7000-8000-000000000002',
  organizationKind: 'platform',
  sessionId: 's',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['platform:dead_letter_replay']),
} as UserPrincipal;

function envelope(type: 'mail.message.received.v1' | 'mail.delivery.approved.v1', org = ORG_A.id) {
  const payload = EXAMPLE_EVENT_PAYLOADS[type] as Record<string, unknown>;
  return {
    eventId: uuidv7(),
    eventType: type,
    occurredAt: '2026-11-03T12:00:00.000Z',
    correlationId: 'corr-dead-letter-1',
    organizationId: org,
    payload:
      type === 'mail.message.received.v1'
        ? { ...payload, emlS3Key: `org/${org}/eml/2026/11/01/x.eml` }
        : { ...payload, emlS3Key: `org/${org}/eml/2026/11/01/x.eml` },
  } satisfies EventEnvelope;
}

let tags = 0;
/** A dead letter as the QueueConsumer publishes it (consumer-published, Q8.5). */
function deadLetter(
  env: EventEnvelope,
  sourceQueue: string,
  extra: Record<string, unknown> = {},
): DeadLetterMessage {
  const encoded = encodeEvent(env, 'event-relay');
  tags += 1;
  return {
    content: encoded.content,
    fields: {
      deliveryTag: tags,
      routingKey: `dead-letter.${sourceQueue}.org.${env.organizationId}.${env.eventType}`,
      exchange: 'email.events',
    },
    properties: {
      ...encoded.options,
      headers: {
        ...(encoded.options.headers as Record<string, unknown>),
        [HEADERS.attempt]: 8,
        [HEADERS.transientRetries]: 2,
        [HEADERS.firstFailedAt]: '2026-11-03T11:00:00.000Z',
        [HEADERS.lastErrorClass]: 'Error',
        [HEADERS.sourceQueue]: sourceQueue,
        [HEADERS.failureReason]: 'max_attempts_exceeded',
        [HEADERS.failureClass]: 'retryable',
        [HEADERS.attempts]: 8,
        [HEADERS.deadLetteredAt]: '2026-11-03T12:00:00.000Z',
        [HEADERS.deadLetteredBy]: 'email-worker.mime-parser',
        traceparent: '00-abc-def-01',
        ...extra,
      },
    },
  };
}

/** An in-memory dead-letter queue and broker session with the AMQP semantics the service uses. */
class FakeSession implements DeadLetterSession {
  readonly queue: DeadLetterMessage[];
  readonly unacked = new Set<DeadLetterMessage>();
  readonly acked: DeadLetterMessage[] = [];
  readonly requeued: DeadLetterMessage[] = [];
  readonly published: {
    msg: DeadLetterMessage;
    target: { exchange: string; routingKey: string; headers: Record<string, string | number> };
  }[] = [];
  /** Event order of confirms and acks (confirm-before-ack). */
  readonly log: string[] = [];
  failPublishAt: number | undefined;
  closed = false;

  constructor(messages: DeadLetterMessage[]) {
    this.queue = [...messages];
  }

  get(): Promise<DeadLetterMessage | null> {
    const msg = this.queue.shift() ?? null;
    if (msg) this.unacked.add(msg);
    return Promise.resolve(msg);
  }

  ack(msg: DeadLetterMessage): void {
    if (!this.unacked.delete(msg)) throw new Error('unknown delivery tag');
    this.acked.push(msg);
    this.log.push(`ack:${msg.fields.deliveryTag}`);
  }

  requeue(msg: DeadLetterMessage): void {
    if (!this.unacked.delete(msg)) throw new Error('unknown delivery tag');
    this.requeued.push(msg);
    this.queue.push(msg);
  }

  async republish(
    msg: DeadLetterMessage,
    target: { exchange: string; routingKey: string; headers: Record<string, string | number> },
  ): Promise<void> {
    await Promise.resolve();
    if (this.failPublishAt !== undefined && this.published.length === this.failPublishAt) {
      throw Object.assign(new Error('channel closed'), { name: 'BrokerUnavailableError' });
    }
    this.published.push({ msg, target });
    this.log.push(`confirm:${msg.fields.deliveryTag}`);
  }

  stats() {
    return Promise.resolve({ messages: this.queue.length, consumers: 0 });
  }

  close(): Promise<void> {
    this.closed = true;
    return Promise.resolve();
  }
}

function setup(messages: DeadLetterMessage[], overrides: Partial<ApiConfig> = {}) {
  const session = new FakeSession(messages);
  const broker = {
    configured: true,
    open: () => Promise.resolve(session),
  } as unknown as DeadLetterBroker & { configured: boolean };
  const kv = new InMemoryKeyValueStore();
  const audits: AuditEntry[] = [];
  const audit = {
    actorFrom: () => ({ type: 'user', id: principal.userPublicId }),
    record: (entry: AuditEntry) => {
      audits.push(entry);
      return Promise.resolve();
    },
  } as unknown as AuditService;
  const repository = {
    organizationIdOf: (publicId: string) =>
      Promise.resolve([ORG_A, ORG_B].find((o) => o.publicId === publicId)?.id ?? null),
    publicIdsOf: (ids: readonly string[]) =>
      Promise.resolve(
        new Map(
          [ORG_A, ORG_B].filter((o) => ids.includes(o.id)).map((o) => [o.id, o.publicId] as const),
        ),
      ),
  } as unknown as DeadLettersRepository;
  const metrics = new MetricsService({ service: 'api-test' });
  const config = { DEAD_LETTER_REPLAY_SCAN_MAX: 10_000, ...overrides } as ApiConfig;
  const service = new DeadLetterReplayService(config, broker, kv, audit, repository, metrics);
  return { service, session, kv, audits, metrics, broker };
}

const request = (body: Record<string, unknown>) =>
  ReplayRequestSchema.parse({ reason: 'replay after fixing the parser', limit: 10, ...body });
const client = { ip: '198.51.100.7', userAgent: null };

describe('DeadLetterReplayService (step 3.2 Q9, fake channel)', () => {
  beforeEach(() => {
    tags = 0;
  });

  it('replays matching dead letters, requeues the rest, confirm before ack, audits', async () => {
    const a = envelope('mail.message.received.v1');
    const b = envelope('mail.message.received.v1');
    const other = envelope('mail.delivery.approved.v1');
    const messages = [
      deadLetter(a, 'email.received'),
      deadLetter(other, 'email.delivery.pending'),
      deadLetter(b, 'email.received', { [HEADERS.replayCount]: 2 }),
    ];
    const { service, session, audits, kv, metrics } = setup(messages);

    const result = await service.replay(
      principal,
      request({ sourceQueue: 'email.received' }),
      client,
    );

    expect(result).toMatchObject({
      dryRun: false,
      scanned: 3,
      matched: 2,
      replayed: 2,
      skipped: { invalid: 0, notMatching: 1 },
    });
    expect(result.items).toEqual([
      {
        eventId: a.eventId,
        eventType: 'mail.message.received.v1',
        organizationId: ORG_A.publicId,
        sourceQueue: 'email.received',
        failureReason: 'max_attempts_exceeded',
        replayed: true,
      },
      expect.objectContaining({ eventId: b.eventId, replayed: true }),
    ]);
    // Confirm before ack, per message.
    expect(session.log).toEqual(['confirm:1', 'ack:1', 'confirm:3', 'ack:3']);
    // The non-matching one is back in the queue, nothing is left unacked.
    expect(session.requeued.map((m) => m.fields.deliveryTag)).toEqual([2]);
    expect(session.unacked.size).toBe(0);
    expect(session.closed).toBe(true);
    // Lock released.
    expect(await kv.get(REPLAY_LOCK_KEY)).toBeNull();

    // Target and the exact header rewrite of Q9 step 3; the body is unchanged.
    const first = session.published[0]!;
    expect(first.msg.content).toBe(messages[0]!.content);
    expect(first.target.exchange).toBe('email.ingestion');
    expect(first.target.routingKey).toBe(
      `retry.email.received.org.${ORG_A.id}.mail.message.received.v1`,
    );
    expect(first.target.headers).toEqual({
      [HEADERS.envelopeVersion]: 1,
      [HEADERS.eventType]: 'mail.message.received.v1',
      [HEADERS.schemaVersion]: 1,
      [HEADERS.organizationId]: ORG_A.id,
      [HEADERS.correlationId]: 'corr-dead-letter-1',
      [HEADERS.attempt]: 0,
      [HEADERS.transientRetries]: 0,
      [HEADERS.replayId]: result.replayId,
      [HEADERS.replayCount]: 1,
      [HEADERS.replayedAt]: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/) as string,
    });
    expect(session.published[1]!.target.headers[HEADERS.replayCount]).toBe(3);

    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({
      organizationId: null,
      action: REPLAY_AUDIT_ACTION,
      resourceType: 'queue',
      resourceId: 'email.received',
      sourceIp: client.ip,
      metadata: {
        replayId: result.replayId,
        dryRun: false,
        filters: { sourceQueue: 'email.received', limit: 10 },
        scanned: 3,
        matched: 2,
        replayed: 2,
        skipped: { invalid: 0, notMatching: 1 },
        reason: 'replay after fixing the parser',
        outcome: 'complete',
        eventIds: [a.eventId, b.eventId],
      },
    });
    expect(await metrics.metrics()).toMatch(
      /dead_letter_replay_total\{[^}]*source_queue="email.received"[^}]*outcome="complete"[^}]*\} 1/,
    );
  });

  it('applies the event type, organization and failure reason filters', async () => {
    const a = envelope('mail.message.received.v1', ORG_A.id);
    const b = envelope('mail.message.received.v1', ORG_B.id);
    const c = envelope('mail.message.received.v1', ORG_A.id);
    const messages = [
      deadLetter(a, 'email.received'),
      deadLetter(b, 'email.received'),
      deadLetter(c, 'email.received', { [HEADERS.failureReason]: 'retry_age_exceeded' }),
    ];
    const { service, session } = setup(messages);
    const result = await service.replay(
      principal,
      request({
        sourceQueue: 'email.received',
        eventType: 'mail.message.received.v1',
        organizationId: ORG_A.publicId,
        failureReason: 'max_attempts_exceeded',
      }),
      client,
    );
    expect(result).toMatchObject({ matched: 1, replayed: 1, skipped: { notMatching: 2 } });
    expect(result.items.map((i) => i.eventId)).toEqual([a.eventId]);
    expect(session.requeued).toHaveLength(2);
  });

  it('matches a broker dead letter (delivery limit) by x-first-death-queue and its reason', async () => {
    const a = envelope('mail.message.received.v1');
    const msg = deadLetter(a, 'email.received');
    const headers = { ...msg.properties.headers };
    delete headers[HEADERS.sourceQueue];
    delete headers[HEADERS.failureReason];
    msg.properties.headers = {
      ...headers,
      'x-first-death-queue': 'email.received',
      'x-first-death-reason': 'delivery_limit',
      'x-death': [{ queue: 'email.received', reason: 'delivery_limit', count: 20 }],
    };
    msg.fields.routingKey = 'dead-letter.email.received';
    const { service, session } = setup([msg]);
    const result = await service.replay(
      principal,
      request({ sourceQueue: 'email.received', failureReason: 'delivery_limit' }),
      client,
    );
    expect(result).toMatchObject({ matched: 1, replayed: 1 });
    // No broker death headers on the copy.
    const copied = session.published[0]!.target.headers;
    expect(Object.keys(copied).some((k) => k.startsWith('x-death') || k.includes('-death-'))).toBe(
      false,
    );
  });

  it('leaves invalid matches (contract, tenant, content) in the queue', async () => {
    const good = envelope('mail.message.received.v1');
    const tampered = deadLetter(envelope('mail.message.received.v1'), 'email.received', {
      [HEADERS.organizationId]: '999',
    });
    const corrupt = deadLetter(envelope('mail.message.received.v1'), 'email.received');
    corrupt.content = Buffer.from('{"not":"an envelope"}');
    // Valid for the schema (unknown keys are stripped) but carrying content in the bytes.
    const withContent = envelope('mail.message.received.v1');
    (withContent.payload as Record<string, unknown>).body = 'Subject: hello\r\n\r\nsecret text';
    const guarded = deadLetter(withContent, 'email.received');
    const { service, session } = setup([
      tampered,
      corrupt,
      guarded,
      deadLetter(good, 'email.received'),
    ]);
    const result = await service.replay(
      principal,
      request({ sourceQueue: 'email.received' }),
      client,
    );
    expect(result).toMatchObject({ matched: 4, replayed: 1, skipped: { invalid: 3 } });
    expect(result.items.filter((i) => !i.replayed)).toHaveLength(3);
    expect(session.published.map((p) => p.msg)).toHaveLength(1);
    expect(session.requeued).toEqual([tampered, corrupt, guarded]);
  });

  it('skips a message the publisher refuses (guard or size) and goes on', async () => {
    const messages = [
      deadLetter(envelope('mail.message.received.v1'), 'email.received'),
      deadLetter(envelope('mail.message.received.v1'), 'email.received'),
    ];
    const ctx = setup(messages);
    const original = ctx.session.republish.bind(ctx.session);
    ctx.session.republish = (msg, target) =>
      msg === messages[0]
        ? Promise.reject(new PublishFailedError('refused', 'message_too_large'))
        : original(msg, target);
    const result = await ctx.service.replay(
      principal,
      request({ sourceQueue: 'email.received' }),
      client,
    );
    expect(result).toMatchObject({ matched: 2, replayed: 1, skipped: { invalid: 1 } });
    expect(ctx.session.requeued).toEqual([messages[0]]);
    expect(ctx.audits[0]!.metadata).toMatchObject({ outcome: 'complete' });
  });

  it('stops at limit matches and at DEAD_LETTER_REPLAY_SCAN_MAX scanned', async () => {
    const many = Array.from({ length: 5 }, () =>
      deadLetter(envelope('mail.message.received.v1'), 'email.received'),
    );
    let ctx = setup(many);
    let result = await ctx.service.replay(
      principal,
      request({ sourceQueue: 'email.received', limit: 2 }),
      client,
    );
    expect(result).toMatchObject({ scanned: 2, matched: 2, replayed: 2 });
    expect(ctx.session.queue).toHaveLength(3);

    const mixed = [
      deadLetter(envelope('mail.delivery.approved.v1'), 'email.delivery.pending'),
      deadLetter(envelope('mail.delivery.approved.v1'), 'email.delivery.pending'),
      deadLetter(envelope('mail.message.received.v1'), 'email.received'),
    ];
    ctx = setup(mixed, { DEAD_LETTER_REPLAY_SCAN_MAX: 2 });
    result = await ctx.service.replay(
      principal,
      request({ sourceQueue: 'email.received' }),
      client,
    );
    expect(result).toMatchObject({ scanned: 2, matched: 0, replayed: 0 });
    expect(ctx.session.queue).toHaveLength(3);
  });

  it('a dry run publishes and acks nothing and returns everything to the queue', async () => {
    const messages = [
      deadLetter(envelope('mail.message.received.v1'), 'email.received'),
      deadLetter(envelope('mail.message.received.v1'), 'email.received'),
    ];
    const { service, session, audits, metrics } = setup(messages);
    const result = await service.replay(
      principal,
      request({ sourceQueue: 'email.received', dryRun: true }),
      client,
    );
    expect(result).toMatchObject({ dryRun: true, matched: 2, replayed: 0 });
    expect(result.items.every((i) => !i.replayed)).toBe(true);
    expect(session.published).toEqual([]);
    expect(session.acked).toEqual([]);
    expect(session.requeued).toHaveLength(2);
    expect(audits[0]!.metadata).toMatchObject({ dryRun: true, outcome: 'complete', eventIds: [] });
    expect(await metrics.metrics()).toMatch(/outcome="dry_run"[^}]*\} 1/);
  });

  it('a broker failure half-way: requeues the rest, audits partial, answers 503', async () => {
    const messages = Array.from({ length: 3 }, () =>
      deadLetter(envelope('mail.message.received.v1'), 'email.received'),
    );
    const { service, session, audits, kv, metrics } = setup(messages);
    session.failPublishAt = 1;
    await expect(
      service.replay(principal, request({ sourceQueue: 'email.received' }), client),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(session.acked).toHaveLength(1);
    // The one whose copy was not confirmed is never acked; it goes back with the rest held.
    expect(session.requeued).toEqual([messages[1]]);
    expect(session.queue).toHaveLength(2);
    expect(audits[0]!.metadata).toMatchObject({ outcome: 'partial', replayed: 1 });
    expect(await kv.get(REPLAY_LOCK_KEY)).toBeNull();
    expect(await metrics.metrics()).toMatch(/outcome="partial"[^}]*\} 1/);
  });

  it('refuses while another replay holds the lock (409) and without a broker URL (503)', async () => {
    const ctx = setup([]);
    await ctx.kv.setIfAbsent(REPLAY_LOCK_KEY, 'other', 300);
    await expect(
      ctx.service.replay(principal, request({ sourceQueue: 'email.received' }), client),
    ).rejects.toThrow(new ConflictException(REPLAY_IN_PROGRESS));
    expect(await ctx.kv.get(REPLAY_LOCK_KEY)).toBe('other');
    expect(ctx.audits).toEqual([]);

    const unconfigured = setup([]);
    (unconfigured.broker as { configured: boolean }).configured = false;
    await expect(
      unconfigured.service.replay(principal, request({ sourceQueue: 'email.received' }), client),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
    await expect(unconfigured.service.stats()).rejects.toBeInstanceOf(ServiceUnavailableException);
  });

  it('answers 404 for an unknown organization filter, before taking the lock', async () => {
    const ctx = setup([]);
    await expect(
      ctx.service.replay(
        principal,
        request({ sourceQueue: 'email.received', organizationId: uuidv7() }),
        client,
      ),
    ).rejects.toBeInstanceOf(NotFoundException);
    expect(await ctx.kv.get(REPLAY_LOCK_KEY)).toBeNull();
  });

  it('reports the dead-letter queue depth', async () => {
    const ctx = setup([deadLetter(envelope('mail.message.received.v1'), 'email.received')]);
    await expect(ctx.service.stats()).resolves.toEqual({
      queue: 'email.dead-letter',
      messages: 1,
      consumers: 0,
    });
    expect(ctx.session.closed).toBe(true);
  });
});

describe('ReplayRequestSchema', () => {
  it('accepts only work queues as the source', () => {
    for (const sourceQueue of ['email.received', 'email.delivery.pending']) {
      expect(request({ sourceQueue }).sourceQueue).toBe(sourceQueue);
    }
    for (const sourceQueue of ['scan.auth', 'email.delivery.retry', 'email.dead-letter', 'x']) {
      const result = ReplayRequestSchema.safeParse({
        sourceQueue,
        limit: 1,
        reason: 'x'.repeat(10),
      });
      expect(result.success).toBe(false);
      expect(result.error?.issues[0]?.message).toBe('source_queue_not_replayable');
    }
  });
});

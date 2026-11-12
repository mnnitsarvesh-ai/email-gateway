import { createHash, randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
import { MetricsService, type PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { EventTypes, messageRescanRequestedV1 } from '@email-gateway/event-contracts';
import { runWithContext } from '@email-gateway/logger';
import {
  decideTransition,
  type LifecycleSnapshot,
  type MessageRef,
  type MessageState,
  transitionKeyHash,
  type TransitionOutcome,
  type TransitionRequest,
} from '@email-gateway/message-lifecycle';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuditService } from '../../../audit/audit.service';
import type { ApiKeyPrincipal, Principal, UserPrincipal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import type {
  IdempotencyRecord,
  IdempotencyRepository,
  NewIdempotencyRecord,
} from '../../../http/idempotency/idempotency.repository';
import { requestFingerprint } from '../../../http/idempotency/idempotency-key';
import { IdempotencyService } from '../../../http/idempotency/idempotency.service';
import { RESCAN_NOTE, RESCAN_SOURCES } from '../domain/lifecycle-operations';
import { ApiLifecycleMetrics } from '../lifecycle-metrics';
import type {
  EmailEventInsert,
  MessageIdentityRow,
  MessageLifecycleRepository,
  OutboxInsert,
  ReleasableRecipient,
} from '../repositories/message-lifecycle.repository';
import type { LifecycleGateway } from './lifecycle-gateway';
import { type LifecycleOperationInput, MessageLifecycleService } from './message-lifecycle.service';

type Tx = Prisma.TransactionClient;

const ORG = 7n;
const OTHER_ORG = 8n;
const scope = systemScope(ORG);
const receivedAt = new Date('2026-11-04T08:00:00.000Z');
const client = { ip: '203.0.113.5', userAgent: null };
const reason = 'operator checked the sender';

const user: UserPrincipal = {
  kind: 'user',
  userId: 10n,
  userPublicId: '0195f3c1-7a2b-7c3d-8e4f-0000000000a1',
  organizationId: ORG,
  organizationPublicId: '0195f3c1-7a2b-7c3d-8e4f-0000000000b1',
  organizationKind: 'customer',
  sessionId: 's',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  // The route guard checks message:rescan; the service checks quarantine:release (step 5.3).
  permissions: new Set(['message:rescan', 'quarantine:release']),
};
const apiKey: ApiKeyPrincipal = {
  kind: 'api_key',
  apiKeyId: 3n,
  apiKeyPublicId: '0195f3c1-7a2b-7c3d-8e4f-0000000000c1',
  organizationId: ORG,
  organizationPublicId: user.organizationPublicId,
  permissions: new Set(['message:rescan', 'quarantine:release']),
};

interface FakeMessage {
  identity: MessageIdentityRow;
  organizationId: bigint;
  snapshot: LifecycleSnapshot;
  recipients: Array<ReleasableRecipient & { status: string }>;
  quarantineEntries: number;
  maxDeliverySeq: number | null;
  historyKeys: Set<string>;
  /** The version a client saw when the fixture was created (default expectedVersion). */
  initialVersion: number;
}

/** Writer state of the fakes; a transaction's effects apply only when it resolves. */
class World {
  messages = new Map<string, FakeMessage>();
  outbox: OutboxInsert[] = [];
  events: EmailEventInsert[] = [];
  audits: Array<Record<string, unknown>> = [];
  idempotency = new Map<string, IdempotencyRecord & NewIdempotencyRecord>();
  transitions: TransitionRequest[] = [];
  /** Replaces the next transition outcome (concurrency cases). */
  nextOutcome: ((request: TransitionRequest) => TransitionOutcome) | null = null;
  private pending: Array<() => void> = [];
  private nextId = 1n;

  add(state: MessageState, options: Partial<FakeMessage> & { version?: number } = {}) {
    const publicId = randomUUID();
    const id = this.nextId++;
    const message: FakeMessage = {
      identity: { id, publicId, receivedAt },
      organizationId: options.organizationId ?? ORG,
      snapshot: {
        state,
        version: options.version ?? 4,
        round: 0,
        statusChangedAt: receivedAt,
        statusReason: null,
        direction: 'inbound',
        emlObjectKey: `org/${(options.organizationId ?? ORG).toString()}/eml/2026/11/04/${id}.eml`,
        ...options.snapshot,
      },
      recipients: options.recipients ?? [
        { id: 100n + id, rcptSeq: 0, status: 'quarantined' },
        { id: 200n + id, rcptSeq: 1, status: 'pending' },
      ],
      quarantineEntries: options.quarantineEntries ?? 0,
      maxDeliverySeq: options.maxDeliverySeq === undefined ? 0 : options.maxDeliverySeq,
      historyKeys: new Set(),
      initialVersion: options.version ?? 4,
    };
    this.messages.set(publicId, message);
    return message;
  }

  private byRef(ref: MessageRef): FakeMessage | undefined {
    return [...this.messages.values()].find((m) => m.identity.id === ref.id);
  }

  defer(fn: () => void) {
    this.pending.push(fn);
  }

  readonly tx = {
    auditLog: {
      create: vi.fn((args: { data: Record<string, unknown> }) => {
        this.defer(() => this.audits.push(args.data));
        return Promise.resolve({});
      }),
    },
  } as unknown as Tx;

  readonly runner = {
    run: vi.fn(async <T>(fn: (tx: Tx) => Promise<T>) => {
      this.pending = [];
      try {
        const result = await fn(this.tx);
        for (const apply of this.pending) apply();
        return result;
      } finally {
        this.pending = [];
      }
    }),
  } as unknown as TransactionRunner & { run: ReturnType<typeof vi.fn> };

  readonly idempotencyRepo = {
    lock: (_tx: Tx, organizationId: bigint, key: string) => {
      return Promise.resolve(this.idempotency.get(`${organizationId}:${key}`) ?? null);
    },
    delete: (_tx: Tx, id: bigint) => {
      this.defer(() => {
        for (const [k, row] of this.idempotency) if (row.id === id) this.idempotency.delete(k);
      });
      return Promise.resolve();
    },
    insert: (_tx: Tx, record: NewIdempotencyRecord) => {
      const id = this.nextId++;
      this.defer(() =>
        this.idempotency.set(`${record.organizationId}:${record.idempotencyKey}`, {
          ...record,
          id,
        }),
      );
      return Promise.resolve();
    },
  } as unknown as IdempotencyRepository;

  readonly repository = {
    findIdentity: (_tx: Tx, s: { organizationId: bigint }, publicId: string) => {
      const m = this.messages.get(publicId);
      return Promise.resolve(m && m.organizationId === s.organizationId ? m.identity : null);
    },
    hasTransitionKey: (_tx: Tx, ref: MessageRef, hash: string) =>
      Promise.resolve(this.byRef(ref)?.historyKeys.has(hash) ?? false),
    quarantineEntryCount: (_tx: Tx, _s: unknown, ref: MessageRef) =>
      Promise.resolve(this.byRef(ref)?.quarantineEntries ?? 0),
    openQuarantineEntryCount: (_tx: Tx, _s: unknown, ref: MessageRef) =>
      Promise.resolve(this.byRef(ref)?.quarantineEntries ?? 0),
    releasableRecipients: (_tx: Tx, _s: unknown, ref: MessageRef) =>
      Promise.resolve(
        (this.byRef(ref)?.recipients ?? [])
          .filter((r) => r.status === 'pending' || r.status === 'quarantined')
          .sort((a, b) => a.rcptSeq - b.rcptSeq)
          .map(({ id, rcptSeq }) => ({ id, rcptSeq })),
      ),
    markReleasedRecipientsPending: (
      _tx: Tx,
      _s: unknown,
      ref: MessageRef,
      ids: readonly bigint[],
    ) => {
      const targets = (this.byRef(ref)?.recipients ?? []).filter(
        (r) => ids.includes(r.id) && r.status === 'quarantined',
      );
      this.defer(() => {
        for (const r of targets) r.status = 'pending';
      });
      return Promise.resolve(targets.length);
    },
    maxDeliverySeq: (_tx: Tx, _s: unknown, ref: MessageRef) =>
      Promise.resolve(this.byRef(ref)?.maxDeliverySeq ?? null),
    insertOutbox: (_tx: Tx, row: OutboxInsert) => {
      this.defer(() => this.outbox.push(row));
      return Promise.resolve();
    },
    insertEmailEvent: (_tx: Tx, event: EmailEventInsert) => {
      this.defer(() => this.events.push(event));
      return Promise.resolve();
    },
  } as unknown as MessageLifecycleRepository;

  /** The package's behaviour on the in-memory row: lock check, key check, decide, apply. */
  readonly gateway = {
    lock: (_tx: Tx, ref: MessageRef) => {
      const m = this.byRef(ref);
      return Promise.resolve(
        m && m.organizationId === ref.organizationId ? { ...m.snapshot } : null,
      );
    },
    transition: (_tx: Tx, request: TransitionRequest): Promise<TransitionOutcome> => {
      this.transitions.push(request);
      if (this.nextOutcome) {
        const make = this.nextOutcome;
        this.nextOutcome = null;
        return Promise.resolve(make(request));
      }
      const m = this.byRef(request.message);
      if (!m || m.organizationId !== request.message.organizationId) {
        return Promise.resolve({ result: 'not_found' });
      }
      const hash = transitionKeyHash(request.transitionKey);
      const snapshot = { ...m.snapshot };
      if (m.historyKeys.has(hash)) {
        return Promise.resolve({ result: 'duplicate', why: 'transition_key', snapshot });
      }
      const decision = decideTransition(snapshot, request);
      if (decision.result !== 'apply') return Promise.resolve({ ...decision, snapshot });
      const next: LifecycleSnapshot = {
        ...snapshot,
        state: request.to,
        version: snapshot.version + 1,
        round: decision.nextRound,
        statusReason: request.reason,
      };
      this.defer(() => {
        m.snapshot = next;
        m.historyKeys.add(hash);
      });
      return Promise.resolve({
        result: 'applied',
        from: snapshot.state,
        to: request.to,
        version: next.version,
        round: next.round,
        historyId: 1n,
        stateEventId: randomUUID(),
        snapshot: next,
      });
    },
  } as unknown as LifecycleGateway;
}

let world: World;
let metrics: ApiLifecycleMetrics;
let service: MessageLifecycleService;

beforeEach(() => {
  world = new World();
  metrics = new ApiLifecycleMetrics(new MetricsService({ service: 'api-test' }));
  service = new MessageLifecycleService(
    new IdempotencyService(world.runner, world.idempotencyRepo),
    world.repository,
    world.gateway,
    new AuditService({} as PrismaService),
    metrics,
  );
});

const input = (
  message: FakeMessage | string,
  overrides: Partial<LifecycleOperationInput> = {},
): LifecycleOperationInput => ({
  messageId: typeof message === 'string' ? message : message.identity.publicId,
  idempotencyKey: 'key-1',
  body: {
    expectedVersion: typeof message === 'string' ? 0 : message.initialVersion,
    reason,
  },
  ...overrides,
});

const rescan = (
  m: FakeMessage | string,
  o?: Partial<LifecycleOperationInput>,
  p: Principal = user,
) =>
  runWithContext({ correlationId: 'corr-abcdef12' }, () =>
    service.rescan(p, scope, input(m, o), client),
  );
const release = (
  m: FakeMessage | string,
  o?: Partial<LifecycleOperationInput>,
  p: Principal = user,
) =>
  runWithContext({ correlationId: 'corr-abcdef12' }, () =>
    service.release(p, scope, input(m, o), client),
  );

async function failure(promise: Promise<unknown>) {
  const error = await promise.then(
    () => {
      throw new Error('expected a failure');
    },
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(HttpException);
  const http = error as HttpException;
  return {
    status: http.getStatus(),
    code: error instanceof CodedHttpException ? error.code : undefined,
    details: error instanceof CodedHttpException ? error.details : undefined,
    message: (http.getResponse() as { message?: unknown }).message,
  };
}

async function operationCounts(): Promise<Record<string, number>> {
  const { values } = await metrics.operations.get();
  return Object.fromEntries(
    values.map((v) => [`${String(v.labels.operation)}:${String(v.labels.outcome)}`, v.value]),
  );
}

const sha = (text: string) => createHash('sha256').update(text).digest('hex');

describe('MessageLifecycleService.rescan (L10.2, E19)', () => {
  it.each(RESCAN_SOURCES)(
    'from %s: 202, new round, rescan_requested.v1, audit row',
    async (state) => {
      const m = world.add(state);
      const result = await rescan(m);
      expect(result.replayed).toBe(false);
      expect(result.statusCode).toBe(202);
      expect(result.body).toEqual({
        messageId: m.identity.publicId,
        state: 'scanning',
        version: 5,
        lifecycleRound: 1,
        rescanEventId: expect.any(String),
        note: RESCAN_NOTE,
      });
      expect(m.snapshot).toMatchObject({ state: 'scanning', version: 5, round: 1 });

      const [request] = world.transitions;
      expect(request).toMatchObject({
        message: { id: m.identity.id, receivedAt, organizationId: ORG },
        to: 'scanning',
        reason: 'admin_rescan',
        actor: { role: 'operator', service: 'api', type: 'user', id: user.userPublicId },
        transitionKey: 'api:7:message.rescan:key-1',
        correlationId: 'api:corr-abcdef12',
        expectedVersion: 4,
        expectedFrom: RESCAN_SOURCES,
        recordIgnored: false,
      });
      expect(request!.expectedRound).toBeUndefined();

      expect(world.outbox).toHaveLength(1);
      const row = world.outbox[0]!;
      expect(row).toMatchObject({
        eventId: result.body.rescanEventId,
        organizationId: ORG,
        eventType: EventTypes.MessageRescanRequested,
        aggregateId: m.identity.id.toString(),
        correlationId: 'api:corr-abcdef12',
      });
      expect(messageRescanRequestedV1.parse(row.payload)).toEqual({
        messageId: m.identity.id.toString(),
        receivedAt: receivedAt.toISOString(),
        direction: 'inbound',
        emlS3Key: m.snapshot.emlObjectKey,
        lifecycleRound: 1,
        scanKind: 'rescan',
        requestedAt: expect.any(String),
        requestedBy: 'user',
      });

      expect(world.audits).toHaveLength(1);
      const audit = world.audits[0]!;
      expect(audit).toMatchObject({
        organizationId: ORG,
        actorType: 'user',
        actorId: user.userPublicId,
        action: 'message.rescan_requested',
        resourceType: 'message',
        resourceId: m.identity.publicId,
        sourceIp: client.ip,
        metadata: {
          fromState: state,
          toState: 'scanning',
          version: 5,
          lifecycleRound: 1,
          reason,
          idempotencyKeyHash: sha('key-1'),
          eventIds: [expect.any(String), result.body.rescanEventId],
        },
      });
      expect(
        JSON.stringify(audit, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)),
      ).not.toContain('"key-1"');
      expect(await operationCounts()).toEqual({ 'rescan:applied': 1 });
    },
  );

  it('step 5.3: a quarantined/held message needs quarantine:release too (403, nothing written)', async () => {
    const rescanOnly: UserPrincipal = { ...user, permissions: new Set(['message:rescan']) };
    for (const state of ['quarantined', 'held_for_review'] as const) {
      const m = world.add(state);
      m.quarantineEntries = 2;
      expect(await failure(rescan(m, {}, rescanOnly))).toMatchObject({
        status: 403,
        code: 'quarantine_rescan_forbidden',
        details: { currentState: state, entries: 2, permission: 'quarantine:release' },
      });
      expect(m.snapshot.state).toBe(state);
    }
    expect(world.transitions).toEqual([]);
    expect(world.outbox).toEqual([]);
    expect(world.audits).toEqual([]);
    // Other rescan sources need message:rescan only.
    const scanned = world.add('scanned');
    expect((await rescan(scanned, {}, rescanOnly)).statusCode).toBe(202);
    expect(world.audits[0]!.metadata).toMatchObject({ quarantineEntriesSuperseded: 0 });
    // With quarantine:release the rescan supersedes the open entries (recorded in the audit).
    const held = world.add('quarantined');
    held.quarantineEntries = 3;
    await rescan(held, { idempotencyKey: 'key-2' }, user);
    expect(world.audits[1]!.metadata).toMatchObject({ quarantineEntriesSuperseded: 3 });
  });

  it('records an API key as the actor and requestedBy', async () => {
    const m = world.add('scanned');
    await rescan(m, {}, apiKey);
    expect(world.transitions[0]!.actor).toEqual({
      role: 'operator',
      service: 'api',
      type: 'api_key',
      id: apiKey.apiKeyPublicId,
    });
    expect((world.outbox[0]!.payload as { requestedBy: string }).requestedBy).toBe('api_key');
    expect(world.audits[0]).toMatchObject({ actorType: 'api_key', actorId: apiKey.apiKeyPublicId });
  });

  it('replays the stored response for the same key and body (exactly one effect)', async () => {
    const m = world.add('quarantined');
    const first = await rescan(m);
    const second = await rescan(m);
    expect(second).toEqual({ ...first, replayed: true });
    expect(world.transitions).toHaveLength(1);
    expect(world.outbox).toHaveLength(1);
    expect(world.audits).toHaveLength(1);
    expect(await operationCounts()).toEqual({ 'rescan:applied': 1, 'rescan:replayed': 1 });
  });

  it('refuses the same key with another body, another message or another caller (422)', async () => {
    const m = world.add('quarantined');
    const other = world.add('quarantined');
    await rescan(m);
    const otherBody = { body: { expectedVersion: 5, reason: 'a different reason text' } };
    for (const attempt of [
      rescan(m, otherBody),
      rescan(other),
      rescan(m, {}, apiKey),
      release(m, { body: { expectedVersion: 4, reason } }),
    ]) {
      expect(await failure(attempt)).toMatchObject({ status: 422, code: 'idempotency_key_reused' });
    }
    expect(world.outbox).toHaveLength(1);
    expect((await operationCounts())['rescan:invalid_request']).toBe(3);
  });

  it('validates the message id, the Idempotency-Key and the body (400, counted)', async () => {
    const m = world.add('scanned');
    expect(await failure(rescan('not-a-uuid'))).toMatchObject({
      status: 400,
      message: ['messageId: Invalid UUID'],
    });
    expect(await failure(rescan(m, { idempotencyKey: undefined }))).toMatchObject({
      status: 400,
      code: 'idempotency_key_required',
    });
    expect(await failure(rescan(m, { idempotencyKey: 'bad key' }))).toMatchObject({
      status: 400,
      code: 'idempotency_key_invalid',
    });
    expect(
      await failure(rescan(m, { body: { expectedVersion: 4, reason: 'short' } })),
    ).toMatchObject({
      status: 400,
      message: ['reason: Too small: expected string to have >=10 characters'],
    });
    expect(
      await failure(rescan(m, { body: { expectedVersion: -1, reason, extra: 1 } })),
    ).toMatchObject({ status: 400 });
    expect(world.runner.run).not.toHaveBeenCalled();
    expect(await operationCounts()).toEqual({ 'rescan:invalid_request': 5 });
  });

  it('404 message_not_found for an unknown id and another organization’s message', async () => {
    const foreign = world.add('scanned', { organizationId: OTHER_ORG });
    expect(await failure(rescan(randomUUID()))).toMatchObject({
      status: 404,
      code: 'message_not_found',
    });
    expect(await failure(rescan(foreign))).toMatchObject({
      status: 404,
      code: 'message_not_found',
    });
    expect(foreign.snapshot.state).toBe('scanned');
    expect(world.transitions).toHaveLength(0);
    expect(await operationCounts()).toEqual({ 'rescan:not_found': 2 });
  });

  it('404 when the partition row is not the organization’s (lock returns null)', async () => {
    const m = world.add('scanned');
    m.organizationId = OTHER_ORG; // registry row of ORG, message row of another tenant
    world.repository.findIdentity = () => Promise.resolve(m.identity);
    expect(await failure(rescan(m))).toMatchObject({ status: 404, code: 'message_not_found' });
  });

  it('409 message_version_conflict for a stale expectedVersion, not stored under the key', async () => {
    const m = world.add('scanned', { version: 9 });
    const stale = await failure(rescan(m, { body: { expectedVersion: 8, reason } }));
    expect(stale).toEqual({
      status: 409,
      code: 'message_version_conflict',
      details: { currentState: 'scanned', currentVersion: 9 },
      message: expect.any(String),
    });
    expect(world.idempotency.size).toBe(0);
    expect(world.transitions).toHaveLength(0);
    // The client fixes the version and retries with the same key.
    const fixed = await rescan(m, { body: { expectedVersion: 9, reason } });
    expect(fixed.replayed).toBe(false);
    expect(await operationCounts()).toEqual({ 'rescan:conflict': 1, 'rescan:applied': 1 });
  });

  it.each<MessageState>([
    'persisted',
    'approved',
    'delivery_pending',
    'delivered',
    'rejected',
    'archived',
  ])('409 message_state_conflict from %s', async (state) => {
    const m = world.add(state);
    expect(await failure(rescan(m))).toMatchObject({
      status: 409,
      code: 'message_state_conflict',
      details: { currentState: state, currentVersion: 4 },
    });
    expect(world.outbox).toHaveLength(0);
    expect(world.audits).toHaveLength(0);
  });

  it('409 message_state_conflict when the EML key is outside the organization prefix', async () => {
    const m = world.add('scanned', {
      snapshot: { emlObjectKey: 'org/8/eml/x.eml' } as LifecycleSnapshot,
    });
    expect(await failure(rescan(m))).toMatchObject({ status: 409, code: 'message_state_conflict' });
    expect(world.transitions).toHaveLength(0);
  });

  it('a concurrent winner with the same key (history has the key) is replayed', async () => {
    const m = world.add('scanned');
    const winner = await rescan(m);
    // The winner's idempotency record is not visible to the loser's first lookup.
    const stored = new Map(world.idempotency);
    world.idempotency.clear();
    let lookups = 0;
    const lock = world.idempotencyRepo.lock.bind(world.idempotencyRepo);
    world.idempotencyRepo.lock = (tx, org, key) => {
      lookups += 1;
      if (lookups === 2) for (const [k, v] of stored) world.idempotency.set(k, v);
      return lock(tx, org, key);
    };
    const loser = await rescan(m);
    expect(loser).toEqual({ ...winner, replayed: true });
    expect(world.outbox).toHaveLength(1);
    expect(world.runner.run).toHaveBeenCalledTimes(3);
  });

  it('a transition-key duplicate from the service is a race too (retried, then replayed)', async () => {
    const m = world.add('scanned');
    const winnerBody = { winner: true };
    world.nextOutcome = () => ({
      result: 'duplicate',
      why: 'transition_key',
      snapshot: { ...m.snapshot },
    });
    let lookups = 0;
    const lock = world.idempotencyRepo.lock.bind(world.idempotencyRepo);
    world.idempotencyRepo.lock = (tx, org, key) => {
      lookups += 1;
      if (lookups === 2) {
        // The concurrent winner committed its record between the two attempts.
        world.idempotency.set(`${org}:${key}`, {
          id: 99n,
          organizationId: org,
          idempotencyKey: key,
          operation: 'message.rescan',
          principal: `user:${user.userPublicId}`,
          requestSha256: requestFingerprint({
            operation: 'message.rescan',
            resourceId: m.identity.publicId,
            body: { expectedVersion: 4, reason },
          }),
          resourceId: m.identity.publicId,
          statusCode: 202,
          response: winnerBody,
          expiresAt: new Date(Date.now() + 60_000),
        });
      }
      return lock(tx, org, key);
    };
    const result = await rescan(m);
    expect(result).toEqual({ replayed: true, statusCode: 202, body: winnerBody });
    expect(world.outbox).toHaveLength(0);
    expect(world.audits).toHaveLength(0);
    expect(world.runner.run).toHaveBeenCalledTimes(2);
  });
});

describe('MessageLifecycleService.release (L10.3; step 5.3 Q30: quarantine workflow only)', () => {
  it.each<MessageState>(['quarantined', 'held_for_review'])(
    '409 quarantine_workflow_required from %s, with the entry count and the quarantine route',
    async (state) => {
      const m = world.add(state, { quarantineEntries: 2 });
      expect(await failure(release(m))).toMatchObject({
        status: 409,
        code: 'quarantine_workflow_required',
        details: {
          currentState: state,
          currentVersion: 4,
          entries: 2,
          route: 'POST /api/v1/quarantine/entries/{entryId}/release',
        },
      });
      expect(world.transitions).toHaveLength(0);
      expect(world.outbox).toHaveLength(0);
      expect(world.events).toHaveLength(0);
      expect(world.audits).toHaveLength(0);
      expect(world.idempotency.size).toBe(0);
      expect(m.snapshot.state).toBe(state);
      expect(m.recipients.find((r) => r.rcptSeq === 0)!.status).toBe('quarantined');
    },
  );

  it('also without entries (a 5.2-held message not adopted yet): no release around the workflow', async () => {
    const m = world.add('quarantined', { quarantineEntries: 0 });
    expect(await failure(release(m))).toMatchObject({
      code: 'quarantine_workflow_required',
      details: { entries: 0 },
    });
    expect(world.transitions).toHaveLength(0);
    expect(await operationCounts()).toEqual({ 'release:conflict': 1 });
  });

  it('state and version are decided first (L10.4 conflicts unchanged)', async () => {
    const stale = world.add('quarantined', { quarantineEntries: 1, version: 3 });
    expect(await failure(release(stale, { body: { expectedVersion: 2, reason } }))).toMatchObject({
      code: 'message_version_conflict',
    });
    const delivered = world.add('delivered', { recipients: [] });
    expect(await failure(release(delivered, { idempotencyKey: 'key-2' }))).toMatchObject({
      code: 'message_state_conflict',
      details: { currentState: 'delivered', currentVersion: 4 },
    });
  });

  it.each<MessageState>(['approved', 'scanning', 'persisted', 'delivery_retry', 'expired'])(
    '409 message_state_conflict from %s',
    async (state) => {
      const m = world.add(state);
      expect(await failure(release(m))).toMatchObject({ code: 'message_state_conflict' });
    },
  );
});

describe('ApiLifecycleMetrics', () => {
  it('adapts the transition-service metrics to the api registry', async () => {
    const registry = new MetricsService({ service: 'api-test' });
    const m = new ApiLifecycleMetrics(registry);
    m.transitions.transition('scanned', 'scanning', 'applied');
    m.transitions.ignored('version_mismatch');
    m.transitions.versionConflict();
    m.transitions.derivedSkipped('expired');
    const text = await registry.metrics();
    expect(text).toContain(
      'lifecycle_transitions_total{from="scanned",to="scanning",result="applied",service="api-test"} 1',
    );
    expect(text).toContain('lifecycle_transitions_ignored_total{reason="version_mismatch"');
    expect(text).toContain('lifecycle_version_conflicts_total{service="api-test"} 1');
    expect(text).toContain('lifecycle_derived_skipped_total{state="expired"');
  });
});

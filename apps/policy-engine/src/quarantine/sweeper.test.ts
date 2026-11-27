import { MetricsService } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import { QuarantineMetrics } from '../metrics/quarantine-metrics';
import { InconsistentQuarantineReadError } from './errors';
import { isOrganizationKey, messageObjectPrefixes } from './disposal';
import { QUARANTINE_SWEEPER_LOCK, QuarantineSweeper } from './sweeper';

/** A writer client whose every read is empty (no work due) unless a test overrides a model. */
function emptyPrisma(over: Record<string, Record<string, unknown>> = {}) {
  const model = (name: string) =>
    new Proxy(
      {},
      {
        get(_t, op: string) {
          const custom = over[name]?.[op];
          if (custom !== undefined) return custom;
          if (op === 'findMany' || op === 'groupBy') return () => Promise.resolve([]);
          if (op === 'count') return () => Promise.resolve(0);
          if (op === 'deleteMany' || op === 'updateMany')
            return () => Promise.resolve({ count: 0 });
          return () => Promise.resolve(null);
        },
      },
    );
  return new Proxy(
    {},
    {
      get(_t, prop: string) {
        if (prop === '$queryRaw') return () => Promise.resolve([]);
        if (prop === '$transaction') return (fn: (tx: unknown) => unknown) => fn({});
        return model(prop);
      },
    },
  );
}

function sweeper(options: {
  ensure?: () => Promise<boolean>;
  prisma?: unknown;
  digests?: () => Promise<{ runs: number; digests: number; alerts: number }>;
  store?: { casEntry: unknown; cancelPendingRequests: unknown; createEntries: unknown };
  objects?: { exists: unknown; purgeKey: unknown; purgePrefix: unknown };
  disposal?: { read: unknown };
}) {
  const service = new MetricsService({ service: 't' });
  const metrics = new QuarantineMetrics(service);
  const locks = {
    ensure: vi.fn(options.ensure ?? (() => Promise.resolve(true))),
    release: vi.fn(() => Promise.resolve()),
  };
  const s = new QuarantineSweeper({
    prisma: (options.prisma ?? emptyPrisma()) as never,
    locks,
    objects: (options.objects ?? {
      exists: vi.fn(),
      purgeKey: vi.fn(),
      purgePrefix: vi.fn(),
    }) as never,
    store: (options.store ?? {
      casEntry: vi.fn(),
      cancelPendingRequests: vi.fn(),
      createEntries: vi.fn(),
    }) as never,
    settings: { resolve: vi.fn() },
    disposal: (options.disposal ?? { read: vi.fn() }) as never,
    digests: {
      run: vi.fn(options.digests ?? (() => Promise.resolve({ runs: 0, digests: 0, alerts: 0 }))),
    },
    metrics,
    lifecycleMetrics: {
      transition: vi.fn(),
      ignored: vi.fn(),
      versionConflict: vi.fn(),
      derivedSkipped: vi.fn(),
    },
    sink: vi.fn(),
    logger: createLogger({ service: 't', level: 'silent' }),
    intervalMs: 60_000,
    txTimeoutMs: 120_000,
    batchSize: 10,
    retentionDays: 186,
    bounds: { maxHoldDays: 60, maxReviewDays: 13 },
    now: () => new Date('2026-11-12T08:00:00.000Z'),
  });
  return { s, locks, service };
}

describe('QuarantineSweeper (Q19): leader election and pass isolation', () => {
  it('does nothing without the lock; reports a lock failure as a database error', async () => {
    const off = sweeper({ ensure: () => Promise.resolve(false) });
    expect((await off.s.sweepOnce()).outcome).toBe('not_leader');
    expect(off.locks.ensure).toHaveBeenCalledWith(QUARANTINE_SWEEPER_LOCK);
    expect(off.s.isLeader).toBe(false);
    expect(await off.service.metrics()).toContain('quarantine_sweeper_leader{service="t"} 0');
    const down = sweeper({ ensure: () => Promise.reject(new Error('mysql down')) });
    expect((await down.s.sweepOnce()).outcome).toBe('database_error');
  });

  it('a quiet pass as leader: swept, gauges at zero, last success stamped', async () => {
    const { s, service } = sweeper({});
    expect(await s.sweepOnce()).toMatchObject({ outcome: 'swept', failedSteps: [] });
    expect(s.isLeader).toBe(true);
    const text = await service.metrics();
    expect(text).toContain('quarantine_sweeper_leader{service="t"} 1');
    expect(text).toContain(
      'quarantine_sweep_last_success_timestamp_seconds{service="t"} 1794470400',
    );
    for (const state of ['held', 'pending_approval', 'releasing']) {
      expect(text).toContain(`quarantine_entries{state="${state}",service="t"} 0`);
    }
    expect(text).toContain('quarantine_pending_approvals{service="t"} 0');
  });

  it('a failing step does not stop the others; the pass is partial and not stamped', async () => {
    const digests = vi.fn(() => Promise.reject(new Error('digest failure')));
    const { s, service } = sweeper({ digests });
    const report = await s.sweepOnce();
    expect(report).toMatchObject({ outcome: 'partial', failedSteps: ['digests'] });
    const text = await service.metrics();
    // Gauges (after the failing step) still ran.
    expect(text).toContain('quarantine_pending_approvals{service="t"} 0');
    expect(text).toContain('quarantine_sweep_last_success_timestamp_seconds{service="t"} 0');
  });

  it('an expiry candidate that does not echo its filter is an inconsistent read (step fails)', async () => {
    const prisma = emptyPrisma({
      quarantineMessage: {
        findMany: () =>
          Promise.resolve([
            {
              messageId: 1n,
              messageReceivedAt: new Date(),
              organizationId: 7n,
              status: 'released',
              expiresAt: new Date('2020-01-01T00:00:00.000Z'),
            },
          ]),
      },
    });
    const { s } = sweeper({ prisma });
    const report = await s.sweepOnce();
    expect(report.failedSteps).toContain('expiry');
    expect(new InconsistentQuarantineReadError('entries', 'x').name).toBe(
      'InconsistentQuarantineReadError',
    );
  });
});

describe('object purge scope (Q17)', () => {
  it('purges only the message prefixes of its organization, by the UTC received date', () => {
    expect(
      messageObjectPrefixes({
        messageId: 42n,
        receivedAt: new Date('2026-01-02T23:30:00.000Z'),
        organizationId: 7n,
      }),
    ).toEqual([
      'org/7/part/2026/01/02/42/',
      'org/7/rewrite/2026/01/02/42/',
      'org/7/policy/2026/01/02/42/',
    ]);
    expect(isOrganizationKey('org/7/eml/a.eml', 7n)).toBe(true);
    expect(isOrganizationKey('org/70/eml/a.eml', 7n)).toBe(false);
    expect(isOrganizationKey('org/7/../8/eml/a.eml', 7n)).toBe(false);
    expect(isOrganizationKey('org/7//a.eml', 7n)).toBe(false);
  });
});

describe('mailbox-located entries (step API-2 R11, ADR-0102)', () => {
  const RECEIVED = new Date('2026-11-01T08:00:00.000Z');
  const PAST = new Date('2026-11-02T08:00:00.000Z');
  const mailboxEntry = (over: Record<string, unknown> = {}) => ({
    id: 5n,
    publicId: '0190f0f0-0000-7000-8000-0000000000e5',
    organizationId: 7n,
    messageId: 100n,
    messageReceivedAt: RECEIVED,
    recipientId: 500n,
    kind: 'quarantine',
    status: 'pending_approval',
    expiresAt: PAST,
    approvalRequestId: 9n,
    rowVersion: 2,
    location: 'mailbox',
    ...over,
  });
  /** The copy's registry message (`journaled`, API-mode intake) as `lockLifecycle` reads it. */
  const copyRow = {
    id: 100n,
    received_at: RECEIVED,
    organization_id: 7n,
    status: 'journaled',
    version: 3,
    lifecycle_round: 0,
    status_changed_at: RECEIVED,
    status_reason: 'mailbox_api_journaled',
    direction: 'inbound',
    eml_object_key: 'org/7/eml/copy.eml',
    ingest_source: 'mailbox_api',
  };

  /** A writer double for one message: the copy row, then its locked entries. */
  function copyTx(entries: Array<Record<string, unknown>>, requests: unknown[]) {
    const writes: string[] = [];
    const tx = {
      $queryRaw: vi.fn((strings: TemplateStringsArray) =>
        Promise.resolve(
          strings.join('?').includes('FROM email_messages')
            ? [copyRow]
            : entries.map((e) => ({ id: e.id })),
        ),
      ),
      quarantineMessage: { findMany: vi.fn(() => Promise.resolve(entries)) },
      quarantineApprovalRequest: {
        findMany: vi.fn(() => Promise.resolve(requests)),
        updateMany: vi.fn(() => {
          writes.push('request.update');
          return Promise.resolve({ count: 1 });
        }),
      },
      quarantineAction: {
        create: vi.fn(() => {
          writes.push('action.create');
          return Promise.resolve({ id: 1n });
        }),
        createMany: vi.fn(() => {
          writes.push('action.createMany');
          return Promise.resolve({ count: 1 });
        }),
      },
      emailRecipient: {
        updateMany: vi.fn(() => {
          writes.push('recipient.update');
          return Promise.resolve({ count: 0 });
        }),
        count: vi.fn(() => Promise.resolve(0)),
      },
      emailMessageStatusHistory: {
        create: vi.fn(() => {
          writes.push('lifecycle');
          return Promise.resolve({});
        }),
      },
      messageOutbox: {
        create: vi.fn(() => {
          writes.push('outbox');
          return Promise.resolve({ id: 1n });
        }),
      },
      emailEvent: {
        create: vi.fn(() => {
          writes.push('event');
          return Promise.resolve({ id: 1n });
        }),
      },
      quarantineObjectPurge: {
        findFirst: vi.fn(() => Promise.resolve(null)),
        create: vi.fn(() => {
          writes.push('purge.create');
          return Promise.resolve({ id: 1n });
        }),
      },
    };
    return { tx, writes };
  }

  /** `prisma` whose `$transaction` runs on `tx` (the one message of a test). */
  const onTx = (prisma: object, tx: unknown): object =>
    new Proxy(prisma as Record<string, unknown>, {
      get(t, prop: string) {
        if (prop === '$transaction') return (fn: (x: unknown) => unknown) => fn(tx);
        return t[prop];
      },
    });

  const store = () => ({
    casEntry: vi.fn((..._a: unknown[]) => Promise.resolve()),
    cancelPendingRequests: vi.fn(() => Promise.resolve([])),
    createEntries: vi.fn(),
  });

  it('entry expiry selects location = gateway only; a mailbox candidate is a wrong read', async () => {
    const findMany = vi.fn((_args: unknown) => Promise.resolve([] as unknown[]));
    const { s } = sweeper({ prisma: emptyPrisma({ quarantineMessage: { findMany } }) });
    expect((await s.sweepOnce()).failedSteps).toEqual([]);
    const expiry = findMany.mock.calls
      .map(([a]) => a as { where: Record<string, unknown> })
      .find((a) => a.where.expiresAt !== undefined)!;
    expect(expiry.where).toMatchObject({
      location: 'gateway',
      status: { in: ['held', 'pending_approval'] },
    });

    const leaked = sweeper({
      prisma: emptyPrisma({
        quarantineMessage: {
          findMany: () =>
            Promise.resolve([
              {
                messageId: 100n,
                messageReceivedAt: RECEIVED,
                organizationId: 7n,
                status: 'held',
                expiresAt: PAST,
                location: 'mailbox',
              },
            ]),
        },
      }),
    });
    expect((await leaked.s.sweepOnce()).failedSteps).toContain('expiry');
  });

  it('approval-request expiry of a mailbox entry only CASes the entry back to held (no lifecycle edge, recipient or purge)', async () => {
    const entry = mailboxEntry();
    const request = {
      id: 9n,
      publicId: '0190f0f0-0000-7000-8000-0000000000c9',
      organizationId: 7n,
      quarantineMessageId: 5n,
      kind: 'release_approval',
      status: 'pending',
      requestedByType: 'user',
      requestedByUserId: 11n,
      rowVersion: 1,
    };
    const { tx, writes } = copyTx([entry], [request]);
    const st = store();
    const disposal = { read: vi.fn() };
    const prisma = emptyPrisma({
      quarantineApprovalRequest: {
        findMany: () =>
          Promise.resolve([{ quarantineMessageId: 5n, status: 'pending', expiresAt: PAST }]),
      },
      quarantineMessage: {
        findMany: (args: { where: Record<string, unknown> }) =>
          Promise.resolve(
            args.where.id !== undefined
              ? [{ messageId: 100n, messageReceivedAt: RECEIVED, organizationId: 7n }]
              : [],
          ),
      },
    });
    const withTx = onTx(prisma, tx);
    const { s } = sweeper({ prisma: withTx, store: st, disposal });
    const report = await s.sweepOnce();
    expect(report.failedSteps).toEqual([]);
    expect(report).toMatchObject({ approvalsExpired: 1, expired: 0, messagesExpired: 0 });
    expect(st.casEntry).toHaveBeenCalledTimes(1);
    expect(st.casEntry).toHaveBeenCalledWith(tx, expect.objectContaining({ id: 5n }), {
      status: 'held',
      stateChangedAt: expect.any(Date),
    });
    expect(writes).toEqual(['request.update', 'action.create', 'outbox']);
    expect(writes).not.toContain('lifecycle');
    expect(writes).not.toContain('recipient.update');
    expect(disposal.read).not.toHaveBeenCalled();
  });

  it('a policy_review request of a mailbox entry never expires the entry here', async () => {
    const entry = mailboxEntry({ kind: 'review' });
    const { tx, writes } = copyTx(
      [entry],
      [
        {
          id: 9n,
          publicId: 'r9',
          organizationId: 7n,
          quarantineMessageId: 5n,
          kind: 'policy_review',
          status: 'pending',
          requestedByType: 'system',
          requestedByUserId: null,
          rowVersion: 1,
        },
      ],
    );
    const st = store();
    const prisma = onTx(
      emptyPrisma({
        quarantineApprovalRequest: {
          findMany: () =>
            Promise.resolve([{ quarantineMessageId: 5n, status: 'pending', expiresAt: PAST }]),
        },
        quarantineMessage: {
          findMany: (args: { where: Record<string, unknown> }) =>
            Promise.resolve(
              args.where.id !== undefined
                ? [{ messageId: 100n, messageReceivedAt: RECEIVED, organizationId: 7n }]
                : [],
            ),
        },
      }),
      tx,
    );
    const { s } = sweeper({ prisma, store: st });
    const report = await s.sweepOnce();
    expect(report).toMatchObject({ failedSteps: [], approvalsExpired: 0, expired: 0 });
    expect(st.casEntry).not.toHaveBeenCalled();
    expect(st.cancelPendingRequests).not.toHaveBeenCalled();
    expect(writes).toEqual([]);
  });

  it('an object purge of a message with mailbox entries is refused before any deletion', async () => {
    const { tx } = copyTx([mailboxEntry({ status: 'expired' })], []);
    const objects = { exists: vi.fn(), purgeKey: vi.fn(), purgePrefix: vi.fn() };
    const disposal = { read: vi.fn() };
    const updateMany = vi.fn((_a: unknown) => Promise.resolve({ count: 1 }));
    const prisma = onTx(
      emptyPrisma({
        quarantineObjectPurge: {
          findMany: () =>
            Promise.resolve([
              {
                id: 1n,
                organizationId: 7n,
                messageId: 100n,
                messageReceivedAt: RECEIVED,
                status: 'pending',
                attempts: 0,
                purgeAfter: PAST,
              },
            ]),
          updateMany,
        },
      }),
      tx,
    );
    const { s } = sweeper({ prisma, objects, disposal });
    const report = await s.sweepOnce();
    expect(report).toMatchObject({ purged: 0, purgeFailures: 1 });
    expect(objects.purgeKey).not.toHaveBeenCalled();
    expect(objects.purgePrefix).not.toHaveBeenCalled();
    expect(disposal.read).not.toHaveBeenCalled();
    expect(updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ status: 'failed', lastErrorCode: 'mailbox_location' }),
      }),
    );
  });
});

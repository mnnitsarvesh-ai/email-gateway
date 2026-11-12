import type { EventEnvelope, QuarantineReleaseRequestedV1 } from '@email-gateway/event-contracts';
import { quarantineNotificationRequestedV1 } from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import type { LifecycleSnapshot } from '@email-gateway/message-lifecycle';
import { resolveQuarantineSettings } from '@email-gateway/quarantine';
import { describe, expect, it, vi } from 'vitest';
import { ReleaseExecutor, type ReleaseExecutorDeps } from './release-executor';

const RECEIVED = '2026-11-12T08:00:00.000Z';
const NOW = new Date('2026-11-12T09:00:00.000Z');
const RELEASE = '0190f0f0-0000-7000-8000-00000000a001';
const ENTRY = '0190f0f0-0000-7000-8000-0000000000e1';
const USER = '0190f0f0-0000-7000-8000-0000000000f1';
const REQUEST = '0190f0f0-0000-7000-8000-0000000000c1';

function event(
  over: Partial<QuarantineReleaseRequestedV1> = {},
): EventEnvelope<QuarantineReleaseRequestedV1> {
  return {
    eventId: '0190f0f0-0000-7000-8000-00000000ee01',
    eventType: 'mail.quarantine.release_requested.v1',
    occurredAt: NOW.toISOString(),
    correlationId: 'corr-12345678',
    organizationId: '7',
    payload: {
      releaseId: RELEASE,
      messageId: '100',
      receivedAt: RECEIVED,
      entryIds: [ENTRY],
      mode: 'operator',
      approvalRequestId: null,
      requestedBy: { type: 'user', id: USER },
      requestedAt: NOW.toISOString(),
      ...over,
    },
  };
}

const snapshot = (state: LifecycleSnapshot['state']): LifecycleSnapshot => ({
  state,
  version: 5,
  round: 0,
  statusChangedAt: NOW,
  statusReason: null,
  direction: 'inbound',
  emlObjectKey: 'org/7/eml/x.eml',
});

function setup(options: {
  state?: LifecycleSnapshot['state'];
  entryStatus?: string;
  logStatus?: string;
  approval?: Record<string, unknown> | null;
  mode?: 'operator' | 'approved';
}) {
  const writes: Array<[string, Record<string, unknown>]> = [];
  const entry = {
    id: 1n,
    publicId: ENTRY,
    organizationId: 7n,
    messageId: 100n,
    messageReceivedAt: new Date(RECEIVED),
    lifecycleRound: 0,
    recipientId: 500n,
    rcptSeq: 0,
    recipientAddress: 'bob@corp.example',
    userId: 66n,
    kind: 'quarantine',
    reason: 'policy',
    status: options.entryStatus ?? 'releasing',
    riskLevel: 'none',
    rowVersion: 2,
  };
  const log = {
    id: 40n,
    quarantineMessageId: 1n,
    organizationId: 7n,
    releasePublicId: RELEASE,
    mode: options.mode ?? 'operator',
    status: options.logStatus ?? 'pending',
    approvalRequestId: null,
    requestedByType: 'user',
    requestedById: USER,
  };
  const tx = {
    $queryRaw: vi.fn(() => Promise.resolve([{ id: 1n }])),
    quarantineMessage: { findMany: vi.fn(() => Promise.resolve([entry])) },
    quarantineReleaseLog: {
      findMany: vi.fn(() => Promise.resolve([log])),
      updateMany: vi.fn((args: Record<string, unknown>) => {
        writes.push(['log', args]);
        return Promise.resolve({ count: 1 });
      }),
    },
    quarantineApprovalRequest: {
      findFirst: vi.fn(() => Promise.resolve(options.approval ?? null)),
    },
    quarantineAction: {
      create: vi.fn((args: Record<string, unknown>) => {
        writes.push(['action', args]);
        return Promise.resolve({ id: 1n });
      }),
    },
    messageOutbox: {
      create: vi.fn((args: Record<string, unknown>) => {
        writes.push(['outbox', args]);
        return Promise.resolve({ id: 1n });
      }),
    },
    user: {
      findFirst: vi.fn(() => Promise.resolve({ id: 11n, organizationId: 7n, publicId: USER })),
    },
    // API key 9 was created by user 12.
    apiKey: {
      findFirst: vi.fn(() => Promise.resolve({ id: 9n, organizationId: 7n, createdByUserId: 12n })),
    },
  };
  const casEntry = vi.fn((..._args: unknown[]) => Promise.resolve());
  const releaseFacts = {
    latestScanRound: vi.fn(() => Promise.resolve(null)),
    staleness: vi.fn(),
  };
  const executor = new ReleaseExecutor({
    facts: { read: vi.fn() },
    snapshots: { get: vi.fn() },
    directory: { resolve: vi.fn() },
    releaseFacts,
    settings: { resolve: vi.fn(() => Promise.resolve(resolveQuarantineSettings(null).settings)) },
    store: { casEntry },
    copies: { write: vi.fn(), writeEdited: vi.fn() },
    copyFacts: { read: vi.fn() },
    objectExists: vi.fn(),
    urlRewrite: {} as ReleaseExecutorDeps['urlRewrite'],
    bannerMaxPartBytes: 1_048_576,
    bounds: { maxHoldDays: 60, maxReviewDays: 13 },
    staleness: { maxVerdictAgeHours: 72, signatureMaxLagHours: 24 },
    copyTimeoutMs: 1_000,
    policySink: vi.fn(),
    sink: vi.fn(),
    lifecycleMetrics: {
      transition: vi.fn(),
      ignored: vi.fn(),
      versionConflict: vi.fn(),
      derivedSkipped: vi.fn(),
    },
    logger: createLogger({ service: 't', level: 'silent' }),
    now: () => NOW,
    lock: vi.fn(() => Promise.resolve(snapshot(options.state ?? 'quarantined'))),
  });
  return { executor, tx, writes, casEntry, releaseFacts };
}

const logData = (writes: Array<[string, Record<string, unknown>]>) =>
  writes.filter(([k]) => k === 'log').map(([, a]) => a.data as Record<string, unknown>);

describe('ReleaseExecutor (Q13.2): outcomes that stop before re-validation', () => {
  it.each([
    ['an entry that is no longer releasing', { entryStatus: 'held' }],
    ['a log that is no longer pending', { logStatus: 'dispatched' }],
  ])('%s → stale: logs marked stale, nothing else', async (_label, options) => {
    const s = setup(options);
    const outcome = await s.executor.execute(event(), s.tx as never);
    expect(outcome).toMatchObject({ result: 'stale', mode: 'operator', released: 0 });
    expect(logData(s.writes)).toEqual([
      expect.objectContaining({ status: 'stale', blockedReason: 'stale' }),
    ]);
    expect(s.casEntry).not.toHaveBeenCalled();
    expect(s.writes.some(([k]) => k === 'outbox')).toBe(false);
  });

  it.each([
    ['scanning', 'message_busy', 'message_busy'],
    ['policy_evaluated', 'message_busy', 'message_busy'],
    ['archived', 'message_archived', 'refused'],
  ] as const)(
    'message %s → %s: entry back to held, log %s, release_blocked to the requester',
    async (state, result, logStatus) => {
      const s = setup({ state });
      const outcome = await s.executor.execute(event(), s.tx as never);
      expect(outcome.result).toBe(result);
      expect(s.casEntry).toHaveBeenCalledWith(
        s.tx,
        expect.objectContaining({ id: 1n, rowVersion: 2 }),
        { status: 'held', stateChangedAt: NOW },
      );
      expect(logData(s.writes)).toEqual([
        expect.objectContaining({ status: logStatus, blockedReason: result }),
      ]);
      expect(s.releaseFacts.latestScanRound).not.toHaveBeenCalled();
      const outbox = s.writes.find(([k]) => k === 'outbox')![1].data as { payload: unknown };
      expect(quarantineNotificationRequestedV1.parse(outbox.payload)).toMatchObject({
        kind: 'release_blocked',
        refs: { releaseId: RELEASE, userId: USER },
      });
    },
  );

  it.each([
    ['missing', null],
    ['not approved', { status: 'pending', decidedByUserId: 12n, requestedByUserId: 11n }],
    [
      'approved by the requester',
      { status: 'approved', decidedByUserId: 11n, requestedByUserId: 11n },
    ],
    [
      'approved by the entry recipient',
      { status: 'approved', decidedByUserId: 66n, requestedByUserId: 11n },
    ],
    [
      'requested with an API key and approved by the key creator',
      {
        status: 'approved',
        decidedByUserId: 12n,
        requestedByType: 'api_key',
        requestedByUserId: null,
        requestedByApiKeyId: 9n,
      },
    ],
  ])('an approved release whose approval is %s is refused (SoD re-check)', async (_l, approval) => {
    const s = setup({
      mode: 'approved',
      approval:
        approval === null
          ? null
          : {
              id: 3n,
              publicId: REQUEST,
              organizationId: 7n,
              quarantineMessageId: 1n,
              approvalReasons: ['hard_block'],
              approvedReasons: ['hard_block'],
              requestedByType: 'user',
              requestedByApiKeyId: null,
              ...approval,
            },
    });
    const outcome = await s.executor.execute(
      event({ mode: 'approved', approvalRequestId: REQUEST }),
      s.tx as never,
    );
    expect(outcome).toMatchObject({ result: 'refused', mode: 'approved' });
    expect(logData(s.writes)).toEqual([
      expect.objectContaining({ status: 'refused', blockedReason: 'approval_not_valid' }),
    ]);
    expect(s.releaseFacts.latestScanRound).not.toHaveBeenCalled();
  });
});

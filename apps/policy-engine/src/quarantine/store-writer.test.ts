import {
  buildPolicyInput,
  compileSnapshot,
  evaluatePolicy,
  POLICY_DEFAULT_PLATFORM_ID,
} from '@email-gateway/policy-dsl';
import { resolveQuarantineSettings } from '@email-gateway/quarantine';
import { describe, expect, it, vi } from 'vitest';
import { EMPTY_DIRECTORY } from '../evaluation/directory.repository';
import { cleanFacts, cleanRiskRow } from '../evaluation/fixtures.test-support';
import { entryFactsFromResult, entryFactsFromView } from './entry-facts';
import { InconsistentQuarantineReadError } from './errors';
import { QuarantineStoreWriter } from './store-writer';

const RECEIVED = new Date('2026-11-12T08:00:00.000Z');
const NOW = new Date('2026-11-12T08:00:05.000Z');
const KEY = { messageId: 100n, receivedAt: RECEIVED, organizationId: 7n };

/** A writer transaction double: records writes, serves the rows a test puts in. */
function fakeTx(state: {
  entries?: Array<Record<string, unknown>>;
  requests?: Array<Record<string, unknown>>;
  users?: Array<Record<string, unknown>>;
  casCount?: number;
}) {
  const writes: Array<[string, unknown]> = [];
  let requestId = 900n;
  const tx = {
    $queryRaw: vi.fn(() => Promise.resolve((state.entries ?? []).map((e) => ({ id: e.id })))),
    quarantineMessage: {
      findMany: vi.fn(() => Promise.resolve(state.entries ?? [])),
      updateMany: vi.fn((args: unknown) => {
        writes.push(['entry.update', args]);
        return Promise.resolve({ count: state.casCount ?? 1 });
      }),
      createMany: vi.fn((args: { data: Array<Record<string, unknown>> }) => {
        writes.push(['entry.createMany', args]);
        state.entries = args.data.map((d, i) => ({
          ...d,
          id: BigInt(10 + i),
          publicId: `0190f0f0-0000-7000-8000-0000000000${String(10 + i)}`,
          _count: { actions: 0 },
        }));
        return Promise.resolve({ count: args.data.length });
      }),
    },
    quarantineApprovalRequest: {
      findMany: vi.fn(() => Promise.resolve(state.requests ?? [])),
      updateMany: vi.fn((args: unknown) => {
        writes.push(['request.update', args]);
        return Promise.resolve({ count: 1 });
      }),
      create: vi.fn((args: unknown) => {
        writes.push(['request.create', args]);
        requestId += 1n;
        return Promise.resolve({
          id: requestId,
          publicId: `0190f0f0-0000-7000-8000-000000000${String(requestId)}`,
        });
      }),
    },
    quarantineAction: {
      createMany: vi.fn((args: unknown) => {
        writes.push(['action.createMany', args]);
        return Promise.resolve({ count: 1 });
      }),
    },
    emailRecipient: {
      updateMany: vi.fn((args: { where: { id?: { in: bigint[] } } }) => {
        writes.push(['recipient.update', args]);
        return Promise.resolve({ count: args.where.id?.in.length ?? 1 });
      }),
    },
    emailEvent: {
      create: vi.fn((args: unknown) => {
        writes.push(['event', args]);
        return Promise.resolve({ id: 1n });
      }),
    },
    messageOutbox: {
      create: vi.fn((args: unknown) => {
        writes.push(['outbox', args]);
        return Promise.resolve({ id: 1n });
      }),
    },
    user: { findMany: vi.fn(() => Promise.resolve(state.users ?? [])) },
  };
  return { tx, writes };
}

function quarantineResult() {
  const compiled = compileSnapshot({
    generation: '1',
    settings: null,
    platformDefaultId: POLICY_DEFAULT_PLATFORM_ID,
    policies: [],
  });
  const input = buildPolicyInput({
    ...cleanFacts({
      risk: [
        cleanRiskRow({
          score: 900,
          level: 'critical',
          verdict: 'malware',
          recommendedAction: 'block',
          hardBlocks: [{ id: 'hb.malware_attachment', action: 'block' }],
        }),
      ],
    }),
    directory: EMPTY_DIRECTORY,
  });
  return { result: evaluatePolicy(input, compiled), input };
}

describe('entry facts (Q6)', () => {
  it('copies the decision facts of a result (content-free, bounded)', () => {
    const { result, input } = quarantineResult();
    const facts = entryFactsFromResult(result, input, null, 'quarantine');
    expect(facts).toMatchObject({
      reason: 'malware',
      primaryEngine: 'attachment',
      hardBlocks: ['hb.malware_attachment'],
      riskScore: 900,
      riskLevel: 'critical',
      recommendedAction: 'block',
      riskVerdict: 'malware',
      decisionSource: 'platform_default',
      approvalReasons: [],
    });
    expect(facts.floorReasons).toContain('policy.floor.hard_block');
    expect(facts.explanation.length).toBeLessThanOrEqual(24);
    expect(JSON.stringify(facts)).not.toContain('@');
    // The malware hard block makes the platform recommendation a reject (policy_reject).
    expect(entryFactsFromResult(result, input, null, 'review').approvalReasons).toEqual([
      'review',
      'hard_block',
      'policy_reject',
    ]);
  });

  it('an adopted entry without an evaluation row falls back to policy/none', () => {
    expect(entryFactsFromView(null, 'review')).toMatchObject({
      reason: 'policy',
      primaryEngine: 'none',
      approvalReasons: ['review'],
      explanation: [],
      explanationText: null,
    });
  });
});

describe('QuarantineStoreWriter.createEntries (Q6)', () => {
  const { result, input } = quarantineResult();
  const settings = resolveQuarantineSettings(null).settings;
  const message = {
    ...KEY,
    round: 2,
    scanId: 900n,
    direction: 'inbound' as const,
    envelopeFrom: 'alice@partner.example',
    headerFrom: 'Alice@Partner.example',
    sizeBytes: 1234,
    attachmentCount: 1,
    emlObjectKey: 'org/7/eml/x.eml',
  };

  it('writes every column, links policy_review requests, actions, events and the notice', async () => {
    const { tx, writes } = fakeTx({
      users: [
        {
          id: 55n,
          organizationId: 7n,
          email: 'Bob@Corp.example',
          status: 'active',
          deletedAt: null,
        },
      ],
    });
    const writer = new QuarantineStoreWriter(() => undefined);
    const out = await writer.createEntries(tx as never, {
      message,
      origin: 'policy',
      candidates: [
        {
          recipientId: 500n,
          rcptSeq: 0,
          address: 'BOB@corp.example',
          kind: 'quarantine',
          facts: entryFactsFromResult(result, input, null, 'quarantine'),
        },
        {
          recipientId: 501n,
          rcptSeq: 1,
          address: 'carol@corp.example',
          kind: 'review',
          facts: entryFactsFromResult(result, input, null, 'review'),
        },
      ],
      settings,
      bounds: { maxHoldDays: 60, maxReviewDays: 13 },
      now: NOW,
      correlationId: 'corr-1',
    });
    const created = writes.find(([k]) => k === 'entry.createMany')![1] as {
      data: Array<Record<string, unknown>>;
      skipDuplicates: boolean;
    };
    expect(created.skipDuplicates).toBe(true);
    expect(created.data[0]).toMatchObject({
      organizationId: 7n,
      messageId: 100n,
      messageReceivedAt: RECEIVED,
      lifecycleRound: 2,
      scanId: 900n,
      evaluationSeq: 2,
      recipientId: 500n,
      rcptSeq: 0,
      recipientAddress: 'bob@corp.example',
      userId: 55n,
      direction: 'inbound',
      kind: 'quarantine',
      origin: 'policy',
      reason: 'malware',
      status: 'held',
      envelopeFrom: 'alice@partner.example',
      headerFrom: 'Alice@Partner.example',
      hasAttachments: true,
      attachmentCount: 1,
      sizeBytes: 1234,
      hasHardBlock: true,
      primaryEngine: 'attachment',
      emlObjectKey: 'org/7/eml/x.eml',
      quarantinedAt: NOW,
      expiresAt: new Date(NOW.getTime() + 30 * 86_400_000),
      stateChangedAt: NOW,
      rowVersion: 1,
    });
    expect(created.data[0]).not.toHaveProperty('subject');
    expect(created.data[1]).toMatchObject({
      kind: 'review',
      status: 'pending_approval',
      userId: null,
      expiresAt: new Date(NOW.getTime() + 7 * 86_400_000),
    });
    const request = writes.find(([k]) => k === 'request.create')![1] as {
      data: Record<string, unknown>;
    };
    expect(request.data).toMatchObject({
      kind: 'policy_review',
      status: 'pending',
      requestedByType: 'system',
      approvalReasons: ['review', 'hard_block', 'policy_reject'],
      expiresAt: new Date(NOW.getTime() + 7 * 86_400_000),
    });
    expect(out.created.map((e) => [e.rcptSeq, e.kind, e.approvalRequestPublicId !== null])).toEqual(
      [
        [0, 'quarantine', false],
        [1, 'review', true],
      ],
    );
    expect(out.notifications).toBe(1);
    const actions = writes.find(([k]) => k === 'action.createMany')![1] as {
      data: Array<Record<string, unknown>>;
    };
    expect(actions.data.map((a) => [a.action, a.actorType])).toEqual([
      ['quarantine', 'system'],
      ['quarantine', 'system'],
    ]);
    expect(writes.filter(([k]) => k === 'event')).toHaveLength(2);
    const outbox = writes.find(([k]) => k === 'outbox')![1] as { data: Record<string, unknown> };
    expect(outbox.data).toMatchObject({
      eventType: 'mail.quarantine.notification_requested.v1',
      aggregateType: 'quarantine',
      aggregateId: '7',
    });
  });

  it('no notice when alerts.approvalRequests is off; adoption expiry is ≥ now + 1 day', async () => {
    const { tx, writes } = fakeTx({});
    const writer = new QuarantineStoreWriter(() => undefined);
    const off = resolveQuarantineSettings({ alerts: { approvalRequests: false } }).settings;
    await writer.createEntries(tx as never, {
      message: { ...message, receivedAt: new Date(NOW.getTime() - 20 * 86_400_000) },
      origin: 'adopted',
      candidates: [
        {
          recipientId: 500n,
          rcptSeq: 0,
          address: 'a@corp.example',
          kind: 'review',
          facts: entryFactsFromView(null, 'review'),
        },
      ],
      settings: off,
      bounds: { maxHoldDays: 60, maxReviewDays: 13 },
      now: NOW,
      expiryFrom: new Date(NOW.getTime() - 20 * 86_400_000),
      correlationId: 'c',
    });
    expect(writes.some(([k]) => k === 'outbox')).toBe(false);
    const created = writes.find(([k]) => k === 'entry.createMany')![1] as {
      data: Array<Record<string, unknown>>;
    };
    expect(created.data[0]).toMatchObject({
      origin: 'adopted',
      evaluationSeq: null,
      expiresAt: new Date(NOW.getTime() + 86_400_000),
    });
    const actions = writes.find(([k]) => k === 'action.createMany')![1] as {
      data: Array<Record<string, unknown>>;
    };
    expect(actions.data[0]!.action).toBe('adopt');
  });
});

describe('QuarantineStoreWriter.supersedeEarlierRounds (Q5)', () => {
  const entry = (over: Record<string, unknown> = {}) => ({
    id: 1n,
    organizationId: 7n,
    messageId: 100n,
    lifecycleRound: 0,
    status: 'held',
    rowVersion: 3,
    ...over,
  });

  it('supersedes earlier non-terminal entries (CAS), cancels their requests, resets recipients', async () => {
    const { tx, writes } = fakeTx({
      entries: [entry(), entry({ id: 2n, status: 'pending_approval' })],
      requests: [
        {
          id: 9n,
          publicId: 'r9',
          organizationId: 7n,
          quarantineMessageId: 2n,
          status: 'pending',
          rowVersion: 1,
        },
      ],
    });
    const writer = new QuarantineStoreWriter(() => undefined);
    expect(await writer.supersedeEarlierRounds(tx as never, KEY, 1, NOW)).toBe(2);
    const updates = writes.filter(([k]) => k === 'entry.update').map(([, a]) => a);
    expect(updates).toEqual([
      expect.objectContaining({
        where: { id: 1n, rowVersion: 3, status: 'held' },
        data: expect.objectContaining({ status: 'superseded', rowVersion: { increment: 1 } }),
      }),
      expect.objectContaining({ where: { id: 2n, rowVersion: 3, status: 'pending_approval' } }),
    ]);
    expect(writes.find(([k]) => k === 'request.update')![1]).toMatchObject({
      where: { id: 9n, rowVersion: 1, status: 'pending' },
      data: { status: 'cancelled' },
    });
    expect(writes.find(([k]) => k === 'recipient.update')![1]).toMatchObject({
      where: { status: 'quarantined' },
      data: { status: 'pending', finalAction: null },
    });
  });

  it('a lost compare-and-set or a foreign row is a retryable inconsistent read', async () => {
    const sink = vi.fn();
    const writer = new QuarantineStoreWriter(sink);
    const lost = fakeTx({ entries: [entry()], casCount: 0 });
    await expect(
      writer.supersedeEarlierRounds(lost.tx as never, KEY, 1, NOW),
    ).rejects.toBeInstanceOf(InconsistentQuarantineReadError);
    const foreign = fakeTx({ entries: [entry({ organizationId: 8n })] });
    await expect(
      writer.supersedeEarlierRounds(foreign.tx as never, KEY, 1, NOW),
    ).rejects.toBeInstanceOf(InconsistentQuarantineReadError);
    expect(sink).toHaveBeenCalledWith('entry_update');
    expect(sink).toHaveBeenCalledWith('entries');
  });
});

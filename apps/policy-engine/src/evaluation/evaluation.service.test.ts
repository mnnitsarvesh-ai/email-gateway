import { MetricsService, NonRetryableError } from '@email-gateway/common';
import {
  deliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
  messageArchiveRequestedV1,
  policyDecidedV1,
  policyNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import type { TransitionOutcome, TransitionRequest } from '@email-gateway/message-lifecycle';
import { compileSnapshot, POLICY_DEFAULT_PLATFORM_ID } from '@email-gateway/policy-dsl';
import { describe, expect, it, vi } from 'vitest';
import type { DeliveryObject } from '../delivery/delivery-object';
import type { PolicyCopyResult, PolicyCopyWriter } from '../delivery/policy-copy';
import { PolicyMetrics } from '../metrics/policy-metrics';
import { InconsistentPolicyReadError } from './errors';
import {
  MAX_APPROVAL_RECIPIENTS,
  PolicyEvaluationService,
  type TriggerPayload,
} from './evaluation.service';
import type { RoundFacts } from './facts.repository';
import { cleanFacts, cleanRiskRow, definition, POLICY_A, RULES } from './fixtures.test-support';
import type { SnapshotLookup } from './snapshot.repository';

const RECEIVED = '2026-11-10T09:59:00.000Z';
const NOW = new Date('2026-11-10T10:00:05.000Z');
const EML = 'org/7/eml/2026/11/10/stored.eml';
const EVENT_ID = '0190f0f0-0000-7000-8000-000000000001';

function scannedEvent(
  options: {
    outcome?: 'scanned' | 'scan_failed';
    direction?: 'inbound' | 'outbound';
    round?: number;
  } = {},
): EventEnvelope<TriggerPayload> {
  const outcome = options.outcome ?? 'scanned';
  return {
    eventId: EVENT_ID,
    eventType: EventTypes.MessageScanned,
    occurredAt: NOW.toISOString(),
    correlationId: 'corr-12345678',
    organizationId: '7',
    payload: {
      messageId: '100',
      receivedAt: RECEIVED,
      direction: options.direction ?? 'inbound',
      emlS3Key: EML,
      lifecycleRound: options.round ?? 0,
      scanId: '900',
      scanKind: (options.round ?? 0) === 0 ? 'initial' : 'rescan',
      outcome,
      verdict: outcome === 'scanned' ? 'clean' : 'timeout',
      engines: [
        {
          engine: 'url',
          required: true,
          outcome: outcome === 'scanned' ? 'clean' : 'timeout',
          attempts: 1,
        },
      ],
      reasonCodes: [],
      completedAt: NOW.toISOString(),
    },
  };
}

const parseFailedEvent: EventEnvelope<TriggerPayload> = {
  eventId: EVENT_ID,
  eventType: EventTypes.MessageParseFailed,
  occurredAt: NOW.toISOString(),
  correlationId: 'corr-12345678',
  organizationId: '7',
  payload: {
    messageId: '100',
    receivedAt: RECEIVED,
    direction: 'inbound',
    emlS3Key: EML,
    reason: 'parser_error',
    attempts: 1,
    parserVersion: 'mime/1',
  } as never,
};

/** Compiled snapshot of the given policies (generation 3). */
function snapshot(
  policies: Array<{
    rules: unknown[];
    direction?: 'inbound' | 'outbound' | 'any';
    publicId?: string;
  }> = [],
  settings: unknown = null,
): SnapshotLookup {
  const source = policies.map((p, i) => {
    const d = definition(p.direction ?? 'inbound', p.rules);
    return {
      publicId: p.publicId ?? POLICY_A,
      versionNo: i + 1,
      definition: d.definition,
      definitionSha256: d.definitionSha256,
    };
  });
  const compiled = compileSnapshot({
    generation: '3',
    settings,
    platformDefaultId: POLICY_DEFAULT_PLATFORM_ID,
    policies: source,
  });
  return {
    compiled,
    policyVersionIds: Object.fromEntries(
      source.map((s, i) => [`${s.publicId}#${s.versionNo}`, String(50 + i)]),
    ),
    cache: 'miss',
    invalidVersions: compiled.invalid.length,
  };
}

/** A transaction double recording every write in order. */
function fakeTx(
  options: { pending?: number; maxDeliverySeq?: number | null; updateCount?: number } = {},
) {
  const writes: Array<{ kind: string; data: Record<string, unknown> }> = [];
  const pending = Array.from({ length: options.pending ?? 1 }, (_, i) => ({
    id: BigInt(500 + i),
    rcptSeq: i,
    messageId: 100n,
    organizationId: 7n,
  }));
  const tx = {
    policyExecutionLog: {
      create: vi.fn((args: { data: Record<string, unknown> }) => {
        writes.push({ kind: 'log', data: args.data });
        return Promise.resolve({ id: 1n });
      }),
    },
    emailMessage: {
      updateMany: vi.fn((args: { data: Record<string, unknown> }) => {
        writes.push({ kind: 'message', data: args.data });
        return Promise.resolve({ count: options.updateCount ?? 1 });
      }),
    },
    emailRecipient: { findMany: vi.fn(() => Promise.resolve(pending)) },
    emailDelivery: {
      aggregate: vi.fn(() =>
        Promise.resolve({ _max: { deliverySeq: options.maxDeliverySeq ?? null } }),
      ),
    },
    messageOutbox: {
      create: vi.fn((args: { data: Record<string, unknown> }) => {
        writes.push({ kind: `outbox:${String(args.data.eventType)}`, data: args.data });
        return Promise.resolve({ id: 1n });
      }),
    },
    emailEvent: {
      create: vi.fn((args: { data: Record<string, unknown> }) => {
        writes.push({ kind: `event:${String(args.data.eventType)}`, data: args.data });
        return Promise.resolve({ id: 1n });
      }),
    },
  };
  return { tx, writes };
}

function harness(
  options: {
    facts?: RoundFacts;
    snapshot?: SnapshotLookup;
    first?: TransitionOutcome['result'];
    object?: DeliveryObject;
    copy?: PolicyCopyResult;
    directory?: Record<string, string[]>;
  } = {},
) {
  const service = new MetricsService({ service: 't' });
  const metrics = new PolicyMetrics(service);
  const transitions: TransitionRequest[] = [];
  const transition = vi.fn((_tx: unknown, request: TransitionRequest) => {
    transitions.push(request);
    const snapshotOf = {
      state: request.to,
      version: 3,
      round: request.expectedRound ?? 0,
      statusChangedAt: NOW,
      statusReason: request.reason,
      direction: options.facts?.message.direction ?? 'inbound',
      emlObjectKey: EML,
    } as const;
    if (transitions.length === 1 && options.first !== undefined && options.first !== 'applied') {
      if (options.first === 'not_found') return Promise.resolve({ result: 'not_found' } as const);
      return Promise.resolve({
        result: options.first,
        why: 'older_round',
        snapshot: snapshotOf,
      } as unknown as TransitionOutcome);
    }
    return Promise.resolve({
      result: 'applied',
      from: 'scanned',
      to: request.to,
      version: 3,
      round: snapshotOf.round,
      historyId: 1n,
      stateEventId: '0190f0f0-0000-7000-8000-0000000000ee',
      snapshot: snapshotOf,
    } as TransitionOutcome);
  });
  const copies: PolicyCopyWriter & { calls: unknown[] } = {
    calls: [],
    write(request) {
      this.calls.push(request);
      return Promise.resolve(options.copy ?? { result: 'written', key: request.key });
    },
  };
  const facts = { read: vi.fn(() => Promise.resolve(options.facts ?? cleanFacts())) };
  const directory = {
    resolve: vi.fn(() =>
      Promise.resolve({ departmentsByAddress: options.directory ?? {}, usersByAddress: {} }),
    ),
  };
  const evaluation = new PolicyEvaluationService({
    facts,
    snapshots: { get: vi.fn(() => Promise.resolve(options.snapshot ?? snapshot())) },
    directory,
    copies,
    metrics,
    logger: createLogger({ service: 't', level: 'silent' }),
    copyTimeoutMs: 60_000,
    now: () => NOW,
    transition: transition,
    resolveObject: vi.fn((): Promise<DeliveryObject> =>
      Promise.resolve(options.object ?? { key: EML, object: 'original' }),
    ),
  });
  return { evaluation, transitions, copies, facts, directory, metrics, service };
}

const outboxOf = (writes: Array<{ kind: string; data: Record<string, unknown> }>, type: string) =>
  writes.filter((w) => w.kind === `outbox:${type}`).map((w) => w.data);

describe('PolicyEvaluationService: scanned round → ALLOW (P13 steps 1–8)', () => {
  it('applies E8, writes the row, the message columns, E10, then the outbox and events in order', async () => {
    const h = harness();
    const { tx, writes } = fakeTx();
    const outcome = await h.evaluation.evaluate(scannedEvent(), tx as never);
    expect(outcome).toMatchObject({ status: 'evaluated', approvals: 1, copy: null, cache: 'miss' });

    expect(h.transitions.map((t) => [t.to, t.reason, t.expectedRound, t.expectedFrom])).toEqual([
      ['policy_evaluated', 'policy_decided', 0, ['scanned']],
      ['approved', 'policy_deliver', 0, ['policy_evaluated']],
    ]);
    expect(h.transitions[0]).toMatchObject({
      actor: { role: 'policy', service: 'policy-engine', type: 'system' },
      transitionKey: `evt:${EVENT_ID}:policy_evaluated`,
      causationEventId: EVENT_ID,
      correlationId: 'corr-12345678',
      message: { id: 100n, organizationId: 7n, receivedAt: new Date(RECEIVED) },
    });
    expect(h.transitions[1]!.transitionKey).toBe(`evt:${EVENT_ID}:approved`);
    expect(writes.map((w) => w.kind)).toEqual([
      'log',
      'message',
      `outbox:${EventTypes.PolicyDecided}`,
      'event:policy.evaluated',
      `outbox:${EventTypes.DeliveryApproved}`,
      'event:delivery.approved',
    ]);

    const log = writes[0]!.data;
    expect(log).toMatchObject({
      messageId: 100n,
      organizationId: 7n,
      evaluationSeq: 0,
      scanId: 900n,
      trigger: 'scanned',
      direction: 'inbound',
      disposition: 'allow',
      decisionSource: 'platform_default',
      decisivePolicyVersionId: null,
      action: 'deliver',
      deliveredObject: 'original',
      objectKey: null,
      policyGeneration: 3n,
      evaluatedAt: NOW,
    });
    expect(typeof log.durationUs).toBe('number');
    expect(writes[1]!.data).toEqual({
      finalVerdict: 'clean',
      finalAction: 'deliver',
      riskScore: 40,
    });

    const decided = policyDecidedV1.parse(outboxOf(writes, EventTypes.PolicyDecided)[0]!.payload);
    expect(decided).toMatchObject({
      messageId: '100',
      lifecycleRound: 0,
      scanId: '900',
      trigger: 'scanned',
      disposition: 'allow',
      finalAction: 'deliver',
      decisive: { source: 'platform_default', policyId: null, versionNo: null, ruleId: null },
      policyGeneration: '3',
      overrideApplied: false,
      nonTerminalActions: [],
    });
    const approvalRow = outboxOf(writes, EventTypes.DeliveryApproved)[0]!;
    expect(approvalRow).toMatchObject({
      organizationId: 7n,
      aggregateType: 'message',
      aggregateId: '100',
      correlationId: 'corr-12345678',
    });
    expect(deliveryApprovedV1.parse(approvalRow.payload)).toEqual({
      messageId: '100',
      receivedAt: RECEIVED,
      deliverySeq: 0,
      lifecycleRound: 0,
      source: 'policy',
      emlS3Key: EML,
      recipients: [{ recipientId: '500', rcptSeq: 0 }],
      approvedAt: NOW.toISOString(),
    });
    const evaluated = writes.find((w) => w.kind === 'event:policy.evaluated')!.data;
    expect(evaluated.details).toEqual({
      disposition: 'allow',
      source: 'platform_default',
      generation: '3',
      evaluationSeq: 0,
    });
    // No content in any stored detail.
    expect(JSON.stringify(writes.map((w) => w.data.details ?? null))).not.toContain('@');
  });

  it('delivers the round rewritten copy and chunks approvals of more than 1000 pending recipients', async () => {
    const h = harness({
      facts: cleanFacts({ round: 1 }),
      object: { key: 'org/7/rewrite/2026/11/10/100/r1-x.eml', object: 'rewritten' },
    });
    const { tx, writes } = fakeTx({ pending: MAX_APPROVAL_RECIPIENTS + 1, maxDeliverySeq: 2 });
    const outcome = await h.evaluation.evaluate(scannedEvent({ round: 1 }), tx as never);
    expect(outcome).toMatchObject({ status: 'evaluated', approvals: 2 });
    const approvals = outboxOf(writes, EventTypes.DeliveryApproved).map((r) =>
      deliveryApprovedV1.parse(r.payload),
    );
    expect(
      approvals.map((a) => [a.recipients.length, a.deliverySeq, a.lifecycleRound, a.emlS3Key]),
    ).toEqual([
      [1000, 3, 1, 'org/7/rewrite/2026/11/10/100/r1-x.eml'],
      [1, 3, 1, 'org/7/rewrite/2026/11/10/100/r1-x.eml'],
    ]);
    expect(writes.filter((w) => w.kind === 'event:delivery.approved')).toHaveLength(2);
    expect(writes[0]!.data).toMatchObject({ deliveredObject: 'rewritten', evaluationSeq: 1 });
  });
});

describe('PolicyEvaluationService: lifecycle skips and triggers', () => {
  it.each(['stale', 'invalid', 'duplicate', 'not_found'] as const)(
    'a first edge that is %s writes nothing (ledger only)',
    async (result) => {
      const h = harness({ first: result });
      const { tx, writes } = fakeTx();
      expect(await h.evaluation.evaluate(scannedEvent(), tx as never)).toEqual({
        status: 'skipped',
        result,
      });
      expect(writes).toEqual([]);
      expect(h.facts.read).not.toHaveBeenCalled();
      expect(h.transitions).toHaveLength(1);
    },
  );

  it('scan_failed → E9 (scan_failed_fail_safe), held by the floor (quarantine, E11), nothing approved', async () => {
    const h = harness({ facts: cleanFacts({ trigger: 'scan_failed' }) });
    const { tx, writes } = fakeTx();
    const outcome = await h.evaluation.evaluate(
      scannedEvent({ outcome: 'scan_failed' }),
      tx as never,
    );
    expect(h.transitions.map((t) => [t.to, t.reason, t.expectedFrom])).toEqual([
      ['policy_evaluated', 'scan_failed_fail_safe', ['scan_failed']],
      ['quarantined', 'policy_quarantine', ['policy_evaluated']],
    ]);
    expect(outcome).toMatchObject({ status: 'evaluated', approvals: 0 });
    if (outcome.status !== 'evaluated') throw new Error('not evaluated');
    expect(outcome.result.floor.reasons).toContain('policy.floor.scan_failed');
    expect(outboxOf(writes, EventTypes.DeliveryApproved)).toEqual([]);
    expect(writes[0]!.data).toMatchObject({ trigger: 'scan_failed', deliveredObject: 'none' });
  });

  it('parse_failed → E5 from persisted in round 0, quarantined (not_scanned), no scan id', async () => {
    const h = harness({ facts: cleanFacts({ trigger: 'parse_failed' }) });
    const { tx, writes } = fakeTx();
    await h.evaluation.evaluate(parseFailedEvent, tx as never);
    expect(h.transitions.map((t) => [t.to, t.reason, t.expectedRound, t.expectedFrom])).toEqual([
      ['policy_evaluated', 'parse_failed_fail_safe', 0, ['persisted']],
      ['quarantined', 'policy_quarantine', 0, ['policy_evaluated']],
    ]);
    expect(h.facts.read).toHaveBeenCalledWith(
      tx,
      expect.objectContaining({ scanId: null, round: 0, trigger: 'parse_failed' }),
    );
    expect(writes[0]!.data).toMatchObject({
      scanId: null,
      trigger: 'parse_failed',
      disposition: 'quarantine',
    });
    expect(
      policyDecidedV1.parse(outboxOf(writes, EventTypes.PolicyDecided)[0]!.payload),
    ).toMatchObject({
      scanId: null,
      trigger: 'parse_failed',
      finalAction: 'quarantine',
    });
  });

  it('a missing revision-0 risk row is held by the floor (risk_missing)', async () => {
    const h = harness({ facts: cleanFacts({ risk: [] }) });
    const { tx } = fakeTx();
    const outcome = await h.evaluation.evaluate(scannedEvent(), tx as never);
    expect(outcome).toMatchObject({ status: 'evaluated', riskMissing: true });
    if (outcome.status !== 'evaluated') throw new Error('not evaluated');
    expect(outcome.result.disposition).toBe('quarantine');
  });
});

describe('PolicyEvaluationService: tenant rules and actions', () => {
  it('TAG with a subject prefix → a policy copy named by the approval, TAG enforced, final action tag', async () => {
    const h = harness({ snapshot: snapshot([{ rules: [RULES.tagExternal] }]) });
    const { tx, writes } = fakeTx();
    const outcome = await h.evaluation.evaluate(scannedEvent(), tx as never);
    if (outcome.status !== 'evaluated') throw new Error('not evaluated');
    expect(h.copies.calls).toHaveLength(1);
    const call = h.copies.calls[0] as { baseKey: string; key: string; edits: unknown };
    expect(call.baseKey).toBe(EML);
    expect(call.key).toMatch(/^org\/7\/policy\/2026\/11\/10\/100\/r0-[0-9a-f]{32}\.eml$/);
    expect(call.edits).toEqual({
      headers: [{ name: 'X-EG-Policy-Tag', value: 'external' }],
      subjectPrefix: '[EXT]',
    });
    expect(h.transitions[1]).toMatchObject({ to: 'approved', reason: 'policy_tag' });
    const approval = deliveryApprovedV1.parse(
      outboxOf(writes, EventTypes.DeliveryApproved)[0]!.payload,
    );
    expect(approval.emlS3Key).toBe(call.key);
    const log = writes[0]!.data;
    expect(log).toMatchObject({
      deliveredObject: 'policy_copy',
      objectKey: call.key,
      action: 'tag',
    });
    const actions = log.actions as Array<{ type: string; status: string }>;
    expect(actions.find((a) => a.type === 'TAG')?.status).toBe('enforced');
    expect(outcome.copy).toBe('written');
    const decided = policyDecidedV1.parse(outboxOf(writes, EventTypes.PolicyDecided)[0]!.payload);
    expect(decided).toMatchObject({ finalAction: 'tag', nonTerminalActions: ['TAG'] });
  });

  it.each(['too_large', 'header_too_large'] as const)(
    'a refused copy (%s) delivers the base object and records TAG instead of enforcing it',
    async (refusal) => {
      const h = harness({
        snapshot: snapshot([{ rules: [RULES.tagExternal] }]),
        copy: { result: refusal },
      });
      const { tx, writes } = fakeTx();
      const outcome = await h.evaluation.evaluate(scannedEvent(), tx as never);
      if (outcome.status !== 'evaluated') throw new Error('not evaluated');
      expect(outcome.copy).toBe(refusal);
      const approval = deliveryApprovedV1.parse(
        outboxOf(writes, EventTypes.DeliveryApproved)[0]!.payload,
      );
      expect(approval.emlS3Key).toBe(EML);
      const log = writes[0]!.data;
      expect(log).toMatchObject({ deliveredObject: 'original', objectKey: null });
      expect(
        (log.actions as Array<{ type: string; status: string }>).find((a) => a.type === 'TAG')
          ?.status,
      ).toBe('recorded');
      const decided = policyDecidedV1.parse(outboxOf(writes, EventTypes.PolicyDecided)[0]!.payload);
      expect(decided.nonTerminalActions).toEqual([]);
    },
  );

  it.each([
    [RULES.quarantineInbound, 'quarantined', 'policy_quarantine', 'quarantine'],
    [RULES.holdInbound, 'held_for_review', 'policy_hold', 'require_approval'],
    [RULES.rejectAny('inbound'), 'rejected', 'policy_discard', 'discard'],
  ] as const)(
    'tenant %# → %s (%s), no approval, decisive rule recorded',
    async (rule, to, reason, finalAction) => {
      const h = harness({ snapshot: snapshot([{ rules: [rule] }]) });
      const { tx, writes } = fakeTx();
      await h.evaluation.evaluate(scannedEvent(), tx as never);
      expect(h.transitions[1]).toMatchObject({ to, reason });
      expect(outboxOf(writes, EventTypes.DeliveryApproved)).toEqual([]);
      expect(writes[0]!.data).toMatchObject({
        decisionSource: 'tenant_rule',
        decisivePolicyPublicId: POLICY_A,
        decisivePolicyVersionId: 50n,
        decisiveRuleId: rule.id,
        matchedPolicyVersionIds: ['50'],
        action: finalAction,
      });
      expect(writes[1]!.data).toMatchObject({ finalAction });
      // Inbound reject: never a notice to the (external) sender.
      expect(outboxOf(writes, EventTypes.PolicyNotificationRequested)).toEqual([]);
    },
  );

  it('outbound REJECT → policy_reject and a sender non-delivery notice request', async () => {
    const h = harness({
      facts: cleanFacts({ direction: 'outbound', recipients: ['x@external.example'] }),
      snapshot: snapshot([{ rules: [RULES.rejectAny('outbound')], direction: 'outbound' }]),
    });
    const { tx, writes } = fakeTx();
    await h.evaluation.evaluate(scannedEvent({ direction: 'outbound' }), tx as never);
    expect(h.transitions[1]).toMatchObject({ to: 'rejected', reason: 'policy_reject' });
    const notices = outboxOf(writes, EventTypes.PolicyNotificationRequested).map((r) =>
      policyNotificationRequestedV1.parse(r.payload),
    );
    expect(notices).toEqual([
      expect.objectContaining({
        kind: 'sender_non_delivery',
        direction: 'outbound',
        disposition: 'reject',
        decisive: { source: 'tenant_rule', policyId: POLICY_A, versionNo: 1, ruleId: 'reject-all' },
        ruleRefs: [`${POLICY_A}#1/reject-all`],
      }),
    ]);
  });

  it('ARCHIVE and ALERT → archive_requested (original EML) and a policy_alert notification', async () => {
    const h = harness({ snapshot: snapshot([{ rules: [RULES.archiveAlert] }]) });
    const { tx, writes } = fakeTx();
    const outcome = await h.evaluation.evaluate(scannedEvent(), tx as never);
    if (outcome.status !== 'evaluated') throw new Error('not evaluated');
    const archive = messageArchiveRequestedV1.parse(
      outboxOf(writes, EventTypes.MessageArchiveRequested)[0]!.payload,
    );
    expect(archive).toMatchObject({
      emlS3Key: EML,
      source: 'policy',
      ruleRef: `${POLICY_A}#1/archive-alert`,
      policyGeneration: '3',
    });
    const alert = policyNotificationRequestedV1.parse(
      outboxOf(writes, EventTypes.PolicyNotificationRequested)[0]!.payload,
    );
    expect(alert).toMatchObject({
      kind: 'policy_alert',
      severity: 'warning',
      disposition: 'allow',
    });
    const statuses = (writes[0]!.data.actions as Array<{ type: string; status: string }>).map(
      (a) => [a.type, a.status],
    );
    expect(statuses).toEqual(
      expect.arrayContaining([
        ['ARCHIVE', 'requested'],
        ['ALERT', 'requested'],
      ]),
    );
    const decided = policyDecidedV1.parse(outboxOf(writes, EventTypes.PolicyDecided)[0]!.payload);
    expect(decided.nonTerminalActions).toEqual(['ARCHIVE', 'ALERT']);
  });

  it('ALERT with alerts disabled is recorded and requests nothing', async () => {
    const h = harness({
      snapshot: snapshot([{ rules: [RULES.archiveAlert] }], { alerts: { enabled: false } }),
    });
    const { tx, writes } = fakeTx();
    await h.evaluation.evaluate(scannedEvent(), tx as never);
    expect(outboxOf(writes, EventTypes.PolicyNotificationRequested)).toEqual([]);
    expect(
      (writes[0]!.data.actions as Array<{ type: string; status: string }>).find(
        (a) => a.type === 'ALERT',
      )?.status,
    ).toBe('recorded');
  });

  it('resolves the directory for referenced departments by the normalized recipient addresses', async () => {
    const dept = '0190f0f0-0000-7000-8000-0000000000d1';
    const h = harness({
      facts: cleanFacts({ recipients: ['Fin@Corp.Example'] }),
      snapshot: snapshot([{ rules: [RULES.departmentException(dept)] }]),
      directory: { 'fin@corp.example': [dept] },
    });
    const { tx, writes } = fakeTx();
    await h.evaluation.evaluate(scannedEvent(), tx as never);
    expect(h.directory.resolve).toHaveBeenCalledWith(
      tx,
      7n,
      { departmentIds: [dept], userIds: [] },
      // Envelope recipients and the authenticated sender (DMARC pass), normalized (P5).
      ['fin@corp.example', 'alice@partner.example'],
    );
    // The department exception applies: not quarantined.
    expect(writes[0]!.data).toMatchObject({ disposition: 'allow' });
  });

  it('skips the directory when the snapshot references none', async () => {
    const h = harness();
    await h.evaluation.evaluate(scannedEvent(), fakeTx().tx as never);
    expect(h.directory.resolve).not.toHaveBeenCalled();
  });
});

describe('PolicyEvaluationService: failures', () => {
  it('malformed rows → NonRetryableError (dead letter), counted, nothing written after E8', async () => {
    const h = harness({ facts: cleanFacts({ risk: [cleanRiskRow({ engines: 'not-a-list' })] }) });
    const { tx, writes } = fakeTx();
    await expect(h.evaluation.evaluate(scannedEvent(), tx as never)).rejects.toBeInstanceOf(
      NonRetryableError,
    );
    expect(writes).toEqual([]);
    expect(await h.service.metrics()).toContain('policy_input_errors_total{service="t"} 1');
  });

  it('an update that does not hit exactly one message row is a retryable inconsistent read', async () => {
    const h = harness();
    const { tx } = fakeTx({ updateCount: 0 });
    await expect(h.evaluation.evaluate(scannedEvent(), tx as never)).rejects.toBeInstanceOf(
      InconsistentPolicyReadError,
    );
    expect(await h.service.metrics()).toContain(
      'policy_inconsistent_reads_total{read="message_update",service="t"} 1',
    );
  });

  it('a decision whose direction disagrees with the locked row is retryable', async () => {
    const h = harness({ facts: cleanFacts({ direction: 'outbound' }) });
    // The fake transition reports the facts' direction; force a disagreement.
    const { tx } = fakeTx();
    const evaluation = h.evaluation as unknown as {
      transition: (...a: unknown[]) => Promise<TransitionOutcome>;
    };
    const original = evaluation.transition;
    evaluation.transition = async (...args) => {
      const out = await original(...args);
      return out.result === 'applied'
        ? { ...out, snapshot: { ...out.snapshot, direction: 'inbound' } }
        : out;
    };
    await expect(h.evaluation.evaluate(scannedEvent(), tx as never)).rejects.toBeInstanceOf(
      InconsistentPolicyReadError,
    );
  });
});

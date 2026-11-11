import { NonRetryableError, uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import {
  deliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
  messageArchiveRequestedV1,
  type MessageParseFailedV1,
  type MessageScannedV1,
  policyDecidedV1,
  policyNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  type ActionStatus,
  buildPolicyInput,
  evaluatePolicy,
  evaluationResultToRow,
  intendedActionStatuses,
  lifecycleOutcome,
  type LifecycleOutcome,
  type PolicyDeliveredObject,
  type PolicyEvaluationResult,
  type PolicyInput,
  PolicyInputError,
  type PolicyRoundRows,
  referencedDirectoryIds,
} from '@email-gateway/policy-dsl';
import {
  transitionMessage,
  type LifecycleSnapshot,
  type TransitionOutcome,
  type TransitionRequest,
} from '@email-gateway/message-lifecycle';
import { deliveryObject, type DeliveryObject } from '../delivery/delivery-object';
import {
  hasEdits,
  policyCopyKey,
  type PolicyCopyResult,
  type PolicyCopyWriter,
} from '../delivery/policy-copy';
import type { PolicyMetrics } from '../metrics/policy-metrics';
import {
  type DirectoryMaps,
  type DirectoryRepository,
  EMPTY_DIRECTORY,
} from './directory.repository';
import { type InconsistencySink, POLICY_INPUT_INVALID, wrongRead } from './errors';
import type { FactsRepository, RoundRef } from './facts.repository';
import type { SnapshotLookup, SnapshotRepository } from './snapshot.repository';

/** `message_idempotency.consumer` of the `email.policy.evaluate` consumer (P13, topology v9). */
export const POLICY_EVALUATE_CONSUMER = 'policy-engine.evaluate';
/** `actor.service`, `email_events.source_service`. */
export const SOURCE_SERVICE = 'policy-engine';
/** `mail.delivery.approved.v1` carries at most 1000 recipients (P15). */
export const MAX_APPROVAL_RECIPIENTS = 1000;

export type TriggerPayload = MessageScannedV1 | MessageParseFailedV1;

/** What a handled event did; turned into metrics only after the transaction committed. */
export type EvaluationOutcome =
  | { status: 'skipped'; result: 'stale' | 'invalid' | 'duplicate' | 'not_found' }
  | {
      status: 'evaluated';
      result: PolicyEvaluationResult;
      statuses: ActionStatus[];
      copy: PolicyCopyResult['result'] | null;
      cache: SnapshotLookup['cache'];
      invalidVersions: number;
      durationSeconds: number;
      riskMissing: boolean;
      approvals: number;
      outcome: LifecycleOutcome;
    };

export interface EvaluationDeps {
  facts: Pick<FactsRepository, 'read'>;
  snapshots: Pick<SnapshotRepository, 'get'>;
  directory: Pick<DirectoryRepository, 'resolve'>;
  copies: PolicyCopyWriter;
  metrics: Pick<PolicyMetrics, 'inconsistentReads' | 'inputErrors' | 'lifecycle'>;
  logger: Logger;
  /** Budget of the policy copy upload (half the transaction budget). */
  copyTimeoutMs: number;
  now?: () => Date;
  /** Monotonic clock in nanoseconds (tests inject a fake). */
  hrtime?: () => bigint;
  transition?: (
    tx: Prisma.TransactionClient,
    request: TransitionRequest,
    deps: Parameters<typeof transitionMessage>[2],
  ) => Promise<TransitionOutcome>;
  resolveObject?: typeof deliveryObject;
}

const ACTOR = { role: 'policy', service: SOURCE_SERVICE, type: 'system' } as const;

/** Is the trigger a `scanned.v1` (vs `parse_failed.v1`)? */
const isScanned = (
  event: EventEnvelope<TriggerPayload>,
): event is EventEnvelope<MessageScannedV1> => event.eventType === EventTypes.MessageScanned;

/**
 * The policy evaluation of one trigger event (step 5.2 P13, ADR-0044), entirely inside the
 * consumer's writer transaction (`processOnceHandler`, ledger `policy-engine.evaluate`):
 *
 * 1. organization = the envelope's (trusted), matched against the writer message row by every
 *    read; `scanned.v1` (`scanned` → E8, `scan_failed` → E9) or `parse_failed.v1` (E5, round 0:
 *    the event carries no round and a parse failure only happens in round 0);
 * 2. the first edge locks the message; not applied (stale, superseded round, already evaluated,
 *    not found) → ledger row only (`policy_lifecycle_skipped_total{result}`);
 * 3. P8 facts (echo-checked), the snapshot of the current generation (LRU), the directory of the
 *    snapshot's references, `buildPolicyInput`, `evaluatePolicy` (a `PolicyInputError` or any
 *    evaluator exception → `NonRetryableError`: dead letter, the message stays held);
 * 4. ALLOW: the delivered object (P20) and, with header edits, the policy copy (P21);
 * 5. the `policy_execution_logs` row (`evaluation_seq` = round; the unique key is the backstop);
 * 6. `email_messages.final_verdict`, `final_action`, `risk_score` (exactly one row);
 * 7. the disposition edge (E10–E13, P18);
 * 8. outbox rows (P15, each parsed with its strict schema) and `email_events` rows.
 */
export class PolicyEvaluationService {
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly hrtime: () => bigint;
  private readonly transition: NonNullable<EvaluationDeps['transition']>;
  private readonly resolveObject: typeof deliveryObject;
  private readonly sink: InconsistencySink;

  constructor(private readonly deps: EvaluationDeps) {
    this.logger = deps.logger.child({ component: 'policy-evaluation' });
    this.now = deps.now ?? (() => new Date());
    this.hrtime = deps.hrtime ?? (() => process.hrtime.bigint());
    this.transition = deps.transition ?? transitionMessage;
    this.resolveObject = deps.resolveObject ?? deliveryObject;
    this.sink = (read) => deps.metrics.inconsistentReads.inc({ read });
  }

  async evaluate(
    event: EventEnvelope<TriggerPayload>,
    tx: Prisma.TransactionClient,
  ): Promise<EvaluationOutcome> {
    const scanned = isScanned(event) ? event.payload : null;
    const organizationId = BigInt(event.organizationId);
    const ref: RoundRef = {
      messageId: BigInt(event.payload.messageId),
      receivedAt: new Date(event.payload.receivedAt),
      organizationId,
      round: scanned?.lifecycleRound ?? 0,
      trigger: scanned === null ? 'parse_failed' : scanned.outcome,
      scanId: scanned === null ? null : BigInt(scanned.scanId),
    };
    const ids = {
      eventId: event.eventId,
      messageId: event.payload.messageId,
      round: ref.round,
      trigger: ref.trigger,
    };
    const lifecycleDeps = { metrics: this.deps.metrics.lifecycle, logger: this.logger };

    // 1–2. First edge (locks the message row).
    const from =
      ref.trigger === 'scanned'
        ? 'scanned'
        : ref.trigger === 'scan_failed'
          ? 'scan_failed'
          : 'persisted';
    const first = await this.transition(
      tx,
      {
        message: { id: ref.messageId, receivedAt: ref.receivedAt, organizationId },
        to: 'policy_evaluated',
        reason:
          ref.trigger === 'scanned'
            ? 'policy_decided'
            : ref.trigger === 'scan_failed'
              ? 'scan_failed_fail_safe'
              : 'parse_failed_fail_safe',
        actor: ACTOR,
        transitionKey: `evt:${event.eventId}:policy_evaluated`,
        causationEventId: event.eventId,
        correlationId: event.correlationId,
        expectedRound: ref.round,
        expectedFrom: [from],
      },
      lifecycleDeps,
    );
    if (first.result !== 'applied') {
      this.logger.info(
        {
          ...ids,
          result: first.result,
          why: first.result === 'not_found' ? null : first.why,
          state: first.result === 'not_found' ? null : first.snapshot.state,
        },
        'message is not awaiting policy in this round for the organization; not evaluated',
      );
      return { status: 'skipped', result: first.result };
    }
    const snapshot = first.snapshot;

    // 3. Facts, snapshot, directory, evaluation.
    const started = this.hrtime();
    const facts = await this.deps.facts.read(tx, ref);
    const loaded = await this.deps.snapshots.get(tx, organizationId);
    const result = await this.decide(tx, ref, facts, loaded, ids);
    const durationSeconds = Number(this.hrtime() - started) / 1e9;
    const evaluatedAt = this.now();
    if (result.round.direction !== snapshot.direction) {
      wrongRead(this.sink, 'lifecycle', 'direction echo');
    }
    const outcome = lifecycleOutcome(result, result.round.direction);

    // 4. Delivered object and policy copy (ALLOW only).
    let statuses = intendedActionStatuses(result);
    let deliveredObject: PolicyDeliveredObject = 'none';
    let delivered: DeliveryObject | null = null;
    let copyKey: string | null = null;
    let copy: PolicyCopyResult['result'] | null = null;
    if (result.disposition === 'allow') {
      if (ref.scanId === null) {
        // The floor never allows a parse failure (P9.5, P20); a result saying so is a defect.
        this.deps.metrics.inputErrors.inc();
        throw new NonRetryableError(POLICY_INPUT_INVALID);
      }
      delivered = await this.resolveObject(
        tx,
        {
          messageId: ref.messageId,
          receivedAt: ref.receivedAt,
          organizationId,
          round: ref.round,
          scanId: ref.scanId,
          original: snapshot.emlObjectKey,
        },
        this.sink,
      );
      if (delivered.fallback !== undefined) {
        this.logger.warn(
          { ...ids, reason: delivered.fallback },
          'rewritten copy of the round is not usable; delivering the original message',
        );
      }
      deliveredObject = delivered.object;
      const edits = result.delivery
        ? { headers: result.delivery.headers, subjectPrefix: result.delivery.subjectPrefix }
        : null;
      if (hasEdits(edits)) {
        const key = policyCopyKey({
          organizationId,
          messageId: ref.messageId,
          receivedAt: ref.receivedAt,
          round: ref.round,
          baseKey: delivered.key,
          edits,
        });
        const written = await this.deps.copies.write({
          baseKey: delivered.key,
          key,
          edits,
          signal: AbortSignal.timeout(this.deps.copyTimeoutMs),
        });
        copy = written.result;
        if (written.result === 'written') {
          copyKey = written.key;
          deliveredObject = 'policy_copy';
        } else {
          // P19: a deterministic size refusal records TAG/WARN instead of claiming them.
          statuses = statuses.map((status, i) => {
            const type = result.actions[i]!.type;
            return (type === 'TAG' || type === 'WARN') && status === 'enforced'
              ? 'recorded'
              : status;
          });
          this.logger.info(
            { ...ids, copy: written.result },
            'policy copy refused by its size limits; delivering without header edits',
          );
        }
      }
    }
    const emlS3Key = copyKey ?? delivered?.key ?? null;

    // 5. The evaluation row.
    const row = evaluationResultToRow(result, {
      actionStatuses: statuses,
      deliveredObject,
      objectKey: copyKey,
      policyVersionIds: loaded.policyVersionIds,
    });
    await tx.policyExecutionLog.create({
      data: {
        receivedAt: ref.receivedAt,
        messageId: ref.messageId,
        organizationId,
        evaluationSeq: row.evaluationSeq,
        scanId: row.scanId === null ? null : BigInt(row.scanId),
        trigger: row.trigger,
        direction: row.direction,
        disposition: row.disposition,
        decisionSource: row.decisionSource,
        decisivePolicyVersionId:
          row.decisivePolicyVersionId === null ? null : BigInt(row.decisivePolicyVersionId),
        decisivePolicyPublicId: row.decisivePolicyPublicId,
        decisiveRuleId: row.decisiveRuleId,
        action: row.action,
        finalVerdict: row.finalVerdict,
        riskScore: row.riskScore,
        overrideApplied: row.overrideApplied,
        matchedPolicyVersionIds: row.matchedPolicyVersionIds,
        actions: row.actions,
        matchedRules: row.matchedRules,
        trace: row.trace,
        floor: row.floor,
        recommendation: row.recommendation,
        overrideDetail:
          row.overrideDetail === null
            ? undefined
            : (row.overrideDetail as unknown as Prisma.InputJsonValue),
        clamps: row.clamps,
        reasonCodes: row.reasonCodes,
        delivery:
          row.delivery === null ? undefined : (row.delivery as unknown as Prisma.InputJsonValue),
        deliveredObject: row.deliveredObject,
        objectKey: row.objectKey,
        explanation: row.explanation,
        explanationText: row.explanationText,
        policyGeneration: BigInt(row.policyGeneration),
        snapshotSha256: row.snapshotSha256,
        policyVersions: row.policyVersions,
        platformDefaultId: row.platformDefaultId,
        dslVersion: row.dslVersion,
        evaluatorVersion: row.evaluatorVersion,
        inputVersion: row.inputVersion,
        inputSha256: row.inputSha256,
        tzdataVersion: row.tzdataVersion,
        durationUs: Math.min(4_294_967_295, Math.round(durationSeconds * 1e6)),
        evaluatedAt,
      },
      select: { id: true },
    });

    // 6. The message's final columns.
    const updated = await tx.emailMessage.updateMany({
      where: { id: ref.messageId, receivedAt: ref.receivedAt, organizationId },
      data: {
        finalVerdict: result.finalVerdict,
        finalAction: outcome.finalAction,
        riskScore: result.riskScore,
      },
    });
    if (updated.count !== 1) wrongRead(this.sink, 'message_update', 'one row expected');

    // 7. The disposition edge (same round, under the lock taken by the first edge).
    const second = await this.transition(
      tx,
      {
        message: { id: ref.messageId, receivedAt: ref.receivedAt, organizationId },
        to: outcome.to,
        reason: outcome.reason,
        actor: ACTOR,
        transitionKey: `evt:${event.eventId}:${outcome.to}`,
        causationEventId: event.eventId,
        correlationId: event.correlationId,
        expectedRound: ref.round,
        expectedFrom: ['policy_evaluated'],
      },
      lifecycleDeps,
    );
    if (second.result !== 'applied') {
      // Impossible while this transaction holds the message lock: retry from scratch.
      return wrongRead(this.sink, 'lifecycle', `disposition edge ${second.result}`);
    }

    // 8. Outbox and email_events rows.
    const approvals = await this.writeOutbox(tx, {
      event,
      ref,
      snapshot,
      result,
      statuses,
      outcome,
      emlS3Key,
      evaluatedAt,
    });
    this.logger.info(
      {
        ...ids,
        disposition: result.disposition,
        source: result.decisive.source,
        reason: result.decisive.reason,
        generation: result.versions.generation,
        object: deliveredObject,
        approvals,
      },
      'policy evaluated',
    );
    return {
      status: 'evaluated',
      result,
      statuses,
      copy,
      cache: loaded.cache,
      invalidVersions: loaded.invalidVersions,
      durationSeconds,
      riskMissing: ref.trigger !== 'parse_failed' && !facts.risk.some((r) => r.revision === 0),
      approvals,
      outcome,
    };
  }

  /** Directory, input, evaluation; malformed rows or an evaluator exception dead-letter. */
  private async decide(
    tx: Prisma.TransactionClient,
    ref: RoundRef,
    facts: Omit<PolicyRoundRows, 'directory'>,
    loaded: SnapshotLookup,
    ids: Record<string, unknown>,
  ): Promise<PolicyEvaluationResult> {
    const guarded = <T>(fn: () => T): T => {
      try {
        return fn();
      } catch (error) {
        this.deps.metrics.inputErrors.inc();
        this.logger.error(
          {
            ...ids,
            errName: error instanceof PolicyInputError ? 'PolicyInputError' : 'EvaluatorError',
          },
          'round facts cannot be evaluated; dead-lettering (the message stays held)',
        );
        throw new NonRetryableError(POLICY_INPUT_INVALID);
      }
    };
    // First pass without directory: yields the normalized addresses to resolve (P5).
    let input: PolicyInput = guarded(() =>
      buildPolicyInput({ ...facts, directory: EMPTY_DIRECTORY }),
    );
    const references = referencedDirectoryIds(loaded.compiled);
    if (references.departmentIds.length > 0 || references.userIds.length > 0) {
      const addresses = input.recipients.map((r) => r.address);
      if (input.sender.authenticated !== null) addresses.push(input.sender.authenticated.address);
      const directory: DirectoryMaps = await this.deps.directory.resolve(
        tx,
        ref.organizationId,
        references,
        addresses,
      );
      input = guarded(() => buildPolicyInput({ ...facts, directory }));
    }
    return guarded(() => evaluatePolicy(input, loaded.compiled));
  }

  private async writeOutbox(
    tx: Prisma.TransactionClient,
    c: {
      event: EventEnvelope<TriggerPayload>;
      ref: RoundRef;
      snapshot: LifecycleSnapshot;
      result: PolicyEvaluationResult;
      statuses: ActionStatus[];
      outcome: LifecycleOutcome;
      emlS3Key: string | null;
      evaluatedAt: Date;
    },
  ): Promise<number> {
    const { event, ref, result } = c;
    const now = c.evaluatedAt;
    const at = now.toISOString();
    const base = {
      messageId: ref.messageId.toString(),
      receivedAt: ref.receivedAt.toISOString(),
      direction: result.round.direction,
      lifecycleRound: ref.round,
    };
    const decisive = {
      source: result.decisive.source,
      policyId: result.decisive.policyPublicId,
      versionNo: result.decisive.versionNo,
      ruleId: result.decisive.ruleId,
    };
    const outbox = async (eventType: string, payload: unknown): Promise<string> => {
      const eventId = uuidv7(now.getTime());
      await tx.messageOutbox.create({
        data: {
          eventId,
          organizationId: ref.organizationId,
          eventType,
          aggregateType: 'message',
          aggregateId: ref.messageId.toString(),
          correlationId: event.correlationId,
          payload: payload as Prisma.InputJsonValue,
        },
        select: { id: true },
      });
      return eventId;
    };
    const emailEvent = async (
      eventType: string,
      eventId: string,
      details: Record<string, string | number | boolean | null>,
    ): Promise<void> => {
      await tx.emailEvent.create({
        data: {
          receivedAt: ref.receivedAt,
          messageId: ref.messageId,
          organizationId: ref.organizationId,
          eventType,
          occurredAt: now,
          sourceService: SOURCE_SERVICE,
          eventId,
          details,
        },
        select: { id: true },
      });
    };

    // Applied or requested non-terminal actions (never a recorded or moot one, ADR-0045).
    const nonTerminal = [
      ...new Set(
        result.actions
          .filter(
            (a, i) =>
              a.type !== 'ALLOW' &&
              a.type !== 'QUARANTINE' &&
              a.type !== 'REQUIRE_APPROVAL' &&
              a.type !== 'REJECT' &&
              (c.statuses[i] === 'enforced' || c.statuses[i] === 'requested'),
          )
          .map((a) => a.type as 'TAG' | 'WARN' | 'URL_REWRITE' | 'ARCHIVE' | 'ALERT'),
      ),
    ];
    const decidedId = await outbox(
      EventTypes.PolicyDecided,
      policyDecidedV1.parse({
        ...base,
        scanId: ref.scanId === null ? null : ref.scanId.toString(),
        trigger: ref.trigger,
        disposition: result.disposition,
        finalAction: c.outcome.finalAction,
        finalVerdict: result.finalVerdict,
        riskScore: result.riskScore,
        nonTerminalActions: nonTerminal,
        decisive,
        overrideApplied: result.override !== null,
        policyGeneration: result.versions.generation,
        snapshotSha256: result.versions.snapshotSha256,
        inputSha256: result.inputSha256,
        evaluatedAt: at,
      }),
    );
    await emailEvent('policy.evaluated', decidedId, {
      disposition: result.disposition,
      source: result.decisive.source,
      generation: result.versions.generation,
      evaluationSeq: ref.round,
    });

    let approvals = 0;
    if (result.disposition === 'allow' && c.emlS3Key !== null) {
      const recipients = await tx.emailRecipient.findMany({
        where: {
          messageId: ref.messageId,
          receivedAt: ref.receivedAt,
          organizationId: ref.organizationId,
          status: 'pending',
        },
        orderBy: { rcptSeq: 'asc' },
        select: { id: true, rcptSeq: true, messageId: true, organizationId: true },
      });
      for (const r of recipients) {
        if (r.messageId !== ref.messageId || r.organizationId !== ref.organizationId) {
          wrongRead(this.sink, 'recipients', 'pending echo');
        }
      }
      const deliverySeq = await nextDeliverySeq(tx, ref);
      for (let i = 0; i < recipients.length; i += MAX_APPROVAL_RECIPIENTS) {
        const chunk = recipients.slice(i, i + MAX_APPROVAL_RECIPIENTS);
        const approvalId = await outbox(
          EventTypes.DeliveryApproved,
          deliveryApprovedV1.parse({
            messageId: base.messageId,
            receivedAt: base.receivedAt,
            deliverySeq,
            lifecycleRound: ref.round,
            source: 'policy',
            emlS3Key: c.emlS3Key,
            recipients: chunk.map((r) => ({ recipientId: r.id.toString(), rcptSeq: r.rcptSeq })),
            approvedAt: at,
          }),
        );
        await emailEvent('delivery.approved', approvalId, {
          source: 'policy',
          approvalEventId: approvalId,
          deliverySeq,
          lifecycleRound: ref.round,
          recipientCount: chunk.length,
        });
        approvals += 1;
      }
      if (approvals === 0) {
        this.logger.info(
          { eventId: event.eventId, messageId: base.messageId, round: ref.round },
          'no pending recipients; nothing approved',
        );
      }
    }

    const archive = result.actions.findIndex((a) => a.type === 'ARCHIVE');
    if (archive >= 0 && c.statuses[archive] === 'requested') {
      await outbox(
        EventTypes.MessageArchiveRequested,
        messageArchiveRequestedV1.parse({
          ...base,
          emlS3Key: c.snapshot.emlObjectKey,
          source: 'policy',
          ruleRef: result.actions[archive]!.ruleRefs[0] ?? null,
          policyGeneration: result.versions.generation,
          requestedAt: at,
        }),
      );
    }

    const alert = result.actions.findIndex((a) => a.type === 'ALERT');
    if (alert >= 0 && c.statuses[alert] === 'requested') {
      const action = result.actions[alert]!;
      await outbox(
        EventTypes.PolicyNotificationRequested,
        policyNotificationRequestedV1.parse({
          ...base,
          kind: 'policy_alert',
          severity: action.params.severity,
          disposition: result.disposition,
          decisive,
          ruleRefs: action.ruleRefs,
          requestedAt: at,
        }),
      );
    }
    if (result.notices.senderNonDelivery) {
      const reject = result.actions.find((a) => a.type === 'REJECT');
      await outbox(
        EventTypes.PolicyNotificationRequested,
        policyNotificationRequestedV1.parse({
          ...base,
          kind: 'sender_non_delivery',
          severity: 'info',
          disposition: result.disposition,
          decisive,
          ruleRefs: reject?.ruleRefs ?? [],
          requestedAt: at,
        }),
      );
    }
    return approvals;
  }
}

/**
 * 0 for the first delivery of a message; after a rescan or release of a message that already
 * has deliveries, the next sequence, so the planner never mistakes the new approval for a
 * duplicate of an old one (moved from the development pass-through, P15).
 */
export async function nextDeliverySeq(
  tx: Prisma.TransactionClient,
  ref: Pick<RoundRef, 'messageId' | 'receivedAt' | 'organizationId'>,
): Promise<number> {
  const result = await tx.emailDelivery.aggregate({
    where: {
      messageId: ref.messageId,
      receivedAt: ref.receivedAt,
      organizationId: ref.organizationId,
    },
    _max: { deliverySeq: true },
  });
  const max = result._max.deliverySeq;
  return max === null || max === undefined ? 0 : max + 1;
}

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
  evaluatePolicyPerRecipient,
  evaluationResultToRow,
  intendedActionStatuses,
  lifecycleOutcome,
  type LifecycleOutcome,
  type PerRecipientEvaluation,
  perRecipientToRowFields,
  type PolicyDeliveredObject,
  type PolicyDelivery,
  type PolicyEvaluationResult,
  type PolicyInput,
  PolicyInputError,
  type PolicyRoundRows,
  type PolicyUrlRewriteAttempt,
  recipientDecisionFor,
  resultForRecipient,
  type SplitOutcome,
} from '@email-gateway/policy-dsl';
import type { QuarantinePlatformBounds } from '@email-gateway/quarantine';
import type { RewriteSkipReason } from '@email-gateway/url-security';
import {
  transitionMessage,
  type LifecycleSnapshot,
  type TransitionOutcome,
  type TransitionRequest,
} from '@email-gateway/message-lifecycle';
import { deliveryObject, type DeliveryObject } from '../delivery/delivery-object';
import {
  type EditedCopyResult,
  hasEdits,
  policyCopyKey,
  type PolicyCopyResult,
  type PolicyCopyWriter,
} from '../delivery/policy-copy';
import {
  type CopyFactsReader,
  planPolicyUrlRewrite,
  type PolicyUrlRewriteConfig,
} from '../delivery/policy-url-rewrite';
import { entryFactsFromResult } from '../quarantine/entry-facts';
import type { QuarantineSettingsRepository } from '../quarantine/settings.repository';
import type {
  CreatedEntry,
  EntryCandidate,
  QuarantineStoreWriter,
} from '../quarantine/store-writer';
import type { PolicyMetrics } from '../metrics/policy-metrics';
import type { DirectoryRepository } from './directory.repository';
import { type InconsistencySink, POLICY_INPUT_INVALID, wrongRead } from './errors';
import { buildInputWithDirectory } from './input-builder';
import type { FactsRepository, RoundRef } from './facts.repository';
import type { SnapshotLookup, SnapshotRepository } from './snapshot.repository';

/** `message_idempotency.consumer` of the `email.policy.evaluate` consumer (P13, topology v9). */
export const POLICY_EVALUATE_CONSUMER = 'policy-engine.evaluate';
/** `actor.service`, `email_events.source_service`. */
export const SOURCE_SERVICE = 'policy-engine';
/** `mail.delivery.approved.v1` carries at most 1000 recipients (P15). */
export const MAX_APPROVAL_RECIPIENTS = 1000;

export type TriggerPayload = MessageScannedV1 | MessageParseFailedV1;

/** The lifecycle outcome of a round (step 5.2 P18, step 5.3 Q5: `policy_partial`, `partial`). */
export interface RoundOutcome {
  edge: 'E10' | 'E11' | 'E12' | 'E13';
  to: LifecycleOutcome['to'];
  reason: LifecycleOutcome['reason'] | 'policy_partial';
  finalAction: LifecycleOutcome['finalAction'];
}

type RecipientFinalAction =
  'deliver' | 'tag' | 'quarantine' | 'require_approval' | 'discard' | 'reject';

/** One decided recipient of the round (Q5). */
export interface RecipientOutcome {
  id: bigint;
  rcptSeq: number;
  address: string;
  disposition: PolicyEvaluationResult['disposition'];
  status: 'pending' | 'quarantined' | 'discarded';
  finalAction: RecipientFinalAction;
}

/** What a handled event did; turned into metrics only after the transaction committed. */
export type EvaluationOutcome =
  | { status: 'skipped'; result: 'stale' | 'invalid' | 'duplicate' | 'not_found' }
  | {
      status: 'evaluated';
      result: PolicyEvaluationResult;
      statuses: ActionStatus[];
      copy: PolicyCopyResult['result'] | EditedCopyResult['result'] | null;
      cache: SnapshotLookup['cache'];
      invalidVersions: number;
      durationSeconds: number;
      riskMissing: boolean;
      approvals: number;
      outcome: RoundOutcome;
      /** Q4 metric label of `policy_recipient_split_total`. */
      split: SplitOutcome;
      entries: CreatedEntry[];
      superseded: number;
      /** Q23 metric label of `policy_url_rewrite_total` (null: no policy rewrite involved). */
      urlRewrite: string | null;
      /** Q22 banner outcome (null: no banner requested). */
      banner: string | null;
      notifications: number;
    };

/** The step 5.3 quarantine side of the evaluation (Q2, Q5, Q6, Q22, Q23). */
export interface EvaluationQuarantineDeps {
  store: Pick<
    QuarantineStoreWriter,
    'supersedeEarlierRounds' | 'setRecipientOutcomes' | 'createEntries'
  >;
  settings: Pick<QuarantineSettingsRepository, 'resolve'>;
  copyFacts: Pick<CopyFactsReader, 'read'>;
  urlRewrite: PolicyUrlRewriteConfig;
  /** POLICY_BANNER_MAX_PART_BYTES. */
  bannerMaxPartBytes: number;
  bounds: QuarantinePlatformBounds;
}

export interface EvaluationDeps {
  facts: Pick<FactsRepository, 'read'>;
  snapshots: Pick<SnapshotRepository, 'get'>;
  directory: Pick<DirectoryRepository, 'resolve'>;
  copies: PolicyCopyWriter;
  quarantine: EvaluationQuarantineDeps;
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

/** `policy_recipient_split_total{result}` label of a split outcome (Q4). */
export function splitMetricLabel(outcome: SplitOutcome): string {
  if (outcome === 'single_recipient') return 'not_scoped';
  if (outcome === 'truncated') return 'too_many';
  return outcome;
}

const tagged = (r: Pick<PolicyEvaluationResult, 'actions'>): boolean =>
  r.actions.some((a) => (a.type === 'TAG' || a.type === 'WARN') && a.applicability === 'applies');

/** A recipient's `email_recipients.final_action` (Q5). */
export function recipientFinalAction(
  result: PolicyEvaluationResult,
  direction: 'inbound' | 'outbound' | 'internal',
): RecipientFinalAction {
  switch (result.disposition) {
    case 'allow':
      return tagged(result) ? 'tag' : 'deliver';
    case 'quarantine':
      return 'quarantine';
    case 'require_approval':
      return 'require_approval';
    case 'reject':
      return direction === 'inbound' ? 'discard' : 'reject';
  }
}

/**
 * The Q5 lifecycle mapping: not split → the P18 edge of the lifecycle disposition (the uniform
 * disposition of every recipient); split → E10 `policy_partial` when a recipient is allowed,
 * else E11 when one is quarantined, else E12; `final_action = partial` for every split.
 */
export function roundOutcome(
  evaluation: PerRecipientEvaluation,
  direction: 'inbound' | 'outbound' | 'internal',
): RoundOutcome {
  if (!evaluation.split) {
    const representative = evaluation.recipients?.[0]?.result ?? evaluation.message;
    return lifecycleOutcome(
      { disposition: evaluation.lifecycleDisposition, actions: representative.actions },
      direction,
    );
  }
  switch (evaluation.lifecycleDisposition) {
    case 'allow':
      return { edge: 'E10', to: 'approved', reason: 'policy_partial', finalAction: 'partial' };
    case 'quarantine':
      return {
        edge: 'E11',
        to: 'quarantined',
        reason: 'policy_quarantine',
        finalAction: 'partial',
      };
    default:
      return { edge: 'E12', to: 'held_for_review', reason: 'policy_hold', finalAction: 'partial' };
  }
}

/**
 * The delivery record of the round's delivered copy (Q4.5): the message result's own record
 * when it decided the allowed recipients (not split, allow), else the merge over the allowed
 * recipients; null when nobody is delivered.
 */
export function deliveryRecordOf(evaluation: PerRecipientEvaluation): PolicyDelivery | null {
  if (evaluation.lifecycleDisposition !== 'allow') return null;
  if (!evaluation.split && evaluation.message.disposition === 'allow') {
    return evaluation.message.delivery;
  }
  return evaluation.mergedDeliveryActions.delivery;
}

/**
 * The action statuses stored with the decision record (P19, ADR-0045 extended by ADR-0049):
 * `intendedActionStatuses` of the stored result; for a split message the TAG / WARN /
 * URL_REWRITE actions merged into the delivered copy are reported as delivered actions; when
 * nobody is delivered TAG/WARN are `not_applicable`; a refused copy records TAG/WARN.
 */
export function storedStatuses(
  stored: PolicyEvaluationResult,
  evaluation: PerRecipientEvaluation,
  copyRefused: boolean,
): ActionStatus[] {
  const delivered = evaluation.lifecycleDisposition === 'allow';
  const merged = evaluation.mergedDeliveryActions.edits;
  const asAllowed = intendedActionStatuses({
    ...stored,
    actions: stored.actions.map((a) => ({ ...a, applicability: 'applies' as const })),
  });
  return intendedActionStatuses(stored).map((status, i) => {
    const a = stored.actions[i]!;
    if (a.type !== 'TAG' && a.type !== 'WARN' && a.type !== 'URL_REWRITE') return status;
    let next = status;
    if (!delivered && (a.type === 'TAG' || a.type === 'WARN') && status !== 'not_applicable') {
      return 'not_applicable';
    }
    if (delivered && status === 'not_applicable' && merged !== null) {
      const refs =
        a.type === 'TAG'
          ? merged.ruleRefs.tag
          : a.type === 'WARN'
            ? merged.ruleRefs.warn
            : merged.ruleRefs.urlRewrite;
      if (a.ruleRefs.some((r) => refs.includes(r))) next = asAllowed[i]!;
    }
    if (copyRefused && (a.type === 'TAG' || a.type === 'WARN') && next === 'enforced') {
      return 'recorded';
    }
    return next;
  });
}

/**
 * The policy evaluation of one trigger event (step 5.2 P13, ADR-0044; step 5.3 Q2–Q6, Q22,
 * Q23, ADR-0046, ADR-0049), entirely inside the consumer's writer transaction
 * (`processOnceHandler`, ledger `policy-engine.evaluate`):
 *
 * 1. organization = the envelope's (trusted), matched against the writer message row by every
 *    read; `scanned.v1` (`scanned` → E8, `scan_failed` → E9) or `parse_failed.v1` (E5, round 0:
 *    the event carries no round and a parse failure only happens in round 0);
 * 2. the first edge locks the message; not applied (stale, superseded round, already evaluated,
 *    not found) → ledger row only (`policy_lifecycle_skipped_total{result}`);
 * 3. a rescan round (> 0) supersedes the earlier rounds' non-terminal entries (their pending
 *    approval requests are cancelled) and resets `quarantined` recipients to `pending` (Q5);
 * 4. P8 facts (echo-checked), the snapshot of the current generation (LRU), the directory of the
 *    snapshot's references, `buildPolicyInput`, `evaluatePolicyPerRecipient` (Q4; a
 *    `PolicyInputError` or any evaluator exception → `NonRetryableError`: dead letter, the
 *    message stays held);
 * 5. allowed recipients: the delivered object (P20) and the policy copy (P21: header edits;
 *    Q23: URL rewrite after the scan; Q22: WARN banner). A deterministic policy-rewrite skip
 *    under `ifNotRewritten = quarantine` re-evaluates once with that skip reason;
 * 6. the `policy_execution_logs` row (`evaluation_seq` = round, `recipient_split`,
 *    `recipient_decisions`; the unique key is the backstop);
 * 7. `email_messages.final_verdict`, `final_action` (`partial` for a split), `risk_score`;
 * 8. the disposition edge (Q5: E10 `policy_partial` / E11 / E12 / E13);
 * 9. recipients (Q5: quarantined / discarded / pending with their `final_action`) and the
 *    quarantine entries of the held recipients (Q6: entries, `policy_review` requests, actions,
 *    `quarantine.created` events, `approval_requested` notifications);
 * 10. outbox rows (P15; approvals for the allowed recipients only) and `email_events` rows.
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
    const key = {
      messageId: ref.messageId,
      receivedAt: ref.receivedAt,
      organizationId,
    };

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
    const q = this.deps.quarantine;
    const evaluatedAt = this.now();

    // 3. Rescan interplay (Q5): supersede earlier rounds, re-decide quarantined recipients.
    const superseded =
      ref.round > 0 ? await q.store.supersedeEarlierRounds(tx, key, ref.round, evaluatedAt) : 0;

    // 4. Facts, snapshot, directory, evaluation.
    const started = this.hrtime();
    const facts = await this.deps.facts.read(tx, ref);
    const loaded = await this.deps.snapshots.get(tx, organizationId);
    const decided = await this.decide(tx, ref, facts, loaded, ids);
    let input = decided.input;
    let evaluation = decided.evaluation;
    let durationSeconds = Number(this.hrtime() - started) / 1e9;
    if (evaluation.message.round.direction !== snapshot.direction) {
      wrongRead(this.sink, 'lifecycle', 'direction echo');
    }
    const direction = evaluation.message.round.direction;

    // 5. Delivered object and policy copy (allowed recipients only).
    let deliveredObject: PolicyDeliveredObject = 'none';
    let delivered: DeliveryObject | null = null;
    let copyKey: string | null = null;
    let copy: PolicyCopyResult['result'] | EditedCopyResult['result'] | null = null;
    let bannerOutcome: EditedCopyResult['banner'] = null;
    let policyAttempt: PolicyUrlRewriteAttempt | null = null;
    let urlRewriteMetric: string | null = null;
    for (let pass = 0; pass < 2; pass += 1) {
      deliveredObject = 'none';
      delivered = null;
      copyKey = null;
      copy = null;
      bannerOutcome = null;
      const record = deliveryRecordOf(evaluation);
      if (evaluation.lifecycleDisposition !== 'allow' || record === null) break;
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
      const merged = evaluation.mergedDeliveryActions.edits;
      const edits = { headers: record.headers, subjectPrefix: record.subjectPrefix };
      const banner = record.bodyBanner === 'requested' && merged?.banner ? merged.banner : null;
      const fallback = merged?.urlRewrite?.ifNotRewritten ?? 'deliver';
      const rewriteWanted =
        pass === 0 &&
        record.urlRewrite.required &&
        record.urlRewrite.policyRewritable &&
        delivered.object !== 'rewritten';
      if (banner === null && !rewriteWanted) {
        if (hasEdits(edits)) {
          const written = await this.deps.copies.write({
            baseKey: delivered.key,
            key: policyCopyKey({
              organizationId,
              messageId: ref.messageId,
              receivedAt: ref.receivedAt,
              round: ref.round,
              baseKey: delivered.key,
              edits,
            }),
            edits,
            signal: AbortSignal.timeout(this.deps.copyTimeoutMs),
          });
          copy = written.result;
          if (written.result === 'written') {
            copyKey = written.key;
            deliveredObject = 'policy_copy';
          } else {
            this.logger.info(
              { ...ids, copy: written.result },
              'policy copy refused by its size limits; delivering without header edits',
            );
          }
        }
        break;
      }
      const copyFacts = await q.copyFacts.read(tx, key);
      let rewritePlan = null;
      let skip: RewriteSkipReason | null = null;
      if (rewriteWanted) {
        const planned = planPolicyUrlRewrite(copyFacts, q.urlRewrite, {
          direction,
          messageSizeBytes: facts.message.sizeBytes,
          organizationId,
          messageId: ref.messageId,
          receivedAt: ref.receivedAt,
          now: evaluatedAt,
        });
        if ('skip' in planned) skip = planned.skip;
        else rewritePlan = planned.plan;
      }
      if (skip !== null) {
        urlRewriteMetric = skip;
        policyAttempt = { status: 'skipped', skipReason: skip };
        if (fallback === 'quarantine' && skip !== 'no_urls') {
          ({ input, evaluation } = this.reevaluate(input, loaded, skip, ids));
          continue;
        }
      }
      const written = await this.deps.copies.writeEdited({
        baseKey: delivered.key,
        key: policyCopyKey({
          organizationId,
          messageId: ref.messageId,
          receivedAt: ref.receivedAt,
          round: ref.round,
          baseKey: delivered.key,
          edits,
          body: { banner, urlRewrite: rewritePlan !== null },
        }),
        edits,
        plan: {
          urlRewrite: rewritePlan,
          banner: banner === null ? null : { ...banner, maxPartBytes: q.bannerMaxPartBytes },
          structure: copyFacts.structure,
          requireUrlRewrite: fallback === 'quarantine',
        },
        signal: AbortSignal.timeout(this.deps.copyTimeoutMs),
      });
      if (written.urlRewrite !== null) {
        policyAttempt = written.urlRewrite;
        urlRewriteMetric =
          written.urlRewrite.status === 'rewritten'
            ? 'rewritten'
            : (written.urlRewrite.skipReason ?? 'error');
        const s = written.urlRewrite.skipReason;
        if (
          written.urlRewrite.status === 'skipped' &&
          s !== null &&
          s !== 'no_urls' &&
          fallback === 'quarantine'
        ) {
          ({ input, evaluation } = this.reevaluate(input, loaded, s, ids));
          continue;
        }
      }
      bannerOutcome = written.banner;
      copy = written.result;
      if (written.result === 'written' && written.key !== undefined) {
        copyKey = written.key;
        deliveredObject = 'policy_copy';
      } else if (written.result !== 'unchanged') {
        this.logger.info(
          { ...ids, copy: written.result },
          'policy copy refused by its size limits; delivering the base object',
        );
      }
      break;
    }
    durationSeconds = Math.max(durationSeconds, Number(this.hrtime() - started) / 1e9);
    if (
      urlRewriteMetric === null &&
      evaluation.lifecycleDisposition === 'allow' &&
      deliveryRecordOf(evaluation)?.urlRewrite.policyRewritable === true &&
      deliveryRecordOf(evaluation)?.urlRewrite.required === true
    ) {
      urlRewriteMetric = q.urlRewrite.enabled ? 'not_eligible' : 'disabled';
    }
    const result = evaluation.message;
    const outcome = roundOutcome(evaluation, direction);
    const emlS3Key = copyKey ?? delivered?.key ?? null;

    // The stored decision record: the message result with the delivered copy's record.
    const record = deliveryRecordOf(evaluation);
    const storedDelivery: PolicyDelivery | null =
      record === null
        ? evaluation.message.disposition === 'allow'
          ? null
          : evaluation.message.delivery
        : {
            ...record,
            bodyBanner:
              record.bodyBanner === 'requested'
                ? (bannerOutcome ?? 'requested')
                : record.bodyBanner,
            urlRewrite: { ...record.urlRewrite, policyAttempt },
          };
    const stored: PolicyEvaluationResult = { ...result, delivery: storedDelivery };
    const copyRefused = copy === 'too_large' || copy === 'header_too_large';
    const statuses = storedStatuses(stored, evaluation, copyRefused);

    // 6. The evaluation row.
    const row = evaluationResultToRow(stored, {
      actionStatuses: statuses,
      deliveredObject,
      objectKey: copyKey,
      policyVersionIds: loaded.policyVersionIds,
    });
    const split = perRecipientToRowFields(evaluation);
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
        action: outcome.finalAction,
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
        recipientSplit: split.recipientSplit,
        recipientDecisions:
          split.recipientDecisions === null
            ? undefined
            : (split.recipientDecisions as unknown as Prisma.InputJsonValue),
      },
      select: { id: true },
    });

    // 7. The message's final columns.
    const updated = await tx.emailMessage.updateMany({
      where: { id: ref.messageId, receivedAt: ref.receivedAt, organizationId },
      data: {
        finalVerdict: result.finalVerdict,
        finalAction: outcome.finalAction,
        riskScore: result.riskScore,
      },
    });
    if (updated.count !== 1) wrongRead(this.sink, 'message_update', 'one row expected');

    // 8. The disposition edge (same round, under the lock taken by the first edge).
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

    // 9. Recipients and quarantine entries (Q5, Q6).
    const recipients = await this.decideRecipients(tx, ref, evaluation, direction);
    let entries: CreatedEntry[] = [];
    let notifications = 0;
    if (recipients.some((r) => r.status !== 'pending' || r.finalAction !== 'deliver')) {
      await q.store.setRecipientOutcomes(tx, key, recipients);
    }
    const held = recipients.filter((r) => r.status === 'quarantined');
    if (held.length > 0) {
      const settings = await q.settings.resolve(tx, organizationId);
      const candidates: EntryCandidate[] = held.map((r) => {
        const kind = r.disposition === 'require_approval' ? 'review' : 'quarantine';
        return {
          recipientId: r.id,
          rcptSeq: r.rcptSeq,
          address: r.address,
          kind,
          facts: entryFactsFromResult(
            resultForRecipient(evaluation, r.rcptSeq),
            input,
            evaluation.recipients === null ? null : recipientDecisionFor(evaluation, r.rcptSeq),
            kind,
          ),
        };
      });
      const createdEntries = await q.store.createEntries(tx, {
        message: {
          ...key,
          round: ref.round,
          scanId: ref.scanId,
          direction,
          envelopeFrom: facts.message.envelopeFrom,
          headerFrom: facts.message.headerFrom,
          sizeBytes: facts.message.sizeBytes,
          attachmentCount: facts.message.attachmentCount,
          emlObjectKey: snapshot.emlObjectKey,
        },
        origin: 'policy',
        candidates,
        settings,
        bounds: q.bounds,
        now: evaluatedAt,
        policyVersionIds: loaded.policyVersionIds,
        correlationId: event.correlationId,
      });
      entries = createdEntries.created;
      notifications = createdEntries.notifications;
    }

    // 10. Outbox and email_events rows.
    const approvals = await this.writeOutbox(tx, {
      event,
      ref,
      snapshot,
      result: stored,
      disposition: evaluation.split ? result.disposition : evaluation.lifecycleDisposition,
      statuses,
      outcome,
      emlS3Key,
      evaluatedAt,
    });
    this.logger.info(
      {
        ...ids,
        disposition: result.disposition,
        lifecycle: outcome.to,
        split: evaluation.outcome,
        source: result.decisive.source,
        reason: result.decisive.reason,
        generation: result.versions.generation,
        object: deliveredObject,
        approvals,
        entries: entries.length,
        superseded,
      },
      'policy evaluated',
    );
    return {
      status: 'evaluated',
      result: stored,
      statuses,
      copy,
      cache: loaded.cache,
      invalidVersions: loaded.invalidVersions,
      durationSeconds,
      riskMissing: ref.trigger !== 'parse_failed' && !facts.risk.some((r) => r.revision === 0),
      approvals,
      outcome,
      split: evaluation.outcome,
      entries,
      superseded,
      urlRewrite: urlRewriteMetric,
      banner: bannerOutcome,
      notifications,
    };
  }

  /**
   * Q23: a deterministic skip of the policy rewrite under `ifNotRewritten = quarantine` →
   * evaluate again with the input's `urls.rewriteSkipReason` = that skip (deterministic; the
   * stored row records `delivery.urlRewrite.policyAttempt`). With policy rewriting disabled
   * (`POLICY_URL_REWRITE_ENABLED=false`, skip `disabled`) the input says no rewrite happened
   * (`rewriteStatus = none`), which raises exactly as in step 5.2.
   */
  private reevaluate(
    input: PolicyInput,
    loaded: SnapshotLookup,
    skip: RewriteSkipReason,
    ids: Record<string, unknown>,
  ): { input: PolicyInput; evaluation: PerRecipientEvaluation } {
    const next: PolicyInput = {
      ...input,
      urls:
        skip === 'disabled'
          ? { ...input.urls, rewriteStatus: 'none', rewriteSkipReason: null }
          : { ...input.urls, rewriteStatus: 'skipped', rewriteSkipReason: skip },
    };
    this.logger.info(
      { ...ids, skip },
      'policy url rewrite skipped under ifNotRewritten=quarantine; re-evaluating',
    );
    return {
      input: next,
      evaluation: this.guarded(() => evaluatePolicyPerRecipient(next, loaded.compiled), ids),
    };
  }

  /** Q5: every `pending` recipient's disposition, status and final action. */
  private async decideRecipients(
    tx: Prisma.TransactionClient,
    ref: RoundRef,
    evaluation: PerRecipientEvaluation,
    direction: 'inbound' | 'outbound' | 'internal',
  ): Promise<RecipientOutcome[]> {
    const rows = await tx.emailRecipient.findMany({
      where: {
        messageId: ref.messageId,
        receivedAt: ref.receivedAt,
        organizationId: ref.organizationId,
        status: 'pending',
      },
      orderBy: { rcptSeq: 'asc' },
      select: {
        id: true,
        rcptSeq: true,
        address: true,
        messageId: true,
        organizationId: true,
        status: true,
      },
    });
    return rows.map((r) => {
      if (
        r.messageId !== ref.messageId ||
        r.organizationId !== ref.organizationId ||
        r.status !== 'pending'
      ) {
        wrongRead(this.sink, 'recipients', 'pending echo');
      }
      const result = resultForRecipient(evaluation, r.rcptSeq);
      const disposition = evaluation.split
        ? recipientDecisionFor(evaluation, r.rcptSeq).disposition
        : evaluation.lifecycleDisposition;
      const decided = { ...result, disposition };
      return {
        id: r.id,
        rcptSeq: r.rcptSeq,
        address: r.address,
        disposition,
        status:
          disposition === 'allow'
            ? 'pending'
            : disposition === 'reject'
              ? 'discarded'
              : 'quarantined',
        finalAction: recipientFinalAction(decided, direction),
      };
    });
  }

  private guarded<T>(fn: () => T, ids: Record<string, unknown>): T {
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
  }

  /** Directory, input, evaluation; malformed rows or an evaluator exception dead-letter. */
  private async decide(
    tx: Prisma.TransactionClient,
    ref: RoundRef,
    facts: Omit<PolicyRoundRows, 'directory'>,
    loaded: SnapshotLookup,
    ids: Record<string, unknown>,
  ): Promise<{ input: PolicyInput; evaluation: PerRecipientEvaluation }> {
    const input = await buildInputWithDirectory(
      tx,
      this.deps.directory,
      ref.organizationId,
      facts,
      loaded.compiled,
      (fn) => this.guarded(fn, ids),
    );
    const evaluation = this.guarded(() => evaluatePolicyPerRecipient(input, loaded.compiled), ids);
    return { input, evaluation };
  }

  private async writeOutbox(
    tx: Prisma.TransactionClient,
    c: {
      event: EventEnvelope<TriggerPayload>;
      ref: RoundRef;
      snapshot: LifecycleSnapshot;
      result: PolicyEvaluationResult;
      /** The disposition of the decided event (Q5: the lifecycle disposition unless split). */
      disposition: PolicyEvaluationResult['disposition'];
      statuses: ActionStatus[];
      outcome: RoundOutcome;
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
        disposition: c.disposition,
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
      disposition: c.disposition,
      source: result.decisive.source,
      generation: result.versions.generation,
      evaluationSeq: ref.round,
    });

    let approvals = 0;
    // Approvals for the allowed recipients only (Q5): the held and rejected ones are no longer
    // `pending` (set before this step).
    if (c.outcome.to === 'approved' && c.emlS3Key !== null) {
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

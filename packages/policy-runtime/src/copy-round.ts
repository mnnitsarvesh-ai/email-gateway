import type { Prisma } from '@email-gateway/database';
import {
  postDeliveryStatusOf,
  POLICY_OUTCOME_ACTION_TYPES,
  recommendationOnlyOf,
  type PolicyActionStatus,
  type PolicyOutcomeFacts,
} from '@email-gateway/mailbox-api';
import {
  evaluatePolicyPerRecipient,
  evaluationResultToRow,
  PolicyInputError,
  recipientDecisionFor,
  resultForRecipient,
  type PerRecipientEvaluation,
  type PolicyEvaluationResult,
  type PolicyInput,
} from '@email-gateway/policy-dsl';
import type { DirectoryRepository } from './directory.repository';
import { InconsistentPolicyReadError } from './errors';
import { durationUsOf, policyExecutionLogData } from './execution-log';
import type { FactsRepository } from './facts.repository';
import { type AtoFactsSource, buildInputWithDirectory } from './input-builder';
import { roundOutcome } from './round-outcome';
import type { SnapshotLookup, SnapshotRepository } from './snapshot.repository';

/**
 * The round of an API-mode copy message evaluated in detect mode (step API-4 A2, A3): the
 * registry message of the copy, organization from the trusted event envelope (matched by every
 * read), the trigger from the copy outcome (`scanned` / `scan_failed`), the scan of the
 * `copy_scanned` event and the message's lifecycle round (0). Never an older round.
 */
export interface CopyRoundRef {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  round: number;
  trigger: 'scanned' | 'scan_failed';
  scanId: bigint;
}

/** The runtime pieces `evaluateCopyRound` uses (the same classes the policy-engine wires). */
export interface CopyRoundDeps {
  facts: Pick<FactsRepository, 'read'>;
  snapshots: Pick<SnapshotRepository, 'get'>;
  directory: Pick<DirectoryRepository, 'resolve'>;
  /** Step 8.4 D23: ATO facts of the authenticated outbound/internal sender (absent = none). */
  atoFacts?: AtoFactsSource;
  /** Monotonic clock in nanoseconds (tests inject a fake). */
  hrtime?: () => bigint;
}

/** Why a copy round could not be evaluated (`policy_state = failed`, A1). */
export const COPY_ROUND_FAILURE_CODES = ['policy_input_invalid', 'evaluator_error'] as const;
export type CopyRoundFailureCode = (typeof COPY_ROUND_FAILURE_CODES)[number];

/** The snapshot facts of an evaluation (metrics and the detect row). */
export interface CopyRoundMeta {
  generation: string;
  snapshotSha256: string;
  platformDefaultId: string;
  policyVersions: PolicyEvaluationResult['versions']['policies'];
  /** `policy_versions.id` (decimal) by `<policyPublicId>#<versionNo>` (P10 row mapping). */
  policyVersionIds: Readonly<Record<string, string>>;
  invalidVersions: number;
  cache: SnapshotLookup['cache'];
}

export interface CopyRoundEvaluated {
  status: 'evaluated';
  input: PolicyInput;
  perRecipient: PerRecipientEvaluation;
  meta: CopyRoundMeta;
  durationUs: number;
}

export type CopyRoundEvaluation =
  CopyRoundEvaluated | { status: 'failed'; code: CopyRoundFailureCode };

class CopyRoundFailure extends Error {
  constructor(readonly code: CopyRoundFailureCode) {
    super(code);
  }
}

const failureCodeOf = (error: unknown): CopyRoundFailureCode =>
  error instanceof PolicyInputError ? 'policy_input_invalid' : 'evaluator_error';

/** Runs a pure step; a `PolicyInputError` or evaluator exception becomes a failure code. */
function guarded<T>(fn: () => T): T {
  try {
    return fn();
  } catch (error) {
    if (error instanceof InconsistentPolicyReadError) throw error;
    throw new CopyRoundFailure(failureCodeOf(error));
  }
}

/**
 * A2: the detect-mode evaluation of one copy round inside the caller's writer transaction, with
 * exactly the policy-engine's runtime (P-I2): the round facts (echo-checked), the snapshot of the
 * current generation (LRU per `(organization, generation)`), the directory of the snapshot's
 * references, the sender's ATO facts for outbound/internal rounds, `buildPolicyInput` and
 * `evaluatePolicyPerRecipient`.
 *
 * Malformed rows (`PolicyInputError`, from the fact reads or the input builder) and evaluator
 * exceptions → `{ status: 'failed', code }` (the caller falls back to the verdict lane). An
 * inconsistent read (`InconsistentPolicyReadError`) and database errors propagate: the whole
 * ledger transaction rolls back and the event is redelivered.
 */
export async function evaluateCopyRound(
  tx: Prisma.TransactionClient,
  deps: CopyRoundDeps,
  ref: CopyRoundRef,
): Promise<CopyRoundEvaluation> {
  const hrtime = deps.hrtime ?? (() => process.hrtime.bigint());
  const started = hrtime();
  try {
    let facts;
    try {
      facts = await deps.facts.read(tx, { ...ref, olderRoundAllowed: false });
    } catch (error) {
      if (error instanceof PolicyInputError) throw new CopyRoundFailure('policy_input_invalid');
      throw error;
    }
    const loaded = await deps.snapshots.get(tx, ref.organizationId);
    const input = await buildInputWithDirectory(
      tx,
      deps.directory,
      ref.organizationId,
      facts,
      loaded.compiled,
      guarded,
      deps.atoFacts,
    );
    const perRecipient = guarded(() => evaluatePolicyPerRecipient(input, loaded.compiled));
    const versions = perRecipient.message.versions;
    return {
      status: 'evaluated',
      input,
      perRecipient,
      meta: {
        generation: versions.generation,
        snapshotSha256: versions.snapshotSha256,
        platformDefaultId: versions.platformDefault,
        policyVersions: versions.policies,
        policyVersionIds: loaded.policyVersionIds,
        invalidVersions: loaded.invalidVersions,
        cache: loaded.cache,
      },
      durationUs: durationUsOf(Number(hrtime() - started) / 1e9),
    };
  } catch (error) {
    if (error instanceof CopyRoundFailure) return { status: 'failed', code: error.code };
    throw error;
  }
}

const applies = (r: PolicyEvaluationResult, types: readonly string[]): boolean =>
  r.actions.some((a) => types.includes(a.type) && a.applicability === 'applies');

const ruleRefOf = (r: PolicyEvaluationResult): string | null =>
  r.decisive.source === 'tenant_rule' &&
  r.decisive.policyPublicId !== null &&
  r.decisive.versionNo !== null &&
  r.decisive.ruleId !== null
    ? `${r.decisive.policyPublicId}#${r.decisive.versionNo}/${r.decisive.ruleId}`
    : null;

/** Origins of the applying TAG and WARN actions of a result (`recommendationOnlyOf`). */
export const tagOriginsOf = (
  actions: readonly Pick<
    PolicyEvaluationResult['actions'][number],
    'type' | 'origin' | 'applicability'
  >[],
): PolicyEvaluationResult['actions'][number]['origin'][] =>
  actions
    .filter((a) => (a.type === 'TAG' || a.type === 'WARN') && a.applicability === 'applies')
    .map((a) => a.origin);

/** Most floor reasons carried by the outcome (A4.1). */
const MAX_FLOOR_REASONS = 8;

/**
 * A2/A4.1: the `PolicyOutcomeFacts` of the remediation decision. With a recipient (`rcptSeq` of
 * the mailbox's recipient row: journal and feed copies) the recipient's decision exactly as the
 * policy-engine decides recipients (Q5: its own result when the message was split, else the
 * uniform lifecycle disposition); with `null` (outbound copies) the message-level result. The DLP
 * action comes from the input's DLP block when the DLP final is definite.
 */
export function policyOutcomeOf(
  evaluated: Pick<CopyRoundEvaluated, 'input' | 'perRecipient'>,
  rcptSeq: number | null,
): PolicyOutcomeFacts {
  const evaluation = evaluated.perRecipient;
  const result = rcptSeq === null ? evaluation.message : resultForRecipient(evaluation, rcptSeq);
  const disposition = !evaluation.split
    ? evaluation.lifecycleDisposition
    : rcptSeq === null
      ? evaluation.message.disposition
      : recipientDecisionFor(evaluation, rcptSeq).disposition;
  const input = evaluated.input;
  const types = new Set(
    result.actions.filter((a) => a.applicability === 'applies').map((a) => a.type),
  );
  return {
    disposition,
    tagged: disposition === 'allow' && applies(result, ['TAG', 'WARN']),
    overrideApplied: result.override !== null,
    decisionSource: result.decisive.source,
    decisiveRuleRef: ruleRefOf(result),
    floorReasons: result.floor.reasons.slice(0, MAX_FLOOR_REASONS),
    dlpAction: input.dlp !== null && input.dlpFinal === 'definite' ? input.dlp.action : null,
    actionTypes: POLICY_OUTCOME_ACTION_TYPES.filter((t) => types.has(t)),
    recommendationOnly: recommendationOnlyOf({
      disposition,
      decisionSource: result.decisive.source,
      decisiveReason: result.decisive.reason,
      floorDisposition: result.floor.disposition,
      tagOrigins: tagOriginsOf(result.actions),
    }),
  };
}

/**
 * A5: the stored status of one action of a detect evaluation — `not_applicable` when the
 * evaluator says it does not apply, else the post-delivery status of its type in the copy's
 * direction (an ALERT whose tenant alerts are off stays `recorded`, as inline).
 */
export function detectActionStatus(
  action: PolicyEvaluationResult['actions'][number],
  direction: 'inbound' | 'outbound' | 'internal',
): PolicyActionStatus {
  if (action.applicability === 'not_applicable') return 'not_applicable';
  const status = postDeliveryStatusOf(action.type, direction).status;
  if (action.type === 'ALERT' && status === 'requested' && action.params.notify !== true) {
    return 'recorded';
  }
  return status;
}

/**
 * The detect row's create data (`policy_execution_logs`, A1/A2). Typed loosely for the
 * `evaluation_mode` column (step API-4 migration): the mailbox-worker compiles it against the
 * regenerated client.
 */
export type DetectRowData = Prisma.PolicyExecutionLogUncheckedCreateInput & {
  evaluationMode: 'detect';
};

/**
 * A2: the `policy_execution_logs` row of a detect evaluation — `evaluationResultToRow` of the
 * message result with `delivery = null`, `deliveredObject = none`, `objectKey = null`, action
 * statuses from the post-delivery table (A5), `action` = the round's lifecycle final action
 * (recorded, never applied), `evaluation_seq` = the round, `evaluation_mode = detect`, the
 * per-recipient columns and the ATO facts exactly as the policy-engine stores them.
 */
export function detectRowData(
  evaluated: CopyRoundEvaluated,
  ref: CopyRoundRef,
  now: Date,
): DetectRowData {
  const evaluation = evaluated.perRecipient;
  const stored: PolicyEvaluationResult = { ...evaluation.message, delivery: null };
  const direction = stored.round.direction;
  if (stored.round.lifecycleRound !== ref.round) {
    throw new RangeError('detect row round does not match the copy round');
  }
  const row = evaluationResultToRow(stored, {
    actionStatuses: stored.actions.map((a) => detectActionStatus(a, direction)),
    deliveredObject: 'none',
    objectKey: null,
    policyVersionIds: evaluated.meta.policyVersionIds,
  });
  return {
    ...policyExecutionLogData({
      key: {
        messageId: ref.messageId,
        receivedAt: ref.receivedAt,
        organizationId: ref.organizationId,
      },
      row,
      action: roundOutcome(evaluation, direction).finalAction,
      evaluation,
      input: evaluated.input,
      durationUs: evaluated.durationUs,
      evaluatedAt: now,
    }),
    evaluationMode: 'detect',
  };
}

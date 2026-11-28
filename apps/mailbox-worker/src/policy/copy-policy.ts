import type { DlpAction, PolicyDisposition, Prisma } from '@email-gateway/database';
import {
  POLICY_OUTCOME_ACTION_TYPES,
  recommendationOnlyOf,
  type PolicyOutcomeActionType,
  type PolicyOutcomeFacts,
} from '@email-gateway/mailbox-api';
import { rowToEvaluationView, type PolicyEvaluationView } from '@email-gateway/policy-dsl';
import {
  detectRowData,
  evaluateCopyRound,
  policyOutcomeOf,
  tagOriginsOf,
  type CopyRoundDeps,
  type CopyRoundEvaluated,
  type CopyRoundRef,
} from '@email-gateway/policy-runtime';
import { big, isDuplicateKey, type Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

/** `api_message_copies.policy_state` values the copies role writes (A1). */
export type CopyPolicyState = 'evaluated' | 'inline' | 'disabled' | 'failed' | 'not_applicable';

/** The DLP facts of a copy round (`dlp_scan_results` with a definite DLP final, A3.1, A8.2). */
export interface CopyDlpFacts {
  action: DlpAction;
  verdict: string;
  /** DLP category codes, unique, sorted (≤ 8). */
  categories: string[];
}

/** An applying ALERT of a fresh evaluation whose tenant alerts are on (A7). */
export interface CopyPolicyAlert {
  severity: string;
  ruleRefs: string[];
  disposition: PolicyDisposition;
  direction: 'inbound' | 'outbound' | 'internal';
  decisive: {
    source: 'tenant_rule' | 'platform_default' | 'floor';
    policyId: string | null;
    versionNo: number | null;
    ruleId: string | null;
  };
}

/**
 * What the detect evaluation of one registry copy message produced (A1–A3): the state written to
 * the message's copies, the outcome per recipient (the remediation decision's policy lane), the
 * message-level outcome (detection event), and — only when the detect row was written now — the
 * ALERT request. `fresh = false` when an existing detect row was reused (manual replay).
 */
export interface MessagePolicyResult {
  state: 'evaluated' | 'disabled' | 'failed';
  fresh: boolean;
  outcomeFor: (rcptSeq: number | null) => PolicyOutcomeFacts | null;
  messageOutcome: PolicyOutcomeFacts | null;
  alert: CopyPolicyAlert | null;
  /** Seconds the evaluation took (fresh evaluations only). */
  durationSeconds: number | null;
  failureCode: string | null;
}

const NONE: Pick<MessagePolicyResult, 'outcomeFor' | 'messageOutcome' | 'alert'> = {
  outcomeFor: () => null,
  messageOutcome: null,
  alert: null,
};

/** A skipped evaluation (platform switch or organization setting off, A1). */
export const DISABLED_RESULT: MessagePolicyResult = Object.freeze({
  ...NONE,
  state: 'disabled',
  fresh: false,
  durationSeconds: null,
  failureCode: null,
});

const MAX_FLOOR_REASONS = 8;
const MAX_DLP_CATEGORIES = 8;
const CODE = /^[a-z][a-z0-9_]{0,31}$/;

/**
 * The detect-mode policy evaluation of API-mode copies (step API-4 A1–A3, ADR-0105), run inside the
 * copies role's ledger transaction with the policy-engine's runtime (`@email-gateway/policy-runtime`,
 * P-I2): once per registry copy message, the detect row (`policy_execution_logs.evaluation_mode =
 * detect`, `evaluation_seq` = the message's lifecycle round) is inserted; a row that already exists
 * for (message, round) — a manual replay — is read back and reused instead of evaluating again.
 * `PolicyInputError` and evaluator exceptions → `failed` (the verdict lane decides alone); an
 * inconsistent read or a database error throws, so the whole ledger transaction is retried.
 * Never a lifecycle edge, a delivery, a hold, a gateway quarantine entry, a policy copy,
 * `mail.policy.decided.v1`, an archive request or a sender notice (P-I1).
 */
export class CopyPolicyEvaluator {
  constructor(
    private readonly deps: Omit<CopyRoundDeps, 'hrtime'> & {
      /** `API_MODE_POLICY_EVALUATION_ENABLED` (platform kill switch, K3). */
      enabled: boolean;
      hrtime?: () => bigint;
    },
  ) {}

  /** The platform switch. */
  get enabled(): boolean {
    return this.deps.enabled;
  }

  async evaluate(
    tx: Prisma.TransactionClient,
    ref: CopyRoundRef,
    now: Date,
  ): Promise<MessagePolicyResult> {
    const stored = await storedDetectRow(tx, ref);
    if (stored) return reuse(tx, ref, stored);
    const result = await evaluateCopyRound(
      tx,
      {
        facts: this.deps.facts,
        snapshots: this.deps.snapshots,
        directory: this.deps.directory,
        ...(this.deps.atoFacts ? { atoFacts: this.deps.atoFacts } : {}),
        ...(this.deps.hrtime ? { hrtime: this.deps.hrtime } : {}),
      },
      ref,
    );
    if (result.status === 'failed') {
      return {
        ...NONE,
        state: 'failed',
        fresh: true,
        durationSeconds: null,
        failureCode: result.code,
      };
    }
    try {
      await tx.policyExecutionLog.create({
        data: detectRowData(result, ref, now),
        select: { id: true },
      });
    } catch (error) {
      if (!isDuplicateKey(error)) throw error;
      const again = await storedDetectRow(tx, ref);
      if (!again) throw new InconsistentReadError('policy_execution_logs');
      return reuse(tx, ref, again);
    }
    return evaluatedResult(result);
  }
}

function evaluatedResult(result: CopyRoundEvaluated): MessagePolicyResult {
  const memo = new Map<string, PolicyOutcomeFacts>();
  const outcomeFor = (rcptSeq: number | null): PolicyOutcomeFacts => {
    const key = rcptSeq === null ? 'm' : String(rcptSeq);
    let known = memo.get(key);
    if (!known) {
      known = policyOutcomeOf(result, rcptSeq);
      memo.set(key, known);
    }
    return known;
  };
  const message = result.perRecipient.message;
  const alert = message.actions.find(
    (a) => a.type === 'ALERT' && a.applicability === 'applies' && a.params.notify === true,
  );
  return {
    state: 'evaluated',
    fresh: true,
    outcomeFor,
    messageOutcome: outcomeFor(null),
    alert: alert
      ? {
          severity: String(alert.params.severity),
          ruleRefs: [...new Set(alert.ruleRefs)].slice(0, 16),
          disposition: message.disposition,
          direction: message.round.direction,
          decisive: {
            source: message.decisive.source,
            policyId: message.decisive.policyPublicId,
            versionNo: message.decisive.versionNo,
            ruleId: message.decisive.ruleId,
          },
        }
      : null,
    durationSeconds: result.durationUs / 1e6,
    failureCode: null,
  };
}

/** The stored row of (message, round) as the api view, or null (organization echo-checked). */
async function storedDetectRow(
  tx: Prisma.TransactionClient,
  ref: CopyRoundRef,
): Promise<PolicyEvaluationView | null> {
  const row = await tx.policyExecutionLog.findUnique({
    where: {
      messageId_evaluationSeq_receivedAt: {
        messageId: ref.messageId,
        evaluationSeq: ref.round,
        receivedAt: ref.receivedAt,
      },
    },
  });
  if (!row) return null;
  if (row.organizationId !== ref.organizationId) {
    throw new InconsistentReadError('policy_execution_logs');
  }
  return rowToEvaluationView(row);
}

/**
 * A1 "duplicate": the stored detect row's result instead of a second evaluation. The recipient's
 * decision comes from `recipient_decisions` when the stored evaluation was split, else the message
 * result (exactly what `policyOutcomeOf` derives for an unsplit evaluation); the DLP action from
 * the round's DLP row (definite final).
 */
async function reuse(
  tx: Prisma.TransactionClient,
  ref: CopyRoundRef,
  view: PolicyEvaluationView,
): Promise<MessagePolicyResult> {
  const dlp = await loadCopyDlpFacts(tx, ref);
  const outcomeFor = (rcptSeq: number | null) =>
    storedOutcomeOf(view, rcptSeq, dlp?.action ?? null);
  return {
    state: 'evaluated',
    fresh: false,
    outcomeFor,
    messageOutcome: outcomeFor(null),
    alert: null,
    durationSeconds: null,
    failureCode: null,
  };
}

/** `PolicyOutcomeFacts` of a stored evaluation (see `reuse`). */
export function storedOutcomeOf(
  view: PolicyEvaluationView,
  rcptSeq: number | null,
  dlpAction: DlpAction | null,
): PolicyOutcomeFacts {
  const types = new Set(
    view.actions.filter((a) => a.applicability === 'applies').map((a) => a.type),
  );
  const actionTypes: PolicyOutcomeActionType[] = POLICY_OUTCOME_ACTION_TYPES.filter((t) =>
    types.has(t),
  );
  const messageRef =
    view.decisive.source === 'tenant_rule' &&
    view.decisive.policyPublicId !== null &&
    view.decisive.versionNo !== null &&
    view.decisive.ruleId !== null
      ? `${view.decisive.policyPublicId}#${view.decisive.versionNo}/${view.decisive.ruleId}`
      : null;
  let disposition = view.disposition;
  let source = view.decisive.source;
  let ruleRef = messageRef;
  let reason: string | null = view.decisive.reason;
  if (rcptSeq !== null && view.recipientSplit && view.recipientDecisions) {
    const decision = view.recipientDecisions.find((d) => d.rcptSeq === rcptSeq);
    if (decision) {
      disposition = decision.disposition;
      source = decision.source;
      ruleRef = decision.decisiveRuleRef;
      reason = decision.reasonCodes[0] ?? null;
    }
  }
  return {
    disposition,
    tagged: disposition === 'allow' && (types.has('TAG') || types.has('WARN')),
    overrideApplied: view.override !== null,
    decisionSource: source,
    decisiveRuleRef: ruleRef,
    floorReasons: [...new Set(view.floor.reasons)].slice(0, MAX_FLOOR_REASONS),
    dlpAction,
    actionTypes,
    recommendationOnly: recommendationOnlyOf({
      disposition,
      decisionSource: source,
      decisiveReason: reason,
      floorDisposition: view.floor.disposition,
      tagOrigins: tagOriginsOf(view.actions),
    }),
  };
}

/**
 * The round's DLP facts (A3.1): the `dlp_scan_results` row of the scan when the DLP engine's final
 * result is definite (not skipped, timed out or failed); null otherwise. Echo-checked.
 */
export async function loadCopyDlpFacts(
  db: Db,
  ref: Pick<CopyRoundRef, 'messageId' | 'receivedAt' | 'organizationId' | 'scanId'>,
): Promise<CopyDlpFacts | null> {
  const finals = await db.$queryRaw<Array<{ organization_id: bigint | number; outcome: string }>>`
    SELECT organization_id, outcome FROM scan_engine_results
    WHERE scan_id = ${ref.scanId} AND received_at = ${ref.receivedAt} AND engine = 'dlp'
      AND is_final = 1
    LIMIT 1`;
  const final = finals[0];
  if (!final) return null;
  if (big(final.organization_id) !== ref.organizationId) {
    throw new InconsistentReadError('scan_engine_results');
  }
  if (final.outcome === 'skipped' || final.outcome === 'timeout' || final.outcome === 'error') {
    return null;
  }
  const rows = await db.$queryRaw<
    Array<{
      organization_id: bigint | number;
      message_id: bigint | number;
      action: DlpAction;
      verdict: string;
      categories: unknown;
    }>
  >`
    SELECT organization_id, message_id, action, verdict, categories FROM dlp_scan_results
    WHERE scan_id = ${ref.scanId} AND received_at = ${ref.receivedAt}`;
  const row = rows[0];
  if (!row) return null;
  if (big(row.organization_id) !== ref.organizationId || big(row.message_id) !== ref.messageId) {
    throw new InconsistentReadError('dlp_scan_results');
  }
  return { action: row.action, verdict: row.verdict, categories: dlpCategoryCodes(row.categories) };
}

/** Category codes of a stored `dlp_scan_results.categories` (`[{ category, … }]`). */
export function dlpCategoryCodes(raw: unknown): string[] {
  const value = typeof raw === 'string' ? safeJson(raw) : raw;
  if (!Array.isArray(value)) return [];
  const codes = new Set<string>();
  for (const item of value) {
    const code =
      item && typeof item === 'object' ? (item as { category?: unknown }).category : undefined;
    if (typeof code === 'string' && CODE.test(code)) codes.add(code);
  }
  return [...codes].sort().slice(0, MAX_DLP_CATEGORIES);
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/**
 * R9.1 address rule: the `rcpt_seq` of the message's recipient row whose address is the mailbox's
 * primary or an alias address (lowest `rcpt_seq`); null when the message has none.
 */
export async function recipientSeqOf(
  db: Db,
  input: { organizationId: bigint; messageId: bigint; receivedAt: Date; mailboxId: bigint },
): Promise<number | null> {
  const rows = await db.$queryRaw<Array<{ organization_id: bigint | number; rcpt_seq: number }>>`
    SELECT r.organization_id, r.rcpt_seq FROM email_recipients r
    WHERE r.message_id = ${input.messageId} AND r.received_at = ${input.receivedAt}
      AND r.organization_id = ${input.organizationId}
      AND (LOWER(r.address) IN (
             SELECT a.address FROM api_mailbox_addresses a
             WHERE a.mailbox_id = ${input.mailboxId} AND a.organization_id = ${input.organizationId})
           OR LOWER(r.address) = (
             SELECT LOWER(m.primary_address) FROM api_mailboxes m
             WHERE m.id = ${input.mailboxId} AND m.organization_id = ${input.organizationId}))
    ORDER BY r.rcpt_seq ASC
    LIMIT 1`;
  const row = rows[0];
  if (!row) return null;
  if (big(row.organization_id) !== input.organizationId) {
    throw new InconsistentReadError('email_recipients');
  }
  return Number(row.rcpt_seq);
}

/**
 * A1 hybrid: the disposition of the linked gateway message's latest inline evaluation (display
 * only on the copy); null without one.
 */
export async function inlineDispositionOf(
  db: Db,
  organizationId: bigint,
  inline: { messageId: bigint; receivedAt: Date },
): Promise<PolicyDisposition | null> {
  const rows = await db.$queryRaw<
    Array<{ organization_id: bigint | number; disposition: PolicyDisposition }>
  >`
    SELECT organization_id, disposition FROM policy_execution_logs
    WHERE message_id = ${inline.messageId} AND received_at = ${inline.receivedAt}
      AND evaluation_mode = 'inline'
    ORDER BY evaluation_seq DESC
    LIMIT 1`;
  const row = rows[0];
  if (!row) return null;
  if (big(row.organization_id) !== organizationId) {
    throw new InconsistentReadError('policy_execution_logs');
  }
  return row.disposition;
}

import type {
  PolicyEvaluationResult,
  PolicyInput,
  RecipientDecision,
} from '@email-gateway/policy-dsl';
import { RISK_HARD_BLOCKS } from '@email-gateway/risk-scoring';
import type { QuarantinePrimaryEngine, QuarantineReason } from './vocabulary';

/**
 * Why an entry is held (step 5.3 Q6): `quarantineReasonFor` picks the strictest present cause in
 * a fixed order; `primaryEngineFor` names the engine (or the tenant policy) behind it. Both read
 * the recipient's evaluation result and, when available, the input it was computed from (the
 * hard-block ids, BEC, attachment, URL and engine facts are input facts; a stored row without
 * the input passes `hardBlocks`).
 */

export interface QuarantineEvaluation {
  /** The result that decided the recipient (its own result when split, else the message's). */
  result: Pick<PolicyEvaluationResult, 'decisive' | 'floor' | 'finalVerdict' | 'trace'>;
  /** The evaluation input (engine side); null/absent for stored rows (adoption). */
  input?: Pick<PolicyInput, 'risk' | 'bec' | 'attachments' | 'urls' | 'scan'> | null;
  /** Hard-block ids when the input is not available (e.g. an entry's stored `hard_blocks`). */
  hardBlocks?: readonly string[];
}

/** The ordered causes of Q6 (the reason table, also used by `primaryEngineFor`). */
export const QUARANTINE_REASON_ORDER = [
  'malware',
  'phishing',
  'bec',
  'dlp',
  'engine_unavailable',
  'policy',
  'spam',
  'bulk',
  'suspicious',
] as const satisfies readonly QuarantineReason[];

const HARD_BLOCK_VERDICT = new Map<string, string>(RISK_HARD_BLOCKS.map((h) => [h.id, h.verdict]));

/** Engine of each hard block (Q6 `primaryEngineFor`). */
export const HARD_BLOCK_ENGINE: Readonly<Record<string, QuarantinePrimaryEngine>> = Object.freeze({
  'hb.malware_attachment': 'attachment',
  'hb.malware_url': 'url',
  'hb.malware_sandbox': 'sandbox',
  'hb.dlp_block': 'dlp',
  'hb.known_phishing': 'url',
  'hb.tenant_domain_spoof': 'rspamd',
  'hb.url_tenant_blocked': 'url',
  'hb.bec_malicious': 'bec',
  'hb.dmarc_reject': 'rspamd',
});

const DLP_HOLD_FLOORS = new Set([
  'policy.floor.dlp_require_approval',
  'policy.floor.dlp_quarantine',
  'policy.floor.dlp_block',
  'policy.floor.dlp_missing',
]);
const ENGINE_FLOORS = new Set([
  'policy.floor.engine_failure',
  'policy.floor.unknown_engine',
  'policy.floor.risk_error',
  'policy.floor.risk_missing',
  'policy.floor.scan_failed',
  'policy.floor.not_scanned',
]);
const FAILED_OUTCOMES = new Set(['timeout', 'error', 'missing']);

/** Hard-block ids of the evaluation (input revisions, else the given list), sorted, unique. */
export function hardBlocksOf(evaluation: QuarantineEvaluation): string[] {
  const ids = new Set<string>(evaluation.hardBlocks ?? []);
  const risk = evaluation.input?.risk;
  for (const rev of [risk?.rev0, risk?.rev1]) for (const h of rev?.hardBlocks ?? []) ids.add(h.id);
  return [...ids].sort();
}

interface Cause {
  reason: Exclude<QuarantineReason, 'manual'>;
  engine: QuarantinePrimaryEngine;
}

const holdFloor = (r: QuarantineEvaluation['result']) =>
  r.floor.disposition !== null && r.floor.disposition !== 'allow';

function decisiveSource(
  evaluation: QuarantineEvaluation,
  decision: Pick<RecipientDecision, 'source' | 'decisiveRuleRef'> | null | undefined,
): { source: string; ref: string | null } {
  if (decision) return { source: decision.source, ref: decision.decisiveRuleRef };
  const d = evaluation.result.decisive;
  const ref =
    d.source === 'tenant_rule' && d.policyPublicId !== null && d.versionNo !== null && d.ruleId
      ? `${d.policyPublicId}#${d.versionNo}/${d.ruleId}`
      : null;
  return { source: d.source, ref };
}

function causeOf(
  evaluation: QuarantineEvaluation,
  decision?: Pick<RecipientDecision, 'source' | 'decisiveRuleRef'> | null,
): Cause {
  const { result, input } = evaluation;
  const blocks = hardBlocksOf(evaluation);
  const byVerdict = (verdict: string) =>
    blocks.filter((id) => HARD_BLOCK_VERDICT.get(id) === verdict);
  const floorCodes = new Set<string>(result.floor.reasons);
  const verdict = result.finalVerdict;

  // 1. Malware: a malware hard block, a malicious attachment with the hard-block floor, or the
  //    malware verdict.
  const malwareBlocks = byVerdict('malware');
  const maliciousAttachment = (input?.attachments.items ?? []).some(
    (a) => a.verdict === 'malicious',
  );
  if (
    malwareBlocks.length > 0 ||
    (floorCodes.has('policy.floor.hard_block') && maliciousAttachment) ||
    verdict === 'malware'
  ) {
    const engine =
      malwareBlocks.length > 0
        ? HARD_BLOCK_ENGINE[malwareBlocks[0]!]!
        : maliciousAttachment
          ? 'attachment'
          : input?.risk.rev1?.sandboxOutcome === 'malicious'
            ? 'sandbox'
            : 'none';
    return { reason: 'malware', engine };
  }
  // 2. Phishing: a phishing hard block or verdict.
  const phishingBlocks = byVerdict('phishing');
  if (phishingBlocks.length > 0 || verdict === 'phishing') {
    const badUrl = (input?.urls.items ?? []).some(
      (u) => u.verdict === 'malicious' || u.verdict === 'suspicious',
    );
    return {
      reason: 'phishing',
      engine:
        phishingBlocks.length > 0
          ? HARD_BLOCK_ENGINE[phishingBlocks[0]!]!
          : badUrl
            ? 'url'
            : 'none',
    };
  }
  // 3. BEC: deterministic suspicious/malicious (or the BEC hard block).
  const becVerdict = input?.bec?.deterministicVerdict;
  if (byVerdict('bec').length > 0 || becVerdict === 'suspicious' || becVerdict === 'malicious') {
    return { reason: 'bec', engine: 'bec' };
  }
  // 4. DLP: a DLP hold floor, the DLP hard block, or a DLP-decisive tenant rule.
  const { source, ref } = decisiveSource(evaluation, decision);
  const dlpDecisive =
    source === 'tenant_rule' &&
    ref !== null &&
    result.trace.some(
      (t) => t.ref === ref && t.result === 'matched' && (t.field ?? '').startsWith('dlp.'),
    );
  if (
    byVerdict('dlp_violation').length > 0 ||
    [...floorCodes].some((c) => DLP_HOLD_FLOORS.has(c)) ||
    dlpDecisive
  ) {
    return { reason: 'dlp', engine: 'dlp' };
  }
  // 5. Engine unavailable: a failure floor that holds.
  if (holdFloor(result) && [...floorCodes].some((c) => ENGINE_FLOORS.has(c))) {
    const failing = (input?.scan.engines ?? []).find((e) => FAILED_OUTCOMES.has(e.outcome));
    return { reason: 'engine_unavailable', engine: failing ? failing.engine : 'none' };
  }
  // 6. A tenant rule decided.
  if (source === 'tenant_rule') return { reason: 'policy', engine: 'policy' };
  // 7. Spam / bulk verdicts; else suspicious.
  if (verdict === 'spam') return { reason: 'spam', engine: 'rspamd' };
  if (verdict === 'bulk') return { reason: 'bulk', engine: 'rspamd' };
  return { reason: 'suspicious', engine: 'none' };
}

/** Q6: the entry reason (the strictest present cause, in `QUARANTINE_REASON_ORDER`). */
export function quarantineReasonFor(
  evaluation: QuarantineEvaluation,
  recipientDecision?: Pick<RecipientDecision, 'source' | 'decisiveRuleRef'> | null,
): Exclude<QuarantineReason, 'manual'> {
  return causeOf(evaluation, recipientDecision).reason;
}

/** Q6: the engine behind the decisive cause. */
export function primaryEngineFor(
  evaluation: QuarantineEvaluation,
  recipientDecision?: Pick<RecipientDecision, 'source' | 'decisiveRuleRef'> | null,
): QuarantinePrimaryEngine {
  return causeOf(evaluation, recipientDecision).engine;
}

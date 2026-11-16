import {
  POLICY_DISPOSITIONS,
  type PerRecipientEvaluation,
  type PolicyDisposition,
} from '@email-gateway/policy-dsl';
import type {
  PolicySampleDryRunResponse,
  PolicySampleItem,
  PolicySampleOutcome,
  PolicyTarget,
} from '../dto/policies.schemas';
import type { SampleRoundRow } from '../repositories/policy-executions.repository';
import { INLINE_POLICY_ID } from './policy-definition';

/**
 * Pure part of the sample dry-run (step 7.3 §4.3, docs/plan/steps/22-policy-builder.md B8): the
 * window, the selection of the newest evaluated round per message, the items and the summary.
 * Items carry message public ids, times, enums, rule ids and counts only (never subjects,
 * addresses or content), like the execution history. No I/O.
 */

const DAY_MS = 86_400_000;

/** Selection rows read per requested round (bounded read, §4.3). */
export const SAMPLE_ROWS_PER_ROUND = 4;

/**
 * The sample window: `to` defaults to the request time, `from` to `to` minus the default days
 * (clamped to the widest allowed range, so a default request is always within the bound).
 */
export function sampleWindow(
  sample: { from?: string; to?: string },
  now: Date,
  defaultDays: number,
  maxDays: number,
): { from: Date; to: Date } {
  const to = sample.to === undefined ? now : new Date(sample.to);
  const from =
    sample.from === undefined
      ? new Date(to.getTime() - Math.min(defaultDays, maxDays) * DAY_MS)
      : new Date(sample.from);
  return { from, to };
}

/** `true` when the range is longer than the bound (`to` − `from` > `maxDays`). */
export const windowTooWide = (window: { from: Date; to: Date }, maxDays: number): boolean =>
  window.to.getTime() - window.from.getTime() > maxDays * DAY_MS;

/**
 * The newest evaluated round per message among `rows` (read newest first by `(receivedAt, id)`):
 * the row with the highest `evaluationSeq` of each message (ties: the higher id), in the order of
 * that row, at most `limit`. Parse-failure evaluations (no scan) are never selected.
 */
export function selectSampleRounds(
  rows: readonly SampleRoundRow[],
  limit: number,
): SampleRoundRow[] {
  const best = new Map<bigint, SampleRoundRow>();
  for (const row of rows) {
    if (row.scanId === null || row.trigger === 'parse_failed') continue;
    const current = best.get(row.messageId);
    if (
      current === undefined ||
      row.evaluationSeq > current.evaluationSeq ||
      (row.evaluationSeq === current.evaluationSeq && row.id > current.id)
    ) {
      best.set(row.messageId, row);
    }
  }
  return [...best.values()]
    .sort((a, b) => {
      const t = b.receivedAt.getTime() - a.receivedAt.getTime();
      if (t !== 0) return t;
      return a.id === b.id ? 0 : a.id > b.id ? -1 : 1;
    })
    .slice(0, limit);
}

/** The target as the response reports it. */
export function sampleTarget(target: PolicyTarget): PolicySampleDryRunResponse['target'] {
  if (target === 'active' || target === 'platform') {
    return { kind: target, policyId: null, versionNo: null };
  }
  if ('policyId' in target) {
    return { kind: 'version', policyId: target.policyId, versionNo: target.versionNo };
  }
  return { kind: 'inline', policyId: INLINE_POLICY_ID, versionNo: 1 };
}

/** The decisive version number of a stored row, from its `policy_versions` JSON (as history). */
function storedVersionNo(row: SampleRoundRow): number | null {
  if (row.decisivePolicyPublicId === null || !Array.isArray(row.policyVersions)) return null;
  const versions = row.policyVersions as Array<{ policyPublicId?: unknown; versionNo?: unknown }>;
  const found = versions.find((v) => v.policyPublicId === row.decisivePolicyPublicId)?.versionNo;
  return typeof found === 'number' && Number.isSafeInteger(found) && found >= 1 ? found : null;
}

/** One item: the stored decision and, for an evaluated round, the recomputed one. */
export function sampleItem(
  row: SampleRoundRow,
  messageId: string | null,
  outcome: PolicySampleOutcome,
  evaluation: PerRecipientEvaluation | null,
): PolicySampleItem {
  const stored: PolicySampleItem['stored'] = {
    disposition: row.disposition,
    source: row.decisionSource,
    policyId: row.decisivePolicyPublicId,
    versionNo: storedVersionNo(row),
    ruleId: row.decisiveRuleId,
    evaluatedAt: row.evaluatedAt.toISOString(),
  };
  const result = evaluation?.message ?? null;
  const dryRun: PolicySampleItem['dryRun'] =
    evaluation === null || result === null
      ? null
      : {
          disposition: result.disposition,
          lifecycleDisposition: evaluation.lifecycleDisposition,
          source: result.decisive.source,
          policyId: result.decisive.policyPublicId,
          versionNo: result.decisive.versionNo,
          ruleId: result.decisive.ruleId,
          matchedRuleCount: result.matchedRules.length,
          actionTypes: result.actions.map((a) => a.type),
          recipientSplit: evaluation.split,
          overrideApplied: result.override !== null,
        };
  return {
    messageId,
    receivedAt: row.receivedAt.toISOString(),
    direction: row.direction,
    lifecycleRound: row.evaluationSeq,
    scanId: (row.scanId ?? 0n).toString(),
    trigger: row.trigger === 'scan_failed' ? 'scan_failed' : 'scanned',
    outcome,
    stored,
    dryRun,
    dispositionChanged: dryRun !== null && dryRun.disposition !== stored.disposition,
    decisiveChanged:
      dryRun !== null &&
      (dryRun.source !== stored.source ||
        dryRun.policyId !== stored.policyId ||
        dryRun.ruleId !== stored.ruleId),
  };
}

const zeroCounts = (): Record<PolicyDisposition, number> => ({
  allow: 0,
  require_approval: 0,
  quarantine: 0,
  reject: 0,
});

/** Changed/unchanged, stored and recomputed disposition counts and the transitions (evaluated items). */
export function sampleSummary(
  items: readonly PolicySampleItem[],
): PolicySampleDryRunResponse['summary'] {
  const stored = zeroCounts();
  const dryRun = zeroCounts();
  const transitions = new Map<
    string,
    { from: PolicyDisposition; to: PolicyDisposition; count: number }
  >();
  let changed = 0;
  let unchanged = 0;
  for (const item of items) {
    if (item.dryRun === null) continue;
    stored[item.stored.disposition] += 1;
    dryRun[item.dryRun.disposition] += 1;
    if (!item.dispositionChanged) {
      unchanged += 1;
      continue;
    }
    changed += 1;
    const key = `${item.stored.disposition}>${item.dryRun.disposition}`;
    const entry = transitions.get(key) ?? {
      from: item.stored.disposition,
      to: item.dryRun.disposition,
      count: 0,
    };
    entry.count += 1;
    transitions.set(key, entry);
  }
  const rank = (d: PolicyDisposition) => POLICY_DISPOSITIONS.indexOf(d);
  return {
    changed,
    unchanged,
    stored,
    dryRun,
    transitions: [...transitions.values()].sort(
      (a, b) => b.count - a.count || rank(a.from) - rank(b.from) || rank(a.to) - rank(b.to),
    ),
  };
}

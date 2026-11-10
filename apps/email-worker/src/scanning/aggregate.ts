import {
  type DefiniteVerdict,
  type EngineOutcome,
  isDefiniteVerdict,
  isAsynchronousEngine,
  isFailureOutcome,
  MAX_REASON_CODES,
  mostSevere,
  type ScanVerdict,
  VERDICT_SEVERITY,
} from '@email-gateway/security-contracts';

/** The final result of one engine in a round, as the aggregation sees it. */
export interface FinalEngineResult {
  engine: string;
  outcome: EngineOutcome;
  errorCode: string | null;
  /** The engine's reason codes, already ordered by rule severity then name. */
  reasonCodes: readonly string[];
  /** Attempts of the engine in the round, the final one included. */
  attempts: number;
}

export type RoundLifecycleOutcome = 'scanned' | 'scan_failed';
export type RoundFailureReason = 'eml_unavailable' | 'scan_error' | 'scan_timeout';

export interface RoundAggregate {
  outcome: RoundLifecycleOutcome;
  /** E6 `scan_complete`, or the E7 reason. */
  lifecycleReason: 'scan_complete' | RoundFailureReason;
  /** `email_scans.status`. */
  scanStatus: 'completed' | 'failed' | 'timed_out';
  /** `email_scans.scan_verdict`. */
  verdict: ScanVerdict;
  /** `email_scans.reason_codes` (≤ 32). */
  reasonCodes: string[];
  /** Required engines whose final outcome is a failure. */
  failedRequired: string[];
}

/** Ordering weight of a final's reason codes: failures first, then by verdict severity. */
function weight(outcome: EngineOutcome): number {
  if (isFailureOutcome(outcome)) return 10;
  return isDefiniteVerdict(outcome) ? VERDICT_SEVERITY[outcome] : 0;
}

/**
 * The round aggregation of step 4.1 S6 (pure).
 *
 * - `failedRequired` = required engines whose final is `timeout` or `error` (a required engine
 *   without a final counts as failed: completion runs only when every required engine has one,
 *   so this is defence in depth, never `clean` by accident);
 * - lifecycle: none failed → `scanned` (`completed`); else `scan_failed` with
 *   `eml_unavailable` (any final `error_code = eml_unavailable`) > `scan_error` (any error) >
 *   `scan_timeout`; status `failed` for errors, `timed_out` for timeouts only;
 * - verdict: `malicious` if any final is malicious; else `error` / `timeout` for a required
 *   failure; else the most severe definite verdict of all finals (`unknown` when none);
 *   non-required engines' failures never fail the round;
 * - reason codes: union of the finals' codes, ordered by the severity of the final that raised
 *   them (failures first), then by name, at most 32.
 *
 * Finals of **asynchronous** engines (`isAsynchronousEngine`, step 4.6 X10: the `sandbox`) are
 * ignored before anything else: their final row may be written before or after the round
 * completes, so counting it would make the verdict depend on arrival order. They never change
 * the verdict, the reason codes or the outcome.
 */
export function aggregateRound(
  required: readonly string[],
  allFinals: readonly FinalEngineResult[],
): RoundAggregate {
  const finals = allFinals.filter((f) => !isAsynchronousEngine(f.engine));
  const byEngine = new Map(finals.map((f) => [f.engine, f]));
  const failedRequired = required.filter((engine) => {
    const final = byEngine.get(engine);
    return final === undefined || isFailureOutcome(final.outcome);
  });
  const requiredFinals = required.flatMap((engine) => {
    const final = byEngine.get(engine);
    return final ? [final] : [];
  });

  let outcome: RoundLifecycleOutcome = 'scanned';
  let lifecycleReason: RoundAggregate['lifecycleReason'] = 'scan_complete';
  let scanStatus: RoundAggregate['scanStatus'] = 'completed';
  if (failedRequired.length > 0) {
    outcome = 'scan_failed';
    const failing = requiredFinals.filter((f) => isFailureOutcome(f.outcome));
    const anyError =
      failing.some((f) => f.outcome === 'error') || failing.length < failedRequired.length;
    if (finals.some((f) => f.errorCode === 'eml_unavailable')) lifecycleReason = 'eml_unavailable';
    else lifecycleReason = anyError ? 'scan_error' : 'scan_timeout';
    scanStatus = anyError || lifecycleReason === 'eml_unavailable' ? 'failed' : 'timed_out';
  }

  let verdict: ScanVerdict;
  if (finals.some((f) => f.outcome === 'malicious')) verdict = 'malicious';
  else if (failedRequired.length > 0) verdict = scanStatus === 'timed_out' ? 'timeout' : 'error';
  else verdict = mostSevere(finals.map((f) => f.outcome)) ?? ('unknown' satisfies DefiniteVerdict);

  const ranked = new Map<string, number>();
  for (const final of finals) {
    for (const code of final.reasonCodes) {
      const w = weight(final.outcome);
      if ((ranked.get(code) ?? -1) < w) ranked.set(code, w);
    }
  }
  const reasonCodes = [...ranked.entries()]
    .sort(([a, wa], [b, wb]) => wb - wa || (a < b ? -1 : a > b ? 1 : 0))
    .slice(0, MAX_REASON_CODES)
    .map(([code]) => code);

  return { outcome, lifecycleReason, scanStatus, verdict, reasonCodes, failedRequired };
}

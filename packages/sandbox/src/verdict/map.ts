import {
  isSandboxFindingCode,
  type NotExecutedReason,
  SANDBOX_ERROR_CODES,
  SANDBOX_FINDING_SEVERITY,
  SANDBOX_ISOLATION_CLASSES,
  SANDBOX_LIMITS,
  SANDBOX_MAPPING_VERSION,
  SANDBOX_MAX_REASON_CODES,
  SANDBOX_NON_RAISING_LIMITS,
  SANDBOX_NOT_EXECUTED_REASONS,
  SANDBOX_REASON_CODES,
  SANDBOX_SKIP_REASONS,
  type SandboxErrorCode,
  type SandboxFindingCode,
  type SandboxIsolationClass,
  type SandboxLimit,
  type SandboxSkipReason,
  type SandboxTaskStatus,
  type SandboxVerdict,
  sandboxErrorCode,
  sandboxFindingReasonCode,
  sandboxFindingSeverityRank,
  sandboxNotExecutedCode,
  sandboxSkipCode,
  sandboxVerdictRank,
} from '@email-gateway/security-contracts';

/**
 * The verdict map `sandbox-map/1` (step 4.6 X14; pure). Ordered rules, first match decides the
 * verdict, the reason codes are the union of every rule that fired:
 *
 * | Rule | Condition                                                                 | Verdict      |
 * | ---- | ------------------------------------------------------------------------- | ------------ |
 * | F1   | status `failed`                                                           | `error`      |
 * | F2   | expired by the sweeper (no result by the deadline)                        | `timeout`    |
 * | N1   | status `not_executed`                                                     | `unknown`    |
 * | M1   | any finding `critical`/`high`                                             | `malicious`  |
 * | S1   | any finding `medium`, or a limit hit other than wall_timeout /            | `suspicious` |
 * |      | output_truncated / artifact_cap                                           |              |
 * | U1   | completed, `executed: false` (static only)                                | `unknown`    |
 * | U2   | completed, executed, isolation ≠ `vm`                                     | `unknown`    |
 * | U3   | completed, executed, `vm`, and (run < minRuntimeMs, an `evasion.*`        | `unknown`    |
 * |      | finding, evidence lost: output_truncated / artifact_cap, or only low      |              |
 * |      | findings)                                                                 |              |
 * | C1   | completed, executed, `vm`, no finding ≥ low, no evasion, complete run     | `clean`      |
 *
 * Low and info findings are kept as codes but never raise the verdict; severities are the fixed
 * `SANDBOX_FINDING_SEVERITY` (the severity a result reports is ignored). A limit hit counts as
 * the finding `limit.<limit>` (its code `sandbox.limit.<limit>`). `clean` is reachable only
 * through C1 with isolation `vm` (unreachable in 4.6): not executed, failed, expired, static-only
 * and container runs are never clean (§2.0 invariant 2).
 *
 * Code order: the analysis-level codes of the deciding and contributing rules first (they explain
 * the verdict; by name), then finding and limit codes by severity (highest first), then name; at
 * most 16.
 */

export const SANDBOX_MAP_VERSION = SANDBOX_MAPPING_VERSION;
/** Default minimum runtime of a complete VM-isolated run (rule U3/C1). */
export const DEFAULT_MIN_RUNTIME_MS = 30_000;

export type SandboxMapRule = 'F1' | 'F2' | 'N1' | 'M1' | 'S1' | 'U1' | 'U2' | 'U3' | 'C1';
const RULE_ORDER: readonly SandboxMapRule[] = [
  'F1',
  'F2',
  'N1',
  'M1',
  'S1',
  'U1',
  'U2',
  'U3',
  'C1',
];

/** Limits whose hit means evidence was lost (the run is not complete for C1). */
const EVIDENCE_LOSS_LIMITS: readonly SandboxLimit[] = ['output_truncated', 'artifact_cap'];

/** A task result as the results consumer applies it (validated observations). */
export interface SandboxResultForMap {
  kind: 'result';
  status: SandboxTaskStatus;
  executed: boolean;
  isolation: SandboxIsolationClass;
  notExecutedReason: NotExecutedReason | null;
  errorCode: SandboxErrorCode | null;
  durationMs: number;
  /** Validated finding codes (`SandboxFindingCode`); an unknown code throws. */
  findings: readonly { code: string }[];
  /** Validated limits (`SandboxLimit`); an unknown limit throws. */
  limitsHit: readonly string[];
}

/** No result by the analysis deadline (sweeper, X16 (b)). */
export interface SandboxExpiredForMap {
  kind: 'expired';
}

export type SandboxMapInput = SandboxResultForMap | SandboxExpiredForMap;

export interface SandboxMapOptions {
  /** Minimum runtime of a complete VM-isolated run (default 30 000 ms). */
  minRuntimeMs?: number;
}

export interface SandboxMapResult {
  verdict: SandboxVerdict;
  /** ≤ 16, each in `SANDBOX_REASON_CODES`. */
  reasonCodes: string[];
  /** The rule that decided the verdict. */
  rule: SandboxMapRule;
  /** Every rule that fired (deciding rule included), in rule order. */
  rules: SandboxMapRule[];
  mapVersion: typeof SANDBOX_MAP_VERSION;
}

/** A result that `sandbox-map/1` cannot map (unknown code, inconsistent status). */
export class SandboxMapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SandboxMapError';
  }
}

const ANALYSIS_LEVEL_CODES: ReadonlySet<string> = new Set([
  'sandbox.timeout',
  'sandbox.no_findings',
  'sandbox.static_only',
  'sandbox.not_vm_isolated',
  'sandbox.incomplete_run',
  'sandbox.evasion_suspected',
  'sandbox.not_executed',
  'sandbox.error',
  ...SANDBOX_NOT_EXECUTED_REASONS.map(sandboxNotExecutedCode),
  ...SANDBOX_ERROR_CODES.map(sandboxErrorCode),
  ...SANDBOX_SKIP_REASONS.map(sandboxSkipCode),
]);
const ANALYSIS_LEVEL_RANK = 100;

/** Severity rank of a reason code for ordering (analysis-level codes above every finding). */
function codeRank(code: string): number {
  if (ANALYSIS_LEVEL_CODES.has(code)) return ANALYSIS_LEVEL_RANK;
  const finding = code.startsWith('sandbox.') ? code.slice('sandbox.'.length) : '';
  if (isSandboxFindingCode(finding)) {
    return sandboxFindingSeverityRank(SANDBOX_FINDING_SEVERITY[finding]);
  }
  return -1;
}

/**
 * Orders reason codes as `sandbox-map/1` does (analysis-level first, then severity, then name),
 * removes duplicates and keeps at most `max` (default 16).
 */
export function orderReasonCodes(
  codes: Iterable<string>,
  max: number = SANDBOX_MAX_REASON_CODES,
): string[] {
  return [...new Set(codes)]
    .sort((a, b) => codeRank(b) - codeRank(a) || (a < b ? -1 : a > b ? 1 : 0))
    .slice(0, max);
}

const isLimit = (value: string): value is SandboxLimit =>
  (SANDBOX_LIMITS as readonly string[]).includes(value);

/** Maps one analysis outcome to its verdict and reason codes (X14). Pure. */
export function mapAnalysis(
  input: SandboxMapInput,
  options: SandboxMapOptions = {},
): SandboxMapResult {
  const minRuntimeMs = options.minRuntimeMs ?? DEFAULT_MIN_RUNTIME_MS;
  if (!Number.isFinite(minRuntimeMs) || minRuntimeMs < 0) {
    throw new SandboxMapError('minRuntimeMs must be a non-negative number');
  }
  const fired = new Map<SandboxMapRule, { verdict: SandboxVerdict; codes: string[] }>();
  const fire = (rule: SandboxMapRule, verdict: SandboxVerdict, codes: string[]) =>
    fired.set(rule, { verdict, codes });

  if (input.kind === 'expired') {
    fire('F2', 'timeout', ['sandbox.timeout']);
    return finish(fired, []);
  }

  // Findings: every reported code plus a `limit.<limit>` finding per limit hit.
  const findingCodes = new Set<SandboxFindingCode>();
  for (const finding of input.findings) {
    if (!isSandboxFindingCode(finding.code)) {
      throw new SandboxMapError('Unknown finding code');
    }
    findingCodes.add(finding.code);
  }
  const raisingLimits: SandboxLimit[] = [];
  const evidenceLost = input.limitsHit.some((l) =>
    EVIDENCE_LOSS_LIMITS.includes(l as SandboxLimit),
  );
  for (const limit of input.limitsHit) {
    if (!isLimit(limit)) throw new SandboxMapError('Unknown limit');
    findingCodes.add(`limit.${limit}` as SandboxFindingCode);
    if (!SANDBOX_NON_RAISING_LIMITS.includes(limit)) raisingLimits.push(limit);
  }
  const severityOf = (code: SandboxFindingCode) =>
    sandboxFindingSeverityRank(SANDBOX_FINDING_SEVERITY[code]);
  const LOW = sandboxFindingSeverityRank('low');
  const MEDIUM = sandboxFindingSeverityRank('medium');
  const HIGH = sandboxFindingSeverityRank('high');
  const all = [...findingCodes];
  const high = all.filter((c) => severityOf(c) >= HIGH);
  const medium = all.filter((c) => severityOf(c) === MEDIUM);
  const noFindingAtLeastLow = all.every((c) => severityOf(c) < LOW);
  const evasion = all.filter((c) => c.startsWith('evasion.'));
  // Low/info findings: kept as codes (never raise the verdict).
  const findingReasonCodes = all.map(sandboxFindingReasonCode);

  if (input.status === 'failed') {
    if (
      input.errorCode === null ||
      !(SANDBOX_ERROR_CODES as readonly string[]).includes(input.errorCode)
    ) {
      throw new SandboxMapError('A failed result needs a known error code');
    }
    fire('F1', 'error', ['sandbox.error', sandboxErrorCode(input.errorCode)]);
  } else if (input.status === 'not_executed') {
    if (
      input.notExecutedReason === null ||
      !(SANDBOX_NOT_EXECUTED_REASONS as readonly string[]).includes(input.notExecutedReason)
    ) {
      throw new SandboxMapError('A not_executed result needs a known reason');
    }
    if (input.executed) throw new SandboxMapError('A not_executed result cannot be executed');
    fire('N1', 'unknown', [
      'sandbox.not_executed',
      sandboxNotExecutedCode(input.notExecutedReason),
    ]);
  }

  if (high.length > 0) fire('M1', 'malicious', high.map(sandboxFindingReasonCode));
  if (medium.length > 0 || raisingLimits.length > 0) {
    fire('S1', 'suspicious', [
      ...medium.map(sandboxFindingReasonCode),
      ...raisingLimits.map((l) => `sandbox.limit.${l}`),
    ]);
  }

  if (input.status === 'completed') {
    const noFindings = noFindingAtLeastLow ? ['sandbox.no_findings'] : [];
    if (!input.executed) {
      fire('U1', 'unknown', ['sandbox.static_only', ...noFindings]);
    } else if (input.isolation !== 'vm') {
      fire('U2', 'unknown', ['sandbox.not_vm_isolated', ...noFindings]);
    } else {
      const short = !(input.durationMs >= minRuntimeMs);
      if (short || evasion.length > 0 || evidenceLost) {
        fire('U3', 'unknown', [
          ...(short || evidenceLost ? ['sandbox.incomplete_run'] : []),
          ...(evasion.length > 0 ? ['sandbox.evasion_suspected'] : []),
        ]);
      } else if (noFindingAtLeastLow) {
        fire('C1', 'clean', ['sandbox.no_findings']);
      } else {
        // Only low findings: C1 needs no finding ≥ low and low findings never raise the verdict,
        // so the run stays unknown (U3 without an extra code; the low codes are kept).
        fire('U3', 'unknown', []);
      }
    }
  }
  return finish(fired, findingReasonCodes);
}

function finish(
  fired: Map<SandboxMapRule, { verdict: SandboxVerdict; codes: string[] }>,
  keptCodes: string[],
): SandboxMapResult {
  const rules = RULE_ORDER.filter((rule) => fired.has(rule));
  const deciding = rules[0];
  // Every status fires one of F1, F2, N1 or U1..C1, so a deciding rule always exists.
  if (deciding === undefined) throw new SandboxMapError('No rule matched');
  const codes = [...rules.flatMap((rule) => fired.get(rule)!.codes), ...keptCodes];
  const reasonCodes = orderReasonCodes(codes);
  for (const code of reasonCodes) {
    if (!SANDBOX_REASON_CODES.includes(code)) throw new SandboxMapError('Unknown reason code');
  }
  return {
    verdict: fired.get(deciding)!.verdict,
    reasonCodes,
    rule: deciding,
    rules,
    mapVersion: SANDBOX_MAP_VERSION,
  };
}

// ---------------------------------------------------------------------------------------------
// Per submission and per round (X14)
// ---------------------------------------------------------------------------------------------

/** The codes of a skipped submission (`sandbox.<skip reason>`); no verdict. */
export function submissionSkipCodes(reason: SandboxSkipReason): string[] {
  if (!(SANDBOX_SKIP_REASONS as readonly string[]).includes(reason)) {
    throw new SandboxMapError('Unknown skip reason');
  }
  return [sandboxSkipCode(reason)];
}

export type SandboxSubmissionOutcome =
  | { status: 'skipped'; skipReason: SandboxSkipReason }
  | {
      status: 'completed' | 'failed' | 'expired';
      verdict: SandboxVerdict;
      reasonCodes: readonly string[];
      executed: boolean;
      isolation: SandboxIsolationClass | null;
    };

export interface SandboxRoundAggregate {
  /** The round-level `sandbox` final outcome (an `ENGINE_OUTCOMES` value). */
  outcome: SandboxVerdict | 'skipped';
  /** ≤ 16. */
  reasonCodes: string[];
  /** Index of the most severe non-skipped submission (its versions go on the final), or null. */
  mostSevereIndex: number | null;
  /** `scan_engine_results.evidence` of the final. */
  evidence: { submissions: number; executed: number; isolation: SandboxIsolationClass[] };
}

/**
 * The round-level final of the `sandbox` engine over the round's submissions (X14):
 * `malicious` > `suspicious` > `error` > `timeout` > `unknown` > `clean` over the non-skipped
 * submissions; all skipped → `skipped` with the codes of the skips. Independent of the input
 * order (codes: the most severe verdict's codes first, then the others, each ordered like
 * `orderReasonCodes`).
 */
export function aggregateSubmissions(
  submissions: readonly SandboxSubmissionOutcome[],
): SandboxRoundAggregate {
  if (submissions.length === 0) throw new SandboxMapError('A round final needs submissions');
  const decided = submissions
    .map((submission, index) => ({ submission, index }))
    .filter(
      (
        entry,
      ): entry is {
        submission: Exclude<SandboxSubmissionOutcome, { status: 'skipped' }>;
        index: number;
      } => entry.submission.status !== 'skipped',
    );
  const evidence = {
    submissions: submissions.length,
    executed: decided.filter((d) => d.submission.executed).length,
    isolation: SANDBOX_ISOLATION_CLASSES.filter((cls) =>
      decided.some((d) => d.submission.isolation === cls),
    ),
  };
  if (decided.length === 0) {
    const skipCodes = submissions.flatMap((s) =>
      s.status === 'skipped' ? submissionSkipCodes(s.skipReason) : [],
    );
    return {
      outcome: 'skipped',
      reasonCodes: orderReasonCodes(skipCodes),
      mostSevereIndex: null,
      evidence,
    };
  }
  let best = decided[0]!;
  for (const entry of decided) {
    if (
      sandboxVerdictRank(entry.submission.verdict) > sandboxVerdictRank(best.submission.verdict)
    ) {
      best = entry;
    }
  }
  const outcome = best.submission.verdict;
  const primary = orderReasonCodes(
    decided
      .filter((d) => d.submission.verdict === outcome)
      .flatMap((d) => d.submission.reasonCodes),
    Number.MAX_SAFE_INTEGER,
  );
  const secondary = orderReasonCodes(
    decided
      .filter((d) => d.submission.verdict !== outcome)
      .flatMap((d) => d.submission.reasonCodes),
    Number.MAX_SAFE_INTEGER,
  );
  return {
    outcome,
    reasonCodes: [...new Set([...primary, ...secondary])].slice(0, SANDBOX_MAX_REASON_CODES),
    mostSevereIndex: best.index,
    evidence,
  };
}

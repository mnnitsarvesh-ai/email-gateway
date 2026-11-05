import { z } from 'zod';

/**
 * The standardized verdicts of the scan pipeline (docs/plan/steps/09-rspamd.md S6, S7;
 * ADR-0026). Lower-case everywhere: `email_scans.scan_verdict` (Prisma `ScanVerdict`),
 * `scan_engine_results.outcome` (Prisma `EngineOutcome`, plus `skipped`) and
 * `mail.message.scanned.v1` use exactly these values.
 *
 * `timeout` and `error` are failures, never a classification: a required engine that ends in a
 * failure fails the round (`scan_failed`), and no failure is ever treated as `clean` (§2.0
 * invariant 1).
 */
export const SCAN_VERDICTS = [
  'clean',
  'spam',
  'suspicious',
  'malicious',
  'unknown',
  'timeout',
  'error',
] as const;
export type ScanVerdict = (typeof SCAN_VERDICTS)[number];
export const scanVerdictSchema = z.enum(SCAN_VERDICTS);

/** Per-engine outcomes: the verdicts plus `skipped` (an engine that did not apply). */
export const ENGINE_OUTCOMES = [...SCAN_VERDICTS, 'skipped'] as const;
export type EngineOutcome = (typeof ENGINE_OUTCOMES)[number];
export const engineOutcomeSchema = z.enum(ENGINE_OUTCOMES);

/** Verdicts an engine can reach from a complete reply (a classification, not a failure). */
export const DEFINITE_VERDICTS = ['clean', 'unknown', 'suspicious', 'spam', 'malicious'] as const;
export type DefiniteVerdict = (typeof DEFINITE_VERDICTS)[number];
export const definiteVerdictSchema = z.enum(DEFINITE_VERDICTS);

/** Engine failures: recorded as attempts, retried, and never a classification. */
export const FAILURE_OUTCOMES = ['timeout', 'error'] as const;
export type FailureOutcome = (typeof FAILURE_OUTCOMES)[number];

/** Severity of the definite verdicts (S7); failures and `skipped` have none. */
export const VERDICT_SEVERITY: Readonly<Record<DefiniteVerdict, number>> = Object.freeze({
  clean: 1,
  unknown: 2,
  suspicious: 3,
  spam: 4,
  malicious: 5,
});

export const isDefiniteVerdict = (value: string): value is DefiniteVerdict =>
  Object.prototype.hasOwnProperty.call(VERDICT_SEVERITY, value);

export const isFailureOutcome = (value: string): value is FailureOutcome =>
  (FAILURE_OUTCOMES as readonly string[]).includes(value);

/**
 * The most severe definite verdict of `outcomes` (`malicious > spam > suspicious > unknown >
 * clean`), ignoring failures (`timeout`, `error`) and `skipped`. Returns `null` when there is no
 * definite verdict at all, so the caller decides the fallback explicitly (the round aggregate
 * uses `unknown`, the Rspamd mapping `clean` only for a complete reply); it never defaults to
 * `clean` by itself.
 */
export function mostSevere(outcomes: Iterable<string>): DefiniteVerdict | null {
  let best: DefiniteVerdict | null = null;
  for (const outcome of outcomes) {
    if (!isDefiniteVerdict(outcome)) continue;
    if (best === null || VERDICT_SEVERITY[outcome] > VERDICT_SEVERITY[best]) best = outcome;
  }
  return best;
}

/**
 * Reason codes (S7): dotted lower-case codes with at least two segments, e.g. `spam.score`,
 * `auth.dmarc_reject`, `engine.timeout`. At most 64 characters; at most 32 per result or round.
 */
export const REASON_CODE_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/;
export const REASON_CODE_MAX_LENGTH = 64;
export const MAX_REASON_CODES = 32;

export const reasonCodeSchema = z
  .string()
  .max(REASON_CODE_MAX_LENGTH)
  .regex(REASON_CODE_PATTERN, 'Expected a dotted lower-case reason code');

const unique = (values: readonly string[]) => new Set(values).size === values.length;

export const reasonCodesSchema = z
  .array(reasonCodeSchema)
  .max(MAX_REASON_CODES)
  .refine(unique, { message: 'Duplicate reason code' });

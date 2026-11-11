import {
  buildScoringInput,
  type ResolvedProfile,
  type RiskResult,
  RiskInputError,
  type RoundRows,
  scoreRisk,
  scoringErrorResult,
  type ScoringInput,
} from '@email-gateway/risk-scoring';
import type {
  DryRunFinalRow,
  DryRunMessageRow,
  DryRunRows,
  DryRunScanRow,
} from '../repositories/risk-dry-run.repository';

/**
 * Pure part of the dry-run (step 5.1 R12, R13, R15): the round's stored rows → `RoundRows`
 * exactly as the email-worker assembles them (Decimal score as `toString()`, JSON columns as
 * read), then the same scoring path as the completion transaction, including its fail-safe
 * error result. No I/O.
 */

/** Round states the dry-run refuses (`409 scan_round_not_complete`). */
export const OPEN_SCAN_STATUSES: ReadonlySet<string> = new Set(['pending', 'running']);

export const toFinal = (row: DryRunFinalRow): RoundRows['finals'][number] => ({
  engine: row.engine,
  outcome: row.outcome,
  errorCode: row.errorCode,
  reasonCodes: row.reasonCodes,
  score: row.score === null ? null : row.score.toString(),
  engineVersion: row.engineVersion,
  settingsVersion: row.settingsVersion,
  attempt: row.attempt,
  completedAt: row.completedAt,
});

/** The R12 row set of a finished round (`scanKind` and `status` are validated by the builder). */
export function roundRowsOf(
  message: DryRunMessageRow,
  scan: DryRunScanRow,
  rows: DryRunRows,
): RoundRows {
  return {
    scan: {
      requiredEngines: scan.requiredEngines,
      scanKind: scan.scanKind as RoundRows['scan']['scanKind'],
      lifecycleRound: scan.lifecycleRound,
      status: scan.status as RoundRows['scan']['status'],
    },
    message: {
      direction: message.direction,
      attachmentCount: message.attachmentCount,
      recipientCount: message.recipientCount,
    },
    finals: rows.finals.map(toFinal),
    auth: rows.auth
      ? {
          spf: rows.auth.spf,
          dkim: rows.auth.dkim,
          dmarc: rows.auth.dmarc,
          dmarcPolicy: rows.auth.dmarcPolicy,
          arc: rows.auth.arc,
        }
      : null,
    bec: rows.bec
      ? {
          deterministicVerdict: rows.bec.deterministicVerdict,
          verdict: rows.bec.verdict,
          rules: rows.bec.rules,
        }
      : null,
    dlp: rows.dlp
      ? {
          action: rows.dlp.action,
          verdict: rows.dlp.verdict,
          coverage: rows.dlp.coverage,
          categories: rows.dlp.categories,
        }
      : null,
  };
}

/** Revision 1 exists only with a non-skipped sandbox final (R12, R13). */
export const hasSandboxRevision = (rows: DryRunRows): boolean =>
  rows.finals.some((f) => f.engine === 'sandbox' && f.outcome !== 'skipped');

/**
 * Scores like the completion transaction (R13): malformed rows → the fail-safe error result
 * (`input_invalid`), an unexpected scorer exception → `scorer_exception`.
 */
export function scoreRound(
  rows: RoundRows,
  revision: 0 | 1,
  resolved: ResolvedProfile,
): { result: RiskResult; input: ScoringInput | null } {
  let input: ScoringInput;
  try {
    input = buildScoringInput(rows, revision);
  } catch (error) {
    if (!(error instanceof RiskInputError)) throw error;
    return { result: scoringErrorResult(null, resolved, 'input_invalid'), input: null };
  }
  try {
    return { result: scoreRisk(input, resolved), input };
  } catch {
    return { result: scoringErrorResult(input, resolved, 'scorer_exception'), input };
  }
}

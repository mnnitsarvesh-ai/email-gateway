import { NonRetryableError, uuidv7 } from '@email-gateway/common';
import { attachmentSandboxCompletedV1, EventTypes } from '@email-gateway/event-contracts';
import {
  aggregateSubmissions,
  mapAnalysis,
  type SandboxSubmissionOutcome,
  submissionSkipCodes,
} from '@email-gateway/sandbox';
import {
  SANDBOX_ISOLATION_CLASSES,
  SANDBOX_SKIP_REASONS,
  type SandboxIsolationClass,
  type SandboxSkipReason,
  type SandboxVerdict,
} from '@email-gateway/security-contracts';
import type { SandboxMetrics } from './sandbox-metrics';
import {
  type AnalysisRow,
  type AnalysisSummary,
  type SandboxTx,
  scanKey,
  type ScanLockRow,
  type SubmissionRow,
  type SubmissionTerminal,
} from './sandbox-store';

/**
 * Completing sandbox submissions and the round's `sandbox` final (step 4.6 X15), shared by the
 * dispatcher (skips, reuse, staging failures), the results consumer and the sweeper, always
 * inside the caller's writer transaction:
 *
 * 1. lock the `email_scans` rows of the submissions (`FOR UPDATE`, ascending id: serializes
 *    concurrent finishers of one round and keeps the lock order analysis → scan → submission);
 * 2. `UPDATE sandbox_submissions … WHERE status IN ('pending','submitted')`; only when the row
 *    changed: one `mail.attachment.sandbox_completed.v1` outbox row for the submission's
 *    organization;
 * 3. per scan of a changed submission: read every submission of the round (`FOR SHARE`, the
 *    latest committed versions); when none is `pending`/`submitted`, insert the `sandbox` final
 *    (`aggregateSubmissions`; a final written earlier is kept by the unique key).
 *
 * The final never touches `email_scans` or the lifecycle (X10): the round's verdict is decided
 * by the synchronous engines only.
 */

/** Most linked submissions completed in one transaction (X13 results step 4; the sweeper does the rest). */
export const SANDBOX_LINKED_BATCH = 200;

/** `engine_version` of a final whose most severe submission has no controller version. */
export const SANDBOX_ENGINE_VERSION = 'sandbox-engine/1';
const ENGINE_VERSION_MAX = 64;

/** What a submission becomes. */
export type SubmissionOutcome =
  | { status: 'skipped'; skipReason: SandboxSkipReason; settingsVersion: string | null }
  | {
      status: 'completed' | 'failed' | 'expired';
      verdict: SandboxVerdict;
      reasonCodes: readonly string[];
      executed: boolean;
      isolation: SandboxIsolationClass | null;
      /** The analysis public id (`external_ref`), or null (expired before dispatch). */
      analysisPublicId: string | null;
    };

const isIsolation = (value: string | null): value is SandboxIsolationClass =>
  value !== null && (SANDBOX_ISOLATION_CLASSES as readonly string[]).includes(value);

/** The outcome of a submission completed from its terminal analysis (X13, X16 (c)). */
export function outcomeFromAnalysis(analysis: AnalysisRow): SubmissionOutcome {
  const status =
    analysis.status === 'failed'
      ? 'failed'
      : analysis.status === 'expired'
        ? 'expired'
        : analysis.status === 'completed' || analysis.status === 'not_executed'
          ? 'completed'
          : null;
  if (status === null) throw new Error('outcomeFromAnalysis needs a terminal analysis');
  const verdict: SandboxVerdict =
    analysis.verdict ??
    (status === 'expired' ? 'timeout' : status === 'failed' ? 'error' : 'unknown');
  const reasonCodes =
    analysis.reasonCodes.length > 0
      ? analysis.reasonCodes
      : status === 'expired'
        ? mapAnalysis({ kind: 'expired' }).reasonCodes
        : [];
  return {
    status,
    verdict,
    reasonCodes,
    executed: status === 'completed' ? analysis.executed === true : false,
    isolation:
      status === 'completed' && isIsolation(analysis.isolation) ? analysis.isolation : null,
    analysisPublicId: analysis.publicId,
  };
}

/** A submission that never reached an analysis and expired (X16 (a)). */
export function expiredOutcome(): SubmissionOutcome {
  return {
    status: 'expired',
    verdict: 'timeout',
    reasonCodes: mapAnalysis({ kind: 'expired' }).reasonCodes,
    executed: false,
    isolation: null,
    analysisPublicId: null,
  };
}

export interface FinishContext {
  now: Date;
  correlationId: string;
  metrics: SandboxMetrics;
}

export interface FinishReport {
  /** Submissions whose state this call changed. */
  changed: number;
  /** Round finals written by this call (outcomes). */
  finals: string[];
}

function terminalData(outcome: SubmissionOutcome, now: Date): SubmissionTerminal {
  if (outcome.status === 'skipped') {
    return {
      status: 'skipped',
      verdict: null,
      reasonCodes: submissionSkipCodes(outcome.skipReason),
      skipReason: outcome.skipReason,
      completedAt: now,
      externalRef: null,
      settingsVersion: outcome.settingsVersion,
    };
  }
  return {
    status: outcome.status,
    verdict: outcome.verdict,
    reasonCodes: [...outcome.reasonCodes],
    skipReason: null,
    completedAt: now,
    externalRef: outcome.analysisPublicId,
  };
}

function completedPayload(
  submission: SubmissionRow,
  scan: ScanLockRow,
  outcome: SubmissionOutcome,
  data: SubmissionTerminal,
) {
  const parsed = attachmentSandboxCompletedV1.safeParse({
    submissionId: submission.id.toString(),
    messageId: submission.messageId.toString(),
    receivedAt: submission.receivedAt.toISOString(),
    scanId: submission.scanId.toString(),
    lifecycleRound: scan.lifecycleRound,
    partIndex: submission.partIndex,
    sha256: submission.sha256,
    status: data.status,
    verdict: data.verdict,
    reasonCodes: data.reasonCodes,
    executed: outcome.status === 'skipped' ? false : outcome.executed,
    isolation: outcome.status === 'skipped' ? null : outcome.isolation,
    completedAt: data.completedAt.toISOString(),
  });
  // A violation is a defect of this code: it never commits half a completion.
  if (!parsed.success) throw new NonRetryableError('sandbox_completed_payload_invalid');
  return parsed.data;
}

/** The per-submission outcome of a terminal row, as `aggregateSubmissions` sees it. */
function aggregateInput(
  row: SubmissionRow,
  summaries: Map<bigint, AnalysisSummary>,
): SandboxSubmissionOutcome {
  if (row.status === 'skipped') {
    const reason = (SANDBOX_SKIP_REASONS as readonly string[]).includes(row.skipReason ?? '')
      ? (row.skipReason as SandboxSkipReason)
      : 'tenant_disabled';
    return { status: 'skipped', skipReason: reason };
  }
  const status =
    row.status === 'failed' ? 'failed' : row.status === 'expired' ? 'expired' : 'completed';
  const summary = row.analysisId !== null ? summaries.get(row.analysisId) : undefined;
  const verdict = (row.sandboxVerdict ??
    (status === 'expired'
      ? 'timeout'
      : status === 'failed'
        ? 'error'
        : 'unknown')) as SandboxVerdict;
  return {
    status,
    verdict,
    reasonCodes: row.sandboxReasonCodes,
    executed: status === 'completed' && summary?.executed === true,
    isolation:
      status === 'completed' && summary && isIsolation(summary.isolation)
        ? summary.isolation
        : null,
  };
}

function engineVersionOf(summary: AnalysisSummary | undefined): string {
  if (!summary?.controllerVersion || !summary.backend) return SANDBOX_ENGINE_VERSION;
  const version = `${summary.controllerVersion}+${summary.backend}/${summary.backendVersion ?? 'unknown'}`;
  return version.length > ENGINE_VERSION_MAX ? version.slice(0, ENGINE_VERSION_MAX) : version;
}

/**
 * Writes the round's `sandbox` final when every submission of the round is terminal (X15
 * step 2). Exported for the sweeper's and the tests' re-checks. Returns the outcome written, or
 * null (not all terminal, or a final existed).
 */
export async function writeRoundFinal(
  tx: SandboxTx,
  scan: ScanLockRow,
  ctx: FinishContext,
): Promise<string | null> {
  const rows = await tx.roundSubmissions(scan);
  if (rows.length === 0) return null;
  if (rows.some((r) => r.status === 'pending' || r.status === 'submitted')) return null;
  const summaries = await tx.analysisSummaries(
    rows.flatMap((r) => (r.analysisId !== null && r.status !== 'skipped' ? [r.analysisId] : [])),
  );
  const aggregate = aggregateSubmissions(rows.map((row) => aggregateInput(row, summaries)));
  const severe = aggregate.mostSevereIndex === null ? undefined : rows[aggregate.mostSevereIndex];
  const settingsVersion =
    severe?.settingsVersion ??
    rows.find((r) => r.settingsVersion !== null)?.settingsVersion ??
    null;
  const written = await tx.insertFinal(scan, {
    outcome: aggregate.outcome,
    engineVersion: engineVersionOf(
      severe?.analysisId != null ? summaries.get(severe.analysisId) : undefined,
    ),
    reasonCodes: aggregate.reasonCodes,
    evidence: { ...aggregate.evidence },
    settingsVersion,
    completedAt: ctx.now,
  });
  if (!written) return null;
  ctx.metrics.final(aggregate.outcome);
  return aggregate.outcome;
}

/**
 * Completes submissions (X15 steps 1–2) in the caller's transaction. Each item is applied with
 * its state condition; only changed rows write their `sandbox_completed.v1` and lead to the
 * round check.
 */
export async function finishSubmissions(
  tx: SandboxTx,
  items: readonly { submission: SubmissionRow; outcome: SubmissionOutcome }[],
  ctx: FinishContext,
): Promise<FinishReport> {
  const report: FinishReport = { changed: 0, finals: [] };
  if (items.length === 0) return report;
  const scans = await tx.lockScans(
    items.map((i) => ({ scanId: i.submission.scanId, receivedAt: i.submission.receivedAt })),
  );
  const changedScans = new Map<string, ScanLockRow>();
  for (const { submission, outcome } of items) {
    const data = terminalData(outcome, ctx.now);
    const changed = await tx.finishSubmission(submission, data);
    if (!changed) continue;
    report.changed += 1;
    const key = scanKey(submission.scanId, submission.receivedAt);
    const scan = scans.get(key);
    // A round whose row is gone (message purged) gets neither an event nor a final.
    if (!scan) continue;
    if (
      scan.organizationId !== submission.organizationId ||
      scan.messageId !== submission.messageId
    ) {
      throw new NonRetryableError('sandbox_submission_scan_mismatch');
    }
    await tx.writeOutbox({
      eventId: uuidv7(ctx.now.getTime()),
      organizationId: submission.organizationId,
      eventType: EventTypes.AttachmentSandboxCompleted,
      aggregateType: 'attachment',
      aggregateId: submission.id.toString(),
      correlationId: ctx.correlationId,
      payload: completedPayload(submission, scan, outcome, data),
    });
    changedScans.set(key, scan);
  }
  for (const scan of changedScans.values()) {
    const outcome = await writeRoundFinal(tx, scan, ctx);
    if (outcome !== null) report.finals.push(outcome);
  }
  return report;
}

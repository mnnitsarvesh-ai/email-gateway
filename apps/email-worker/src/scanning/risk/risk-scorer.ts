import type { Prisma } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  buildScoringInput,
  platformProfile,
  type ProfileFallback,
  RISK_SCORER_VERSION,
  RiskInputError,
  RiskProfileError,
  type RiskResult,
  riskResultToRowJson,
  type ScoringErrorReason,
  type ScoringInput,
  scoreRisk,
  scoringErrorResult,
} from '@email-gateway/risk-scoring';
import {
  type ProfileResolution,
  readProfileSnapshot,
  RiskProfileProvider,
} from './profile-provider';
import type { RiskFallbackReason, RiskMetrics } from './risk-metrics';
import {
  type RiskFinal,
  type RiskRound,
  RiskRoundReader,
  type RiskScanStatus,
} from './risk-reader';

/** Most microseconds `message_risk_scores.duration_us` (INT UNSIGNED) holds. */
const UINT32_MAX = 4_294_967_295;

const json = (value: unknown): Prisma.InputJsonValue => value as Prisma.InputJsonValue;

/** Ids of a row for logs (never content). */
interface RiskIds {
  organizationId: string;
  messageId: string;
  scanId: string;
  round: number;
}

/**
 * What one `scoreRound` call did, recorded (metrics, logs) only after the caller's transaction
 * committed (`RiskScorer.record`), so a rolled-back completion is never counted.
 */
export type RiskScoreRecord =
  | { kind: 'skipped'; revision: 0 | 1; reason: 'message_gone'; ids: RiskIds }
  | { kind: 'duplicate'; revision: 0 | 1; ids: RiskIds }
  | {
      kind: 'written';
      revision: 0 | 1;
      ids: RiskIds;
      direction: string;
      status: RiskResult['status'];
      score: number;
      level: string;
      action: string;
      hardBlocks: string[];
      failures: Array<{ engine: string; status: string }>;
      trust: string;
      fallback: RiskFallbackReason | null;
      errorReason: ScoringErrorReason | null;
      unmappedEngines: string[];
      durationUs: number;
    };

/** The fallback label of a resolution (`base_profile_retired` is an invalid version). */
function fallbackReason(fallback: ProfileFallback | null): RiskFallbackReason | null {
  if (fallback === null) return null;
  return fallback === 'base_profile_retired' ? 'invalid' : fallback;
}

export interface RiskScorerOptions {
  provider: Pick<RiskProfileProvider, 'resolve'>;
  reader: Pick<RiskRoundReader, 'read' | 'lockRound' | 'lockedFinals'>;
  metrics: RiskMetrics;
  logger: Logger;
  /** RISK_PLATFORM_PROFILE (validated at start). */
  platformId: string;
  /** Monotonic clock in nanoseconds (tests). */
  clock?: () => bigint;
}

/**
 * Risk scoring of a completed round (step 5.1 R13, ADR-0042), inside the caller's writer
 * transaction and under its `email_scans` row lock: reads the round's rows (R12), resolves the
 * profile snapshot, builds the input, scores it (`@email-gateway/risk-scoring`, pure) and inserts
 * one `message_risk_scores` row per `(scan, revision)` with `createMany … skipDuplicates` (the
 * unique key `(scan_id, revision, received_at)` makes a second attempt a counted no-op). Revision 0
 * also sets `email_scans.verdict`, `risk_score` and `scoring_version` of the round row.
 *
 * Scoring never blocks a round: an input the builder refuses (`RiskInputError`), an exception of
 * the scorer or a malformed profile row writes the fail-safe error row (`scoringErrorResult`:
 * status error, high, quarantine) instead. Database errors and wrong reads
 * (`InconsistentRiskReadError`) propagate: the whole transaction rolls back and is retried.
 */
export class RiskScorer {
  readonly reader: RiskScorerOptions['reader'];
  private readonly clock: () => bigint;

  constructor(private readonly options: RiskScorerOptions) {
    this.reader = options.reader;
    this.clock = options.clock ?? (() => process.hrtime.bigint());
  }

  /** R13: the organization's active profile version when a round opens (null = platform). */
  profileSnapshot(tx: Prisma.TransactionClient, organizationId: bigint): Promise<bigint | null> {
    const { metrics } = this.options;
    return readProfileSnapshot(tx, organizationId, (read) => metrics.inconsistent(read));
  }

  async scoreRound(
    tx: Prisma.TransactionClient,
    round: RiskRound,
    revision: 0 | 1,
    context: { scanStatus: RiskScanStatus; finals: readonly RiskFinal[] },
  ): Promise<RiskScoreRecord> {
    const ids: RiskIds = {
      organizationId: round.organizationId.toString(),
      messageId: round.messageId.toString(),
      scanId: round.scanId.toString(),
      round: round.round,
    };
    const started = this.clock();
    const rows = await this.options.reader.read(tx, round, context.scanStatus, context.finals);
    if (rows === null) return { kind: 'skipped', revision, reason: 'message_gone', ids };

    let profile: ProfileResolution;
    let errorReason: ScoringErrorReason | null = null;
    try {
      profile = await this.options.provider.resolve(
        tx,
        round.organizationId,
        round.riskProfileVersionId,
      );
    } catch (error) {
      if (!(error instanceof RiskProfileError)) throw error;
      profile = { resolved: platformProfile(this.options.platformId), versionId: null };
      errorReason = 'profile_error';
    }

    let input: ScoringInput | null = null;
    let result: RiskResult | null = null;
    if (errorReason === null) {
      try {
        input = buildScoringInput(rows, revision);
        result = scoreRisk(input, profile.resolved);
        // The mapping validates the result (bounds); a violation is a scorer defect.
        riskResultToRowJson(result);
      } catch (error) {
        errorReason = error instanceof RiskInputError ? 'input_invalid' : 'scorer_exception';
        result = null;
      }
    }
    if (result === null || errorReason !== null) {
      result = scoringErrorResult(input, profile.resolved, errorReason ?? 'scorer_exception');
    }
    const row = riskResultToRowJson(result);
    const elapsedUs = Number((this.clock() - started) / 1000n);
    const durationUs = Math.min(UINT32_MAX, Math.max(0, elapsedUs));

    const created = await tx.messageRiskScore.createMany({
      data: [
        {
          receivedAt: round.receivedAt,
          messageId: round.messageId,
          organizationId: round.organizationId,
          scanId: round.scanId,
          lifecycleRound: round.round,
          revision,
          direction: rows.message.direction,
          status: row.status,
          score: row.score,
          level: row.level,
          verdict: row.verdict,
          recommendedAction: row.recommendedAction,
          hardBlocks: json(row.hardBlocks),
          reasonCodes: json(row.reasonCodes),
          contributions: json(row.contributions),
          groups: json(row.groups),
          engines: json(row.engines),
          failures: json(row.failures),
          floors: json(row.floors),
          trust: json(row.trust),
          evidence: json(row.evidence),
          explanation: json(row.explanation),
          explanationText: row.explanationText,
          profileSource: row.profileSource,
          profileVersionId: profile.versionId,
          profileIdText: row.profileIdText,
          profileSha256: row.profileSha256,
          inputSha256: row.inputSha256,
          scorerVersion: row.scorerVersion,
          signalMapVersion: row.signalMapVersion,
          inputVersion: row.inputVersion,
          durationUs,
        },
      ],
      // Unique (scan_id, revision, received_at): a row written earlier is kept (R13).
      skipDuplicates: true,
    });
    if (created.count === 0) return { kind: 'duplicate', revision, ids };
    if (revision === 0) {
      await tx.emailScan.updateMany({
        where: {
          id: round.scanId,
          receivedAt: round.receivedAt,
          organizationId: round.organizationId,
        },
        data: { verdict: row.verdict, riskScore: row.score, scoringVersion: RISK_SCORER_VERSION },
      });
    }
    return {
      kind: 'written',
      revision,
      ids,
      direction: rows.message.direction,
      status: row.status,
      score: row.score,
      level: row.level,
      action: row.recommendedAction,
      hardBlocks: row.hardBlocks.map((h) => h.id),
      failures: row.failures.map((f) => ({ engine: f.engine, status: f.status })),
      trust: row.trust.status,
      fallback: fallbackReason(profile.resolved.fallback),
      errorReason,
      unmappedEngines: row.evidence.unmappedCodes.map((code) => code.split(':')[0] ?? 'other'),
      durationUs,
    };
  }

  /**
   * The sandbox path (R13 (a)): revision 1 of a round that is no longer running, after its
   * non-skipped sandbox final was inserted in this transaction. Re-locks the `email_scans` row
   * (the caller holds it) for its snapshot and status, reads the finals with `FOR SHARE`.
   * Returns null when the round row is gone or still running (completion writes revision 1).
   */
  async scoreSandboxRevision(
    tx: Prisma.TransactionClient,
    ref: { scanId: bigint; receivedAt: Date; organizationId: bigint; messageId: bigint },
  ): Promise<RiskScoreRecord | null> {
    const round = await this.reader.lockRound(tx, ref);
    if (!round || round.status === 'running') return null;
    const scanStatus: RiskScanStatus =
      round.status === 'completed' || round.status === 'failed' || round.status === 'timed_out'
        ? round.status
        : 'failed';
    const finals = await this.reader.lockedFinals(tx, round);
    return this.scoreRound(tx, round, 1, { scanStatus, finals });
  }

  /** Metrics and logs of committed scorings (ids, codes and integers only). */
  record(records: readonly RiskScoreRecord[]): void {
    const { metrics, logger } = this.options;
    for (const record of records) {
      if (record.kind === 'skipped') {
        metrics.skip(record.revision, record.reason);
        logger.warn(
          { ...record.ids, revision: record.revision, reason: record.reason },
          'risk score not written: the message row is gone',
        );
        continue;
      }
      if (record.kind === 'duplicate') {
        metrics.duplicate(record.revision);
        logger.info(
          { ...record.ids, revision: record.revision },
          'risk score of this round and revision already written (no-op)',
        );
        continue;
      }
      metrics.written({ ...record, durationSeconds: record.durationUs / 1e6 });
      if (record.errorReason !== null) {
        logger.error(
          { ...record.ids, revision: record.revision, reason: record.errorReason },
          'risk scoring failed; fail-safe error row written (high, quarantine)',
        );
      } else if (record.fallback !== null) {
        logger.warn(
          { ...record.ids, revision: record.revision, fallback: record.fallback },
          'risk profile version unusable; scored with the platform default',
        );
      }
    }
  }
}

/** The worker's scorer (one per process: completion, the deadline sweeper and the sandbox path). */
export function createRiskScorer(options: {
  config: { RISK_PLATFORM_PROFILE: string; RISK_PROFILE_CACHE_MAX_ENTRIES: number };
  /** `ScanMetrics.risk` (the worker registry's risk series). */
  metrics: RiskMetrics;
  logger: Logger;
}): RiskScorer {
  const { metrics } = options;
  const onInconsistent = metrics.inconsistent.bind(metrics);
  return new RiskScorer({
    provider: new RiskProfileProvider({
      platformId: options.config.RISK_PLATFORM_PROFILE,
      maxEntries: options.config.RISK_PROFILE_CACHE_MAX_ENTRIES,
      onInconsistent,
    }),
    reader: new RiskRoundReader(onInconsistent),
    metrics,
    logger: options.logger.child({ component: 'risk-scoring' }),
    platformId: options.config.RISK_PLATFORM_PROFILE,
  });
}

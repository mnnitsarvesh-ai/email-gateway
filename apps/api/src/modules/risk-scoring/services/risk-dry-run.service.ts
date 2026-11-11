import { Inject, Injectable } from '@nestjs/common';
import { platformProfile, type ResolvedProfile } from '@email-gateway/risk-scoring';
import { API_CONFIG } from '../../../api-config.token';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedHttpException } from '../../../http/coded-exception';
import { MESSAGE_NOT_FOUND, messageNotFound } from '../../messages/messages.errors';
import {
  hasSandboxRevision,
  OPEN_SCAN_STATUSES,
  roundRowsOf,
  scoreRound,
} from '../domain/risk-dry-run';
import { checkOverrides, inlineProfile, resolveVersion } from '../domain/risk-profile';
import type { RiskDryRun, RiskDryRunResponse } from '../dto/risk-scoring.schemas';
import { RiskDryRunRepository, type DryRunScanRow } from '../repositories/risk-dry-run.repository';
import { RiskProfilesRepository } from '../repositories/risk-profiles.repository';
import {
  RISK_PROFILE_INVALID,
  RISK_PROFILE_VERSION_NOT_FOUND,
  RISK_REVISION_UNAVAILABLE,
  RISK_SCAN_NOT_FOUND,
  riskProfileInvalid,
  riskProfileVersionNotFound,
  riskRevisionUnavailable,
  riskScanNotFound,
  SCAN_ROUND_NOT_COMPLETE,
  scanRoundNotComplete,
} from '../risk-scoring.errors';
import { type RiskDryRunResult, RiskMetrics } from './risk-writer';

type Settings = { RISK_PLATFORM_PROFILE: string };

const RESULT_OF_CODE: Readonly<Record<string, RiskDryRunResult>> = {
  [MESSAGE_NOT_FOUND]: 'not_found',
  [RISK_SCAN_NOT_FOUND]: 'not_found',
  [RISK_PROFILE_VERSION_NOT_FOUND]: 'not_found',
  [SCAN_ROUND_NOT_COMPLETE]: 'not_complete',
  [RISK_REVISION_UNAVAILABLE]: 'not_complete',
  [RISK_PROFILE_INVALID]: 'invalid_profile',
};

/**
 * `POST /messages/{messageId}/scans/{scanId}/risk/dry-run` (step 5.1 R12, R15): scores a stored
 * round of the caller's organization against a profile (`active`: the round's snapshot, or the
 * platform default when it has none; `platform`; a draft or published version; or an inline
 * overrides document) and compares with the stored score of that revision. It reads the
 * replica only and **writes nothing**: no score row, no audit row, no outbox row, no cache
 * entry (this service has no writer, audit or cache dependency). Counted
 * `risk_dry_runs_total{result}`.
 */
@Injectable()
export class RiskDryRunService {
  constructor(
    @Inject(API_CONFIG) private readonly settings: Settings,
    private readonly rounds: RiskDryRunRepository,
    private readonly profiles: RiskProfilesRepository,
    private readonly metrics: RiskMetrics,
  ) {}

  async dryRun(
    scope: TenantScope,
    messageId: string,
    scanId: bigint,
    body: RiskDryRun,
  ): Promise<RiskDryRunResponse> {
    try {
      const response = await this.evaluate(scope, messageId, scanId, body);
      this.metrics.dryRuns.inc({ result: 'ok' });
      return response;
    } catch (error) {
      const result = error instanceof CodedHttpException ? RESULT_OF_CODE[error.code] : undefined;
      if (result !== undefined) this.metrics.dryRuns.inc({ result });
      throw error;
    }
  }

  private async evaluate(
    scope: TenantScope,
    messageId: string,
    scanId: bigint,
    body: RiskDryRun,
  ): Promise<RiskDryRunResponse> {
    const platformId = this.settings.RISK_PLATFORM_PROFILE;
    // An inline document is checked before any database access.
    let inline: ResolvedProfile | null = null;
    if (typeof body.profile === 'object' && 'overrides' in body.profile) {
      const check = checkOverrides(body.profile.overrides, platformId);
      if (!check.ok) throw riskProfileInvalid(check.violations);
      inline = inlineProfile(platformId, check.overrides);
    }
    const message = await this.rounds.message(scope, messageId);
    if (!message) throw messageNotFound();
    const scan = await this.rounds.scan(scope, message, scanId);
    if (!scan) throw riskScanNotFound();
    if (OPEN_SCAN_STATUSES.has(scan.status)) throw scanRoundNotComplete(scan.status);
    const rows = await this.rounds.roundRows(scope, message, scanId);
    if (body.revision === 1 && !hasSandboxRevision(rows)) throw riskRevisionUnavailable();
    const resolved = inline ?? (await this.resolve(scope, scan, body.profile, platformId));
    const { result } = scoreRound(roundRowsOf(message, scan, rows), body.revision, resolved);
    const stored = await this.rounds.storedScore(scope, message, scanId, body.revision);
    return {
      result: { ...result, revision: body.revision },
      stored:
        stored === null
          ? null
          : {
              revision: stored.revision === 1 ? 1 : 0,
              score: stored.score,
              level: stored.level,
              recommendedAction: stored.recommendedAction,
              inputSha256: stored.inputSha256,
              profileSha256: stored.profileSha256,
            },
      reproducible: stored !== null && stored.inputSha256 === result.inputSha256,
    };
  }

  /**
   * `active` = the round's snapshot (`email_scans.risk_profile_version_id`) resolved as the
   * email-worker does (platform default when NULL; `missing` when the row is not the
   * organization's; `foreign` when it is not published); `platform`; a version of the
   * organization (draft or published; one the platform bounds no longer accept is a `400`).
   */
  private async resolve(
    scope: TenantScope,
    scan: DryRunScanRow,
    profile: RiskDryRun['profile'],
    platformId: string,
  ): Promise<ResolvedProfile> {
    if (profile === 'platform') return platformProfile(platformId);
    if (profile === 'active') {
      if (scan.riskProfileVersionId === null) return platformProfile(platformId);
      const row = await this.profiles.versionById(scope, scan.riskProfileVersionId);
      if (!row) return platformProfile(platformId, 'missing');
      if (row.status !== 'published') return platformProfile(platformId, 'foreign');
      return resolveVersion(platformId, row);
    }
    if (!('versionId' in profile)) throw new Error('inline profiles are resolved by the caller');
    const row = await this.profiles.findVersion(scope, profile.versionId);
    if (!row) throw riskProfileVersionNotFound();
    const resolved = resolveVersion(platformId, row);
    if (resolved.source !== 'tenant') throw riskProfileInvalid(resolved.violations);
    return resolved;
  }
}

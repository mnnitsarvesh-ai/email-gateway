import type { Prisma } from '@email-gateway/database';
import { platformProfile, type ResolvedProfile, resolveProfile } from '@email-gateway/risk-scoring';
import type { RiskRead } from './risk-metrics';
import { InconsistentRiskReadError } from './risk-reader';

/** The profile a round is scored with, and the version id stored with its row (R11). */
export interface ProfileResolution {
  resolved: ResolvedProfile;
  /** `message_risk_scores.profile_version_id`: the tenant version used; null = platform. */
  versionId: bigint | null;
}

/**
 * R13 snapshot at round open: `risk_scoring_profiles.active_version_id` of the organization (the
 * writer, inside the open transaction; null = no profile row or no active version, i.e. the
 * platform default). The row is echo-checked by organization (a wrong read is retryable).
 */
export async function readProfileSnapshot(
  tx: Prisma.TransactionClient,
  organizationId: bigint,
  onInconsistent?: (read: RiskRead) => void,
): Promise<bigint | null> {
  const row = await tx.riskScoringProfile.findUnique({
    where: { organizationId },
    select: { organizationId: true, activeVersionId: true },
  });
  if (!row) return null;
  if (row.organizationId !== organizationId) {
    onInconsistent?.('profile');
    throw new InconsistentRiskReadError('profile', 'organization echo');
  }
  return row.activeVersionId;
}

interface CacheEntry {
  organizationId: bigint;
  resolution: ProfileResolution;
}

/**
 * Resolves a round's profile snapshot (step 5.1 R10, R13, §6). `email_scans.risk_profile_version_id`
 * NULL → the platform default (no fallback). Otherwise the `risk_scoring_profile_versions` row by
 * id, read inside the caller's writer transaction and echo-checked (`id`; a row of another id is a
 * wrong read, retryable): a row of another organization → the platform default with fallback
 * `foreign`; a missing row or a draft → `missing`; a published version → `resolveProfile` (its
 * violations, if the platform bounds changed since publish, fall back to the platform default with
 * `invalid`, decided by the library). Published versions are immutable, so their resolutions are
 * kept in a per-process LRU keyed by version id (RISK_PROFILE_CACHE_MAX_ENTRIES); the organization
 * is checked again on every hit. Drafts and missing rows are never cached (a draft may be
 * published later; it is still refused then, as the snapshot names it only if it was active).
 * `resolveProfile` throws `RiskProfileError` for a malformed row (public id, version number): the
 * scorer turns that into the `profile_error` error row.
 */
export class RiskProfileProvider {
  private readonly cache = new Map<string, CacheEntry>();
  /** Version rows read from MySQL (cache misses), for tests and diagnostics. */
  reads = 0;

  constructor(
    private readonly options: {
      platformId: string;
      maxEntries: number;
      onInconsistent?: (read: RiskRead) => void;
    },
  ) {}

  get size(): number {
    return this.cache.size;
  }

  async resolve(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    versionId: bigint | null,
  ): Promise<ProfileResolution> {
    const { platformId } = this.options;
    if (versionId === null) return { resolved: platformProfile(platformId), versionId: null };
    const key = versionId.toString();
    const hit = this.cache.get(key);
    if (hit) {
      // LRU: refresh the entry.
      this.cache.delete(key);
      this.cache.set(key, hit);
      return hit.organizationId === organizationId
        ? hit.resolution
        : { resolved: platformProfile(platformId, 'foreign'), versionId: null };
    }
    this.reads += 1;
    const row = await tx.riskScoringProfileVersion.findUnique({
      where: { id: versionId },
      select: {
        id: true,
        organizationId: true,
        status: true,
        publicId: true,
        versionNo: true,
        baseProfile: true,
        overrides: true,
      },
    });
    if (row && row.id !== versionId) {
      this.options.onInconsistent?.('profile_version');
      throw new InconsistentRiskReadError('profile_version', 'identity echo');
    }
    if (!row || row.status !== 'published') {
      return { resolved: platformProfile(platformId, 'missing'), versionId: null };
    }
    const resolved = resolveProfile(platformId, {
      publicId: row.publicId,
      versionNo: row.versionNo,
      baseProfile: row.baseProfile,
      overrides: row.overrides,
    });
    const resolution: ProfileResolution = {
      resolved,
      versionId: resolved.source === 'tenant' ? versionId : null,
    };
    this.cache.set(key, { organizationId: row.organizationId, resolution });
    while (this.cache.size > this.options.maxEntries) {
      const oldest = this.cache.keys().next().value;
      if (oldest === undefined) break;
      this.cache.delete(oldest);
    }
    return row.organizationId === organizationId
      ? resolution
      : { resolved: platformProfile(platformId, 'foreign'), versionId: null };
  }
}

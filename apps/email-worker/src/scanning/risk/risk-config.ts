import { isPlatformProfileId, RISK_DEFAULT_PLATFORM_PROFILE_ID } from '@email-gateway/risk-scoring';
import { z } from 'zod';

/**
 * The risk scorer's keys of the email-worker (step 5.1 R16, §5, docs/plan/steps/15-risk-scoring.md;
 * `.env.example` section "Risk scoring (step 5.1 …)"). Every key has the design default and an
 * explicit bound. The api reads RISK_PLATFORM_PROFILE (and RISK_PROFILE_MAX_VERSIONS) itself.
 */

const int = z.coerce.number().int();

export const RISK_PROFILE_CACHE_MIN_ENTRIES = 100;
export const RISK_PROFILE_CACHE_MAX_ENTRIES_LIMIT = 100_000;

export function riskConfigShape() {
  return {
    /**
     * The shipped platform profile every round falls back to and every tenant version is validated
     * against at use (R10): a key of RISK_PLATFORM_PROFILES. A changed default is a new id.
     */
    RISK_PLATFORM_PROFILE: z
      .string()
      .trim()
      .default(RISK_DEFAULT_PLATFORM_PROFILE_ID)
      .refine((value) => isPlatformProfileId(value), {
        message: 'must name a shipped platform risk profile (RISK_PLATFORM_PROFILES)',
      }),
    /**
     * Resolved published profile versions kept per process (R13): published versions are
     * immutable, so the cache is keyed by version id and never invalidated (LRU eviction only).
     */
    RISK_PROFILE_CACHE_MAX_ENTRIES: int
      .min(RISK_PROFILE_CACHE_MIN_ENTRIES)
      .max(RISK_PROFILE_CACHE_MAX_ENTRIES_LIMIT)
      .default(10_000),
  };
}

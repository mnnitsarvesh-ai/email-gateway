import { createHash } from 'node:crypto';
import {
  SANDBOX_MAPPING_VERSION,
  type SandboxProfile,
  type SandboxTaskLimits,
  sandboxProfileSchema,
  sandboxTaskLimitsSchema,
} from '@email-gateway/security-contracts';

/**
 * The content-addressed dedup key of a sandbox analysis (step 4.6 X13 step 4):
 *
 *     analysisKey = first 16 hex of SHA-256(canonical JSON { profile, limits, epoch, map })
 *     dedupeKey   = <sample sha256> ":" <analysisKey>        (81 characters, sandbox_analyses.dedupe_key)
 *
 * Canonical JSON: keys sorted recursively, so the key never depends on property order. Bumping
 * `SANDBOX_ANALYSIS_EPOCH` (or the map version) forces new analyses for every sample.
 */

export interface AnalysisKeyInput {
  profile: SandboxProfile;
  limits: SandboxTaskLimits;
  /** `SANDBOX_ANALYSIS_EPOCH` (positive integer). */
  epoch: number;
  /** The verdict map version (default `sandbox-map/1`). */
  map?: string;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;
export const ANALYSIS_KEY_PATTERN = /^[0-9a-f]{16}$/;

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/** The 16-hex analysis key. Throws on an invalid profile, limits or epoch. */
export function analysisKey(input: AnalysisKeyInput): string {
  const profile = sandboxProfileSchema.parse(input.profile);
  const limits = sandboxTaskLimitsSchema.parse(input.limits);
  if (!Number.isSafeInteger(input.epoch) || input.epoch < 1) {
    throw new Error('The analysis epoch must be a positive integer');
  }
  const map = input.map ?? SANDBOX_MAPPING_VERSION;
  return createHash('sha256')
    .update(canonicalJson({ profile, limits, epoch: input.epoch, map }), 'utf8')
    .digest('hex')
    .slice(0, 16);
}

/** `<sha256>:<analysisKey>`. */
export function dedupeKey(sha256: string, key: string): string {
  if (!SHA256_HEX.test(sha256) || !ANALYSIS_KEY_PATTERN.test(key)) {
    throw new Error('Invalid sha256 or analysis key');
  }
  return `${sha256}:${key}`;
}

import { hardBlockReasonCode, RISK_HARD_BLOCK_IDS } from './hard-blocks';
import { RISK_ROW_MISSING_CODES, RISK_SIGNAL_IDS } from './signals';
import { RISK_LEVELS } from './vocabulary';

/**
 * Every `risk.*` reason code the scorer can emit (step 5.1 R1, R11). Each matches
 * `REASON_CODE_PATTERN` and is at most 64 characters (unit-tested). Also the vocabulary of the
 * `reasonCodes` of `RiskResult`, so the api can document it.
 */

/** Engines that can carry `risk.engine.<engine>.<status>` (the sandbox in revision 1 only). */
export const RISK_ENGINE_CODE_ENGINES = [
  'rspamd',
  'attachment',
  'url',
  'bec',
  'dlp',
  'sandbox',
] as const;
export const RISK_ENGINE_CODE_STATUSES = ['timeout', 'error', 'missing', 'unknown'] as const;
export type RiskEngineCodeStatus = (typeof RISK_ENGINE_CODE_STATUSES)[number];

export const engineReasonCode = (engine: string, status: RiskEngineCodeStatus): string =>
  `risk.engine.${engine}.${status}`;

/** Synthetic engine-level codes added by `buildScoringInput` for a missing child row (R2). */
export const RISK_INPUT_CODES: readonly string[] = Object.freeze(
  Object.values(RISK_ROW_MISSING_CODES),
);

export const RISK_PROFILE_CODES = [
  'risk.profile.tenant',
  'risk.profile.platform',
  'risk.profile.invalid_fallback',
  'risk.profile.missing_fallback',
  'risk.profile.foreign_fallback',
] as const;

export const RISK_TRUST_CODES = [
  'risk.trust.applied',
  'risk.trust.denied_unauthenticated',
  'risk.trust.denied_auth_failure',
] as const;

export const RISK_FLOOR_CODES = [
  'risk.floor.engine_malicious',
  'risk.floor.bec_suspicious',
  'risk.floor.engine_failure',
  'risk.floor.engine_unknown',
] as const;

export const RISK_UNMAPPED_CODE = 'risk.signal.unmapped_code';
export const RISK_AI_RAISE_ONLY_CODE = 'risk.ai.raise_only';
export const RISK_SANDBOX_INCLUDED_CODE = 'risk.sandbox.included';
export const RISK_SCORING_ERROR_CODE = 'risk.scoring_error';

export const levelReasonCode = (level: string): string => `risk.level.${level}`;
export const signalReasonCode = (signal: string): string => `risk.signal.${signal}`;

export const RISK_REASON_CODES: readonly string[] = Object.freeze([
  ...RISK_LEVELS.map(levelReasonCode),
  ...RISK_HARD_BLOCK_IDS.map(hardBlockReasonCode),
  ...RISK_ENGINE_CODE_ENGINES.flatMap((engine) =>
    RISK_ENGINE_CODE_STATUSES.map((status) => engineReasonCode(engine, status)),
  ),
  ...RISK_INPUT_CODES,
  ...RISK_SIGNAL_IDS.map(signalReasonCode),
  RISK_UNMAPPED_CODE,
  ...RISK_TRUST_CODES,
  ...RISK_FLOOR_CODES,
  RISK_AI_RAISE_ONLY_CODE,
  ...RISK_PROFILE_CODES,
  RISK_SANDBOX_INCLUDED_CODE,
  RISK_SCORING_ERROR_CODE,
]);

const RISK_REASON_CODE_SET = new Set(RISK_REASON_CODES);
export const isRiskReasonCode = (code: string): boolean => RISK_REASON_CODE_SET.has(code);

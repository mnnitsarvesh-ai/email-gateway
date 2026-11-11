/**
 * `@email-gateway/risk-scoring` (step 5.1 R1, docs/plan/steps/15-risk-scoring.md; ADR-0041): the
 * pure, deterministic risk scorer. No I/O, no clock, no randomness, integer arithmetic only.
 * The default weights and thresholds are engineering defaults calibrated on a synthetic dataset;
 * they are not validated detection accuracy.
 */
export {
  RISK_SCORER_VERSION,
  RISK_SIGNAL_MAP_VERSION,
  RISK_INPUT_VERSION,
  RISK_LEVELS,
  RISK_ACTIONS,
  RISK_VERDICTS,
  riskLevelSchema,
  riskActionSchema,
  riskVerdictSchema,
  levelRank,
  actionRank,
  maxLevel,
  strictestAction,
  type RiskLevel,
  type RiskAction,
  type RiskVerdict,
} from './vocabulary';
export {
  RISK_SIGNAL_GROUPS,
  RISK_GROUP_DEFINITIONS,
  RISK_LOCKED_GROUPS,
  RISK_SIGNALS,
  RISK_SIGNAL_IDS,
  RISK_INFORMATIONAL_CODES,
  ROUND_ENGINES,
  riskSignal,
  signalForAssertion,
  isInformationalAssertion,
  engineFailedSignal,
  engineUnknownSignal,
  type RiskSignalGroup,
  type RiskGroupDefinition,
  type RiskSignalDefinition,
  type GroupRule,
  type MessageDirection,
  type SignalWeightSource,
} from './signals';
export {
  RISK_HARD_BLOCKS,
  RISK_HARD_BLOCK_IDS,
  HARD_BLOCK_VERDICT_PRIORITY,
  riskHardBlock,
  hardBlockReasonCode,
  type RiskHardBlockId,
  type RiskHardBlockDefinition,
  type HardBlockControl,
} from './hard-blocks';
export {
  RISK_REASON_CODES,
  RISK_INPUT_CODES,
  RISK_PROFILE_CODES,
  RISK_TRUST_CODES,
  RISK_FLOOR_CODES,
  isRiskReasonCode,
} from './reason-codes';
export { canonicalJson, sha256Hex } from './canonical';
export {
  scoringInputSchema,
  engineInputSchema,
  buildScoringInput,
  RiskInputError,
  ENGINE_INPUT_STATUSES,
  TRUSTED_SENDER_STATES,
  SANDBOX_INPUT_OUTCOMES,
  MAX_INPUT_REASON_CODES,
  type ScoringInput,
  type EngineInput,
  type EngineInputStatus,
  type RoundRows,
} from './input';
export {
  effectiveProfileSchema,
  riskProfileOverridesSchema,
  violationSchema,
  RISK_PLATFORM_PROFILE_IDS,
  RISK_TUNABLE_GROUPS,
  TRUST_MODES,
  type EffectiveProfile,
  type RiskProfileOverrides,
  type RiskPlatformProfileId,
  type Violation,
} from './profile-schema';
export {
  RISK_PLATFORM_PROFILES,
  RISK_DEFAULT_PLATFORM_PROFILE_ID,
  RISK_OVERRIDE_BOUNDS,
  isPlatformProfileId,
  resolveProfile,
  platformProfile,
  validateOverrides,
  validateEffectiveProfile,
  mergeOverrides,
  RiskProfileError,
  type ResolvedProfile,
  type ProfileFallback,
} from './profile';
export {
  riskResultSchema,
  riskScoreViewSchema,
  riskResultViewSchema,
  explanationLineSchema,
  riskResultToRowJson,
  rowJsonToRiskView,
  EXPLANATION_LINE_CODES,
  TRUST_STATUSES,
  FAILURE_STATUSES,
  FLOOR_SOURCES,
  type RiskResult,
  type RiskScoreView,
  type RiskScoreRowJson,
  type RiskScoreRowRead,
  type ExplanationLine,
  type ExplanationLineCode,
  type TrustStatus,
} from './result';
export { renderExplanation, renderLine } from './explanation';
export {
  scoreRisk,
  scoringErrorResult,
  levelForScore,
  SCORING_ERROR_REASONS,
  type ScoringErrorReason,
} from './score';

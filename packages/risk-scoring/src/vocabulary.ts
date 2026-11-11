import { z } from 'zod';

/**
 * Versions and vocabularies of the risk scorer (step 5.1 R1, R4, R8;
 * docs/plan/steps/15-risk-scoring.md; ADR-0041). Every result records the scorer, signal-map,
 * input and profile versions; a changed algorithm, map or input shape is a new id, never an edit.
 */
export const RISK_SCORER_VERSION = 'risk-score/1';
export const RISK_SIGNAL_MAP_VERSION = 'risk-signals/1';
export const RISK_INPUT_VERSION = 'risk-input/1';

/** Risk levels, least to most severe (Prisma `RiskLevel`). */
export const RISK_LEVELS = ['none', 'low', 'medium', 'high', 'critical'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];
export const riskLevelSchema = z.enum(RISK_LEVELS);

/** Recommended actions in strictness order (Prisma `RiskAction`). */
export const RISK_ACTIONS = ['deliver', 'tag', 'require_approval', 'quarantine', 'block'] as const;
export type RiskAction = (typeof RISK_ACTIONS)[number];
export const riskActionSchema = z.enum(RISK_ACTIONS);

/** The Prisma `MessageVerdict` values (`bulk` is never produced by `risk-signals/1`). */
export const RISK_VERDICTS = [
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
  'unknown',
] as const;
export type RiskVerdict = (typeof RISK_VERDICTS)[number];
export const riskVerdictSchema = z.enum(RISK_VERDICTS);

export const levelRank = (level: RiskLevel): number => RISK_LEVELS.indexOf(level);
export const actionRank = (action: RiskAction): number => RISK_ACTIONS.indexOf(action);

/** The more severe of two levels. */
export const maxLevel = (a: RiskLevel, b: RiskLevel): RiskLevel =>
  levelRank(a) >= levelRank(b) ? a : b;

/** The stricter of two actions. */
export const strictestAction = (a: RiskAction, b: RiskAction): RiskAction =>
  actionRank(a) >= actionRank(b) ? a : b;

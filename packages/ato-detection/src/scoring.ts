/**
 * Account risk scoring `ato-score/1` (step 8.4 D11, ADR-0071): integer arithmetic only, like 5.1.
 *
 * - contribution `c = ⌊⌊weight × multiplier / 1000⌋ × DECAY[k] / 1000⌋`, `k = min(160, ⌊16 × age /
 *   halfLife⌋)`, `age = now − last_occurred_at`;
 * - per category: `c₁ + ⌊(c₂ + c₃ + c₄) × 250 / 1000⌋`, capped by `GROUP_CAPS`;
 * - raw score `min(100, Σ totals)`;
 * - gates: weak-only → `min(raw, weakOnlyCap)`; a strong or correlation signal younger than one
 *   half-life → `max(raw, strongFloor)`;
 * - override: `compromised` → `max(score, 90)`; `benign` → `min(score, bands.medium − 1)` unless a
 *   strong signal occurred after the override was set (then `contradicted`, not applied);
 * - level from the tenant's bands.
 */
import type { AtoRiskLevel } from '@email-gateway/security-contracts';
import type { ResolvedAtoSettings } from './settings';
import {
  GROUP_CAPS,
  GROUP_MAX_CONTRIBUTIONS,
  GROUP_STACKING_PERMILLE,
  SIGNAL_CATEGORIES,
  type SignalCategory,
  type SignalStatus,
  type SignalStrength,
} from './taxonomy';
import { ATO_RULES_VERSION, ATO_SCORER_VERSION } from './versions';

/** `DECAY_PERMILLE[k] = round(1000 × 2^(−k/16))` for k = 0..159 and `DECAY_PERMILLE[160] = 0`. */
// prettier-ignore
export const DECAY_PERMILLE: readonly number[] = Object.freeze([
  1000, 958, 917, 878, 841, 805, 771, 738, 707, 677, 648, 621, 595, 569, 545, 522,
  500, 479, 459, 439, 420, 403, 386, 369, 354, 339, 324, 310, 297, 285, 273, 261,
  250, 239, 229, 220, 210, 201, 193, 185, 177, 169, 162, 155, 149, 142, 136, 131,
  125, 120, 115, 110, 105, 101, 96, 92, 88, 85, 81, 78, 74, 71, 68, 65,
  63, 60, 57, 55, 53, 50, 48, 46, 44, 42, 41, 39, 37, 36, 34, 33,
  31, 30, 29, 27, 26, 25, 24, 23, 22, 21, 20, 19, 19, 18, 17, 16,
  16, 15, 14, 14, 13, 13, 12, 12, 11, 11, 10, 10, 9, 9, 9, 8,
  8, 7, 7, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 4, 4, 4,
  4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  0,
]);

export const DECAY_STEPS_PER_HALF_LIFE = 16;
export const DECAY_MAX_STEP = 160;
/** A signal contributes for at most ten half-lives of its category. */
export const DECAY_HALF_LIVES = 10;
export const COMPROMISED_OVERRIDE_FLOOR = 90;

export interface ScoreSignal {
  id?: bigint | string;
  code: string;
  category: SignalCategory;
  strength: SignalStrength;
  weight: number;
  status: SignalStatus;
  lastOccurredAt: Date;
}

export interface ScoreOverride {
  verdict: 'benign' | 'compromised';
  createdAt: Date;
  expiresAt: Date;
  clearedAt: Date | null;
  contradictedAt: Date | null;
}

export interface ScoreContribution {
  signalId: string | null;
  code: string;
  category: SignalCategory;
  strength: SignalStrength;
  weight: number;
  multiplierPermille: number;
  decayPermille: number;
  contribution: number;
  /** Counted in its group (first four of the category, non-zero). */
  counted: boolean;
}

export interface ScoreResult {
  scorerVersion: typeof ATO_SCORER_VERSION;
  score: number;
  raw: number;
  level: AtoRiskLevel;
  contributions: ScoreContribution[];
  groups: Partial<Record<SignalCategory, { total: number; cap: number; capped: boolean }>>;
  gates: { weakOnly: boolean; weakOnlyCapApplied: boolean; strongFloorApplied: boolean };
  override: {
    verdict: 'benign' | 'compromised' | null;
    outcome: 'none' | 'applied' | 'contradicted' | 'expired';
  };
}

/** Decay step of an age (milliseconds) for a half-life (minutes). */
export function decayStep(ageMs: number, halfLifeMinutes: number): number {
  const age = Math.max(0, ageMs);
  return Math.min(
    DECAY_MAX_STEP,
    Math.floor((DECAY_STEPS_PER_HALF_LIFE * age) / (halfLifeMinutes * 60_000)),
  );
}

/** Integer contribution of one signal (D11). */
export function signalContribution(
  weight: number,
  multiplierPermille: number,
  decayPermille: number,
): number {
  return Math.floor((Math.floor((weight * multiplierPermille) / 1000) * decayPermille) / 1000);
}

/** Level of a score for the tenant's bands. */
export function levelFor(
  score: number,
  bands: { medium: number; high: number; critical: number },
): AtoRiskLevel {
  if (score >= bands.critical) return 'critical';
  if (score >= bands.high) return 'high';
  if (score >= bands.medium) return 'medium';
  return 'low';
}

/** Whether an override is active at `now` (not cleared, not expired, not contradicted). */
export function overrideActive(override: ScoreOverride | null, now: Date): boolean {
  return (
    override !== null &&
    override.clearedAt === null &&
    override.contradictedAt === null &&
    override.expiresAt.getTime() > now.getTime()
  );
}

/** `scoreAccount` (D11): deterministic for equal inputs. */
export function scoreAccount(
  signals: readonly ScoreSignal[],
  settings: Pick<ResolvedAtoSettings, 'scoring'>,
  override: ScoreOverride | null,
  now: Date,
): ScoreResult {
  const { categoryMultipliers, halfLifeMinutes, bands, weakOnlyCap, strongFloor } =
    settings.scoring;
  const contributions: ScoreContribution[] = [];
  for (const s of signals) {
    if (s.status !== 'active') continue;
    const halfLife = halfLifeMinutes[s.category];
    const ageMs = now.getTime() - s.lastOccurredAt.getTime();
    if (ageMs > halfLife * 60_000 * DECAY_HALF_LIVES) continue;
    const decay = DECAY_PERMILLE[decayStep(ageMs, halfLife)]!;
    const multiplier = categoryMultipliers[s.category];
    contributions.push({
      signalId: s.id === undefined ? null : s.id.toString(),
      code: s.code,
      category: s.category,
      strength: s.strength,
      weight: s.weight,
      multiplierPermille: multiplier,
      decayPermille: decay,
      contribution: signalContribution(s.weight, multiplier, decay),
      counted: false,
    });
  }
  // Deterministic order: contribution desc, then code, then signal id.
  contributions.sort(
    (a, b) =>
      b.contribution - a.contribution ||
      (a.code < b.code ? -1 : a.code > b.code ? 1 : 0) ||
      (a.signalId ?? '').localeCompare(b.signalId ?? ''),
  );

  const groups: ScoreResult['groups'] = {};
  let raw = 0;
  for (const category of SIGNAL_CATEGORIES) {
    const members = contributions.filter((c) => c.category === category && c.contribution > 0);
    if (members.length === 0) continue;
    const top = members.slice(0, GROUP_MAX_CONTRIBUTIONS);
    for (const m of top) m.counted = true;
    const [first, ...rest] = top;
    const stacked = rest.reduce((sum, c) => sum + c.contribution, 0);
    const total = first!.contribution + Math.floor((stacked * GROUP_STACKING_PERMILLE) / 1000);
    const cap = GROUP_CAPS[category];
    groups[category] = { total: Math.min(total, cap), cap, capped: total > cap };
    raw += Math.min(total, cap);
  }
  raw = Math.min(100, raw);

  const counted = contributions.filter((c) => c.counted);
  const weakOnly = counted.length > 0 && counted.every((c) => c.strength === 'weak');
  let score = raw;
  let weakOnlyCapApplied = false;
  let strongFloorApplied = false;
  if (weakOnly && raw > weakOnlyCap) {
    score = weakOnlyCap;
    weakOnlyCapApplied = true;
  }
  const freshStrong = signals.some(
    (s) =>
      s.status === 'active' &&
      (s.strength === 'strong' || s.category === 'correlation') &&
      now.getTime() - s.lastOccurredAt.getTime() < halfLifeMinutes[s.category] * 60_000 &&
      counted.some((c) => c.code === s.code),
  );
  if (freshStrong && score < strongFloor) {
    score = strongFloor;
    strongFloorApplied = true;
  }

  let overrideOutcome: ScoreResult['override'] = { verdict: null, outcome: 'none' };
  if (override && override.clearedAt === null) {
    if (override.contradictedAt !== null) {
      overrideOutcome = { verdict: override.verdict, outcome: 'contradicted' };
    } else if (override.expiresAt.getTime() <= now.getTime()) {
      overrideOutcome = { verdict: override.verdict, outcome: 'expired' };
    } else if (override.verdict === 'compromised') {
      score = Math.max(score, COMPROMISED_OVERRIDE_FLOOR);
      overrideOutcome = { verdict: 'compromised', outcome: 'applied' };
    } else {
      const contradicted = signals.some(
        (s) =>
          s.status === 'active' &&
          s.strength === 'strong' &&
          s.lastOccurredAt.getTime() > override.createdAt.getTime(),
      );
      if (contradicted) {
        overrideOutcome = { verdict: 'benign', outcome: 'contradicted' };
      } else {
        score = Math.min(score, bands.medium - 1);
        overrideOutcome = { verdict: 'benign', outcome: 'applied' };
      }
    }
  }

  return {
    scorerVersion: ATO_SCORER_VERSION,
    score,
    raw,
    level: levelFor(score, bands),
    contributions,
    groups,
    gates: { weakOnly, weakOnlyCapApplied, strongFloorApplied },
    override: overrideOutcome,
  };
}

/** The stored explanation (`ato_risk_scores.explanation`, `ato_accounts.risk_explanation`). */
export interface ScoreExplanation {
  version: typeof ATO_SCORER_VERSION;
  rulesVersion: typeof ATO_RULES_VERSION;
  settingsVersion: number;
  score: number;
  raw: number;
  level: AtoRiskLevel;
  top: Array<Omit<ScoreContribution, 'counted'>>;
  groups: ScoreResult['groups'];
  gates: ScoreResult['gates'];
  override: ScoreResult['override'];
}

/** Top 10 counted contributions with groups, gates and override (D11). */
export function scoreExplanation(result: ScoreResult, settingsVersion: number): ScoreExplanation {
  return {
    version: ATO_SCORER_VERSION,
    rulesVersion: ATO_RULES_VERSION,
    settingsVersion,
    score: result.score,
    raw: result.raw,
    level: result.level,
    top: result.contributions
      .filter((c) => c.counted)
      .slice(0, 10)
      .map(({ counted: _counted, ...rest }) => rest),
    groups: result.groups,
    gates: result.gates,
    override: result.override,
  };
}

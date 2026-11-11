import { RISK_HARD_BLOCKS } from '../hard-blocks';
import { RISK_SIGNAL_GROUPS } from '../signals';
import type { EffectiveProfile } from '../profile-schema';

/**
 * The platform default profile `rsk-default/1` (step 5.1 R4–R10). Reviewed with the calibration
 * report (docs/performance/risk-scoring-calibration.md). A changed default is a new id
 * (`rsk-default/2`), never an edit. These are engineering defaults calibrated on a synthetic
 * dataset; they are not validated detection accuracy.
 */
export const RSK_DEFAULT_1: EffectiveProfile = {
  base: 'rsk-default/1',
  thresholds: { low: 100, medium: 300, high: 550, critical: 800 },
  actions: {
    none: 'deliver',
    low: 'deliver',
    medium: 'tag',
    high: 'quarantine',
    critical: 'quarantine',
  },
  groupMultipliersPermille: Object.fromEntries(
    RISK_SIGNAL_GROUPS.map((g) => [g, 1000]),
  ) as EffectiveProfile['groupMultipliersPermille'],
  hardBlocks: Object.fromEntries(
    RISK_HARD_BLOCKS.map((h) => [h.id, { enabled: h.defaultEnabled, action: h.defaultAction }]),
  ) as EffectiveProfile['hardBlocks'],
  failures: {
    engineFailureWeight: 300,
    groupCap: 600,
    unknownWeight: 60,
    minLevel: 'medium',
    unknownMinLevel: 'low',
    action: 'quarantine',
    unknownAction: 'tag',
  },
  floors: { engineMalicious: 'high', becSuspicious: 'low' },
  trust: { mode: 'reduce_content', contentFactorPermille: 500 },
  ai: { tagOnAiOnlyRaise: true },
};

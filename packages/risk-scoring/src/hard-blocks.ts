import type { RiskAction, RiskVerdict } from './vocabulary';

/**
 * Hard-block indicators (step 5.1 R5; ADR-0041 decision 4). A fired hard block sets the level to
 * `critical`, the score to at least `thresholds.critical`, the verdict and a non-delivery action
 * regardless of score, trust and weights. Evaluated before trust and never reduced by it.
 */
export const RISK_HARD_BLOCK_IDS = [
  'hb.malware_attachment',
  'hb.malware_url',
  'hb.malware_sandbox',
  'hb.dlp_block',
  'hb.known_phishing',
  'hb.tenant_domain_spoof',
  'hb.url_tenant_blocked',
  'hb.bec_malicious',
  'hb.dmarc_reject',
] as const;
export type RiskHardBlockId = (typeof RISK_HARD_BLOCK_IDS)[number];

/** `locked`: always on; `may_disable`: on by default; `may_enable`: off by default. */
export type HardBlockControl = 'locked' | 'may_disable' | 'may_enable';

export interface RiskHardBlockDefinition {
  readonly id: RiskHardBlockId;
  readonly verdict: RiskVerdict;
  readonly defaultEnabled: boolean;
  readonly defaultAction: RiskAction;
  readonly control: HardBlockControl;
  /** Actions a profile may choose (a single entry: the action is locked). */
  readonly allowedActions: readonly RiskAction[];
  /** What fires it (documentation; the scorer implements it). */
  readonly firesWhen: string;
}

const BQ: readonly RiskAction[] = Object.freeze(['block', 'quarantine']);

const hb = (
  id: RiskHardBlockId,
  verdict: RiskVerdict,
  defaultEnabled: boolean,
  defaultAction: RiskAction,
  control: HardBlockControl,
  allowedActions: readonly RiskAction[],
  firesWhen: string,
): RiskHardBlockDefinition =>
  Object.freeze({ id, verdict, defaultEnabled, defaultAction, control, allowedActions, firesWhen });

/** The R5 table, in catalog order. */
export const RISK_HARD_BLOCKS: readonly RiskHardBlockDefinition[] = Object.freeze([
  hb('hb.malware_attachment', 'malware', true, 'block', 'locked', BQ, 'signal attachment_malware'),
  hb('hb.malware_url', 'malware', true, 'block', 'locked', BQ, 'signal url_known_malware'),
  hb(
    'hb.malware_sandbox',
    'malware',
    true,
    'quarantine',
    'locked',
    BQ,
    'revision 1, sandbox outcome malicious',
  ),
  hb(
    'hb.dlp_block',
    'dlp_violation',
    true,
    'block',
    'locked',
    Object.freeze(['block'] as RiskAction[]),
    'dlp action block (changed only through the tenant DLP policy)',
  ),
  hb(
    'hb.known_phishing',
    'phishing',
    true,
    'quarantine',
    'may_disable',
    BQ,
    'signal url_known_phishing',
  ),
  hb(
    'hb.tenant_domain_spoof',
    'phishing',
    true,
    'quarantine',
    'may_disable',
    BQ,
    'inbound, signals auth_tenant_domain_spoof and auth_dmarc_reject',
  ),
  hb(
    'hb.url_tenant_blocked',
    'phishing',
    true,
    'quarantine',
    'may_disable',
    BQ,
    'signal url_tenant_blocked',
  ),
  hb(
    'hb.bec_malicious',
    'bec',
    true,
    'quarantine',
    'may_disable',
    BQ,
    'bec deterministicVerdict malicious',
  ),
  hb(
    'hb.dmarc_reject',
    'phishing',
    false,
    'quarantine',
    'may_enable',
    BQ,
    'inbound, signal auth_dmarc_reject (any sender domain)',
  ),
]);

export function riskHardBlock(id: RiskHardBlockId): RiskHardBlockDefinition {
  const found = RISK_HARD_BLOCKS.find((h) => h.id === id);
  if (!found) throw new Error(`Unknown hard block ${id}`);
  return found;
}

/** Verdict priority of hard blocks (R5): malware > phishing > bec > dlp_violation. */
export const HARD_BLOCK_VERDICT_PRIORITY: readonly RiskVerdict[] = Object.freeze([
  'malware',
  'phishing',
  'bec',
  'dlp_violation',
]);

/** `risk.hard_block.<id without hb.>`. */
export const hardBlockReasonCode = (id: RiskHardBlockId): string =>
  `risk.hard_block.${id.slice('hb.'.length)}`;

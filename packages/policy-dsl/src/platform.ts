import type { RiskAction } from '@email-gateway/risk-scoring';
import type { DlpAction } from '@email-gateway/security-contracts';
import type { PolicyDisposition } from './vocabulary';

/**
 * Platform defaults (step 5.2 P9 steps 4–5; ADR-0043 decision 5). Data in the library: a
 * changed default is a new id (`pol-default/2`), never an edit. `POLICY_PLATFORM_DEFAULT`
 * (env, api and policy-engine) selects the shipped id.
 */
export interface PlatformDefault {
  readonly id: string;
  readonly description: string;
  /** Recommendation and floor mapping of the 5.1 recommended action (P9.4). */
  readonly riskActionMap: Readonly<Record<RiskAction, PolicyDisposition>>;
  /** Risk actions that add a platform TAG (label `<riskTagPrefix><level>`). */
  readonly riskTagActions: readonly RiskAction[];
  readonly riskTagPrefix: string;
  /**
   * Rule D2: a deterministic BEC verdict in `verdicts` recommends `disposition` (the 4.4 B17
   * hold of the former pass-through). `levelOnlyVerdicts` stay overridable as level-only.
   */
  readonly becDeterministicHold: {
    readonly verdicts: readonly string[];
    readonly disposition: PolicyDisposition;
    readonly levelOnlyVerdicts: readonly string[];
  };
  /** The DLP binding of ADR-0037 (floor): `null` = no floor; `alert` adds a mandatory TAG. */
  readonly dlpBinding: Readonly<Record<DlpAction, PolicyDisposition | null>>;
  readonly dlpTagActions: readonly DlpAction[];
  readonly dlpTagLabel: string;
  /** Floor of a definite, non-skipped DLP final without its result row. */
  readonly dlpMissing: PolicyDisposition;
  /** Floor of a scanned/scan-failed round without a revision-0 risk row. */
  readonly riskMissing: PolicyDisposition;
  /** Floor of a scan-failed round. */
  readonly scanFailed: PolicyDisposition;
  /** Floor of a parse failure (no scan). */
  readonly notScanned: PolicyDisposition;
}

const POL_DEFAULT_1: PlatformDefault = Object.freeze({
  id: 'pol-default/1',
  description:
    'Follow the 5.1 risk recommendation (deliver/tag → allow, tag adds a platform tag, require_approval, quarantine, block → reject); deterministic BEC suspicious/malicious → quarantine (D2); mandatory floor for hard blocks, failures, unknown engines, the DLP binding and missing data.',
  riskActionMap: Object.freeze({
    deliver: 'allow',
    tag: 'allow',
    require_approval: 'require_approval',
    quarantine: 'quarantine',
    block: 'reject',
  }),
  riskTagActions: Object.freeze(['tag'] as const),
  riskTagPrefix: 'risk-',
  becDeterministicHold: Object.freeze({
    verdicts: Object.freeze(['suspicious', 'malicious']),
    disposition: 'quarantine',
    levelOnlyVerdicts: Object.freeze(['suspicious']),
  }),
  dlpBinding: Object.freeze({
    allow: null,
    alert: 'allow',
    require_approval: 'require_approval',
    quarantine: 'quarantine',
    block: 'reject',
  }),
  dlpTagActions: Object.freeze(['alert'] as const),
  dlpTagLabel: 'dlp-alert',
  dlpMissing: 'quarantine',
  riskMissing: 'quarantine',
  scanFailed: 'quarantine',
  notScanned: 'quarantine',
});

export const POLICY_DEFAULT_PLATFORM_ID = 'pol-default/1';

export const POLICY_PLATFORM_DEFAULTS: Readonly<Record<string, PlatformDefault>> = Object.freeze({
  'pol-default/1': POL_DEFAULT_1,
});

export const isPlatformDefaultId = (id: unknown): id is string =>
  typeof id === 'string' && Object.prototype.hasOwnProperty.call(POLICY_PLATFORM_DEFAULTS, id);

import {
  DEFAULT_LOOKALIKE_PARAMS,
  ProtectedSet,
  detectLookalikes,
  normalizeDomainInput,
  type Brand,
  type LookalikeFinding,
  type LookalikeParams,
  type LookalikeResult,
} from '@email-gateway/url-security';

/**
 * Sender-domain lookalikes through url-security (B5): one `ProtectedSet` per evaluation with
 * the brands, the tenant's active domains and the extra domains (vendor profile domains ∪
 * platform/tenant extra protected domains). Findings on a vendor domain are attributed to that
 * vendor; tenant and brand findings keep their kind. Nothing of url-security is copied.
 */

export type BecTargetKind = 'tenant' | 'vendor' | 'brand' | 'extra';

export interface AttributedFinding extends LookalikeFinding {
  attributedKind: BecTargetKind;
  /** Vendor public id when attributed to a vendor. */
  vendorId: string | null;
  highConfidence: boolean;
}

export interface DomainLookalike {
  findings: AttributedFinding[];
  mixedScript: boolean;
  idn: boolean;
}

export interface BecProtectedSetInput {
  brands: readonly Brand[];
  tenantDomains: readonly string[];
  /** vendor public id → its domains. */
  vendorDomains: ReadonlyArray<{ vendorId: string; domains: readonly string[] }>;
  extraDomains: readonly string[];
}

export class BecProtectedSet {
  readonly set: ProtectedSet;
  /** registrable domain → vendor public id (first vendor wins). */
  readonly vendorByDomain: ReadonlyMap<string, string>;

  constructor(input: BecProtectedSetInput) {
    const vendorByDomain = new Map<string, string>();
    for (const vendor of input.vendorDomains) {
      for (const raw of vendor.domains) {
        const normalized = normalizeDomainInput(raw);
        if (normalized.ok && !vendorByDomain.has(normalized.registrableDomain)) {
          vendorByDomain.set(normalized.registrableDomain, vendor.vendorId);
        }
      }
    }
    this.vendorByDomain = vendorByDomain;
    this.set = new ProtectedSet({
      brands: input.brands,
      tenantDomains: input.tenantDomains,
      extraDomains: [...vendorByDomain.keys(), ...input.extraDomains],
    });
  }
}

const isHigh = (finding: LookalikeFinding, params: LookalikeParams): boolean =>
  finding.rule === 'L1' ||
  finding.rule === 'L3' ||
  (finding.rule === 'L2' && finding.score >= params.highScore);

/** Lookalike findings of one (ASCII, lower-case) domain, attributed for the bec rules. */
export function detectDomainLookalike(
  domain: string | null,
  registrableDomain: string | null,
  protectedSet: BecProtectedSet,
  params: LookalikeParams = DEFAULT_LOOKALIKE_PARAMS,
): DomainLookalike {
  if (!domain) return { findings: [], mixedScript: false, idn: false };
  const result: LookalikeResult = detectLookalikes(
    { host: domain, hostKind: 'domain', registrableDomain },
    protectedSet.set,
    params,
  );
  const findings = result.findings.map((finding): AttributedFinding => {
    const vendorId =
      finding.targetKind === 'extra'
        ? (protectedSet.vendorByDomain.get(finding.targetDomain) ?? null)
        : null;
    const attributedKind: BecTargetKind =
      finding.targetKind === 'extra' ? (vendorId ? 'vendor' : 'extra') : finding.targetKind;
    return { ...finding, attributedKind, vendorId, highConfidence: isHigh(finding, params) };
  });
  return { findings, mixedScript: result.mixedScript, idn: result.idn };
}

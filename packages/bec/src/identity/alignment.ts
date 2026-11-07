import { registrableDomainOf } from '@email-gateway/url-security';

/**
 * Alignment from the stored authentication results (B5; `email_auth_results` of the round's
 * Rspamd final, step 4.1). Nothing is re-evaluated: DKIM relaxed alignment over the signature
 * list, SPF alignment over `spf_domain` (else the envelope sender domain), DMARC result.
 */

export const AUTH_OUTCOMES = [
  'pass',
  'fail',
  'softfail',
  'neutral',
  'none',
  'temperror',
  'permerror',
] as const;
export type AuthOutcome = (typeof AUTH_OUTCOMES)[number];
export type DmarcPolicy = 'none' | 'quarantine' | 'reject';

/** Shape of an `email_auth_results` row (camel-cased by the caller). */
export interface AuthResultRow {
  spf: AuthOutcome | null;
  spfDomain: string | null;
  dkim: AuthOutcome | null;
  dkimSignatures: ReadonlyArray<{ domain: string; result: string; selector?: string | null }>;
  dmarc: AuthOutcome | null;
  dmarcPolicy: DmarcPolicy | null;
  dmarcDomain: string | null;
  arc: AuthOutcome | null;
}

export interface Alignment {
  dkimAligned: boolean;
  spfAligned: boolean;
  dmarcPass: boolean;
  /** dmarcPass || dkimAligned || spfAligned. */
  authenticatedAsFrom: boolean;
  /** Registrable domain of the first aligned passing DKIM signature (history fingerprint). */
  dkimAlignedDomain: string | null;
  /** Registrable domain of the SPF-pass identity (history fingerprint). */
  spfPassDomain: string | null;
}

const reg = (domain: string | null | undefined): string | null =>
  domain ? (registrableDomainOf(domain.toLowerCase().replace(/\.+$/, '')) ?? null) : null;

export function computeAlignment(
  auth: AuthResultRow | null,
  fromDomain: string | null,
  envelopeDomain: string | null,
): Alignment {
  const none: Alignment = {
    dkimAligned: false,
    spfAligned: false,
    dmarcPass: false,
    authenticatedAsFrom: false,
    dkimAlignedDomain: null,
    spfPassDomain: null,
  };
  if (!auth) return none;
  const fromReg = reg(fromDomain);
  let dkimAlignedDomain: string | null = null;
  for (const signature of auth.dkimSignatures.slice(0, 10)) {
    if (signature.result !== 'pass') continue;
    const signer = reg(signature.domain);
    if (signer !== null && fromReg !== null && signer === fromReg) {
      dkimAlignedDomain = signer;
      break;
    }
  }
  const spfPassDomain = auth.spf === 'pass' ? (reg(auth.spfDomain) ?? reg(envelopeDomain)) : null;
  const dkimAligned = dkimAlignedDomain !== null;
  const spfAligned = spfPassDomain !== null && fromReg !== null && spfPassDomain === fromReg;
  const dmarcPass = auth.dmarc === 'pass';
  return {
    dkimAligned,
    spfAligned,
    dmarcPass,
    authenticatedAsFrom: dmarcPass || dkimAligned || spfAligned,
    dkimAlignedDomain,
    spfPassDomain,
  };
}

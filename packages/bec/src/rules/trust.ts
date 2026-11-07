import { normalizeDomainInput } from '@email-gateway/url-security';
import { BEC_TRUST_NEUTRALIZED_RULE_IDS, type BecRuleId } from './codes';
import type { FiredRule, RuleEvidence, TrustedSender } from './types';

/**
 * Trusted senders (B7). Match: the exact lower-case From address, or a domain entry equal to
 * the From registrable domain (no suffix wildcards). Only when the message authenticates as
 * From (T1) are the listed categories neutralized (weight 0, `suppressed: 'trust'`); A*, L*,
 * R3, X*, K*, E rules never are. Without authentication T2 fires and nothing is neutralized.
 */

export interface TrustContext {
  fromAddress: string | null;
  fromReg: string | null;
  authenticated: boolean;
  now: Date;
}

export function findTrustedSender(
  entries: readonly TrustedSender[],
  context: Pick<TrustContext, 'fromAddress' | 'fromReg' | 'now'>,
): TrustedSender | null {
  for (const entry of entries) {
    if (entry.expiresAt !== null && entry.expiresAt.getTime() <= context.now.getTime()) continue;
    if (entry.kind === 'address') {
      if (
        context.fromAddress !== null &&
        entry.value.trim().toLowerCase() === context.fromAddress
      ) {
        return entry;
      }
    } else {
      const normalized = normalizeDomainInput(entry.value);
      if (
        normalized.ok &&
        normalized.domain === normalized.registrableDomain &&
        context.fromReg !== null &&
        normalized.registrableDomain === context.fromReg
      ) {
        return entry;
      }
    }
  }
  return null;
}

export function applyTrust(
  fired: Map<BecRuleId, FiredRule>,
  entries: readonly TrustedSender[],
  context: TrustContext,
  fire: (id: BecRuleId, evidence: RuleEvidence) => void,
): TrustedSender | null {
  const entry = findTrustedSender(entries, context);
  if (!entry) return null;
  if (!context.authenticated) {
    fire('T2', {
      header: 'From',
      address: context.fromAddress,
      domain: context.fromReg,
      trusted: { id: entry.publicId },
    });
    return entry;
  }
  // Neutralized rules stay in the result with `suppressed: 'trust'` (B7 "listed as
  // suppressed-by-trust in evidence").
  for (const rule of fired.values()) {
    if (rule.suppressed === null && BEC_TRUST_NEUTRALIZED_RULE_IDS.has(rule.id)) {
      rule.suppressed = 'trust';
    }
  }
  fire('T1', {
    header: 'From',
    address: context.fromAddress,
    domain: context.fromReg,
    trusted: { id: entry.publicId },
  });
  return entry;
}

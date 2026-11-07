import { BadRequestException } from '@nestjs/common';
import {
  comparableAddress,
  type FreemailList,
  isFreemailDomain,
  loadFreemail,
  normalizeName,
  parseAddrSpec,
} from '@email-gateway/bec';
import { normalizeDomainInput } from '@email-gateway/url-security';

/**
 * Pure normalization of the BEC tenant data inputs (step 4.4 B5, B7, B18): names through the
 * `@email-gateway/bec` B5 normalization (the uniqueness key), addresses through its addr-spec
 * parser (IDNA domain, lower case), domains through `@email-gateway/url-security` (public
 * suffixes, IP literals and single labels refused) and free-mail checks against the packaged
 * free-mail list. Invalid input is a `400` naming the field (`<field>.<index>: …`).
 */

/** Longest stored normalized name (`normalized_name VARCHAR(160)`). */
export const MAX_NORMALIZED_NAME = 160;

let freemail: FreemailList | null = null;
/** The packaged free-mail list (`packages/bec/data/freemail.txt`), loaded once. */
export function freemailList(): FreemailList {
  freemail ??= loadFreemail();
  return freemail;
}

/** True when the registrable domain of `domain` is on the packaged free-mail list. */
export const isFreemail = (domain: string): boolean => isFreemailDomain(domain, freemailList());

/** The B5 normalized form of a display name (token string); `400` when nothing is left. */
export function normalizedProfileName(field: string, raw: string): string {
  const normalized = normalizeName(raw).normalized;
  if (normalized.length === 0) {
    throw new BadRequestException([`${field}: Must contain letters or digits`]);
  }
  return [...normalized].slice(0, MAX_NORMALIZED_NAME).join('');
}

/** An e-mail address normalized for comparison (`local@a-label-domain`, lower case), or null. */
export function normalizeAddress(raw: string): string | null {
  const spec = parseAddrSpec(raw.trim().replace(/^<(.*)>$/, '$1'));
  const address = comparableAddress(spec.address);
  return address !== null && address.length <= 320 ? address : null;
}

/** Every address normalized, duplicates removed (first occurrence kept); `400` on the first bad one. */
export function normalizeAddresses(field: string, raw: readonly string[]): string[] {
  const out: string[] = [];
  raw.forEach((value, index) => {
    const address = normalizeAddress(value);
    if (address === null) {
      throw new BadRequestException([`${field}.${index}: Not a valid e-mail address`]);
    }
    if (!out.includes(address)) out.push(address);
  });
  return out;
}

/** Alias names trimmed, duplicates (by normalized form) removed. */
export function normalizeAliases(field: string, raw: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  raw.forEach((value, index) => {
    const key = normalizedProfileName(`${field}.${index}`, value);
    if (seen.has(key)) return;
    seen.add(key);
    out.push(value.trim());
  });
  return out;
}

const DOMAIN_MESSAGES: Record<string, string> = {
  invalid: 'Not a valid domain or host name',
  ip_literal: 'An IP address is not a domain',
  single_label: 'A single label is not a registrable domain',
  public_suffix: 'A public suffix (e.g. co.uk, github.io) is not allowed',
};

/** A domain as its ASCII registrable domain (url-security); `400` naming the field otherwise. */
export function normalizeRegistrableDomain(
  field: string,
  raw: string,
): { domain: string; registrableDomain: string } {
  const result = normalizeDomainInput(raw);
  if (!result.ok) {
    throw new BadRequestException([
      `${field}: ${DOMAIN_MESSAGES[result.code] ?? 'Invalid domain'}`,
    ]);
  }
  return { domain: result.domain, registrableDomain: result.registrableDomain };
}

/**
 * Vendor domains (B18): each normalized to its registrable domain (the rules compare
 * registrable domains), duplicates removed; returns the index of the first free-mail domain.
 */
export function normalizeVendorDomains(raw: readonly string[]): {
  domains: string[];
  freemailIndex: number | null;
} {
  const domains: string[] = [];
  let freemailIndex: number | null = null;
  raw.forEach((value, index) => {
    const { registrableDomain } = normalizeRegistrableDomain(`domains.${index}`, value);
    if (freemailIndex === null && isFreemail(registrableDomain)) freemailIndex = index;
    if (!domains.includes(registrableDomain)) domains.push(registrableDomain);
  });
  return { domains, freemailIndex };
}

/**
 * A trusted sender value (B7): an address normalized for comparison, or a domain that must be a
 * registrable domain (a trusted subdomain would never match: trust compares the From
 * registrable domain). `freemail` is true for a free-mail domain (refused by the service).
 */
export function normalizeTrustedValue(
  kind: 'address' | 'domain',
  raw: string,
): { value: string; freemail: boolean } {
  if (kind === 'address') {
    const address = normalizeAddress(raw);
    if (address === null) throw new BadRequestException(['value: Not a valid e-mail address']);
    return { value: address, freemail: false };
  }
  const { domain, registrableDomain } = normalizeRegistrableDomain('value', raw);
  if (domain !== registrableDomain) {
    throw new BadRequestException([
      `value: Must be a registrable domain (${registrableDomain}), not a subdomain`,
    ]);
  }
  return { value: registrableDomain, freemail: isFreemail(registrableDomain) };
}

/** Longest a trusted sender may be trusted ahead (B7: 365 days). */
export const TRUSTED_MAX_EXPIRY_MS = 365 * 24 * 60 * 60 * 1000;

/** A trusted sender expiry: null, or in the future and at most 365 days ahead; `400` otherwise. */
export function checkTrustedExpiry(value: string | null | undefined, now: Date): Date | null {
  if (value === null || value === undefined) return null;
  const at = new Date(value);
  if (at.getTime() <= now.getTime()) {
    throw new BadRequestException(['expiresAt: must be in the future']);
  }
  if (at.getTime() - now.getTime() > TRUSTED_MAX_EXPIRY_MS) {
    throw new BadRequestException(['expiresAt: must be at most 365 days ahead']);
  }
  return at;
}

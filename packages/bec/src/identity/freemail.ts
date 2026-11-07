import { registrableDomainOf, normalizeDomainInput } from '@email-gateway/url-security';
import { readDataFile, sha256Hex } from '../data';

/**
 * Free-mail registrable domains (B5): packaged `data/freemail.txt`, versioned by its SHA-256
 * (`fm=` of the engine version), extended per tenant by `freemailExtraDomains`.
 */
export interface FreemailList {
  domains: ReadonlySet<string>;
  /** First 8 hex of the SHA-256 of the file. */
  version: string;
}

export function loadFreemail(text: string = readDataFile('freemail.txt')): FreemailList {
  const domains = new Set<string>();
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*/, '').trim().toLowerCase();
    if (!line) continue;
    const normalized = normalizeDomainInput(line);
    if (!normalized.ok || normalized.registrableDomain !== line) {
      throw new Error(`freemail.txt: ${line} is not a registrable domain`);
    }
    domains.add(line);
  }
  return { domains, version: sha256Hex(text).slice(0, 8) };
}

/** True when the registrable domain of `domain` is a free-mail domain (packaged or extra). */
export function isFreemailDomain(
  domain: string | null,
  list: FreemailList,
  extra: ReadonlySet<string> = new Set(),
): boolean {
  if (!domain) return false;
  const registrable = registrableDomainOf(domain) ?? domain;
  return list.domains.has(registrable) || extra.has(registrable);
}

/** Normalizes tenant extra domains to registrable domains (invalid entries dropped). */
export function normalizeExtraDomains(domains: readonly string[] | undefined): Set<string> {
  const out = new Set<string>();
  for (const raw of domains ?? []) {
    const normalized = normalizeDomainInput(raw);
    if (normalized.ok) out.add(normalized.registrableDomain);
  }
  return out;
}

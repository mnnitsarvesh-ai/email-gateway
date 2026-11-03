/**
 * Reconciliation plan of the DKIM signing key store (step 2.2 D12, ADR-0020). Pure: compares
 * the desired signing keys with what redis-dkim holds and lists the changes.
 *
 * Layout (read by rspamd-outbound's `dkim_signing`, probed by the smtp-adapter):
 * - hash `dkim_selectors`: field `<domain>` → `<selector>`
 * - hash `dkim_keys`: field `<selector>.<domain>` → PKCS#8 PEM
 */

export const DKIM_SELECTORS_HASH = 'dkim_selectors';
export const DKIM_KEYS_HASH = 'dkim_keys';

/** `dkim_keys` field of a selector of a domain. */
export const dkimKeyField = (selector: string, domain: string): string => `${selector}.${domain}`;

export interface DesiredSigningKey {
  /** ASCII domain name. */
  domain: string;
  selector: string;
  pem: string;
}

/** What redis-dkim holds (never the PEMs: only the key field names). */
export interface PublishedSigningState {
  selectors: Readonly<Record<string, string>>;
  keyFields: readonly string[];
}

export interface SigningSyncCounts {
  /** Domains whose selector or key was (re)written. */
  published: number;
  /** Domains no longer signable whose selector was removed. */
  removed: number;
  /** Domains already published with the desired selector and key. */
  unchanged: number;
  /** Signable domains left as they were because their key could not be decrypted. */
  skipped: number;
  /** `dkim_keys` fields deleted because no selector references them any more. */
  pruned: number;
}

export interface SigningPlan {
  /** Written first (`HSET dkim_keys`). Contains PEMs: never log it. */
  keysToWrite: ReadonlyArray<readonly [field: string, pem: string]>;
  /** `HSET dkim_selectors`, after the keys. */
  selectorsToWrite: ReadonlyArray<readonly [domain: string, selector: string]>;
  /** `HDEL dkim_selectors`, before the keys are deleted. */
  selectorsToDelete: readonly string[];
  /** `HDEL dkim_keys`, last. */
  keysToDelete: readonly string[];
  counts: SigningSyncCounts;
}

export function isEmptyPlan(plan: SigningPlan): boolean {
  return (
    plan.keysToWrite.length === 0 &&
    plan.selectorsToWrite.length === 0 &&
    plan.selectorsToDelete.length === 0 &&
    plan.keysToDelete.length === 0
  );
}

/**
 * Plans the changes that make redis-dkim hold exactly the desired keys:
 * - a desired domain whose selector differs (rotation) or whose key field is missing is
 *   (re)published: key first, then selector;
 * - a published domain that is no longer desired loses its selector, unless it is in `keep`
 *   (its key could not be decrypted this time: the published entry stays as it was);
 * - every `dkim_keys` field not referenced by the resulting selectors is pruned (old selectors
 *   after a rotation, keys of removed domains, leftovers).
 */
export function planSigningSync(
  desired: readonly DesiredSigningKey[],
  current: PublishedSigningState,
  keep: ReadonlySet<string> = new Set(),
): SigningPlan {
  const presentKeys = new Set(current.keyFields);
  const desiredByDomain = new Map(desired.map((d) => [d.domain, d]));
  const keysToWrite: Array<readonly [string, string]> = [];
  const selectorsToWrite: Array<readonly [string, string]> = [];
  const selectorsToDelete: string[] = [];
  const counts: SigningSyncCounts = {
    published: 0,
    removed: 0,
    unchanged: 0,
    skipped: 0,
    pruned: 0,
  };
  const finalSelectors = new Map<string, string>();

  for (const key of desiredByDomain.values()) {
    const field = dkimKeyField(key.selector, key.domain);
    const currentSelector = current.selectors[key.domain];
    finalSelectors.set(key.domain, key.selector);
    if (currentSelector === key.selector && presentKeys.has(field)) {
      counts.unchanged++;
      continue;
    }
    counts.published++;
    keysToWrite.push([field, key.pem]);
    if (currentSelector !== key.selector) selectorsToWrite.push([key.domain, key.selector]);
  }

  for (const [domain, selector] of Object.entries(current.selectors)) {
    if (desiredByDomain.has(domain)) continue;
    if (keep.has(domain)) {
      finalSelectors.set(domain, selector);
      continue;
    }
    selectorsToDelete.push(domain);
    counts.removed++;
  }
  counts.skipped = [...keep].filter((domain) => !desiredByDomain.has(domain)).length;

  const referenced = new Set(
    [...finalSelectors].map(([domain, selector]) => dkimKeyField(selector, domain)),
  );
  const keysToDelete = current.keyFields.filter((field) => !referenced.has(field));
  counts.pruned = keysToDelete.length;

  return { keysToWrite, selectorsToWrite, selectorsToDelete, keysToDelete, counts };
}

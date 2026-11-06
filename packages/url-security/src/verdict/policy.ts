import { readFileSync } from 'node:fs';
import { readDataFile } from '../data';
import { hostMatchesAny, type NormalizedUrl } from '../normalize/url';
import type { UrlVerdict } from './codes';

/**
 * Click policy (U14 step 5) and scan-time fetch selection (U9).
 */

export type ClickAction = 'allow' | 'warn' | 'block';
export interface ClickPolicy {
  /** `click.suspicious` (default warn). */
  suspicious: 'warn' | 'block';
  /** `click.unknown` (default warn). */
  unknown: 'allow' | 'warn' | 'block';
}

export const DEFAULT_CLICK_POLICY: ClickPolicy = { suspicious: 'warn', unknown: 'warn' };

/** clean → allow and malicious → block are not configurable. */
export function decideClick(
  verdict: UrlVerdict,
  policy: ClickPolicy = DEFAULT_CLICK_POLICY,
): ClickAction {
  switch (verdict) {
    case 'clean':
      return 'allow';
    case 'malicious':
      return 'block';
    case 'suspicious':
      return policy.suspicious;
    case 'unknown':
      return policy.unknown;
  }
}

/** Shortener hosts: data/shorteners.txt (or URL_SHORTENER_HOSTS_FILE) ∪ URL_SHORTENER_EXTRA_HOSTS. */
export function loadShorteners(file?: string | null, extra: readonly string[] = []): string[] {
  const text = file ? readFileSync(file, 'utf8') : readDataFile('shorteners.txt');
  const hosts = text
    .split('\n')
    .map((line) => line.replace(/#.*$/, '').trim().toLowerCase())
    .filter(Boolean);
  for (const host of hosts) {
    if (!/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(host)) throw new Error(`invalid shortener host ${host}`);
  }
  return [...new Set([...hosts, ...extra.map((h) => h.trim().toLowerCase()).filter(Boolean)])];
}

export const isShortener = (host: string, shorteners: readonly string[]): boolean =>
  hostMatchesAny(host, shorteners);

export const SCAN_TIME_FETCH_MODES = ['off', 'shorteners', 'suspicious', 'all'] as const;
export type ScanTimeFetch = (typeof SCAN_TIME_FETCH_MODES)[number];

export interface FetchCandidate {
  seq: number;
  url: Pick<NormalizedUrl, 'truncated'>;
  shortened: boolean;
  /**
   * Static risk (U9 `suspicious` mode): count of static S-rule signals plus non-clear reputation
   * answers; 0 = none. Used for selection and ordering ("then by risk").
   */
  risk: number;
}

export interface FetchSelection {
  /** Seqs to fetch, in fetch order (shorteners first, then by risk, then seq). */
  fetch: number[];
  /** Selected but over URL_FETCH_MAX_PER_MESSAGE (`url.fetch_skipped_limit`). */
  skippedLimit: number[];
  /** Seqs whose fetch is required (shorteners): not fetched → never clean. */
  required: number[];
}

/**
 * `scanTimeFetch` selection: `off` none; `shorteners`; `suspicious` = shorteners plus URLs with a
 * static risk signal or a non-clear reputation answer; `all`. Truncated URLs are never fetched.
 * Shorteners are always "required" (their destination is unknown until resolved), also in `off`
 * mode: an unresolved shortener is `unknown` at scan time and is resolved at click time.
 */
export function selectScanTimeFetch(
  candidates: readonly FetchCandidate[],
  mode: ScanTimeFetch,
  maxPerMessage: number,
): FetchSelection {
  const required = candidates.filter((c) => c.shortened && !c.url.truncated).map((c) => c.seq);
  const eligible = candidates.filter((c) => {
    if (c.url.truncated) return false;
    switch (mode) {
      case 'off':
        return false;
      case 'shorteners':
        return c.shortened;
      case 'suspicious':
        return c.shortened || c.risk > 0;
      case 'all':
        return true;
    }
  });
  const ordered = [...eligible].sort(
    (a, b) => Number(b.shortened) - Number(a.shortened) || b.risk - a.risk || a.seq - b.seq,
  );
  return {
    fetch: ordered.slice(0, maxPerMessage).map((c) => c.seq),
    skippedLimit: ordered.slice(maxPerMessage).map((c) => c.seq),
    required,
  };
}

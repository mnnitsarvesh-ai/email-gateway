import {
  BLOCKED_REASONS,
  dynamicSignalsSchema,
  FETCH_ERRORS,
  landingSchema,
  type BlockedReason,
  type DynamicSignals,
  type FetchError,
  type FetchHop,
  type FetchResult,
  type LookalikeFinding,
  type UrlMapInput,
} from '@email-gateway/url-security';
import type { DynamicRow, ScanResultRow } from './click-repository';

/**
 * Readers of the JSON columns written by the URL engine (WP3) and the results consumer, turned
 * into the structural inputs of `mapUrlVerdict` (U10). Everything is parsed defensively: an
 * unknown element is skipped, never trusted, and a value that cannot be read leaves the part
 * "unanswered" (the caller then counts it as an error → never clean).
 */

const CODE = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/;
const HOST = /^[a-z0-9._:[\]-]{1,253}$/;
const MAX_CODES = 64;

const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** `message_urls.flags` / `reason_codes`: dotted lower-case codes only. */
export function parseCodes(value: unknown): string[] {
  return asArray(value)
    .filter((code): code is string => typeof code === 'string' && CODE.test(code))
    .slice(0, MAX_CODES);
}

type MapperLookalike = NonNullable<UrlMapInput['lookalike']>;

/**
 * `url_scan_results.lookalike` (≤ 5 `{ rule, targetKind, targetDomain, score, distance }`) plus
 * the row's reason codes. L1/L2/L3/L5 are findings; L4 (mixed script) and L6 (IDN) may be stored
 * either as rule entries or only as codes (`url.mixed_script`, `url.idn`). High confidence =
 * L1, L3, or L2 with score ≥ `highScore` (U7).
 */
export function parseStoredLookalike(
  lookalike: unknown,
  reasonCodes: readonly string[],
  highScore: number,
): MapperLookalike {
  const findings: LookalikeFinding[] = [];
  let mixedScript = reasonCodes.includes('url.mixed_script');
  let idn = reasonCodes.includes('url.idn');
  for (const entry of asArray(lookalike)) {
    if (!isRecord(entry)) continue;
    const rule = entry.rule;
    if (rule === 'L4') {
      mixedScript = true;
      continue;
    }
    if (rule === 'L6') {
      idn = true;
      continue;
    }
    if (rule !== 'L1' && rule !== 'L2' && rule !== 'L3' && rule !== 'L5') continue;
    const targetKind = entry.targetKind;
    if (targetKind !== 'brand' && targetKind !== 'tenant' && targetKind !== 'extra') continue;
    const score =
      typeof entry.score === 'number' && entry.score >= 0 && entry.score <= 1 ? entry.score : 0;
    findings.push({
      rule,
      targetKind,
      targetDomain:
        typeof entry.targetDomain === 'string' && HOST.test(entry.targetDomain)
          ? entry.targetDomain
          : '',
      score,
      distance: typeof entry.distance === 'number' ? entry.distance : null,
    });
    if (findings.length >= 5) break;
  }
  const highConfidence = findings.some(
    (f) => f.rule === 'L1' || f.rule === 'L3' || (f.rule === 'L2' && f.score >= highScore),
  );
  return { findings, mixedScript, idn, highConfidence };
}

type StoredFetch = NonNullable<UrlMapInput['fetch']['result']>;

const isBlockedReason = (value: unknown): value is BlockedReason =>
  typeof value === 'string' && (BLOCKED_REASONS as readonly string[]).includes(value);
const isFetchError = (value: unknown): value is FetchError =>
  typeof value === 'string' && (FETCH_ERRORS as readonly string[]).includes(value);

function parseHops(value: unknown): FetchHop[] {
  const hops: FetchHop[] = [];
  for (const entry of asArray(value).slice(0, 32)) {
    if (!isRecord(entry) || typeof entry.host !== 'string' || !HOST.test(entry.host)) continue;
    const kind =
      entry.kind === 'initial' || entry.kind === 'http' || entry.kind === 'meta'
        ? entry.kind
        : 'http';
    hops.push({
      host: entry.host,
      port: typeof entry.port === 'number' ? entry.port : null,
      status: typeof entry.status === 'number' ? entry.status : null,
      kind,
      blocked: isBlockedReason(entry.blocked) ? entry.blocked : null,
    });
  }
  return hops;
}

/**
 * The scan-time fetch of a stored result, or null when none was attempted. A `blocked` row takes
 * its reason from `fetch_error` (when it is a guard reason) or from the last hop.
 */
export function storedFetch(row: ScanResultRow): StoredFetch | null {
  if (row.fetchStatus === 'not_attempted') return null;
  const hops = parseHops(row.redirectChain);
  const landing = landingSchema.safeParse(row.landing);
  let blockedReason: BlockedReason | null = null;
  if (row.fetchStatus === 'blocked') {
    blockedReason = isBlockedReason(row.fetchError)
      ? row.fetchError
      : (hops.findLast((hop) => hop.blocked !== null)?.blocked ?? 'name');
  }
  return {
    status: row.fetchStatus,
    error:
      row.fetchStatus === 'error'
        ? isFetchError(row.fetchError)
          ? row.fetchError
          : 'connection_error'
        : null,
    blockedReason,
    hops,
    finalUrl: row.finalUrl,
    landing: row.fetchStatus === 'completed' && landing.success ? landing.data : null,
  };
}

/** The chain of a fresh or cached fetch, in the mapper's shape. */
export const fetchForMapper = (result: FetchResult): StoredFetch => ({
  status: result.status,
  error: result.error,
  blockedReason: result.blockedReason,
  hops: result.hops,
  finalUrl: result.finalUrl,
  landing: result.landing,
});

/**
 * `url_dynamic_inspections.signals` holds the event's `signals` object (possibly with the
 * navigation hosts added): only the known keys are read and validated. Unreadable signals of a
 * completed inspection → treated as no dynamic result (null).
 */
export function parseDynamic(
  row: DynamicRow | null,
): { status: 'completed' | 'failed'; signals: DynamicSignals | null } | null {
  if (row === null) return null;
  if (row.status === 'failed') return { status: 'failed', signals: null };
  if (!isRecord(row.signals)) return null;
  const s = row.signals;
  const picked = {
    passwordFields: s.passwordFields,
    forms: s.forms,
    crossOriginFormAction: s.crossOriginFormAction,
    formActionHosts: s.formActionHosts,
    downloadAttempted: s.downloadAttempted,
    blockedRequests: s.blockedRequests,
    requests: s.requests,
    bytes: s.bytes,
    titleBrandMatches: s.titleBrandMatches,
    jsRedirect: s.jsRedirect,
    dialogs: s.dialogs,
  };
  const parsed = dynamicSignalsSchema.safeParse(picked);
  return parsed.success ? { status: 'completed', signals: parsed.data } : null;
}

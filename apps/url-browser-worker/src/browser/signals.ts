import { createHash } from 'node:crypto';
import type { UrlInspectionCompletedV1 } from '@email-gateway/event-contracts';
import { normalizeUrl, registrableDomainOf } from '@email-gateway/url-security';

/**
 * Signal collection helpers of one inspection (U2 `inspection_completed.v1`, U15): counts,
 * booleans, hosts and brand ids only — never page text, a title, a URL (only the final URL's
 * hash and host) or a screenshot. Pure, unit-tested; the Playwright glue is in `inspector.ts`.
 */

export type Signals = UrlInspectionCompletedV1['signals'];
export type Navigation = UrlInspectionCompletedV1['navigations'][number];

export const MAX_NAVIGATIONS = 10;
export const MAX_FORM_ACTION_HOSTS = 5;
export const MAX_TITLE_BRAND_MATCHES = 5;
/** Brand ids the event accepts (`brandId` of event-contracts). */
const BRAND_ID = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const COUNT_MAX = {
  passwordFields: 1000,
  forms: 1000,
  dialogs: 1000,
  blockedRequests: 100_000,
  requests: 100_000,
};

export function emptySignals(): Signals {
  return {
    passwordFields: 0,
    forms: 0,
    crossOriginFormAction: false,
    formActionHosts: [],
    downloadAttempted: false,
    blockedRequests: 0,
    requests: 0,
    bytes: 0,
    titleBrandMatches: [],
    jsRedirect: false,
    dialogs: 0,
  };
}

/** Clamps the counters to the event's bounds. */
export function boundedSignals(signals: Signals): Signals {
  const clamp = (value: number, max: number): number =>
    Math.max(0, Math.min(max, Math.floor(value)));
  return {
    ...signals,
    passwordFields: clamp(signals.passwordFields, COUNT_MAX.passwordFields),
    forms: clamp(signals.forms, COUNT_MAX.forms),
    dialogs: clamp(signals.dialogs, COUNT_MAX.dialogs),
    blockedRequests: clamp(signals.blockedRequests, COUNT_MAX.blockedRequests),
    requests: clamp(signals.requests, COUNT_MAX.requests),
    bytes: Math.max(0, Math.floor(signals.bytes)),
    formActionHosts: [...new Set(signals.formActionHosts)].slice(0, MAX_FORM_ACTION_HOSTS),
    titleBrandMatches: [...new Set(signals.titleBrandMatches)].slice(0, MAX_TITLE_BRAND_MATCHES),
  };
}

/** The ASCII host of an http(s) URL as `URL.hostname` serializes it, else null. */
export function httpHost(url: string): string | null {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    return parsed.hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

/** `finalUrlSha256` (identity form, U5) and `finalHost`, or both null for a non-http(s) page. */
export function finalUrlFields(url: string): {
  finalUrlSha256: string | null;
  finalHost: string | null;
} {
  const result = normalizeUrl(url);
  const host = httpHost(url);
  if (!result.ok || host === null) return { finalUrlSha256: null, finalHost: null };
  return { finalUrlSha256: result.url.sha256, finalHost: host };
}

/**
 * Form signals from the forms' action attributes (resolved against the page): hosts of actions
 * on another host (≤ 5) and whether any action's registrable domain differs from the page's.
 */
export function formSignals(
  pageUrl: string,
  actions: ReadonlyArray<string | null>,
): { crossOriginFormAction: boolean; formActionHosts: string[] } {
  const pageHost = httpHost(pageUrl);
  const pageDomain = pageHost === null ? null : (registrableDomainOf(pageHost) ?? pageHost);
  const hosts: string[] = [];
  let cross = false;
  for (const action of actions) {
    if (!action || !action.trim()) continue;
    let resolved: string;
    try {
      resolved = new URL(action.trim(), pageUrl).href;
    } catch {
      continue;
    }
    const host = httpHost(resolved);
    if (host === null) continue;
    if (host !== pageHost && !hosts.includes(host) && hosts.length < MAX_FORM_ACTION_HOSTS)
      hosts.push(host);
    const domain = registrableDomainOf(host) ?? host;
    if (pageDomain !== null && domain !== pageDomain) cross = true;
  }
  return { crossOriginFormAction: cross, formActionHosts: hosts };
}

export interface TitleBrandEntry {
  id: string;
  label: string;
  official: ReadonlySet<string>;
}

/**
 * Brand ids whose label is a word of the title while the page's registrable domain is not
 * official for the brand (U9). Only ids the event accepts are reported (protected extra domains
 * have dotted ids and are not brands of the event).
 */
export function titleBrandMatches(
  title: string,
  pageUrl: string,
  brands: readonly TitleBrandEntry[],
): string[] {
  const words = new Set(
    title
      .slice(0, 1024)
      .toLowerCase()
      .split(/[^\p{L}\p{N}]+/u)
      .filter(Boolean),
  );
  const host = httpHost(pageUrl);
  const pageDomain = host === null ? null : registrableDomainOf(host);
  const matches: string[] = [];
  for (const brand of brands) {
    if (matches.length >= MAX_TITLE_BRAND_MATCHES) break;
    if (!BRAND_ID.test(brand.id)) continue;
    if (pageDomain !== null && brand.official.has(pageDomain)) continue;
    if (words.has(brand.label.toLowerCase())) matches.push(brand.id);
  }
  return matches;
}

/**
 * Main-frame navigation chain (U15: "navigation chain hosts come from main-frame navigations and
 * redirect responses"): the first request is `initial`, a redirect hop is `http`, a later
 * navigation is `meta` when the previous document had a meta refresh, else `js`.
 */
export class NavigationTracker {
  readonly entries: Navigation[] = [];
  private requests = 0;
  private metaRefreshSeen = false;
  jsRedirect = false;
  lastAt = 0;

  /** A main-frame navigation request. Returns the entry index, or -1 when capped/not http(s). */
  request(url: string, isRedirect: boolean, now = Date.now()): number {
    this.lastAt = now;
    const host = httpHost(url);
    const first = this.requests === 0;
    this.requests += 1;
    let kind: Navigation['kind'];
    if (first) kind = 'initial';
    else if (isRedirect) kind = 'http';
    else if (this.metaRefreshSeen) kind = 'meta';
    else kind = 'js';
    if (kind === 'js') this.jsRedirect = true;
    if (!first && !isRedirect) this.metaRefreshSeen = false;
    if (host === null || this.entries.length >= MAX_NAVIGATIONS) return -1;
    this.entries.push({
      host: host.startsWith('[') || !host.includes(':') ? host : `[${host}]`,
      status: null,
      kind,
    });
    return this.entries.length - 1;
  }

  /** The HTTP status of a recorded navigation. */
  status(index: number, status: number): void {
    const entry = this.entries[index];
    if (entry && Number.isInteger(status) && status >= 100 && status <= 599) entry.status = status;
  }

  /** The current document declares a meta refresh (next navigation is `meta`). */
  sawMetaRefresh(): void {
    this.metaRefreshSeen = true;
  }
}

/** Stable short hash for logs (never the URL). */
export const urlLogId = (url: string): string =>
  createHash('sha256').update(url).digest('hex').slice(0, 12);

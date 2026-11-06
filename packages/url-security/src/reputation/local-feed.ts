import { canonicalIp } from '../normalize/ip';
import { normalizeUrl, registrableDomainOf, sha256Hex } from '../normalize/url';
import {
  clearAnswer,
  errorAnswer,
  THREAT_CATEGORIES,
  type ProviderAnswer,
  type ReputationItem,
  type ReputationKind,
  type ReputationProvider,
  type ThreatCategory,
  type ThreatSeverity,
} from './types';

/**
 * `local_feed` (U6): the platform's own `threat_indicators` rows (`org_scope = 0`, not expired),
 * looked up through an injected query function (no Prisma here): one call per kind with the
 * SHA-256 hashes of the normalized values, in chunks of 500. Never cached (authoritative).
 *
 * Values: url → identity form; domain → the host and every parent down to the registrable
 * domain; ip → canonical text.
 */

export const LOCAL_FEED_VERSION = 'local_feed/1';
export const LOCAL_FEED_CHUNK = 500;

export interface FeedRow {
  valueSha256: string;
  severity: string;
  category: string | null;
}

/** `SELECT value_sha256, severity, category FROM threat_indicators WHERE org_scope = 0 AND …`. */
export type FeedQuery = (
  kind: ReputationKind,
  hashes: readonly string[],
  signal: AbortSignal,
) => Promise<FeedRow[]>;

/** The normalized feed values an item expands to (the hash input of `value_sha256`). */
export function feedValues(item: ReputationItem): string[] {
  switch (item.kind) {
    case 'url': {
      const result = normalizeUrl(item.value);
      return result.ok ? [result.url.identity] : [];
    }
    case 'ip': {
      const ip = canonicalIp(item.value);
      return ip === null ? [] : [ip];
    }
    case 'domain': {
      const host = item.value.toLowerCase().replace(/\.+$/, '');
      const registrable = registrableDomainOf(host);
      if (registrable === null) return host ? [host] : [];
      const values: string[] = [];
      const labels = host.split('.');
      const stop = registrable.split('.').length;
      for (let i = 0; labels.length - i >= stop; i += 1) values.push(labels.slice(i).join('.'));
      return values;
    }
  }
}

const SEVERITY_ORDER: readonly ThreatSeverity[] = ['critical', 'high', 'medium', 'low'];

export class LocalFeedProvider implements ReputationProvider {
  readonly id = 'local_feed';
  readonly version = LOCAL_FEED_VERSION;
  readonly kinds = ['url', 'domain', 'ip'] as const;
  readonly cacheable = false;

  constructor(private readonly query: FeedQuery) {}

  async lookup(items: readonly ReputationItem[], signal: AbortSignal): Promise<ProviderAnswer[]> {
    const expanded = items.map((item) => feedValues(item).map((value) => sha256Hex(value)));
    const rows = new Map<string, FeedRow>();
    try {
      for (const kind of this.kinds) {
        const hashes = [
          ...new Set(
            items.flatMap((item, index) => (item.kind === kind ? (expanded[index] ?? []) : [])),
          ),
        ];
        for (let i = 0; i < hashes.length; i += LOCAL_FEED_CHUNK) {
          const chunk = hashes.slice(i, i + LOCAL_FEED_CHUNK);
          for (const row of await this.query(kind, chunk, signal))
            rows.set(`${kind}:${row.valueSha256}`, row);
        }
      }
    } catch {
      return items.map((item) => errorAnswer(item, 'query_failed'));
    }
    return items.map((item, index) => {
      const hits = (expanded[index] ?? [])
        .map((hash) => rows.get(`${item.kind}:${hash}`))
        .filter((row): row is FeedRow => row !== undefined);
      if (hits.length === 0) return clearAnswer(item);
      // Most severe hit; a severity outside the enum counts as medium (never dropped).
      const severity: ThreatSeverity =
        SEVERITY_ORDER.find((s) => hits.some((h) => h.severity === s)) ?? 'medium';
      const hit = hits.find((h) => h.severity === severity) ?? hits[0];
      const category = (THREAT_CATEGORIES as readonly string[]).includes(hit?.category ?? '')
        ? (hit?.category as ThreatCategory)
        : null;
      return {
        kind: item.kind,
        value: item.value,
        status: 'listed',
        category,
        severity,
        detail: 'feed',
      };
    });
  }
}

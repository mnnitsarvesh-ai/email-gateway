import type { MessageVerdict } from '@email-gateway/database';

/**
 * Top attacked domains (step 7.1, docs/plan/steps/20-admin-portal.md §3.3): inbound messages per
 * tenant domain with a threat verdict. Pure tallying and ranking; the SQL and the name lookup are
 * in ReportsRepository.
 */

/** Final verdicts that count as a threat in this report. */
export const THREAT_VERDICTS = Object.freeze([
  'spam',
  'phishing',
  'malware',
  'bec',
  'suspicious',
] as const satisfies readonly MessageVerdict[]);
export type ThreatVerdict = (typeof THREAT_VERDICTS)[number];

/** `limit` of `GET /reports/top-domains`. */
export const TOP_DOMAINS_DEFAULT_LIMIT = 10;
export const TOP_DOMAINS_MAX_LIMIT = 25;

export interface DomainVerdictCount {
  /** Internal `domains.id`; `null` = the message has no tenant domain. */
  domainId: bigint | null;
  verdict: MessageVerdict | null;
  count: number;
}

export interface DomainTally {
  domainId: bigint;
  inbound: number;
  threats: number;
  verdicts: Record<ThreatVerdict, number>;
}

export interface DomainTallies {
  /** Domains with at least one threat, unordered. */
  domains: DomainTally[];
  /** Messages without a domain (`domain_id IS NULL`). */
  unattributed: { inbound: number; threats: number };
}

const isThreat = (verdict: MessageVerdict | null): verdict is ThreatVerdict =>
  verdict !== null && (THREAT_VERDICTS as readonly string[]).includes(verdict);

const zeroVerdicts = (): Record<ThreatVerdict, number> =>
  Object.fromEntries(THREAT_VERDICTS.map((v) => [v, 0])) as Record<ThreatVerdict, number>;

/** Sums the (domain, verdict) counts per domain; keeps domains with threats only. */
export function tallyDomains(rows: readonly DomainVerdictCount[]): DomainTallies {
  const byDomain = new Map<bigint, DomainTally>();
  const unattributed = { inbound: 0, threats: 0 };
  for (const row of rows) {
    if (row.domainId === null) {
      unattributed.inbound += row.count;
      if (isThreat(row.verdict)) unattributed.threats += row.count;
      continue;
    }
    let tally = byDomain.get(row.domainId);
    if (!tally) {
      tally = { domainId: row.domainId, inbound: 0, threats: 0, verdicts: zeroVerdicts() };
      byDomain.set(row.domainId, tally);
    }
    tally.inbound += row.count;
    if (isThreat(row.verdict)) {
      tally.threats += row.count;
      tally.verdicts[row.verdict] += row.count;
    }
  }
  return { domains: [...byDomain.values()].filter((d) => d.threats > 0), unattributed };
}

const byCounts = (a: DomainTally, b: DomainTally): number =>
  b.threats - a.threats || b.inbound - a.inbound;

/**
 * The domains that can appear in the top `limit`: the first `limit` by threats and inbound,
 * plus every domain tied with the last of them (the name decides ties, and names are resolved
 * only for these candidates).
 */
export function topDomainCandidates(domains: readonly DomainTally[], limit: number): DomainTally[] {
  const sorted = [...domains].sort(byCounts);
  if (sorted.length <= limit) return sorted;
  const last = sorted[limit - 1]!;
  return sorted.filter((d, i) => i < limit || byCounts(d, last) === 0);
}

/** Final order: threats desc, inbound desc, name asc (code-point order); top `limit`. */
export function rankTopDomains<T extends DomainTally & { name: string }>(
  candidates: readonly T[],
  limit: number,
): T[] {
  return [...candidates]
    .sort((a, b) => byCounts(a, b) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .slice(0, limit);
}

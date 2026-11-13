import { describe, expect, it } from 'vitest';
import {
  type DomainTally,
  rankTopDomains,
  tallyDomains,
  THREAT_VERDICTS,
  topDomainCandidates,
} from './top-domains';

const tally = (domainId: bigint, threats: number, inbound: number): DomainTally => ({
  domainId,
  inbound,
  threats,
  verdicts: { spam: threats, phishing: 0, malware: 0, bec: 0, suspicious: 0 },
});

describe('tallyDomains', () => {
  it('sums inbound and threat verdicts per domain, NULL domain_id → unattributed', () => {
    const result = tallyDomains([
      { domainId: 1n, verdict: 'clean', count: 10 },
      { domainId: 1n, verdict: 'spam', count: 3 },
      { domainId: 1n, verdict: 'phishing', count: 2 },
      { domainId: 1n, verdict: null, count: 1 },
      { domainId: 2n, verdict: 'clean', count: 7 },
      { domainId: 2n, verdict: 'bulk', count: 4 },
      { domainId: 2n, verdict: 'dlp_violation', count: 1 },
      { domainId: 3n, verdict: 'malware', count: 1 },
      { domainId: null, verdict: 'clean', count: 5 },
      { domainId: null, verdict: 'suspicious', count: 2 },
    ]);
    expect(THREAT_VERDICTS).toEqual(['spam', 'phishing', 'malware', 'bec', 'suspicious']);
    // Domain 2 has no threat verdict (bulk and dlp_violation are not threats here).
    expect(result.domains.map((d) => d.domainId).sort()).toEqual([1n, 3n]);
    const one = result.domains.find((d) => d.domainId === 1n)!;
    expect(one).toEqual({
      domainId: 1n,
      inbound: 16,
      threats: 5,
      verdicts: { spam: 3, phishing: 2, malware: 0, bec: 0, suspicious: 0 },
    });
    expect(result.unattributed).toEqual({ inbound: 7, threats: 2 });
  });
});

describe('topDomainCandidates / rankTopDomains', () => {
  it('orders by threats desc, inbound desc, then name asc, and keeps boundary ties for naming', () => {
    const domains = [
      tally(1n, 5, 10),
      tally(2n, 9, 9),
      tally(3n, 5, 10),
      tally(4n, 5, 10),
      tally(5n, 1, 100),
      tally(6n, 5, 12),
    ];
    const candidates = topDomainCandidates(domains, 3);
    // 2 (9), 6 (5/12), then three tied at 5/10: all three are candidates.
    expect(candidates.map((d) => d.domainId)).toEqual([2n, 6n, 1n, 3n, 4n]);
    const names: Record<string, string> = {
      '1': 'c.test',
      '2': 'z.test',
      '3': 'a.test',
      '4': 'b.test',
      '6': 'y.test',
    };
    const ranked = rankTopDomains(
      candidates.map((d) => ({ ...d, name: names[d.domainId.toString()]! })),
      3,
    );
    expect(ranked.map((d) => d.name)).toEqual(['z.test', 'y.test', 'a.test']);
  });

  it('returns everything when there are fewer domains than the limit', () => {
    expect(topDomainCandidates([tally(1n, 1, 1)], 10)).toHaveLength(1);
    expect(topDomainCandidates([], 10)).toEqual([]);
  });
});

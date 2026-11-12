import { BadRequestException, Injectable } from '@nestjs/common';
import { AuditService } from '../../audit/audit.service';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import type { ClientContext } from '../auth/services/session.service';
import { normalizeLookup } from './domain/lookup-value';
import { ThreatIntelligenceRepository } from './threat-intelligence.repository';
import type { ThreatLookupQuery, ThreatLookupResponse } from './threat-intelligence.schemas';

type Match = ThreatLookupResponse['matches'][number];

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 } as const;

/**
 * `GET /threat-intelligence/lookup` (step 6.1 §3.3, §8): is a value known to the platform's
 * threat intelligence as the engines use it? Normalized with the engines' functions, matched by
 * `value_sha256` against platform `threat_indicators` (not expired) and, for `sha256`, the
 * `malware_signatures` catalogue (not expired). The answer carries severities, categories and
 * dates only (never the analyst reason, user ids, sources' internal names or the value). Every
 * lookup is audited (`threat_intel.looked_up` with the value's SHA-256 and the result), because a
 * lookup is an oracle (§8); invalid values are `400 validation_failed`.
 */
@Injectable()
export class ThreatIntelligenceService {
  constructor(
    private readonly repository: ThreatIntelligenceRepository,
    private readonly audit: AuditService,
  ) {}

  async lookup(
    principal: Principal,
    scope: TenantScope,
    query: ThreatLookupQuery,
    client: ClientContext,
    now: Date = new Date(),
  ): Promise<ThreatLookupResponse> {
    const normalized = normalizeLookup(query.type, query.value);
    if (!normalized.ok) {
      throw new BadRequestException([`value: not a valid ${query.type} (${normalized.reason})`]);
    }
    const { lookup } = normalized;
    const [indicators, signature] = await Promise.all([
      this.repository.indicators(lookup.indicatorType, lookup.matchHashes, now),
      lookup.type === 'sha256' ? this.repository.signature(lookup.value, now) : null,
    ]);
    const matches: Match[] = indicators.map((row) => ({
      source: 'platform_indicator',
      severity: row.severity,
      category: row.category,
      firstSeenAt: row.firstSeenAt.toISOString(),
      lastSeenAt: row.lastSeenAt.toISOString(),
      expiresAt: row.expiresAt?.toISOString() ?? null,
    }));
    if (signature) {
      matches.push({
        source: 'hash_catalog',
        severity: signature.severity,
        // The catalogue has no category; its severity decides malicious vs suspicious (A17).
        category: null,
        firstSeenAt: signature.firstSeenAt.toISOString(),
        lastSeenAt: signature.lastSeenAt.toISOString(),
        expiresAt: signature.expiresAt?.toISOString() ?? null,
      });
    }
    matches.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
    const response: ThreatLookupResponse = {
      type: lookup.type,
      valueSha256: lookup.valueSha256,
      known: matches.length > 0,
      matches,
    };
    await this.audit.record({
      organizationId: scope.organizationId,
      actor: this.audit.actorFrom(principal),
      action: 'threat_intel.looked_up',
      resourceType: 'threat_intelligence',
      resourceId: null,
      sourceIp: client.ip,
      metadata: {
        type: lookup.type,
        valueSha256: lookup.valueSha256,
        known: response.known,
        matchCount: matches.length,
      },
    });
    return response;
  }
}

import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { IndicatorType, Severity, ThreatCategory } from '@email-gateway/database';
import { InconsistentReadError } from '../../http/listing/echo-check';

export interface IndicatorMatchRow {
  valueSha256: string;
  severity: Severity;
  category: ThreatCategory | null;
  firstSeenAt: Date;
  lastSeenAt: Date;
  expiresAt: Date | null;
}

export interface SignatureMatchRow {
  severity: Severity;
  firstSeenAt: Date;
  lastSeenAt: Date;
  expiresAt: Date | null;
}

/** At most this many keys per lookup (a domain expands to itself and its parents). */
export const MAX_LOOKUP_HASHES = 16;

/**
 * Platform threat intelligence as the engines read it (step 6.1 §3.3), on the replica:
 * `threat_indicators` with `org_scope = 0` (platform rows, `organization_id` NULL), of one
 * indicator type, not expired — the predicate of the URL engine's local feed and the
 * click-service — and `malware_signatures` not expired (the attachment engine's hash catalogue).
 * Tenant-owned indicator rows are never read (no engine consumes them). Analyst reasons and user
 * ids are not selected. Every row is echo-checked (D15).
 */
@Injectable()
export class ThreatIntelligenceRepository {
  constructor(private readonly reader: PrismaReadService) {}

  async indicators(
    indicatorType: IndicatorType,
    hashes: readonly string[],
    now: Date,
  ): Promise<IndicatorMatchRow[]> {
    if (hashes.length === 0) return [];
    if (hashes.length > MAX_LOOKUP_HASHES) throw new Error('too many lookup hashes');
    const rows = await this.reader.client.threatIndicator.findMany({
      where: {
        orgScope: 0n,
        indicatorType,
        valueSha256: { in: [...hashes] },
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      select: {
        organizationId: true,
        orgScope: true,
        indicatorType: true,
        valueSha256: true,
        severity: true,
        category: true,
        firstSeenAt: true,
        lastSeenAt: true,
        expiresAt: true,
      },
      orderBy: { id: 'asc' },
    });
    const requested = new Set(hashes);
    for (const row of rows) {
      if (
        row.organizationId !== null ||
        (row.orgScope !== null && row.orgScope !== 0n) ||
        row.indicatorType !== indicatorType ||
        !requested.has(row.valueSha256) ||
        (row.expiresAt !== null && row.expiresAt.getTime() <= now.getTime())
      ) {
        throw new InconsistentReadError('threat_indicators');
      }
    }
    return rows.map((row) => ({
      valueSha256: row.valueSha256,
      severity: row.severity,
      category: row.category,
      firstSeenAt: row.firstSeenAt,
      lastSeenAt: row.lastSeenAt,
      expiresAt: row.expiresAt,
    }));
  }

  async signature(sha256: string, now: Date): Promise<SignatureMatchRow | null> {
    const row = await this.reader.client.malwareSignature.findFirst({
      where: { sha256, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
      select: {
        sha256: true,
        severity: true,
        firstSeenAt: true,
        lastSeenAt: true,
        expiresAt: true,
      },
    });
    if (row === null) return null;
    if (
      row.sha256 !== sha256 ||
      (row.expiresAt !== null && row.expiresAt.getTime() <= now.getTime())
    ) {
      throw new InconsistentReadError('malware_signatures');
    }
    return {
      severity: row.severity,
      firstSeenAt: row.firstSeenAt,
      lastSeenAt: row.lastSeenAt,
      expiresAt: row.expiresAt,
    };
  }
}

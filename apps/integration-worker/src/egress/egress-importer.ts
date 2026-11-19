import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import {
  diffEgressSets,
  EgressImportError,
  type IntegrationProvider,
  parseEgressImport,
} from '@email-gateway/provider-integrations';
import { systemAudit } from '../shared/db';

export interface EgressImportRequest {
  provider: IntegrationProvider;
  /** The parsed JSON document (`provider-egress-import/1`). */
  document: unknown;
  /** Where the operator took the data from (stored, never fetched). */
  source: string;
  /** The provider's publication date of the data. */
  publishedAt: Date;
  /** Operator name for the audit row (`--operator`). */
  operator: string;
  /** Accept a set that removes more than 50 % of the active ranges. */
  force: boolean;
  dryRun?: boolean;
  now?: Date;
}

export interface EgressImportResult {
  outcome: 'imported' | 'unchanged' | 'dry_run';
  provider: IntegrationProvider;
  version: number | null;
  previousVersion: number | null;
  rangeCount: number;
  added: number;
  removed: number;
  removedFraction: number;
  sha256: string;
  duplicatesRemoved: number;
}

const OPERATOR = /^[A-Za-z0-9._@-]{1,64}$/;

/**
 * Operator egress-range import (D11 CLI, ADR-0078; no automatic Internet fetch, §15 Q8):
 * validates the document (CIDR syntax, public ranges only, ≤ 5 000 entries, IPv4 ≥ /8, IPv6 ≥
 * /16; `parseEgressImport`), refuses a set that removes more than 50 % of the active ranges
 * unless `force`, and in ONE writer transaction creates the next `provider_egress_range_sets`
 * version with its ranges, supersedes the previous active set and audits
 * `integration.egress_ranges_imported` (actor system, platform row). An identical set (same
 * SHA-256) is a no-op. The smtp-adapter loads the new set within `PROVIDER_EGRESS_CACHE_SECONDS`.
 */
export async function importEgressRanges(
  writer: PrismaClient,
  request: EgressImportRequest,
): Promise<EgressImportResult> {
  const now = request.now ?? new Date();
  if (!OPERATOR.test(request.operator)) {
    throw new EgressImportError('--operator must be 1-64 characters [A-Za-z0-9._@-]');
  }
  const source = request.source.trim();
  if (source.length === 0 || source.length > 512 || /[\r\n]/.test(source)) {
    throw new EgressImportError('--source must be 1-512 characters on one line');
  }
  if (Number.isNaN(request.publishedAt.getTime())) {
    throw new EgressImportError('--published-at must be an ISO 8601 date');
  }
  if (request.publishedAt.getTime() > now.getTime() + 86_400_000) {
    throw new EgressImportError('--published-at must not be in the future');
  }
  const parsed = parseEgressImport(request.document, { expectedProvider: request.provider });

  return writer.$transaction(async (tx) => {
    // Serializes concurrent imports of one provider (the active set row is locked).
    const sets = await tx.$queryRaw<
      Array<{ id: bigint; version: number; status: string; sha256: string }>
    >`
      SELECT id, version, status, sha256 FROM provider_egress_range_sets
       WHERE provider = ${request.provider} ORDER BY version DESC FOR UPDATE`;
    const active = sets.find((s) => s.status === 'active') ?? null;
    const activeCidrs = active
      ? (
          await tx.providerEgressRange.findMany({
            where: { setId: BigInt(active.id) },
            select: { cidr: true },
          })
        ).map((r) => r.cidr)
      : [];
    const diff = diffEgressSets(activeCidrs, parsed.cidrs);
    const base = {
      provider: request.provider,
      previousVersion: active ? Number(active.version) : null,
      rangeCount: parsed.cidrs.length,
      added: diff.added.length,
      removed: diff.removed.length,
      removedFraction: Math.round(diff.removedFraction * 1000) / 1000,
      sha256: parsed.sha256,
      duplicatesRemoved: parsed.duplicatesRemoved,
    };
    if (active && active.sha256 === parsed.sha256 && diff.unchanged) {
      return { ...base, outcome: 'unchanged' as const, version: Number(active.version) };
    }
    if (diff.requiresForce && !request.force) {
      throw new EgressImportError(
        `the new set removes ${Math.round(diff.removedFraction * 100)} % of the active ranges; re-run with --force if this is intended`,
      );
    }
    const version = (sets[0] ? Number(sets[0].version) : 0) + 1;
    if (request.dryRun) return { ...base, outcome: 'dry_run' as const, version };
    if (active) {
      await tx.providerEgressRangeSet.update({
        where: { id: BigInt(active.id) },
        data: { status: 'superseded' },
      });
    }
    await tx.providerEgressRangeSet.create({
      data: {
        provider: request.provider,
        version,
        status: 'active',
        source,
        publishedAt: request.publishedAt,
        sha256: parsed.sha256,
        rangeCount: parsed.cidrs.length,
        importedBy: request.operator,
        importedAt: now,
        ranges: {
          createMany: {
            data: parsed.ranges.map((r) => ({
              provider: request.provider,
              cidr: r.cidr,
              ipVersion: r.ipVersion,
              rangeStart: Uint8Array.from(r.rangeStart),
              rangeEnd: Uint8Array.from(r.rangeEnd),
            })),
          },
        },
      },
      select: { id: true },
    });
    await systemAudit(tx, {
      organizationId: null,
      action: 'integration.egress_ranges_imported',
      resourceId: null,
      correlationId: randomUUID(),
      metadata: {
        ...base,
        version,
        source,
        publishedAt: request.publishedAt.toISOString(),
        operator: request.operator,
        forced: diff.requiresForce,
      },
      at: now,
    });
    return { ...base, outcome: 'imported' as const, version };
  });
}

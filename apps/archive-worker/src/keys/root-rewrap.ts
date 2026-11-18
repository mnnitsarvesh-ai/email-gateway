import {
  type ArchiveRootKeyProvider,
  unwrapTenantKey,
  wrapTenantKey,
} from '@email-gateway/archive';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { big, orgFilter, systemAudit } from '../shared/db';
import { errorFields } from '../shared/errors';

/** Leader lock of the root re-wrap (A9). */
export const ROOT_REWRAP_LOCK = 'eg:archive-root-rewrap';
export const ROOT_REWRAP_ACTION = 'archive.root_key_rewrapped';
const PENDING_CAP = 1_000_000;

export interface RootRewrapReport {
  pending: number;
  rewrapped: number;
  failed: number;
  skipped: number;
}

/**
 * Root key re-wrap (A9, lifecycle role, leader `GET_LOCK('eg:archive-root-rewrap')`): while
 * `ARCHIVE_ROOT_KEY_PREVIOUS_ID` is configured, every `archive_encryption_keys` row still wrapped
 * under it is unwrapped (previous key) and wrapped under the current key in bounded batches, each
 * row with `UPDATE … WHERE id = ? AND root_key_id = ?` (a concurrent change wins). Gauge
 * `archive_root_rewrap_pending`; one system audit row `archive.root_key_rewrapped` per run that
 * changed or failed something (counts only, never key material).
 */
export class RootRewrapJob {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      provider: ArchiveRootKeyProvider;
      metrics: ArchiveMetrics;
      logger: Logger;
      batchSize: number;
      maxBatches?: number;
      organizationIds?: readonly bigint[];
    },
  ) {}

  async runOnce(): Promise<RootRewrapReport> {
    const report: RootRewrapReport = { pending: 0, rewrapped: 0, failed: 0, skipped: 0 };
    const previous = this.options.provider.previousKeyId;
    const current = this.options.provider.currentKeyId;
    if (previous === null) {
      this.options.metrics.rootRewrapPending.set(await this.pending(null));
      return report;
    }
    const failedIds = new Set<string>();
    const maxBatches = this.options.maxBatches ?? 20;
    for (let batch = 0; batch < maxBatches; batch += 1) {
      const rows = await this.prisma.$queryRaw<
        Array<{
          id: bigint | number;
          organization_id: bigint | number;
          version: number | bigint;
          wrapped_key: string | null;
        }>
      >`
        SELECT id, organization_id, version, wrapped_key FROM archive_encryption_keys
        WHERE root_key_id = ${previous} AND wrapped_key IS NOT NULL
          ${orgFilter('organization_id', this.options.organizationIds)}
          ${failedIds.size > 0 ? Prisma.sql`AND id NOT IN (${Prisma.join([...failedIds].map((i) => BigInt(i)))})` : Prisma.empty}
        ORDER BY id LIMIT ${this.options.batchSize}`;
      if (rows.length === 0) break;
      for (const row of rows) {
        const ids = { organizationId: big(row.organization_id), version: Number(row.version) };
        try {
          const opened = await unwrapTenantKey(this.options.provider, row.wrapped_key!, ids);
          const rewrapped = await wrapTenantKey(this.options.provider, ids, opened.key);
          opened.key.fill(0);
          const changed = await this.prisma.$executeRaw`
            UPDATE archive_encryption_keys SET wrapped_key = ${rewrapped}, root_key_id = ${current}
            WHERE id = ${big(row.id)} AND root_key_id = ${previous}`;
          if (changed === 1) report.rewrapped += 1;
          else report.skipped += 1;
        } catch (error) {
          report.failed += 1;
          failedIds.add(big(row.id).toString());
          this.options.logger.warn(
            { job: 'root-rewrap', ...errorFields(error) },
            'tenant key re-wrap failed; retried next run',
          );
        }
      }
      if (rows.length < this.options.batchSize) break;
    }
    report.pending = await this.pending(previous);
    this.options.metrics.rootRewrapPending.set(report.pending);
    if (report.rewrapped > 0 || report.failed > 0) {
      await systemAudit(this.prisma, {
        organizationId: null,
        action: ROOT_REWRAP_ACTION,
        resourceType: 'archive_key',
        resourceId: null,
        correlationId: `archive-root-rewrap:${new Date().toISOString()}`,
        metadata: {
          fromRootKeyId: previous,
          toRootKeyId: current,
          rewrapped: report.rewrapped,
          failed: report.failed,
          skipped: report.skipped,
          pending: report.pending,
        },
      });
    }
    return report;
  }

  private async pending(previous: string | null): Promise<number> {
    if (previous === null) return 0;
    const [row] = await this.prisma.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COUNT(*) AS n FROM (
        SELECT 1 FROM archive_encryption_keys
        WHERE root_key_id = ${previous} AND wrapped_key IS NOT NULL
          ${orgFilter('organization_id', this.options.organizationIds)}
        LIMIT ${PENDING_CAP}
      ) AS bounded`;
    return Number(row?.n ?? 0);
  }
}

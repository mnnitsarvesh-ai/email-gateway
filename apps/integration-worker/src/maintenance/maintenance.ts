import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  INTEGRATION_PROVIDERS,
  type ProviderGrantStore,
} from '@email-gateway/provider-integrations';
import type { IntegrationMetrics } from '../metrics/integration-metrics';
import type { ValidationRunner } from '../tasks/validation-runner';
import { num, orgFilter, systemAudit } from '../shared/db';
import { errorFields } from '../shared/errors';

/** Retention of §3.3 (Q14). */
export const RETENTION = Object.freeze({
  consentStateGraceHours: 24,
  validationRunDays: 180,
  validationRunsPerConnection: 50,
  probeObservationDays: 30,
  healthEventDays: 365,
  relayCounterDays: 35,
  supersededEgressSetsPerProvider: 5,
});

export const MAINTENANCE_BATCH = 1_000;
/** Re-encryption batch (ADR-0077 decision 6). */
export const REENCRYPT_BATCH = 100;
export const MAINTENANCE_LOCK = 'eg:integration:maintenance';

const DAY_MS = 86_400_000;

export interface MaintenanceSummary {
  deleted: Record<string, number>;
  probesExpired: number;
  reencrypted: { scanned: number; reencrypted: number; failed: number; skipped: number };
  sharedNetworks: number;
}

/**
 * D11 `maintenance` role (leader-elected `GET_LOCK('eg:integration:maintenance')`): expires
 * consent states and probe addresses, purges per §3.3, re-encrypts credentials still under the
 * previous key after a rotation (batches of 100, counts audited), and computes the platform
 * gauges (`provider_connections`, outbound-active connections, `smtp_connector_shared_provider_
 * networks`, egress set age). Every step is idempotent and bounded.
 */
export class Maintenance {
  constructor(
    private readonly writer: PrismaClient,
    private readonly options: {
      grants: ProviderGrantStore;
      validations: ValidationRunner;
      metrics: IntegrationMetrics;
      logger: Logger;
      now: () => Date;
      hasPreviousKey: boolean;
      organizationIds?: readonly bigint[];
    },
  ) {}

  async runOnce(): Promise<MaintenanceSummary> {
    const summary: MaintenanceSummary = {
      deleted: {},
      probesExpired: 0,
      reencrypted: { scanned: 0, reencrypted: 0, failed: 0, skipped: 0 },
      sharedNetworks: 0,
    };
    const step = async (name: string, fn: () => Promise<void>) => {
      try {
        await fn();
      } catch (error) {
        this.options.logger.warn(
          { step: name, ...errorFields(error) },
          'integration maintenance step failed',
        );
      }
    };
    await step('probe_expiry', async () => {
      summary.probesExpired = await this.options.validations.expireProbes(MAINTENANCE_BATCH);
    });
    await step('retention', async () => {
      summary.deleted = await this.retention();
    });
    await step('reencrypt', async () => {
      summary.reencrypted = await this.reencrypt();
    });
    await step('gauges', async () => {
      summary.sharedNetworks = await this.gauges();
    });
    return summary;
  }

  /** §3.3 retention; returns rows deleted per table. */
  async retention(): Promise<Record<string, number>> {
    const now = this.options.now().getTime();
    const only = this.options.organizationIds;
    const out: Record<string, number> = {};
    const count = (table: string, n: number) => {
      out[table] = (out[table] ?? 0) + n;
      if (n > 0) this.options.metrics.maintenanceDeleted.inc({ table }, n);
    };
    const orgWhere = only ? { organizationId: { in: [...only] } } : {};

    count(
      'provider_consent_states',
      await this.deleteBatches(
        () =>
          this.writer.$executeRaw`DELETE FROM provider_consent_states
          WHERE expires_at < ${new Date(now - RETENTION.consentStateGraceHours * 3_600_000)}
          ${orgFilter('organization_id', only)} LIMIT ${MAINTENANCE_BATCH}`,
      ),
    );
    count(
      'provider_probe_observations',
      await this.deleteBatches(
        () =>
          this.writer.$executeRaw`DELETE FROM provider_probe_observations
          WHERE received_at < ${new Date(now - RETENTION.probeObservationDays * DAY_MS)}
          ${orgFilter('organization_id', only)} LIMIT ${MAINTENANCE_BATCH}`,
      ),
    );
    count(
      'provider_health_events',
      await this.deleteBatches(
        () =>
          this.writer.$executeRaw`DELETE FROM provider_health_events
          WHERE created_at < ${new Date(now - RETENTION.healthEventDays * DAY_MS)}
          ${orgFilter('organization_id', only)} LIMIT ${MAINTENANCE_BATCH}`,
      ),
    );
    count(
      'provider_relay_counters',
      await this.deleteBatches(
        () =>
          this.writer.$executeRaw`DELETE FROM provider_relay_counters
          WHERE hour_start < ${new Date(now - RETENTION.relayCounterDays * DAY_MS)}
          ${orgFilter('organization_id', only)} LIMIT ${MAINTENANCE_BATCH}`,
      ),
    );
    // Validation runs: 180 days for finished runs, and at most the newest 50 per connection.
    const finished = ['passed', 'warning', 'failed', 'expired', 'cancelled'] as const;
    const old = await this.writer.providerValidationRun.deleteMany({
      where: {
        ...orgWhere,
        status: { in: [...finished] },
        createdAt: { lt: new Date(now - RETENTION.validationRunDays * DAY_MS) },
      },
    });
    let runs = old.count;
    const crowded = await this.writer.$queryRaw<Array<{ connection_id: bigint }>>`
      SELECT connection_id FROM provider_validation_runs
       WHERE 1 = 1 ${orgFilter('organization_id', only)}
       GROUP BY connection_id HAVING COUNT(*) > ${RETENTION.validationRunsPerConnection}`;
    for (const row of crowded) {
      const keep = await this.writer.providerValidationRun.findMany({
        where: { connectionId: BigInt(row.connection_id) },
        select: { id: true },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take: RETENTION.validationRunsPerConnection,
      });
      const removed = await this.writer.providerValidationRun.deleteMany({
        where: {
          connectionId: BigInt(row.connection_id),
          status: { in: [...finished] },
          id: { notIn: keep.map((k) => k.id) },
        },
      });
      runs += removed.count;
    }
    count('provider_validation_runs', runs);
    // Superseded egress sets: the newest 5 per provider (platform data; not organization-scoped).
    if (!only) {
      let sets = 0;
      for (const provider of INTEGRATION_PROVIDERS) {
        const keep = await this.writer.providerEgressRangeSet.findMany({
          where: { provider, status: 'superseded' },
          select: { id: true },
          orderBy: { version: 'desc' },
          take: RETENTION.supersededEgressSetsPerProvider,
        });
        const removed = await this.writer.providerEgressRangeSet.deleteMany({
          where: { provider, status: 'superseded', id: { notIn: keep.map((k) => k.id) } },
        });
        sets += removed.count;
      }
      count('provider_egress_range_sets', sets);
    }
    return out;
  }

  private async deleteBatches(batch: () => Promise<number>): Promise<number> {
    let total = 0;
    for (let i = 0; i < 100; i += 1) {
      const n = await batch();
      total += n;
      if (n < MAINTENANCE_BATCH) break;
    }
    return total;
  }

  /** Key rotation (ADR-0077): re-encrypts every grant still under the previous key. */
  async reencrypt(): Promise<MaintenanceSummary['reencrypted']> {
    const total = { scanned: 0, reencrypted: 0, failed: 0, skipped: 0 };
    if (!this.options.hasPreviousKey) return total;
    for (let i = 0; i < 1_000; i += 1) {
      const batch = await this.options.grants.reencryptBatch({ limit: REENCRYPT_BATCH });
      total.scanned += batch.scanned;
      total.reencrypted += batch.reencrypted;
      total.failed += batch.failed;
      total.skipped += batch.skipped;
      if (batch.reencrypted === 0) break;
    }
    for (const result of ['reencrypted', 'failed', 'skipped'] as const) {
      if (total[result] > 0)
        this.options.metrics.credentialsReencrypted.inc({ result }, total[result]);
    }
    if (total.reencrypted > 0 || total.failed > 0) {
      await systemAudit(this.writer, {
        organizationId: null,
        action: 'integration.credentials_reencrypted',
        resourceId: null,
        correlationId: randomUUID(),
        metadata: { ...total },
        at: this.options.now(),
      });
      this.options.logger.info(
        { ...total },
        'provider credentials re-encrypted under the current key',
      );
    }
    return total;
  }

  /** Platform gauges (leader only); returns the shared-network count. */
  async gauges(): Promise<number> {
    const metrics = this.options.metrics;
    const now = this.options.now().getTime();
    const rows = await this.writer.$queryRaw<
      Array<{ provider: string; status: string; health_status: string; n: bigint | number }>
    >`SELECT provider, status, health_status, COUNT(*) AS n FROM provider_connections
       GROUP BY provider, status, health_status`;
    metrics.connections.reset();
    for (const r of rows) {
      metrics.connections.set(
        { provider: r.provider, status: r.status, health: r.health_status },
        num(r.n),
      );
    }
    const outbound = await this.writer.$queryRaw<Array<{ provider: string; n: bigint | number }>>`
      SELECT provider, COUNT(*) AS n FROM provider_connections
       WHERE status = 'active' AND outbound_mode = 'active' GROUP BY provider`;
    for (const provider of INTEGRATION_PROVIDERS) {
      metrics.outboundActive.set(
        { provider },
        num(outbound.find((o) => o.provider === provider)?.n ?? 0),
      );
    }
    for (const provider of INTEGRATION_PROVIDERS) {
      const set = await this.writer.providerEgressRangeSet.findFirst({
        where: { provider, status: 'active' },
        select: { publishedAt: true, importedAt: true },
        orderBy: { version: 'desc' },
      });
      if (set) {
        metrics.egressSetAge.set(
          { provider },
          Math.max(0, (now - (set.publishedAt ?? set.importedAt).getTime()) / 1000),
        );
      } else {
        metrics.egressSetAge.remove({ provider });
      }
    }
    // D7.6: active source_ip connector networks overlapping an active provider egress range.
    const [shared] = await this.writer.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COUNT(DISTINCT n.id) AS n
        FROM smtp_connector_networks n
        JOIN smtp_connectors c ON c.id = n.connector_id
        JOIN provider_egress_ranges r ON r.ip_version = n.ip_version
        JOIN provider_egress_range_sets s ON s.id = r.set_id AND s.status = 'active'
       WHERE c.status = 'active' AND c.auth_type = 'source_ip'
         AND n.range_start <= r.range_end AND r.range_start <= n.range_end`;
    const count = num(shared?.n);
    metrics.sharedNetworks.set(count);
    return count;
  }

  /** Zeroes the leader-written gauges (this replica lost or never had leadership). */
  resetGauges(): void {
    const metrics = this.options.metrics;
    metrics.connections.reset();
    metrics.outboundActive.reset();
    metrics.egressSetAge.reset();
    metrics.sharedNetworks.set(0);
  }
}

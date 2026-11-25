import type { AtoStore } from '@email-gateway/ato-detection';
import { Prisma, type AtoProviderIntegration, type PrismaClient } from '@email-gateway/database';
import {
  computeEffectiveCapabilities,
  computeHealthStatus,
  directoryRefHash,
  GOOGLE_DECLARED_CAPABILITIES,
  MICROSOFT_DECLARED_CAPABILITIES,
  STREAM_ROLES,
  PROVIDER_STREAMS,
  type AtoProviderKind,
  type IdpAdapter,
  type IntegrationHealth,
  type ProbeReport,
  type ProviderConnectionView,
  type StreamRuntimeState,
} from '@email-gateway/idp-adapters';
import type { Logger } from '@email-gateway/logger';
import type { IdpMetrics } from '../metrics/idp-metrics';
import { atoEnabled, type OrgContextCache } from '../reads/org-context';
import { IDP_FEATURE_OFF_RETRY_MS } from './stream-runner';
import { big, orgFilter, type AtoDb, type Tx } from '../shared/db';
import { errorCode, errorFields } from '../shared/errors';
import { bindingSettingsOf, type IdpRuntime } from './idp-runtime';
import {
  deferDelayMs,
  IDP_WRITE_ATTEMPTS,
  isTransientDbFailure,
  withTransientRetry,
  type RetrySleep,
} from './transient';

/** Integrations probed per pass. */
export const IDP_PROBE_BATCH = 10;
/** Budget of one probe (several provider reads). */
export const IDP_PROBE_TIMEOUT_MS = 120_000;
/** One `provider_unhealthy` notification per integration per this window (D11, PQ16). */
export const PROVIDER_UNHEALTHY_THROTTLE_MINUTES = 360;
/** `notification_alert_windows.kind` of the provider-health notice. */
export const PROVIDER_UNHEALTHY_WINDOW_KIND = 'ato_provider_health';
/** `health_detail` bound (§4.1). */
const HEALTH_DETAIL_MAX_BYTES = 8192;
const MAX_GRANTED_PERMISSIONS = 64;
const MAX_DIRECTORY_DOMAINS = 500;
/** Paused reasons the probe sets and lifts itself (a user's pause is lifted only by a user). */
export const AUTO_PAUSE_REASONS = [
  'connection_inactive',
  'telemetry_grant_inactive',
  'directory_changed',
  'directory_in_use',
] as const;
/** Re-schedule cap after an unexpected (non-transient) probe exception (the "failed" cap). */
export const IDP_PROBE_ERROR_RETRY_MS = 300_000;
/** Probe codes that mean the integration cannot reach the provider at all (D6 "unhealthy"). */
const PASSING_CODES = new Set([undefined, 'stream_unavailable']);

const TELEMETRY_PROFILE: Readonly<Record<AtoProviderKind, string>> = {
  microsoft_entra: 'm365.ato_telemetry',
  google_workspace: 'google.ato_telemetry',
};
const DECLARED = {
  microsoft_entra: MICROSOFT_DECLARED_CAPABILITIES,
  google_workspace: GOOGLE_DECLARED_CAPABILITIES,
} as const;

export interface IdpProbeConfig {
  healthIntervalSeconds: number;
  lagWarnSeconds: number;
}

type Transition =
  | { kind: 'probed'; report: ProbeReport; connection: ProviderConnectionView }
  | {
      kind: 'paused';
      reason: (typeof AUTO_PAUSE_REASONS)[number];
      report: ProbeReport | null;
      connection: ProviderConnectionView | null;
    }
  | { kind: 'disabled'; reason: 'connection_removed' }
  | { kind: 'failed'; code: string };

/**
 * The probe loop of the `provider` role (step 8.5 D6, D11; ADR-0084): claims integrations whose
 * `next_health_at` is due (`FOR UPDATE SKIP LOCKED`, leased for one health interval) and probes
 * them read-only: the 8.2 connection (removed or disabled ⇒ integration `disabled`
 * `connection_removed` and its in-flight provider actions `failed` `integration_disabled`; not
 * active ⇒ `paused` `connection_inactive`; telemetry grant not active ⇒ `paused`
 * `telemetry_grant_inactive`), then `adapter.probe` (another directory ⇒ `paused`
 * `directory_changed`). It stores the report, effective capabilities, stream availability, the
 * connection's provider-verified linked domains and granted permission names, computes the D6
 * health, recovers `error` and auto-paused integrations when the probe passes, and — in the same
 * transaction as a transition to `unhealthy` — requests 8.4's `ato.notification.requested.v1`
 * kind `provider_unhealthy` (one per integration per 6 h through `notification_alert_windows`;
 * recovery sends nothing).
 */
export class IdpProbeLoop {
  private lastStatusAt = 0;
  /**
   * Consecutive deferrals per integration id after transient database errors (step AI-4 D14);
   * reset when a probe completes. In-process only.
   */
  private readonly deferrals = new Map<string, number>();

  constructor(
    private readonly deps: {
      db: AtoDb;
      prisma: PrismaClient;
      store: AtoStore;
      runtime: IdpRuntime;
      orgs: OrgContextCache;
      idpMetrics: IdpMetrics | null;
      logger: Logger;
      now: () => Date;
      config: IdpProbeConfig;
      organizationIds?: readonly bigint[];
      /** Test seam: the wait between transient retries (default: a timer). */
      retrySleep?: RetrySleep;
    },
  ) {}

  /** One pass; true when more integrations may be due. */
  async runOnce(): Promise<boolean> {
    const rows = await this.claim();
    let rescheduleError: Error | undefined;
    for (const row of rows) {
      try {
        await this.probe(row);
        this.deferrals.delete(row.id.toString());
      } catch (error) {
        // The claim leased the integration for a whole health interval: a probe that threw is
        // re-scheduled instead (D14), so a database outage costs seconds, not 15 minutes.
        try {
          await this.reschedule(row, error);
        } catch (writeError) {
          this.deps.logger.warn(
            { integrationId: row.id.toString(), ...errorFields(writeError) },
            'ato idp probe re-schedule failed',
          );
          rescheduleError ??=
            writeError instanceof Error ? writeError : new Error('probe_reschedule_failed');
        }
      }
    }
    const now = this.deps.now().getTime();
    if (now - this.lastStatusAt >= 30_000) {
      this.lastStatusAt = now;
      await this.reportStatus().catch(() => undefined);
    }
    // The pass failed to hand an integration back: the Periodic loop's own back-off applies.
    if (rescheduleError !== undefined) throw rescheduleError;
    return rows.length === IDP_PROBE_BATCH;
  }

  /**
   * After a probe exception: a transient database error re-schedules `next_health_at` by
   * 5–60 s (k-th deferral) without touching `health_status` or `last_error_code`; any other
   * exception re-schedules after min(health interval, 300 s).
   */
  private async reschedule(row: AtoProviderIntegration, error: unknown): Promise<void> {
    const key = row.id.toString();
    let delayMs: number;
    if (isTransientDbFailure(error)) {
      const k = (this.deferrals.get(key) ?? 0) + 1;
      this.deferrals.set(key, k);
      delayMs = deferDelayMs(k);
      this.deps.idpMetrics?.transientDbError('probe', 'deferred');
      this.deps.logger.warn(
        { integrationId: key, deferMs: delayMs, ...errorFields(error) },
        'ato idp probe deferred after a transient database error',
      );
    } else {
      delayMs = Math.min(this.deps.config.healthIntervalSeconds * 1000, IDP_PROBE_ERROR_RETRY_MS);
      this.deps.logger.warn(
        { integrationId: key, deferMs: delayMs, ...errorFields(error) },
        'ato idp probe failed',
      );
    }
    await this.write(() =>
      this.deps.prisma.atoProviderIntegration.updateMany({
        where: { id: row.id, organizationId: row.organizationId },
        data: { nextHealthAt: new Date(this.deps.now().getTime() + delayMs) },
      }),
    );
  }

  /** A bounded retry of one idempotent write or read of the loop (transient errors only). */
  private write<T>(fn: () => Promise<T>): Promise<T> {
    return withTransientRetry(fn, {
      attempts: IDP_WRITE_ATTEMPTS,
      ...(this.deps.retrySleep ? { sleep: this.deps.retrySleep } : {}),
      onRetry: () => this.deps.idpMetrics?.transientDbError('probe', 'retried'),
    });
  }

  private async claim(): Promise<AtoProviderIntegration[]> {
    const now = this.deps.now();
    const lease = new Date(now.getTime() + this.deps.config.healthIntervalSeconds * 1000);
    const ids = await this.write(() => this.claimIds(now, lease));
    if (ids.length === 0) return [];
    try {
      return await this.write(() =>
        this.deps.prisma.atoProviderIntegration.findMany({
          where: { id: { in: ids } },
          orderBy: { id: 'asc' },
        }),
      );
    } catch (error) {
      // The claim committed but its rows could not be read: hand them back after a short
      // deferral instead of a whole health interval (best effort; D14).
      if (isTransientDbFailure(error)) {
        await this.deps.prisma.atoProviderIntegration
          .updateMany({
            where: { id: { in: ids } },
            data: { nextHealthAt: new Date(this.deps.now().getTime() + deferDelayMs(1)) },
          })
          .catch(() => undefined);
        this.deps.idpMetrics?.transientDbError('probe', 'deferred');
      }
      throw error;
    }
  }

  private claimIds(now: Date, lease: Date): Promise<bigint[]> {
    return this.deps.db.transaction(async (tx) => {
      const rows = await tx.$queryRaw<Array<{ id: bigint | number }>>`
        SELECT id FROM ato_provider_integrations
        WHERE status IN ('active', 'error', 'paused')
          AND provider IN ('microsoft_entra', 'google_workspace')
          AND next_health_at <= ${now}
          ${orgFilter('organization_id', this.deps.organizationIds)}
        ORDER BY next_health_at, id
        LIMIT ${IDP_PROBE_BATCH}
        FOR UPDATE SKIP LOCKED`;
      if (rows.length === 0) return [];
      const claimed = rows.map((r) => big(r.id));
      await tx.atoProviderIntegration.updateMany({
        where: { id: { in: claimed } },
        data: { nextHealthAt: lease },
      });
      return claimed;
    });
  }

  /** Probes one integration and stores the outcome (exported for the api's "check now"). */
  async probe(row: AtoProviderIntegration): Promise<void> {
    const org = await this.deps.orgs.get(row.organizationId);
    if (!atoEnabled(org)) {
      // ATO is off (or was off when the organization context was cached, ≤ the settings cache
      // TTL): probe again within a minute instead of after the whole lease (WP6), so a binding
      // made right after the feature was enabled is not idle for a health interval.
      await this.deps.prisma.atoProviderIntegration.updateMany({
        where: { id: row.id, organizationId: row.organizationId },
        data: { nextHealthAt: new Date(this.deps.now().getTime() + IDP_FEATURE_OFF_RETRY_MS) },
      });
      return;
    }
    const kind = row.provider as AtoProviderKind;
    const transition = await this.observe(row, kind);
    await this.store(row, kind, transition);
    this.deps.runtime.forget(row.id);
  }

  private async observe(row: AtoProviderIntegration, kind: AtoProviderKind): Promise<Transition> {
    const signal = AbortSignal.timeout(IDP_PROBE_TIMEOUT_MS);
    if (!row.connectorRef) return { kind: 'disabled', reason: 'connection_removed' };
    let connection: ProviderConnectionView | null;
    try {
      connection = await this.deps.runtime.connections.get(
        row.organizationId.toString(),
        row.connectorRef,
        signal,
      );
    } catch (error) {
      // The connection is read from the worker's database: an outage defers the probe (D14).
      if (isTransientDbFailure(error)) throw error;
      return { kind: 'failed', code: errorCode(error, 'connection_read_failed') };
    }
    if (
      !connection ||
      connection.status === 'disabled' ||
      connection.organizationId !== row.organizationId.toString()
    ) {
      return { kind: 'disabled', reason: 'connection_removed' };
    }
    if (connection.status !== 'active') {
      return { kind: 'paused', reason: 'connection_inactive', report: null, connection };
    }
    const telemetry = connection.grants.find((g) => g.profile === TELEMETRY_PROFILE[kind]);
    if (!telemetry || telemetry.status !== 'active') {
      return { kind: 'paused', reason: 'telemetry_grant_inactive', report: null, connection };
    }
    let adapter: IdpAdapter;
    try {
      this.deps.runtime.forget(row.id);
      adapter = this.deps.runtime.adapterFor(row);
    } catch (error) {
      return { kind: 'failed', code: errorCode(error, 'adapter_unavailable') };
    }
    let report: ProbeReport;
    try {
      report = await adapter.probe(signal);
    } catch (error) {
      // A database error of the adapter's own stores defers; provider errors are recorded.
      if (isTransientDbFailure(error, 'adapter')) throw error;
      return { kind: 'failed', code: errorCode(error, 'probe_failed') };
    }
    if (report.code === 'directory_changed') {
      return { kind: 'paused', reason: 'directory_changed', report, connection };
    }
    return { kind: 'probed', report, connection };
  }

  private async streamStates(
    tx: Tx,
    row: AtoProviderIntegration,
    now: Date,
  ): Promise<StreamRuntimeState[]> {
    const streams = await tx.atoProviderStream.findMany({
      where: { integrationId: row.id, organizationId: row.organizationId },
    });
    return streams.map((s) => ({
      stream: s.stream,
      enabled: s.enabled,
      role: s.role,
      consecutiveFailures: s.consecutiveFailures,
      // Throttled since the last success (no extra column): long throttling degrades health.
      throttledSinceMs:
        s.throttledUntil && s.throttledUntil > now
          ? (s.lastSuccessAt ?? s.updatedAt).getTime()
          : null,
      lagSeconds: s.watermarkAt
        ? Math.max(0, Math.round((now.getTime() - s.watermarkAt.getTime()) / 1000))
        : null,
    }));
  }

  private async store(
    row: AtoProviderIntegration,
    kind: AtoProviderKind,
    t: Transition,
  ): Promise<void> {
    const now = this.deps.now();
    const interval = this.deps.config.healthIntervalSeconds * 1000;
    await this.deps.db
      .transaction(async (tx) => {
        const locked = await tx.$queryRaw<
          Array<{
            id: bigint | number;
            organization_id: bigint | number;
            status: string;
            health_status: IntegrationHealth;
            paused_reason: string | null;
          }>
        >`
        SELECT id, organization_id, status, health_status, paused_reason
        FROM ato_provider_integrations
        WHERE id = ${row.id} AND organization_id = ${row.organizationId}
        FOR UPDATE`;
        const current = locked[0];
        if (!current || big(current.organization_id) !== row.organizationId) return;
        if (current.status === 'disabled') return; // unbound in between
        const previous = current.health_status;
        if (t.kind === 'disabled') {
          await tx.atoProviderIntegration.updateMany({
            where: { id: row.id, organizationId: row.organizationId },
            data: {
              status: 'disabled',
              disabledReason: t.reason,
              disabledAt: now,
              pausedReason: null,
              healthStatus: 'unknown',
              healthCheckedAt: now,
              nextHealthAt: null,
              rowVersion: { increment: 1 },
            },
          });
          await this.deps.store.failProviderActionsOfIntegration(tx, {
            organizationId: row.organizationId,
            integrationId: row.id,
          });
          return;
        }
        if (t.kind === 'failed') {
          // The probe itself could not run (database or adapter construction): try again soon.
          await tx.atoProviderIntegration.updateMany({
            where: { id: row.id, organizationId: row.organizationId },
            data: {
              lastErrorCode: t.code.slice(0, 64),
              nextHealthAt: new Date(now.getTime() + Math.min(interval, 300_000)),
            },
          });
          return;
        }
        const connection = t.connection;
        const report = t.report;
        const streams = await this.streamStates(tx, row, now);
        const health: IntegrationHealth =
          t.kind === 'paused'
            ? 'unhealthy'
            : computeHealthStatus({
                report: t.report,
                connectionActive: true,
                tokenFailing: !PASSING_CODES.has(t.report.code),
                streams,
                now,
                lagWarnSeconds: this.deps.config.lagWarnSeconds,
                failingAfter: 3,
              });
        const data: Prisma.AtoProviderIntegrationUncheckedUpdateInput = {
          healthStatus: health,
          healthCheckedAt: now,
          nextHealthAt: new Date(now.getTime() + interval),
          rowVersion: { increment: 1 },
        };
        if (connection) {
          data.displayName = connection.displayName.slice(0, 128);
          data.directoryDomains = connection.linkedDomains
            .filter((d) => d.providerVerified)
            .map((d) => d.name.toLowerCase())
            .slice(0, MAX_DIRECTORY_DOMAINS);
          const granted = new Set<string>();
          for (const g of connection.grants) {
            if (!g.profile.includes('.ato_')) continue;
            for (const p of g.observedPermissions ?? []) granted.add(p);
          }
          data.grantedPermissions = [...granted].sort().slice(0, MAX_GRANTED_PERMISSIONS);
          if (row.directoryRefHash === null && connection.externalTenantId) {
            data.directoryRefHash = directoryRefHash(kind, connection.externalTenantId);
          }
        }
        if (report) {
          const detail = JSON.stringify(report);
          data.healthDetail =
            Buffer.byteLength(detail, 'utf8') <= HEALTH_DETAIL_MAX_BYTES
              ? (report as unknown as Prisma.InputJsonValue)
              : ({
                  ...report,
                  grants: report.grants.map((g) => ({
                    ...g,
                    missingPermissions: g.missingPermissions.slice(0, 10),
                  })),
                } as unknown as Prisma.InputJsonValue);
          let settings;
          try {
            settings = bindingSettingsOf(kind, row.settings);
          } catch {
            settings = null;
          }
          if (settings) {
            data.capabilities = computeEffectiveCapabilities({
              provider: kind,
              declared: DECLARED[kind],
              report,
              settings,
              now,
              healthIntervalSeconds: this.deps.config.healthIntervalSeconds,
            }).capabilities as unknown as Prisma.InputJsonValue;
          }
          await this.storeAvailability(tx, row, kind, report, now);
        }
        if (t.kind === 'paused') {
          if (current.status !== 'paused' || current.paused_reason !== t.reason) {
            // A user's pause stays a user's pause; an automatic one records its cause.
            if (
              current.status !== 'paused' ||
              (AUTO_PAUSE_REASONS as readonly string[]).includes(current.paused_reason ?? '')
            ) {
              data.status = 'paused';
              data.pausedReason = t.reason;
            }
          }
          data.lastErrorCode = t.reason;
        } else {
          const probed = t.report;
          const recovered =
            probed.ok &&
            (current.status === 'error' ||
              (current.status === 'paused' &&
                (AUTO_PAUSE_REASONS as readonly string[]).includes(current.paused_reason ?? '')));
          if (recovered) {
            data.status = 'active';
            data.pausedReason = null;
            data.consecutiveFailures = 0;
            data.lastErrorCode = null;
            await tx.atoProviderStream.updateMany({
              where: { integrationId: row.id, organizationId: row.organizationId },
              data: { consecutiveFailures: 0, nextPollAt: now, lastErrorCode: null },
            });
          } else if (!probed.ok && probed.code) {
            data.lastErrorCode = probed.code.slice(0, 64);
          }
        }
        await tx.atoProviderIntegration.updateMany({
          where: { id: row.id, organizationId: row.organizationId },
          data,
        });
        if (
          health === 'unhealthy' &&
          previous !== 'unhealthy' &&
          !(current.status === 'paused' && current.paused_reason === 'user')
        ) {
          await this.notifyUnhealthy(tx, row, now);
        }
      })
      .catch(async (error: unknown) => {
        // Another active integration already holds this directory (unique directory key).
        if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
          await this.deps.prisma.atoProviderIntegration.updateMany({
            where: { id: row.id, organizationId: row.organizationId },
            data: {
              status: 'paused',
              pausedReason: 'directory_in_use',
              healthStatus: 'unhealthy',
              healthCheckedAt: now,
              nextHealthAt: new Date(now.getTime() + interval),
            },
          });
          return;
        }
        throw error;
      });
  }

  /** Stream availability from the report (companions mirror their primary, D3). */
  private async storeAvailability(
    tx: Tx,
    row: AtoProviderIntegration,
    kind: AtoProviderKind,
    report: ProbeReport,
    now: Date,
  ): Promise<void> {
    for (const stream of PROVIDER_STREAMS) {
      const def = STREAM_ROLES[kind][stream];
      const source = def.role === 'companion' && def.primary ? def.primary : stream;
      const probed = report.streams[source] ?? report.streams[stream];
      const availability =
        def.role === 'unsupported' ? 'not_offered' : (probed?.availability ?? 'error');
      await tx.atoProviderStream.updateMany({
        where: { integrationId: row.id, organizationId: row.organizationId, stream },
        data: {
          availability,
          availabilityCode: probed?.code?.slice(0, 64) ?? null,
          updatedAt: now,
        },
      });
    }
  }

  /**
   * `provider_unhealthy` through 8.4's notification outbox path (D11), at most once per
   * integration per 6 h: a request inside the window of an earlier one only counts.
   */
  private async notifyUnhealthy(tx: Tx, row: AtoProviderIntegration, now: Date): Promise<void> {
    const windowMs = PROVIDER_UNHEALTHY_THROTTLE_MINUTES * 60_000;
    const recent = await tx.notificationAlertWindow.findFirst({
      where: {
        organizationId: row.organizationId,
        kind: PROVIDER_UNHEALTHY_WINDOW_KIND,
        scopeKey: row.publicId,
        windowStart: { gt: new Date(now.getTime() - windowMs) },
      },
      orderBy: { windowStart: 'desc' },
    });
    if (recent) {
      if (recent.organizationId !== row.organizationId) return;
      await tx.notificationAlertWindow.updateMany({
        where: { id: recent.id, organizationId: row.organizationId },
        data: { eventCount: { increment: 1 }, updatedAt: now },
      });
      return;
    }
    await this.deps.store.requestNotification(tx, {
      organizationId: row.organizationId,
      kind: 'provider_unhealthy',
      audience: 'tenant',
      severity: null,
      refs: { integrationPublicId: row.publicId },
      throttle: {
        kind: PROVIDER_UNHEALTHY_WINDOW_KIND,
        scope: row.publicId,
        minutes: PROVIDER_UNHEALTHY_THROTTLE_MINUTES,
        windowStart: new Date(Math.floor(now.getTime() / 1000) * 1000),
      },
    });
  }

  /** D11 gauges (integrations by health, stream lag, active backfills); no tenant labels. */
  async reportStatus(): Promise<void> {
    const metrics = this.deps.idpMetrics;
    if (!metrics) return;
    const now = this.deps.now();
    const filter = orgFilter('i.organization_id', this.deps.organizationIds);
    const health = await this.deps.prisma.$queryRaw<
      Array<{ provider: string; health_status: string; n: bigint | number }>
    >`
      SELECT i.provider, i.health_status, COUNT(*) AS n FROM ato_provider_integrations i
      WHERE i.status <> 'disabled' AND i.provider IN ('microsoft_entra', 'google_workspace') ${filter}
      GROUP BY i.provider, i.health_status`;
    metrics.integrations.reset();
    for (const provider of ['microsoft_entra', 'google_workspace']) {
      for (const h of ['unknown', 'healthy', 'degraded', 'unhealthy']) {
        metrics.integrations.set({ provider, health: h }, 0);
      }
    }
    for (const r of health)
      metrics.integrations.set({ provider: r.provider, health: r.health_status }, Number(r.n));
    const lag = await this.deps.prisma.$queryRaw<
      Array<{ provider: string; stream: string; oldest: Date | null }>
    >`
      SELECT i.provider, s.stream, MIN(s.watermark_at) AS oldest
      FROM ato_provider_streams s
      JOIN ato_provider_integrations i ON i.id = s.integration_id AND i.organization_id = s.organization_id
      WHERE i.status = 'active' AND s.enabled = 1 AND s.role = 'primary'
        AND s.status IN ('active', 'backfilling') AND s.watermark_at IS NOT NULL ${filter}
      GROUP BY i.provider, s.stream`;
    metrics.streamLag.reset();
    for (const r of lag) {
      if (!r.oldest) continue;
      metrics.streamLag.set(
        { provider: r.provider, stream: r.stream },
        Math.max(0, Math.round((now.getTime() - new Date(r.oldest).getTime()) / 1000)),
      );
    }
    const backfills = await this.deps.prisma.$queryRaw<
      Array<{ provider: string; n: bigint | number }>
    >`
      SELECT i.provider, COUNT(*) AS n FROM ato_provider_streams s
      JOIN ato_provider_integrations i ON i.id = s.integration_id AND i.organization_id = s.organization_id
      WHERE i.status <> 'disabled' AND s.status = 'backfilling' AND s.role = 'primary' ${filter}
      GROUP BY i.provider`;
    metrics.backfillsActive.reset();
    for (const provider of ['microsoft_entra', 'google_workspace'])
      metrics.backfillsActive.set({ provider }, 0);
    for (const r of backfills) metrics.backfillsActive.set({ provider: r.provider }, Number(r.n));
  }
}

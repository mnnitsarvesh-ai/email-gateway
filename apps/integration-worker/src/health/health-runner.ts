import { randomUUID } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import {
  EventTypes,
  type IntegrationHealthChangedV1,
  integrationHealthChangedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  evaluateHealth,
  failingCheckCodes,
  periodicHealthChecks,
  type ProviderHealthStatus,
} from '@email-gateway/provider-integrations';
import {
  type CheckCode,
  type CheckResult,
  type CheckRunner,
  PROVIDER_CHECK_CODES,
} from '../checks/checks';
import { type ConnectionView, loadConnection } from '../checks/context';
import type { IntegrationMetrics } from '../metrics/integration-metrics';
import { orgFilter, systemAudit } from '../shared/db';
import { errorFields } from '../shared/errors';
import type { TenantBinder } from '../tasks/tenant-binding';

/** Lease of a claimed health check (a crashed replica's claim expires). */
export const HEALTH_LEASE_MS = 5 * 60_000;
/** Provider back-off ceiling (D11: ×2 up to 3600 s). */
export const PROVIDER_BACKOFF_MAX_SECONDS = 3_600;
/** Upper bound of one connection's checks. */
const HEALTH_DEADLINE_MS = 4 * 60_000;

/** Implemented periodic codes (the registry's periodic list; 8.5 checks run in their own step). */
const IMPLEMENTED: ReadonlySet<string> = new Set<CheckCode>([
  'credentials.token',
  'permissions.granted',
  'tenant.identity',
  'domains.provider_verified',
  'dns.mx_gateway',
  'inbound.recent_deliveries',
  'outbound.relay_activity',
  'routing.loops',
  'credential.expiry',
  'egress.ranges_fresh',
]);

interface StoredCheck {
  checkCode: string;
  subject: string;
  status: CheckResult['status'];
  severity: CheckResult['severity'];
  evidence: Prisma.JsonValue | null;
  firstFailedAt: Date | null;
  checkedAt: Date;
}

export interface HealthOutcome {
  previous: ProviderHealthStatus;
  status: ProviderHealthStatus;
  failingChecks: string[];
  changed: boolean;
  providerChecksSkipped: boolean;
}

/** Test seam: fails the transition transaction after the event row (rollback test). */
export interface HealthFaults {
  afterEventInsert?: () => void;
}

/**
 * D11 `health` role: claims connections due (`status IN ('configuring','active')`,
 * `next_health_check_at ≤ now`) with `FOR UPDATE SKIP LOCKED` and a lease, runs the periodic
 * checks, upserts `provider_health_checks` (latest per check and subject, `first_failed_at` per
 * failing streak), evaluates the status (`evaluateHealth`: worst failing severity, provider
 * errors only after the grace period, D15) and, on a change, writes the `provider_health_events`
 * row, the connection's health columns, the audit row (`integration.health_changed`, actor
 * system) and the outbox event `integration.connection.health_changed.v1` in ONE transaction. A
 * provider-API failure backs off that connection's provider checks (interval ×2 per failure up to
 * 3600 s) without delaying the mail-flow checks. Health never changes mail flow (I1). Health
 * columns are written without `row_version` (it binds impact tokens).
 */
export class HealthRunner {
  constructor(
    private readonly writer: PrismaClient,
    private readonly options: {
      checks: CheckRunner;
      binder: TenantBinder;
      metrics: IntegrationMetrics;
      logger: Logger;
      now: () => Date;
      intervalSeconds: number;
      graceMinutes: number;
      organizationIds?: readonly bigint[];
      faults?: HealthFaults;
    },
  ) {}

  async runOnce(limit: number, signal: AbortSignal): Promise<number> {
    const claimed = await this.claim(limit);
    for (const id of claimed) {
      if (signal.aborted) break;
      await this.check(id, signal).catch((error: unknown) => {
        this.options.logger.warn(
          { connectionId: id.toString(), ...errorFields(error) },
          'connection health check failed; retried after the lease',
        );
      });
    }
    return claimed.length;
  }

  async claim(limit: number): Promise<bigint[]> {
    const now = this.options.now();
    const until = new Date(now.getTime() + HEALTH_LEASE_MS);
    return this.writer.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
        SELECT id FROM provider_connections
         WHERE status IN ('configuring', 'active')
           AND (next_health_check_at IS NULL OR next_health_check_at <= ${now})
           AND (health_claimed_until IS NULL OR health_claimed_until < ${now})
           ${orgFilter('organization_id', this.options.organizationIds)}
         ORDER BY next_health_check_at, id
         LIMIT ${limit}
         FOR UPDATE SKIP LOCKED`;
      if (rows.length === 0) return [];
      const ids = rows.map((r) => BigInt(r.id));
      await tx.$executeRaw`UPDATE provider_connections SET health_claimed_until = ${until}
                            WHERE id IN (${Prisma.join(ids)})`;
      return ids;
    });
  }

  /** One connection's periodic checks and evaluation (exposed for the integration suite). */
  async check(connectionId: bigint, signal: AbortSignal): Promise<HealthOutcome | null> {
    const connection = await loadConnection(this.writer, connectionId);
    if (!connection || (connection.status !== 'configuring' && connection.status !== 'active')) {
      await this.writer.providerConnection.updateMany({
        where: { id: connectionId },
        data: { healthClaimedUntil: null },
      });
      return null;
    }
    const now = this.options.now();
    const stored = await this.storedChecks(connection);
    const backoffUntil = this.providerBackoffUntil(stored);
    const skipProvider = backoffUntil !== null && backoffUntil > now;
    const codes = periodicHealthChecks(connection.provider)
      .map((c) => c.code)
      .filter((code): code is CheckCode => IMPLEMENTED.has(code))
      .filter((code) => !(skipProvider && PROVIDER_CHECK_CODES.has(code)));
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(HEALTH_DEADLINE_MS)]);
    const results = await this.options.checks.run(connection, codes, deadline);
    if (signal.aborted) return null;
    const outcome = await this.persist(connection, codes, results, stored, now);
    if (codes.includes('domains.provider_verified')) {
      // Provider verification may have changed: the tenant binding on proof of control and I10
      // (never demotes an active connection). A failure here is retried on the next run.
      await this.options.binder
        .settle(connection.id, signal, randomUUID())
        .catch((error: unknown) => {
          this.options.logger.warn(
            { connectionId: connection.id.toString(), ...errorFields(error) },
            'tenant binding after the health run failed; retried',
          );
        });
    }
    return { ...outcome, providerChecksSkipped: skipProvider };
  }

  private async storedChecks(c: ConnectionView): Promise<StoredCheck[]> {
    return this.writer.providerHealthCheck.findMany({
      where: { connectionId: c.id, organizationId: c.organizationId },
      select: {
        checkCode: true,
        subject: true,
        status: true,
        severity: true,
        evidence: true,
        firstFailedAt: true,
        checkedAt: true,
      },
    });
  }

  /** When the provider checks may run again after `error` results (stored back-off). */
  private providerBackoffUntil(stored: readonly StoredCheck[]): Date | null {
    let until: number | null = null;
    for (const row of stored) {
      if (!PROVIDER_CHECK_CODES.has(row.checkCode) || row.status !== 'error') continue;
      const seconds = backoffSecondsOf(row.evidence);
      if (seconds === null) continue;
      const at = row.checkedAt.getTime() + seconds * 1000;
      until = until === null ? at : Math.max(until, at);
    }
    return until === null ? null : new Date(until);
  }

  private async persist(
    c: ConnectionView,
    codes: readonly string[],
    results: CheckResult[],
    stored: readonly StoredCheck[],
    now: Date,
  ): Promise<Omit<HealthOutcome, 'providerChecksSkipped'>> {
    const key = (code: string, subject: string) => `${code}\u0000${subject}`;
    const previousByKey = new Map(stored.map((s) => [key(s.checkCode, s.subject), s]));
    // Provider errors carry their back-off (×2 per consecutive error, ≤ 3600 s).
    const withBackoff = results.map((r) => {
      if (r.status !== 'error' || !PROVIDER_CHECK_CODES.has(r.code)) return r;
      const before = previousByKey.get(key(r.code, r.subject));
      const previousSeconds = before?.status === 'error' ? backoffSecondsOf(before.evidence) : null;
      const seconds = Math.min(
        PROVIDER_BACKOFF_MAX_SECONDS,
        previousSeconds === null ? this.options.intervalSeconds : previousSeconds * 2,
      );
      return { ...r, evidence: { ...r.evidence, backoffSeconds: seconds } };
    });
    const ran = new Set(codes);
    const fresh = new Set(withBackoff.map((r) => key(r.code, r.subject)));
    // Rows of checks that did not run this round (provider back-off) keep counting; rows of checks
    // that ran are replaced by the fresh results (or removed when their subject is gone).
    const current = [
      ...stored
        .filter((s) => !ran.has(s.checkCode))
        .map((s) => ({
          code: s.checkCode,
          status: s.status,
          severity: s.severity,
          firstFailedAt: s.firstFailedAt,
        })),
      ...withBackoff.map((r) => {
        const before = previousByKey.get(key(r.code, r.subject));
        const failing = r.status === 'fail' || r.status === 'error';
        const wasFailing = before?.status === 'fail' || before?.status === 'error';
        return {
          code: r.code,
          status: r.status,
          severity: r.severity,
          firstFailedAt: failing ? (wasFailing ? (before?.firstFailedAt ?? now) : now) : null,
        };
      }),
    ];
    const grace = this.options.graceMinutes;
    const status = evaluateHealth(current, now, grace, c.healthStatus);
    const failingChecks = failingCheckCodes(current, now, grace, 10);
    const changed = status !== c.healthStatus;
    const nextAt = new Date(now.getTime() + this.options.intervalSeconds * 1000);

    await this.writer.$transaction(async (tx) => {
      for (const r of withBackoff) {
        const before = previousByKey.get(key(r.code, r.subject));
        const failing = r.status === 'fail' || r.status === 'error';
        const wasFailing = before?.status === 'fail' || before?.status === 'error';
        const firstFailedAt = failing ? (wasFailing ? (before?.firstFailedAt ?? now) : now) : null;
        await tx.providerHealthCheck.upsert({
          where: {
            connectionId_checkCode_subject: {
              connectionId: c.id,
              checkCode: r.code,
              subject: r.subject,
            },
          },
          create: {
            organizationId: c.organizationId,
            connectionId: c.id,
            checkCode: r.code,
            subject: r.subject,
            status: r.status,
            severity: r.severity,
            evidence: r.evidence as Prisma.InputJsonValue,
            firstFailedAt,
            checkedAt: now,
          },
          update: {
            status: r.status,
            severity: r.severity,
            evidence: r.evidence as Prisma.InputJsonValue,
            firstFailedAt,
            checkedAt: now,
          },
        });
      }
      // Rows of checks that ran but no longer have this subject (e.g. an unlinked domain).
      const stale = stored.filter(
        (s) => ran.has(s.checkCode) && !fresh.has(key(s.checkCode, s.subject)),
      );
      for (const s of stale) {
        await tx.providerHealthCheck.deleteMany({
          where: { connectionId: c.id, checkCode: s.checkCode, subject: s.subject },
        });
      }
      await tx.providerConnection.updateMany({
        where: { id: c.id, organizationId: c.organizationId },
        data: {
          healthStatus: status,
          healthCheckedAt: now,
          nextHealthCheckAt: nextAt,
          healthClaimedUntil: null,
          ...(changed ? { healthChangedAt: now } : {}),
        },
      });
      if (changed) await this.transition(tx, c, status, failingChecks, now);
    });
    if (changed) this.options.metrics.healthTransitions.inc({ provider: c.provider, to: status });
    return { previous: c.healthStatus, status, failingChecks, changed };
  }

  /** Event row, audit row and outbox event of one transition (inside the caller's transaction). */
  private async transition(
    tx: Prisma.TransactionClient,
    c: ConnectionView,
    status: ProviderHealthStatus,
    failingChecks: string[],
    now: Date,
  ): Promise<void> {
    await tx.providerHealthEvent.create({
      data: {
        organizationId: c.organizationId,
        connectionId: c.id,
        fromStatus: c.healthStatus,
        toStatus: status,
        failingChecks,
        createdAt: now,
      },
      select: { id: true },
    });
    this.options.faults?.afterEventInsert?.();
    const correlationId = randomUUID();
    await systemAudit(tx, {
      organizationId: c.organizationId,
      action: 'integration.health_changed',
      resourceId: c.publicId,
      correlationId,
      metadata: {
        connectionId: c.publicId,
        provider: c.provider,
        previousStatus: c.healthStatus,
        status,
        failingChecks,
      },
      at: now,
    });
    const payload: IntegrationHealthChangedV1 = integrationHealthChangedV1.parse({
      connectionId: c.publicId,
      provider: c.provider,
      previousStatus: c.healthStatus,
      status,
      changedAt: now.toISOString(),
      failingChecks,
    });
    await tx.messageOutbox.create({
      data: {
        eventId: uuidv7(now.getTime()),
        organizationId: c.organizationId,
        eventType: EventTypes.IntegrationHealthChanged,
        aggregateType: 'provider_connection',
        // Contracts §33: the decimal provider_connections.id.
        aggregateId: c.id.toString(),
        correlationId,
        payload,
      },
      select: { id: true },
    });
  }
}

function backoffSecondsOf(evidence: Prisma.JsonValue | null): number | null {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) return null;
  const value = (evidence as Record<string, Prisma.JsonValue>).backoffSeconds;
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : null;
}

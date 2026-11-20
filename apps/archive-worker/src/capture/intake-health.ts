import { uuidv7 } from '@email-gateway/common';
import {
  type JournalIntakeHealthStatus,
  type JournalIntakeSourceKind,
  type JournalIntakeSourceStatus,
  type Prisma,
  type PrismaClient,
} from '@email-gateway/database';
import { EventTypes, notificationAlertRequestedV1 } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { systemAudit } from '../shared/db';
import { errorFields } from '../shared/errors';

/** Leader lock of the intake health job (capture role, step 8.6 D9). */
export const INTAKE_HEALTH_LOCK = 'eg:archive-intake-health';
/** The alert kind of a silent or failing source (notification-worker template). */
export const INTAKE_ALERT_KIND = 'journal_intake_silent';
/** The look-back of the "refused or dropped without acceptance" and unwrap-failure checks. */
export const INTAKE_FAILING_WINDOW_MS = 3_600_000;
/** Provider kinds bound to a step 8.2 provider connection (D1). */
const PROVIDER_KINDS: readonly JournalIntakeSourceKind[] = [
  'microsoft_365_journal',
  'google_workspace_copy',
];
const HEALTH_VALUES: readonly JournalIntakeHealthStatus[] = [
  'unknown',
  'healthy',
  'silent',
  'failing',
  'paused',
];

/** The facts of one source the health is computed from (pure input). */
export interface IntakeHealthFacts {
  status: JournalIntakeSourceStatus;
  kind: JournalIntakeSourceKind;
  verifiedAt: Date | null;
  lastAcceptedAt: Date | null;
  lastRefusedAt: Date | null;
  silenceAlertMinutes: number | null;
  /** Provider kinds: the bound connection (null = none or not of the organization). */
  connection: { status: string; bound: boolean } | null;
  /** `journal_report_unparsed` messages of the source in the last hour (unwrap failures). */
  unwrapFailuresLastHour: number;
}

export type IntakeHealthReason =
  | 'paused'
  | 'connection_unusable'
  | 'refused_without_acceptance'
  | 'unwrap_failures'
  | 'not_verified'
  | 'silent'
  | 'healthy';

/**
 * The health of a non-disabled journal intake source (step 8.6 D9), pure: `paused` (status
 * paused); `failing` (a provider kind whose connection is missing, disabled or unbound; or mail
 * refused or dropped in the last hour without any acceptance in it; or unwrap failures in the last
 * hour); `unknown` (never verified); `silent` (`silence_alert_minutes` set and nothing accepted
 * for longer than that); `healthy` otherwise.
 */
export function computeIntakeHealth(
  f: IntakeHealthFacts,
  now: Date,
): { health: JournalIntakeHealthStatus; reason: IntakeHealthReason } {
  if (f.status === 'paused') return { health: 'paused', reason: 'paused' };
  if (
    PROVIDER_KINDS.includes(f.kind) &&
    (f.connection === null || f.connection.status === 'disabled' || !f.connection.bound)
  ) {
    return { health: 'failing', reason: 'connection_unusable' };
  }
  const hourAgo = now.getTime() - INTAKE_FAILING_WINDOW_MS;
  if (
    f.lastRefusedAt !== null &&
    f.lastRefusedAt.getTime() >= hourAgo &&
    (f.lastAcceptedAt === null || f.lastAcceptedAt.getTime() < hourAgo)
  ) {
    return { health: 'failing', reason: 'refused_without_acceptance' };
  }
  if (f.unwrapFailuresLastHour > 0) return { health: 'failing', reason: 'unwrap_failures' };
  if (f.verifiedAt === null) return { health: 'unknown', reason: 'not_verified' };
  if (
    f.silenceAlertMinutes !== null &&
    (f.lastAcceptedAt === null ||
      now.getTime() - f.lastAcceptedAt.getTime() > f.silenceAlertMinutes * 60_000)
  ) {
    return { health: 'silent', reason: 'silent' };
  }
  return { health: 'healthy', reason: 'healthy' };
}

/** The throttle window `{ from, to }` containing `at` (the webhook-worker's N2 rule). */
export function alertWindowOf(at: Date, minutes: number): { from: Date; to: Date } {
  const size = minutes * 60_000;
  const from = new Date(Math.floor(at.getTime() / size) * size);
  return { from, to: new Date(from.getTime() + size) };
}

export interface IntakeHealthReport {
  sources: number;
  transitions: number;
  alerts: number;
  throttled: number;
  failed: number;
}

interface SourceRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  kind: JournalIntakeSourceKind;
  status: JournalIntakeSourceStatus;
  verifiedAt: Date | null;
  lastAcceptedAt: Date | null;
  lastRefusedAt: Date | null;
  lastRefusalCode: string | null;
  silenceAlertMinutes: number | null;
  healthStatus: JournalIntakeHealthStatus;
  healthAlertedAt: Date | null;
  providerConnectionId: bigint | null;
}

const PAGE = 500;

/**
 * The journal intake health job (step 8.6 D9, capture role, leader lock
 * `eg:archive-intake-health`, every `JOURNAL_INTAKE_HEALTH_INTERVAL_MS`): every non-disabled
 * source's health from its row, its provider connection and its recent intake messages and
 * counters. A transition writes, in one writer transaction with a CAS on the previous health: the
 * source (`health_status`, `health_changed_at`), a system `audit_logs` row
 * `journal_intake.health_changed` (resource `journal_intake_source`, metadata codes and counts
 * only) and, for `silent` / `failing`, at most once per source per
 * `JOURNAL_INTAKE_ALERT_MIN_INTERVAL_HOURS` (`health_alerted_at` and a
 * `notification_alert_windows` row of that size, as the webhook-worker throttles), a
 * `notification.alert_requested.v1` outbox row of kind `journal_intake_silent` (aggregate
 * `organization`, refs `intakeSourceId`, validated with the event contract), published by the
 * event-relay on the existing route. The gauge `journal_intake_sources{health}` is set from the
 * run. Tenant from the source row only; never an address in a log, an audit row or an alert.
 */
export class IntakeHealthJob {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      metrics: ArchiveMetrics;
      logger: Logger;
      /** `JOURNAL_INTAKE_ALERT_MIN_INTERVAL_HOURS`. */
      alertMinIntervalHours: number;
      organizationIds?: readonly bigint[];
      now?: () => Date;
    },
  ) {}

  private now(): Date {
    return this.options.now?.() ?? new Date();
  }

  async runOnce(): Promise<IntakeHealthReport> {
    const now = this.now();
    const report: IntakeHealthReport = {
      sources: 0,
      transitions: 0,
      alerts: 0,
      throttled: 0,
      failed: 0,
    };
    const counts = new Map<JournalIntakeHealthStatus, number>(HEALTH_VALUES.map((h) => [h, 0]));
    let after = 0n;
    for (;;) {
      const page = await this.prisma.journalIntakeSource.findMany({
        where: {
          id: { gt: after },
          status: { not: 'disabled' },
          ...(this.options.organizationIds
            ? { organizationId: { in: [...this.options.organizationIds] } }
            : {}),
        },
        orderBy: { id: 'asc' },
        take: PAGE,
        select: {
          id: true,
          publicId: true,
          organizationId: true,
          kind: true,
          status: true,
          verifiedAt: true,
          lastAcceptedAt: true,
          lastRefusedAt: true,
          lastRefusalCode: true,
          silenceAlertMinutes: true,
          healthStatus: true,
          healthAlertedAt: true,
          providerConnectionId: true,
        },
      });
      for (const source of page) {
        report.sources += 1;
        try {
          const health = await this.evaluate(source, now, report);
          counts.set(health, (counts.get(health) ?? 0) + 1);
        } catch (error) {
          report.failed += 1;
          counts.set(source.healthStatus, (counts.get(source.healthStatus) ?? 0) + 1);
          this.options.logger.warn(
            { sourceId: source.publicId, ...errorFields(error) },
            'journal intake health not evaluated; retried next run',
          );
        }
      }
      if (page.length < PAGE) break;
      after = page[page.length - 1]!.id;
    }
    for (const [health, n] of counts) this.options.metrics.intakeSources.set({ health }, n);
    return report;
  }

  /** The facts, the health and (on a transition) the writes of one source; returns its health. */
  private async evaluate(
    source: SourceRow,
    now: Date,
    report: IntakeHealthReport,
  ): Promise<JournalIntakeHealthStatus> {
    const org = source.organizationId;
    let connection: IntakeHealthFacts['connection'] = null;
    if (source.providerConnectionId !== null) {
      const row = await this.prisma.providerConnection.findUnique({
        where: { id: source.providerConnectionId },
        select: {
          organizationId: true,
          status: true,
          activeTenantKey: true,
          externalTenantId: true,
        },
      });
      if (row !== null && row.organizationId === org) {
        connection = {
          status: row.status,
          bound: row.activeTenantKey !== null && row.externalTenantId !== null,
        };
      }
    }
    const since = new Date(now.getTime() - INTAKE_FAILING_WINDOW_MS);
    const unwrapFailuresLastHour = await this.prisma.journalIntakeMessage.count({
      where: {
        sourceId: source.id,
        organizationId: org,
        receivedAt: { gte: since },
        format: 'journal_report_unparsed',
      },
    });
    const { health, reason } = computeIntakeHealth(
      {
        status: source.status,
        kind: source.kind,
        verifiedAt: source.verifiedAt,
        lastAcceptedAt: source.lastAcceptedAt,
        lastRefusedAt: source.lastRefusedAt,
        silenceAlertMinutes: source.silenceAlertMinutes,
        connection,
        unwrapFailuresLastHour,
      },
      now,
    );
    if (health === source.healthStatus) return health;

    const today = await this.prisma.journalIntakeCounter.findUnique({
      where: {
        sourceId_day: {
          sourceId: source.id,
          day: new Date(`${now.toISOString().slice(0, 10)}T00:00:00.000Z`),
        },
      },
      select: {
        organizationId: true,
        accepted: true,
        refusedAddress: true,
        refusedNetwork: true,
        refusedTls: true,
        refusedSize: true,
        refusedRate: true,
        refusedUnavailable: true,
        droppedProof: true,
        unwrapFailed: true,
      },
    });
    const counters =
      today !== null && today.organizationId === org
        ? {
            accepted: today.accepted,
            refused:
              today.refusedAddress +
              today.refusedNetwork +
              today.refusedTls +
              today.refusedSize +
              today.refusedRate +
              today.refusedUnavailable,
            droppedProof: today.droppedProof,
            unwrapFailed: today.unwrapFailed,
          }
        : { accepted: 0, refused: 0, droppedProof: 0, unwrapFailed: 0 };
    const alerting = health === 'silent' || health === 'failing';
    const intervalMs = this.options.alertMinIntervalHours * 3_600_000;
    const recentlyAlerted =
      source.healthAlertedAt !== null &&
      now.getTime() - source.healthAlertedAt.getTime() < intervalMs;
    const outcome = await this.prisma.$transaction(async (tx) => {
      const changed = await tx.$executeRaw`
        UPDATE journal_intake_sources
        SET health_status = ${health}, health_changed_at = ${now}, updated_at = NOW(3)
        WHERE id = ${source.id} AND organization_id = ${org}
          AND health_status = ${source.healthStatus} AND status <> 'disabled'`;
      if (changed !== 1) return 'raced' as const;
      const transitionId = uuidv7(now.getTime());
      await systemAudit(tx, {
        organizationId: org,
        action: 'journal_intake.health_changed',
        resourceType: 'journal_intake_source',
        resourceId: source.publicId,
        correlationId: `journal-intake-health:${source.publicId}`,
        metadata: {
          from: source.healthStatus,
          to: health,
          reason,
          kind: source.kind,
          lastRefusalCode: source.lastRefusalCode,
          today: counters,
        },
      });
      if (!alerting) return 'no_alert' as const;
      if (recentlyAlerted) return 'throttled' as const;
      const requested = await this.requestAlert(tx, {
        organizationId: org,
        sourcePublicId: source.publicId,
        severity: health === 'failing' ? 'high' : 'medium',
        transitionId,
        now,
      });
      if (!requested) return 'throttled' as const;
      await tx.$executeRaw`
        UPDATE journal_intake_sources SET health_alerted_at = ${now}
        WHERE id = ${source.id} AND organization_id = ${org}`;
      return 'alerted' as const;
    });
    if (outcome === 'raced') return health;
    report.transitions += 1;
    this.options.metrics.intakeHealthTransitions.inc({ health });
    if (outcome === 'alerted') {
      report.alerts += 1;
      this.options.metrics.intakeAlerts.inc({ result: 'requested' });
    } else if (outcome === 'throttled') {
      report.throttled += 1;
      this.options.metrics.intakeAlerts.inc({ result: 'throttled' });
    }
    this.options.logger.info(
      {
        sourceId: source.publicId,
        organizationId: org.toString(),
        from: source.healthStatus,
        to: health,
        reason,
        alert: outcome,
      },
      'journal intake source health changed',
    );
    return health;
  }

  /**
   * The throttle window (`notification_alert_windows`, size `JOURNAL_INTAKE_ALERT_MIN_INTERVAL_HOURS`,
   * scope = the source public id) and, for the first transition of a window only, the
   * `notification.alert_requested.v1` outbox row. True when the alert was requested.
   */
  private async requestAlert(
    tx: Prisma.TransactionClient,
    input: {
      organizationId: bigint;
      sourcePublicId: string;
      severity: 'medium' | 'high';
      transitionId: string;
      now: Date;
    },
  ): Promise<boolean> {
    const minutes = this.options.alertMinIntervalHours * 60;
    const window = alertWindowOf(input.now, minutes);
    const affected = await tx.$executeRaw`
      INSERT INTO notification_alert_windows
        (organization_id, kind, scope_key, window_start, event_count, first_source_event_id,
         created_at, updated_at)
      VALUES (${input.organizationId}, ${INTAKE_ALERT_KIND}, ${input.sourcePublicId}, ${window.from},
              1, ${input.transitionId}, NOW(3), NOW(3))
      ON DUPLICATE KEY UPDATE event_count = event_count + 1, updated_at = NOW(3)`;
    // MySQL: 1 = inserted (first event of the window), 2 = an existing window was counted.
    if (affected !== 1) return false;
    const previous = await tx.$queryRaw<Array<{ event_count: number | bigint }>>`
      SELECT event_count FROM notification_alert_windows
      WHERE organization_id = ${input.organizationId} AND kind = ${INTAKE_ALERT_KIND}
        AND scope_key = ${input.sourcePublicId}
        AND window_start = ${new Date(window.from.getTime() - minutes * 60_000)}`;
    const suppressedBefore = Math.max(0, Number(previous[0]?.event_count ?? 0) - 1);
    const eventId = uuidv7(input.now.getTime());
    const payload = notificationAlertRequestedV1.parse({
      kind: INTAKE_ALERT_KIND,
      severity: input.severity,
      refs: { intakeSourceId: input.sourcePublicId },
      window: { from: window.from.toISOString(), to: window.to.toISOString() },
      counts: { suppressedBefore },
      requestedAt: input.now.toISOString(),
    });
    await tx.messageOutbox.create({
      data: {
        eventId,
        organizationId: input.organizationId,
        eventType: EventTypes.NotificationAlertRequested,
        aggregateType: 'organization',
        aggregateId: input.organizationId.toString(),
        correlationId: `journal-intake-health:${input.sourcePublicId}`,
        payload,
      },
      select: { id: true },
    });
    await tx.$executeRaw`
      UPDATE notification_alert_windows SET alert_event_id = ${eventId}
      WHERE organization_id = ${input.organizationId} AND kind = ${INTAKE_ALERT_KIND}
        AND scope_key = ${input.sourcePublicId} AND window_start = ${window.from}`;
    return true;
  }
}

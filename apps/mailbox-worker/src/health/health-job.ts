import { uuidv7 } from '@email-gateway/common';
import {
  Prisma,
  type ApiMailboxCoverageState,
  type ApiModeHealthStatus,
  type JournalIntakeSourceKind,
  type PrismaClient,
} from '@email-gateway/database';
import { EventTypes, notificationAlertRequestedV1 } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  evaluateApiModeHealth,
  evaluateMailboxCoverage,
  lagPercentileSeconds,
  type ApiModeHealthConfig,
  type ApiModeHealthInput,
  type ApiModeRemediationHealthInput,
  type LagBucket,
} from '@email-gateway/mailbox-api';
import { isApiSide, loadOrgApiModeState, type OrgApiModeState } from '../domain/api-mode-state';
import { loadConnectionContext, type ConnectionContext } from '../domain/connections';
import type { MailboxMetrics } from '../metrics/mailbox-metrics';
import type { RemediationPolicyLoader } from '../remediation/policy-loader';
import { hourOf } from '../runtime/redis-stores';
import { bool, systemAudit } from '../shared/db';
import { errorFields } from '../shared/errors';

/** Leader lock of the health role (D5, D11). */
export const HEALTH_LOCK = 'eg:mailbox:health';
/** The alert kind of a degraded or failing API-mode connection (notification-worker template). */
export const API_MODE_ALERT_KIND = 'api_mode_unhealthy';
/** Provider journal kinds that can carry API-mode intake (D6). */
const PROVIDER_JOURNAL_KINDS: readonly JournalIntakeSourceKind[] = [
  'microsoft_365_journal',
  'google_workspace_copy',
];
const HEALTH_VALUES: readonly ApiModeHealthStatus[] = ['unknown', 'healthy', 'degraded', 'failing'];
const COVERAGE_VALUES: readonly ApiMailboxCoverageState[] = ['covered', 'gap', 'out_of_scope'];
const PAGE = 500;
const MAILBOX_PAGE = 5_000;

export interface HealthConfig extends ApiModeHealthConfig {
  alertMinIntervalHours: number;
  journalCoverageDays: number;
  feedPollSeconds: number;
  safetyPollSeconds: number;
  renewBeforeMinutes: number;
  /** Notifications available (URL and secret configured): `notify` connections poll safely. */
  notificationsAvailable: boolean;
  /** Step API-2 R14 thresholds of the four `remediation.*` checks. */
  remediation: ApiModeRemediationHealthInput['thresholds'];
}

export interface HealthDeps {
  prisma: PrismaClient;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  config: HealthConfig;
  /** Effective remediation policies (`remediation.access`), shared with the copies role. */
  policies: RemediationPolicyLoader;
  organizationIds?: readonly bigint[];
}

export interface HealthReport {
  connections: number;
  transitions: number;
  alerts: number;
  throttled: number;
  coverageChanges: number;
  failed: number;
}

/** The throttle window `{ from, to }` containing `at` (the webhook-worker's N2 rule). */
export function alertWindowOf(at: Date, minutes: number): { from: Date; to: Date } {
  const size = minutes * 60_000;
  const from = new Date(Math.floor(at.getTime() / size) * size);
  return { from, to: new Date(from.getTime() + size) };
}

interface CoverageSummary {
  covered: number;
  gap: number;
  inScope: number;
  feedMailboxes: number;
  activeFeeds: number;
  errorFeeds: number;
  changes: number;
  byState: Map<ApiMailboxCoverageState, number>;
  subscriptions: { active: number; expiring: number; missing: number };
}

/**
 * The health role (design D11.2, D11.3, D11.5): leader-locked `GET_LOCK('eg:mailbox:health')`,
 * every `API_MODE_HEALTH_INTERVAL_MS`, per API connection: the coverage state of every mailbox
 * (`evaluateMailboxCoverage`, stored when it changes), then the connection health
 * (`evaluateApiModeHealth` over the 8.2 connection and grant, the 8.6 journal source health, the
 * feed and coverage counts, the last hour's counters and the MX observations of its API-mode
 * domains). A status transition writes, in one writer transaction with a CAS on the previous
 * status: the connection (`health_status`, `health_checks`, `health_changed_at`), a system audit
 * row `api_mode.health_changed` and — for `degraded` / `failing`, at most once per connection per
 * `API_MODE_ALERT_MIN_INTERVAL_HOURS` (`health_alerted_at` and a `notification_alert_windows`
 * row) — the `notification.alert_requested.v1` outbox row of kind `api_mode_unhealthy`. Gauges
 * carry no organization label. Tenant from the connection row only; never an address anywhere.
 */
export class HealthJob {
  constructor(private readonly deps: HealthDeps) {}

  async runOnce(): Promise<HealthReport> {
    const now = this.deps.now();
    const report: HealthReport = {
      connections: 0,
      transitions: 0,
      alerts: 0,
      throttled: 0,
      coverageChanges: 0,
      failed: 0,
    };
    const health = new Map<ApiModeHealthStatus, number>(HEALTH_VALUES.map((h) => [h, 0]));
    const coverage = new Map<ApiMailboxCoverageState, number>(COVERAGE_VALUES.map((c) => [c, 0]));
    const subscriptions = { active: 0, expiring: 0, missing: 0 };
    const states = new Map<bigint, OrgApiModeState | null>();
    let after = 0n;
    for (;;) {
      const page = await this.deps.prisma.apiModeConnection.findMany({
        where: {
          id: { gt: after },
          ...(this.deps.organizationIds
            ? { organizationId: { in: [...this.deps.organizationIds] } }
            : {}),
        },
        orderBy: { id: 'asc' },
        take: PAGE,
        select: { id: true, organizationId: true, healthStatus: true },
      });
      for (const row of page) {
        report.connections += 1;
        try {
          let state = states.get(row.organizationId);
          if (state === undefined) {
            state = await loadOrgApiModeState(this.deps.prisma, row.organizationId);
            states.set(row.organizationId, state);
          }
          const ctx = await loadConnectionContext(this.deps.prisma, row.id);
          if (!ctx || !state) continue;
          const summary = await this.coverage(ctx, state, now);
          report.coverageChanges += summary.changes;
          for (const [c, n] of summary.byState) coverage.set(c, (coverage.get(c) ?? 0) + n);
          subscriptions.active += summary.subscriptions.active;
          subscriptions.expiring += summary.subscriptions.expiring;
          subscriptions.missing += summary.subscriptions.missing;
          const status = await this.evaluate(ctx, state, summary, now, report);
          health.set(status, (health.get(status) ?? 0) + 1);
        } catch (error) {
          report.failed += 1;
          health.set(row.healthStatus, (health.get(row.healthStatus) ?? 0) + 1);
          this.deps.logger.warn(
            { apiConnectionId: row.id.toString(), ...errorFields(error) },
            'api-mode connection health not evaluated; retried next run',
          );
        }
      }
      if (page.length < PAGE) break;
      after = page[page.length - 1]!.id;
    }
    const m = this.deps.metrics;
    if (m) {
      for (const [provider, b] of await this.remediationBacklog(now)) {
        m.remediationBacklog.set({ provider }, b.count);
        m.remediationOldestPending.set({ provider }, b.oldestSeconds);
      }
      for (const [h, n] of health) m.connections.set({ health: h }, n);
      for (const [c, n] of coverage) m.mailboxes.set({ coverage: c }, n);
      m.subscriptions.set({ state: 'active' }, subscriptions.active);
      m.subscriptions.set({ state: 'expiring' }, subscriptions.expiring);
      m.subscriptions.set({ state: 'missing' }, subscriptions.missing);
    }
    return report;
  }

  /** D11.2 coverage of every mailbox of the connection (changed states written in batches). */
  private async coverage(
    ctx: ConnectionContext,
    state: OrgApiModeState,
    now: Date,
  ): Promise<CoverageSummary> {
    const cfg = this.deps.config;
    const notify = ctx.feedMode === 'notify' && cfg.notificationsAvailable;
    const coverageConfig = {
      feedPollIntervalSeconds: notify ? cfg.safetyPollSeconds : cfg.feedPollSeconds,
      journalCoverageDays: cfg.journalCoverageDays,
    };
    const summary: CoverageSummary = {
      covered: 0,
      gap: 0,
      inScope: 0,
      feedMailboxes: 0,
      activeFeeds: 0,
      errorFeeds: 0,
      changes: 0,
      byState: new Map(),
      subscriptions: { active: 0, expiring: 0, missing: 0 },
    };
    const modes = new Map(state.domains.map((d) => [d.id, d.effectiveMode]));
    const renewMs = cfg.renewBeforeMinutes * 60_000;
    let after = 0n;
    for (;;) {
      const rows = await this.deps.prisma.apiMailbox.findMany({
        where: { apiConnectionId: ctx.id, organizationId: ctx.organizationId, id: { gt: after } },
        orderBy: { id: 'asc' },
        take: MAILBOX_PAGE,
        select: {
          id: true,
          status: true,
          domainId: true,
          feedStatus: true,
          lastSyncAt: true,
          journalLastSeenAt: true,
          coverageState: true,
          subscriptionId: true,
          subscriptionExpiresAt: true,
        },
      });
      const changed = new Map<ApiMailboxCoverageState, bigint[]>();
      for (const m of rows) {
        const mode = m.domainId === null ? null : (modes.get(m.domainId) ?? null);
        const next = evaluateMailboxCoverage(
          {
            status: m.status,
            domainEffectiveMode: mode,
            feedStatus: m.feedStatus,
            lastSyncAt: m.lastSyncAt,
            journalLastSeenAt: m.journalLastSeenAt,
          },
          now,
          coverageConfig,
        );
        summary.byState.set(next, (summary.byState.get(next) ?? 0) + 1);
        if (next !== m.coverageState) {
          const list = changed.get(next) ?? [];
          list.push(m.id);
          changed.set(next, list);
        }
        const inScope = m.status === 'active' && isApiSide(mode);
        if (inScope) {
          summary.inScope += 1;
          if (next === 'covered') summary.covered += 1;
          else if (next === 'gap') summary.gap += 1;
        }
        if (m.feedStatus !== 'off') {
          summary.feedMailboxes += 1;
          if (m.feedStatus === 'active') summary.activeFeeds += 1;
          if (m.feedStatus === 'error') summary.errorFeeds += 1;
          if (notify && ctx.provider === 'microsoft_365' && m.feedStatus !== 'revoked') {
            if (!m.subscriptionId || !m.subscriptionExpiresAt) summary.subscriptions.missing += 1;
            else if (m.subscriptionExpiresAt.getTime() - renewMs <= now.getTime()) {
              summary.subscriptions.expiring += 1;
            } else summary.subscriptions.active += 1;
          }
        }
      }
      for (const [next, ids] of changed) {
        summary.changes += await this.deps.prisma.$executeRaw`
          UPDATE api_mailboxes SET coverage_state = ${next}, coverage_changed_at = ${now}
          WHERE id IN (${Prisma.join(ids)}) AND organization_id = ${ctx.organizationId}`;
      }
      if (rows.length < MAILBOX_PAGE) break;
      after = rows[rows.length - 1]!.id;
    }
    return summary;
  }

  /** The D11.3 inputs other than coverage, then the evaluation and (on a transition) the writes. */
  private async evaluate(
    ctx: ConnectionContext,
    state: OrgApiModeState,
    summary: CoverageSummary,
    now: Date,
    report: HealthReport,
  ): Promise<ApiModeHealthStatus> {
    const prisma = this.deps.prisma;
    const sources = await prisma.journalIntakeSource.findMany({
      where: {
        organizationId: ctx.organizationId,
        providerConnectionId: ctx.providerConnectionId,
        status: { not: 'disabled' },
        kind: { in: [...PROVIDER_JOURNAL_KINDS] },
        verifiedAt: { not: null },
      },
      orderBy: { id: 'asc' },
      select: { healthStatus: true },
      take: 1,
    });
    const since = hourOf(new Date(now.getTime() - 3_600_000));
    const counters = await prisma.apiModeCounter.findMany({
      where: { apiConnectionId: ctx.id, organizationId: ctx.organizationId, hour: { gte: since } },
      select: {
        lagLe60s: true,
        lagLe300s: true,
        lagLe900s: true,
        lagLe3600s: true,
        lagGt3600s: true,
        lagMaxMs: true,
        throttled429: true,
        throttled503: true,
        remediationSucceeded: true,
        remediationFailed: true,
      },
    });
    const buckets: Record<LagBucket, number> = {
      le_60s: 0,
      le_300s: 0,
      le_900s: 0,
      le_3600s: 0,
      gt_3600s: 0,
    };
    let maxMs = 0;
    let throttles = 0;
    let remediationSucceeded = 0;
    let remediationFailed = 0;
    for (const c of counters) {
      remediationSucceeded += c.remediationSucceeded;
      remediationFailed += c.remediationFailed;
      buckets.le_60s += c.lagLe60s;
      buckets.le_300s += c.lagLe300s;
      buckets.le_900s += c.lagLe900s;
      buckets.le_3600s += c.lagLe3600s;
      buckets.gt_3600s += c.lagGt3600s;
      maxMs = Math.max(maxMs, c.lagMaxMs);
      throttles += c.throttled429 + c.throttled503;
    }
    const linked = new Set(ctx.linkedDomainIds.map(String));
    const apiDomains = state.domains
      .filter((d) => d.effectiveMode === 'api' && linked.has(d.id.toString()))
      .map((d) => d.id);
    const gatewayMx =
      apiDomains.length === 0
        ? 0
        : (
            await prisma.domainMxRecord.groupBy({
              by: ['domainId'],
              where: {
                organizationId: ctx.organizationId,
                domainId: { in: apiDomains },
                pointsToGateway: true,
              },
            })
          ).length;
    const input: ApiModeHealthInput = {
      connection: { active: ctx.providerConnectionStatus === 'active', bound: ctx.bound },
      journal: {
        verifiedSource: sources.length > 0,
        sourceHealth: sources[0]?.healthStatus ?? null,
      },
      grantStatus: ctx.grant?.status ?? null,
      feeds: {
        enabled: ctx.feedsEnabled,
        feedMailboxes: summary.feedMailboxes,
        activeMailboxes: summary.activeFeeds,
        errorMailboxes: summary.errorFeeds,
      },
      coverage: {
        inventoryOk: ctx.inventoryStatus === 'ok',
        inScopeMailboxes: summary.inScope,
        covered: summary.covered,
        gap: summary.gap,
      },
      lagP95SecondsLastHour: lagPercentileSeconds(buckets, 0.95, maxMs),
      throttleEventsLastHour: throttles,
      apiModeDomainsWithGatewayMx: gatewayMx,
      remediation: await this.remediationInput(ctx, state, now, {
        succeeded1h: remediationSucceeded,
        failed1h: remediationFailed,
      }),
    };
    const result = evaluateApiModeHealth(input, this.deps.config);
    const document = result.document as unknown as Prisma.InputJsonValue;
    if (result.status === ctx.healthStatus) {
      await prisma.apiModeConnection.updateMany({
        where: { id: ctx.id, organizationId: ctx.organizationId, healthStatus: ctx.healthStatus },
        data: { healthChecks: document },
      });
      return result.status;
    }
    const intervalMs = this.deps.config.alertMinIntervalHours * 3_600_000;
    const alerting = result.status === 'degraded' || result.status === 'failing';
    const recentlyAlerted =
      ctx.healthAlertedAt !== null && now.getTime() - ctx.healthAlertedAt.getTime() < intervalMs;
    const outcome = await prisma.$transaction(async (tx) => {
      const changed = await tx.$executeRaw`
        UPDATE api_mode_connections
        SET health_status = ${result.status}, health_checks = ${JSON.stringify(result.document)},
            health_changed_at = ${now}, updated_at = ${now}
        WHERE id = ${ctx.id} AND organization_id = ${ctx.organizationId}
          AND health_status = ${ctx.healthStatus}`;
      if (changed !== 1) return 'raced' as const;
      await systemAudit(tx, {
        organizationId: ctx.organizationId,
        action: 'api_mode.health_changed',
        resourceType: 'api_mode_connection',
        resourceId: ctx.publicId,
        correlationId: `api-mode-health:${ctx.publicId}`,
        metadata: {
          connectionId: ctx.publicId,
          from: ctx.healthStatus,
          to: result.status,
          failingChecks: result.failingChecks,
        },
      });
      if (!alerting) return 'no_alert' as const;
      if (recentlyAlerted) return 'throttled' as const;
      const requested = await this.requestAlert(tx, {
        organizationId: ctx.organizationId,
        connectionPublicId: ctx.publicId,
        severity: result.status === 'failing' ? 'high' : 'medium',
        transitionId: uuidv7(now.getTime()),
        now,
      });
      if (!requested) return 'throttled' as const;
      await tx.$executeRaw`
        UPDATE api_mode_connections SET health_alerted_at = ${now}
        WHERE id = ${ctx.id} AND organization_id = ${ctx.organizationId}`;
      return 'alerted' as const;
    });
    if (outcome === 'raced') return result.status;
    report.transitions += 1;
    this.deps.metrics?.healthTransitions.inc({ health: result.status });
    if (outcome === 'alerted') {
      report.alerts += 1;
      this.deps.metrics?.alerts.inc({ result: 'requested' });
    } else if (outcome === 'throttled') {
      report.throttled += 1;
      this.deps.metrics?.alerts.inc({ result: 'throttled' });
    }
    this.deps.logger.info(
      {
        apiConnectionId: ctx.publicId,
        organizationId: ctx.organizationId.toString(),
        from: ctx.healthStatus,
        to: result.status,
        failingChecks: result.failingChecks,
        alert: outcome,
      },
      'api-mode connection health changed',
    );
    return result.status;
  }

  /**
   * Step API-2 R14: the remediation facts of a connection — the last hour's remediation counters,
   * the age of the oldest `pending` / `in_progress` action (throttle-delayed rows count; policy
   * rows of a paused connection do not, the pause is its own check), whether the effective policy
   * of an api/hybrid domain of the connection enforces while no mailbox-access grant is active,
   * and the pause flag.
   */
  private async remediationInput(
    ctx: ConnectionContext,
    state: OrgApiModeState,
    now: Date,
    counts: { succeeded1h: number; failed1h: number },
  ): Promise<ApiModeRemediationHealthInput> {
    const prisma = this.deps.prisma;
    const flags = await prisma.$queryRaw<Array<{ remediation_paused: unknown }>>`
      SELECT remediation_paused FROM api_mode_connections
      WHERE id = ${ctx.id} AND organization_id = ${ctx.organizationId}`;
    const paused = bool(flags[0]?.remediation_paused);
    const oldest = await prisma.apiRemediationAction.findFirst({
      where: {
        apiConnectionId: ctx.id,
        organizationId: ctx.organizationId,
        status: { in: ['pending', 'in_progress'] },
        trigger: {
          in: paused
            ? ['admin', 'release', 'end_user']
            : ['policy', 'admin', 'release', 'end_user'],
        },
      },
      orderBy: { createdAt: 'asc' },
      select: { createdAt: true },
    });
    let enforceWithoutGrant = false;
    if (ctx.grant?.status !== 'active') {
      const linked = new Set(ctx.linkedDomainIds.map(String));
      for (const d of state.domains) {
        if (!linked.has(d.id.toString()) || !isApiSide(d.effectiveMode)) continue;
        const effective = await this.deps.policies.effective(prisma, ctx.organizationId, d.id);
        if (effective.policy.mode === 'enforce' && effective.policy.document.rules.length > 0) {
          enforceWithoutGrant = true;
          break;
        }
      }
    }
    return {
      succeeded1h: counts.succeeded1h,
      failed1h: counts.failed1h,
      oldestPendingAgeSeconds: oldest
        ? Math.max(0, Math.floor((now.getTime() - oldest.createdAt.getTime()) / 1000))
        : null,
      enforceWithoutGrant,
      paused,
      thresholds: this.deps.config.remediation,
    };
  }

  /**
   * `api_mode_remediation_backlog{provider}` and `api_mode_remediation_oldest_pending_seconds`:
   * pending or in-progress actions per provider and the age of the oldest (0 when none).
   */
  async remediationBacklog(
    now: Date,
  ): Promise<Map<string, { count: number; oldestSeconds: number }>> {
    const orgs = this.deps.organizationIds;
    const rows = await this.deps.prisma.$queryRaw<
      Array<{ provider: string; n: bigint | number; oldest: Date | null }>
    >`
      SELECT c.provider AS provider, COUNT(*) AS n, MIN(a.created_at) AS oldest
      FROM api_remediation_actions a
      JOIN api_mode_connections c ON c.id = a.api_connection_id
      WHERE a.status IN ('pending', 'in_progress')
        ${orgs ? Prisma.sql`AND a.organization_id IN (${Prisma.join(orgs)})` : Prisma.empty}
      GROUP BY c.provider`;
    const out = new Map<string, { count: number; oldestSeconds: number }>([
      ['microsoft_365', { count: 0, oldestSeconds: 0 }],
      ['google_workspace', { count: 0, oldestSeconds: 0 }],
    ]);
    for (const r of rows) {
      out.set(r.provider, {
        count: Number(r.n),
        oldestSeconds: r.oldest
          ? Math.max(0, Math.floor((now.getTime() - r.oldest.getTime()) / 1000))
          : 0,
      });
    }
    return out;
  }

  /**
   * The throttle window (`notification_alert_windows`, size `API_MODE_ALERT_MIN_INTERVAL_HOURS`,
   * scope = the API connection public id) and, for its first event only, the
   * `notification.alert_requested.v1` outbox row (aggregate `organization`). True when requested.
   */
  private async requestAlert(
    tx: Prisma.TransactionClient,
    input: {
      organizationId: bigint;
      connectionPublicId: string;
      severity: 'medium' | 'high';
      transitionId: string;
      now: Date;
    },
  ): Promise<boolean> {
    const minutes = this.deps.config.alertMinIntervalHours * 60;
    const window = alertWindowOf(input.now, minutes);
    const affected = await tx.$executeRaw`
      INSERT INTO notification_alert_windows
        (organization_id, kind, scope_key, window_start, event_count, first_source_event_id,
         created_at, updated_at)
      VALUES (${input.organizationId}, ${API_MODE_ALERT_KIND}, ${input.connectionPublicId},
              ${window.from}, 1, ${input.transitionId}, NOW(3), NOW(3))
      ON DUPLICATE KEY UPDATE event_count = event_count + 1, updated_at = NOW(3)`;
    // MySQL: 1 = inserted (first event of the window), 2 = an existing window was counted.
    if (affected !== 1) return false;
    const previous = await tx.$queryRaw<Array<{ event_count: number | bigint }>>`
      SELECT event_count FROM notification_alert_windows
      WHERE organization_id = ${input.organizationId} AND kind = ${API_MODE_ALERT_KIND}
        AND scope_key = ${input.connectionPublicId}
        AND window_start = ${new Date(window.from.getTime() - minutes * 60_000)}`;
    const suppressedBefore = Math.max(0, Number(previous[0]?.event_count ?? 0) - 1);
    const eventId = uuidv7(input.now.getTime());
    const payload = notificationAlertRequestedV1.parse({
      kind: API_MODE_ALERT_KIND,
      severity: input.severity,
      refs: { apiModeConnectionId: input.connectionPublicId },
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
        correlationId: `api-mode-health:${input.connectionPublicId}`,
        payload,
      },
      select: { id: true },
    });
    await tx.$executeRaw`
      UPDATE notification_alert_windows SET alert_event_id = ${eventId}
      WHERE organization_id = ${input.organizationId} AND kind = ${API_MODE_ALERT_KIND}
        AND scope_key = ${input.connectionPublicId} AND window_start = ${window.from}`;
    return true;
  }
}

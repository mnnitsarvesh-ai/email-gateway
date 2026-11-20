import {
  activityFromRow,
  ATO_BASELINE_VERSION,
  atoMailKey,
  buildBaseline,
  type GEOIP_DATABASES,
  resolveAtoSettings,
  RESPONSE_STATUSES,
  type AtoStore,
  type ProviderActionResult,
  type ProviderRegistry,
} from '@email-gateway/ato-detection';
import { type Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  SECURITY_INCIDENT_RESOLUTION_CODES,
  SECURITY_INCIDENT_SEVERITIES,
} from '@email-gateway/security-contracts';
import type { MailHandler } from '../detect/mail.handler';
import type { WorkerCapabilities } from '../detect/pipeline';
import type { AtoGeoIp } from '../enrichment/geoip';
import type { AtoReputation } from '../enrichment/reputation';
import type { AtoMetrics } from '../metrics/ato-metrics';
import { atoEnabled, ATO_FEATURE_KEY, type OrgContextCache } from '../reads/org-context';
import {
  failedResult,
  PROVIDER_CALL_TIMEOUT_MS,
  RESPONSE_MAX_ATTEMPTS,
  RESPONSE_STALE_AFTER_MS,
} from '../respond/respond.consumer';
import { IDP_KINDS } from '../provider/provider-context';
import type { IdpActionExecutor, IdpCallOutcome } from '../respond/idp-actions';
import { big, LEDGERS, orgFilter, readCursor, writeCursor, type AtoDb } from '../shared/db';
import { errorFields } from '../shared/errors';
import { localDayStart, localParts } from './time';

/** `system_settings` key of the worker capabilities read by the api (D17). */
export const CAPABILITIES_KEY = 'ato.worker.capabilities';
export const CAPABILITIES_INTERVAL_MS = 5 * 60_000;
/** Accounts without an event for this long are retired (D22, 13 months). */
export const ACCOUNT_IDLE_DAYS = 395;
const RESTRICTION_RETENTION_DAYS = 400;
/** Step 8.5 (§4.1): removed mailbox items are kept 400 days after `removed_at`. */
export const IDP_REMOVED_ITEM_RETENTION_DAYS = 400;
/** Step 8.5 (§4.1, D4): stream rows and items of disabled integrations are kept 30 days. */
export const IDP_DISABLED_INTEGRATION_RETENTION_DAYS = 30;
const TRUSTED_CONTEXT_GRACE_DAYS = 30;
const SETTINGS_VERSION_RETENTION_DAYS = 730;
const PURGE_BATCH = 500;
const SWEEP_BATCH = 200;
const DECAY_BATCH = 500;
const CONFIRM_BATCH = 50;
const BASELINE_AUTH_EVENTS = 5000;
const DAY_MS = 86_400_000;

export interface MaintenanceConfig {
  mailCatchupLagSeconds: number;
  mailCatchupBatch: number;
  mailCatchupMaxAgeHours: number;
  decayIntervalSeconds: number;
  baselineRebuildHourUtc: number;
  baselineBatch: number;
  retentionIncidentDays: number;
  digestEnabled: boolean;
}

export interface MaintenanceDeps {
  db: AtoDb;
  prisma: PrismaClient;
  store: AtoStore;
  orgs: OrgContextCache;
  mail: MailHandler;
  registry: ProviderRegistry;
  geo: AtoGeoIp;
  reputation: AtoReputation;
  capabilities: WorkerCapabilities;
  metrics: AtoMetrics | null;
  logger: Logger;
  now: () => Date;
  config: MaintenanceConfig;
  organizationIds?: readonly bigint[];
  /** Step 8.5: confirmations of identity-provider actions (D9.4) and their timeout. */
  idp?: { executor: IdpActionExecutor; confirmTimeoutMinutes: number } | null;
}

/**
 * The maintenance role's jobs (D3, D9, D11, D13, D15, D16, D17, D22); each runs leader-elected
 * (`GET_LOCK('eg:ato:<job>')`, see `AtoComponents`) and returns `true` when it left work for an
 * immediate next pass. Platform-wide sweeps take bounded batches; every row they act on is
 * echo-checked by the store.
 */
export class AtoMaintenance {
  private lastCapabilitiesAt = 0;
  private resolvedSince: Date | null = null;

  constructor(private readonly deps: MaintenanceDeps) {}

  /** ATO-enabled organizations (feature on, active), restricted in tests. */
  private async enabledOrganizations(): Promise<bigint[]> {
    const rows = await this.deps.prisma.$queryRaw<Array<{ id: bigint | number }>>`
      SELECT o.id FROM organizations o
      JOIN organization_features f
        ON f.organization_id = o.id AND f.feature_key = ${ATO_FEATURE_KEY} AND f.enabled = 1
      WHERE o.status = 'active' ${orgFilter('o.id', this.deps.organizationIds)}
      ORDER BY o.id`;
    return rows.map((r) => big(r.id));
  }

  // ------------------------------------------------------------------ mail catch-up (D3)

  /**
   * Completeness of the lossy `ato.mail` feed: per ATO-enabled organization, walks
   * `email_messages` (outbound/internal) from its cursor (`ato-mail-catchup:<org>`) up to
   * `now − ATO_MAIL_CATCHUP_LAG_SECONDS`, takes each message's latest completed scan round and
   * processes the keys the ledger does not have through the live handler.
   */
  async mailCatchup(): Promise<boolean> {
    const { prisma, config } = this.deps;
    const now = this.deps.now();
    const end = new Date(now.getTime() - config.mailCatchupLagSeconds * 1000);
    let more = false;
    let lag = 0;
    for (const orgId of await this.enabledOrganizations()) {
      const ctx = await this.deps.orgs.get(orgId);
      if (!atoEnabled(ctx)) continue;
      const name = `ato-mail-catchup:${orgId}`;
      const cursor = await readCursor(prisma, name);
      const floor = new Date(now.getTime() - config.mailCatchupMaxAgeHours * 3_600_000);
      const enabledAt = ctx.featureEnabledAt ?? now;
      const start =
        cursor?.lastEventAt ?? new Date(Math.max(floor.getTime(), enabledAt.getTime()) - 1);
      const startId = cursor?.positionId ?? 0n;
      if (start >= end) continue;
      const rows = await prisma.$queryRaw<
        Array<{ id: bigint | number; received_at: Date; direction: string }>
      >`
        SELECT id, received_at, direction FROM email_messages
        WHERE organization_id = ${orgId}
          AND received_at <= ${end}
          AND (received_at > ${start} OR (received_at = ${start} AND id > ${startId}))
          AND direction IN ('outbound', 'internal')
        ORDER BY received_at, id
        LIMIT ${config.mailCatchupBatch}`;
      for (const row of rows) {
        const messageId = big(row.id);
        const receivedAt = row.received_at;
        const scan = await prisma.emailScan.findFirst({
          where: { messageId, receivedAt, organizationId: orgId, status: 'completed' },
          orderBy: { lifecycleRound: 'desc' },
          select: { id: true, scanVerdict: true, reasonCodes: true, organizationId: true },
        });
        if (!scan || scan.organizationId !== orgId) continue;
        if (await this.deps.db.processed(LEDGERS.mail, atoMailKey(messageId, scan.id))) continue;
        const result = await this.deps.mail.process(ctx, {
          messageId,
          receivedAt,
          scanId: scan.id,
          direction: row.direction as 'outbound' | 'internal',
          verdict: scan.scanVerdict,
          reasonCodes: Array.isArray(scan.reasonCodes)
            ? scan.reasonCodes.filter((c): c is string => typeof c === 'string')
            : [],
        });
        if (result === 'processed') this.deps.metrics?.catchupProcessed.inc();
      }
      const last = rows[rows.length - 1];
      if (last) await writeCursor(prisma, name, big(last.id), last.received_at);
      if (rows.length === config.mailCatchupBatch) {
        more = true;
        lag = Math.max(
          lag,
          (now.getTime() - (last?.received_at.getTime() ?? now.getTime())) / 1000,
        );
      }
    }
    this.deps.metrics?.catchupLag.set(lag);
    return more;
  }

  // ------------------------------------------------------------------ decay (D11)

  async decaySweep(): Promise<boolean> {
    const now = this.deps.now();
    const before = new Date(now.getTime() - this.deps.config.decayIntervalSeconds * 1000);
    const rows = await this.deps.prisma.$queryRaw<
      Array<{ id: bigint | number; organization_id: bigint | number }>
    >`
      SELECT id, organization_id FROM ato_accounts
      WHERE risk_score > 0 AND risk_updated_at < ${before}
        ${orgFilter('organization_id', this.deps.organizationIds)}
      ORDER BY risk_updated_at, id
      LIMIT ${DECAY_BATCH}`;
    for (const row of rows) {
      const organizationId = big(row.organization_id);
      await this.deps.db.transaction(async (tx) => {
        const settings = await this.deps.store.ensureSettings(tx, organizationId);
        await this.deps.store.rescore(tx, {
          organizationId,
          accountId: big(row.id),
          trigger: 'decay',
          settings,
        });
      });
    }
    return rows.length === DECAY_BATCH;
  }

  // ------------------------------------------------------------------ baselines (D9)

  /** The rebuild cutoff: today's `ATO_BASELINE_REBUILD_HOUR_UTC` if passed, else yesterday's. */
  rebuildCutoff(now: Date): Date {
    const today = new Date(
      Date.UTC(
        now.getUTCFullYear(),
        now.getUTCMonth(),
        now.getUTCDate(),
        this.deps.config.baselineRebuildHourUtc,
      ),
    );
    return today <= now ? today : new Date(today.getTime() - DAY_MS);
  }

  async baselineRebuild(): Promise<boolean> {
    const now = this.deps.now();
    const cutoff = this.rebuildCutoff(now);
    const activeSince = new Date(now.getTime() - 60 * DAY_MS);
    const rows = await this.deps.prisma.$queryRaw<
      Array<{ id: bigint | number; organization_id: bigint | number }>
    >`
      SELECT a.id, a.organization_id FROM ato_accounts a
      LEFT JOIN ato_account_baselines b ON b.account_id = a.id
      WHERE a.status = 'active' AND a.last_seen_at >= ${activeSince}
        AND (b.rebuilt_at < ${cutoff} OR (b.account_id IS NULL AND a.first_seen_at < ${cutoff}))
        ${orgFilter('a.organization_id', this.deps.organizationIds)}
      ORDER BY a.id
      LIMIT ${this.deps.config.baselineBatch}`;
    for (const row of rows) {
      try {
        await this.rebuildOne(big(row.organization_id), big(row.id), now);
        this.deps.metrics?.baselineRebuild.inc({ result: 'rebuilt' });
      } catch (error) {
        this.deps.metrics?.baselineRebuild.inc({ result: 'error' });
        this.deps.logger.warn({ ...errorFields(error) }, 'ato baseline rebuild failed');
      }
    }
    return rows.length === this.deps.config.baselineBatch;
  }

  /** Rebuilds one account's `ato-baseline/1` from its daily rows and successful auth events. */
  async rebuildOne(organizationId: bigint, accountId: bigint, now: Date): Promise<void> {
    const { prisma } = this.deps;
    const loaded = await this.deps.store.loadSettings(prisma, organizationId);
    const settings = loaded?.settings ?? resolveAtoSettings(null).settings;
    const ctx = await this.deps.orgs.get(organizationId);
    const windowEnd = new Date(Math.floor(now.getTime() / DAY_MS) * DAY_MS);
    const windowStart = new Date(windowEnd.getTime() - settings.baselines.windowDays * DAY_MS);
    const [days, auth, existing] = await Promise.all([
      prisma.atoAccountActivityDaily.findMany({
        where: { organizationId, accountId, dayStart: { gte: windowStart, lt: windowEnd } },
      }),
      prisma.atoAuthEvent.findMany({
        where: {
          organizationId,
          accountId,
          outcome: 'success',
          occurredAt: { gte: windowStart, lt: now },
        },
        select: {
          occurredAt: true,
          outcome: true,
          channel: true,
          ipPrefix: true,
          countryCode: true,
          asn: true,
          deviceHash: true,
          organizationId: true,
        },
        orderBy: { occurredAt: 'desc' },
        take: BASELINE_AUTH_EVENTS,
      }),
      prisma.atoAccountBaseline.findUnique({ where: { accountId } }),
    ]);
    const baseline = buildBaseline(
      days.filter((d) => d.organizationId === organizationId).map(activityFromRow),
      auth
        .filter((a) => a.organizationId === organizationId)
        .map((a) => ({
          occurredAt: a.occurredAt,
          outcome: a.outcome,
          channel: a.channel,
          ipPrefix: a.ipPrefix,
          countryCode: a.countryCode,
          asn: a.asn,
          deviceHash: a.deviceHash,
        })),
      settings,
      now,
      ctx.timeZone,
    );
    const data = {
      organizationId,
      baseline: baseline as unknown as Prisma.InputJsonValue,
      version: ATO_BASELINE_VERSION,
      eventCount: baseline.eventCount,
      activeDays: baseline.activeDays,
      mature: baseline.mature,
      maturedAt: baseline.mature ? (existing?.maturedAt ?? now) : null,
      windowStart: new Date(baseline.windowStart),
      windowEnd: new Date(baseline.windowEnd),
      rebuiltAt: now,
    };
    await prisma.atoAccountBaseline.upsert({
      where: { accountId },
      create: { accountId, ...data },
      update: data,
    });
  }

  // ------------------------------------------------------------------ expiry (D13, D14)

  async expiry(): Promise<boolean> {
    const approvals = await this.deps.db.transaction((tx) =>
      this.deps.store.expireApprovals(tx, { limit: SWEEP_BATCH }),
    );
    const restrictions = await this.deps.db.transaction((tx) =>
      this.deps.store.expireRestrictions(tx, { limit: SWEEP_BATCH }),
    );
    // Provider actions the respond role gave up on (D15): `approved` (or an unpolled rollback)
    // with no progress past the queue's retry horizon end `provider_retry_exhausted`.
    const stale = await this.deps.db.transaction((tx) =>
      this.deps.store.failStaleProviderActions(tx, {
        before: new Date(this.deps.now().getTime() - RESPONSE_STALE_AFTER_MS),
        limit: SWEEP_BATCH,
        ...(this.deps.organizationIds !== undefined && {
          organizationIds: this.deps.organizationIds,
        }),
      }),
    );
    if (approvals > 0)
      this.deps.metrics?.responses.inc({ action: 'any', outcome: 'expired' }, approvals);
    if (stale > 0) {
      this.deps.metrics?.responses.inc({ action: 'any', outcome: 'failed' }, stale);
      this.deps.logger.warn({ count: stale }, 'ato provider actions failed after retry horizon');
    }
    return approvals === SWEEP_BATCH || restrictions === SWEEP_BATCH || stale === SWEEP_BATCH;
  }

  // ------------------------------------------------------------------ provider confirmations (D15)

  async providerConfirmations(): Promise<boolean> {
    const now = this.deps.now();
    const rows = await this.deps.prisma.$queryRaw<
      Array<{ id: bigint | number; organization_id: bigint | number }>
    >`
      SELECT id, organization_id FROM ato_response_actions
      WHERE status IN ('executing', 'rollback_requested') AND next_check_at <= ${now}
        ${orgFilter('organization_id', this.deps.organizationIds)}
      ORDER BY next_check_at, id
      LIMIT ${CONFIRM_BATCH}`;
    for (const row of rows) {
      const action = await this.deps.prisma.atoResponseAction.findUnique({
        where: { id: big(row.id) },
      });
      if (!action || action.organizationId !== big(row.organization_id)) continue;
      if (
        !action.providerReference ||
        !(RESPONSE_STATUSES as readonly string[]).includes(action.status)
      ) {
        continue;
      }
      const phase = action.status === 'executing' ? 'execute' : 'rollback';
      const idp = this.deps.idp;
      let detail: IdpCallOutcome['detail'] | undefined;
      const adapter = this.deps.registry.get(action.provider);
      let result: ProviderActionResult;
      if (idp && (IDP_KINDS.has(action.provider) || action.integrationId !== null)) {
        // Step 8.5 (D9.4): read-back confirmation through the action's integration; after
        // ATO_IDP_CONFIRM_TIMEOUT_MINUTES the action ends failed `unconfirmed`.
        const outcome = await idp.executor.confirm(action, idp.confirmTimeoutMinutes, phase);
        result = outcome.result;
        detail = outcome.detail;
      } else if (!adapter) {
        result = { status: 'failed', code: 'adapter_unavailable', retryable: false };
      } else {
        try {
          result = await adapter.confirm(
            { type: action.actionType as never, providerReference: action.providerReference },
            AbortSignal.timeout(PROVIDER_CALL_TIMEOUT_MS),
          );
        } catch (error) {
          result = failedResult(error);
        }
        this.deps.metrics?.providerOperations.inc({
          provider: adapter.kind,
          operation: 'confirm',
          outcome: result.status,
        });
      }
      const final =
        result.status !== 'failed' ||
        !result.retryable ||
        action.attempts + 1 >= RESPONSE_MAX_ATTEMPTS;
      await this.deps.db.transaction(async (tx) => {
        const done = await this.deps.store.completeProviderAction(tx, {
          organizationId: action.organizationId,
          actionId: action.id,
          phase,
          result,
          final,
          ...(detail ? { detail } : {}),
        });
        if (!final) {
          // Retry the confirmation later (exponential in the attempts, at most 15 minutes).
          await tx.atoResponseAction.updateMany({
            where: { id: done.id, rowVersion: done.rowVersion },
            data: {
              nextCheckAt: new Date(now.getTime() + Math.min(900_000, 5000 * 2 ** done.attempts)),
              rowVersion: { increment: 1 },
            },
          });
        } else if (done.status !== action.status) {
          this.deps.metrics?.responses.inc({ action: done.actionType, outcome: done.status });
        }
      });
    }
    return rows.length === CONFIRM_BATCH;
  }

  // ------------------------------------------------------------------ digests (D16)

  /**
   * Daily (previous local day) and weekly (previous ISO week, on Mondays) digests at
   * `notifications.digest.hourLocal` or later in the organization's time zone; the throttle window
   * (`ato_digest`, scope `daily|weekly`, window = period start) makes each exactly once per period.
   */
  async digests(): Promise<boolean> {
    if (!this.deps.config.digestEnabled) return false;
    const now = this.deps.now();
    for (const orgId of await this.enabledOrganizations()) {
      const ctx = await this.deps.orgs.get(orgId);
      if (!atoEnabled(ctx)) continue;
      const loaded = await this.deps.store.loadSettings(this.deps.prisma, orgId);
      const digest = (loaded?.settings ?? resolveAtoSettings(null).settings).notifications.digest;
      const local = localParts(now, ctx.timeZone);
      if (local.hour < digest.hourLocal) continue;
      const today = localDayStart(now, ctx.timeZone);
      if (digest.daily) {
        await this.requestDigest(orgId, 'daily', localDayStart(now, ctx.timeZone, -1), today);
      }
      if (digest.weekly && local.weekday === 1) {
        await this.requestDigest(orgId, 'weekly', localDayStart(now, ctx.timeZone, -7), today);
      }
    }
    return false;
  }

  private async requestDigest(
    organizationId: bigint,
    period: 'daily' | 'weekly',
    from: Date,
    to: Date,
  ): Promise<void> {
    const now = this.deps.now();
    await this.deps.db.transaction(async (tx) => {
      const [opened, critical, pending, restricted] = await Promise.all([
        tx.securityIncident.count({
          where: {
            organizationId,
            category: 'account_takeover',
            detectedAt: { gte: from, lt: to },
          },
        }),
        tx.securityIncident.count({
          where: {
            organizationId,
            category: 'account_takeover',
            severity: 'critical',
            status: { in: ['open', 'investigating', 'confirmed', 'mitigated'] },
          },
        }),
        tx.atoResponseAction.count({ where: { organizationId, status: 'pending_approval' } }),
        tx.atoSmtpRestriction.count({
          where: { organizationId, status: 'active', expiresAt: { gt: now } },
        }),
      ]);
      await this.deps.store.requestNotification(tx, {
        organizationId,
        kind: 'digest',
        audience: 'tenant',
        severity: null,
        refs: {},
        throttle: {
          kind: 'ato_digest',
          scope: period,
          minutes: Math.max(1, Math.round((to.getTime() - from.getTime()) / 60_000)),
          windowStart: from,
        },
        counts: {
          incidents: opened,
          criticalIncidents: critical,
          pendingApprovals: pending,
          restrictedAccounts: restricted,
        },
        digestPeriod: period,
      });
    });
  }

  // ------------------------------------------------------------------ retention (D22)

  async retention(): Promise<boolean> {
    const { db, store, prisma } = this.deps;
    const now = this.deps.now();
    const incidentsBefore = new Date(
      now.getTime() - this.deps.config.retentionIncidentDays * DAY_MS,
    );
    const incidents = await db.transaction((tx) =>
      store.purgeClosedIncidents(tx, { before: incidentsBefore, limit: PURGE_BATCH }),
    );
    const history = await db.transaction((tx) =>
      store.purgeHistory(tx, { before: incidentsBefore, limit: PURGE_BATCH }),
    );
    const filter = orgFilter('organization_id', this.deps.organizationIds);
    const restrictions = await prisma.$executeRaw`
      DELETE FROM ato_smtp_restrictions
      WHERE status IN ('lifted', 'expired')
        AND updated_at < ${new Date(now.getTime() - RESTRICTION_RETENTION_DAYS * DAY_MS)} ${filter}
      LIMIT ${PURGE_BATCH}`;
    const contexts = await prisma.$executeRaw`
      DELETE FROM ato_trusted_contexts
      WHERE expires_at < ${new Date(now.getTime() - TRUSTED_CONTEXT_GRACE_DAYS * DAY_MS)} ${filter}
      LIMIT ${PURGE_BATCH}`;
    const versions = await prisma.$queryRaw<Array<{ id: bigint | number }>>`
      SELECT v.id FROM ato_settings_versions v
      JOIN ato_settings s ON s.organization_id = v.organization_id
      WHERE v.version < s.version
        AND v.created_at < ${new Date(now.getTime() - SETTINGS_VERSION_RETENTION_DAYS * DAY_MS)}
        ${orgFilter('v.organization_id', this.deps.organizationIds)}
      LIMIT ${PURGE_BATCH}`;
    if (versions.length > 0) {
      await prisma.atoSettingsVersion.deleteMany({
        where: { id: { in: versions.map((v) => big(v.id)) } },
      });
    }
    const idp = await this.idpRetention(now);
    return [
      incidents,
      history.logs,
      history.overrides,
      restrictions,
      contexts,
      versions.length,
      idp,
    ].some((n) => n >= PURGE_BATCH);
  }

  /**
   * Step 8.5 retention (§4.1): mailbox items removed more than 400 days ago; stream rows and
   * mailbox items of integrations disabled more than 30 days ago (their signals, auth events and
   * actions follow 8.4's retention; the integration row stays while actions reference it). Returns
   * the largest batch deleted.
   */
  async idpRetention(now: Date): Promise<number> {
    const { prisma } = this.deps;
    const filter = orgFilter('organization_id', this.deps.organizationIds);
    const removed = await prisma.$executeRaw`
      DELETE FROM ato_provider_mailbox_items
      WHERE state = 'removed'
        AND removed_at < ${new Date(now.getTime() - IDP_REMOVED_ITEM_RETENTION_DAYS * DAY_MS)}
        ${filter}
      LIMIT ${PURGE_BATCH}`;
    const disabled = await prisma.$queryRaw<
      Array<{ id: bigint | number; organization_id: bigint | number }>
    >`
      SELECT id, organization_id FROM ato_provider_integrations
      WHERE status = 'disabled'
        AND disabled_at < ${new Date(now.getTime() - IDP_DISABLED_INTEGRATION_RETENTION_DAYS * DAY_MS)}
        ${filter}
      ORDER BY id
      LIMIT 50`;
    let items = 0;
    let streams = 0;
    for (const row of disabled) {
      const id = big(row.id);
      const organizationId = big(row.organization_id);
      items += await prisma.$executeRaw`
        DELETE FROM ato_provider_mailbox_items
        WHERE integration_id = ${id} AND organization_id = ${organizationId}
        LIMIT ${PURGE_BATCH}`;
      streams += await prisma.$executeRaw`
        DELETE FROM ato_provider_streams
        WHERE integration_id = ${id} AND organization_id = ${organizationId}`;
    }
    if (removed + items + streams > 0) {
      this.deps.logger.info({ removed, items, streams }, 'ato idp retention');
    }
    return Math.max(removed, items);
  }

  // ------------------------------------------------------------------ account retirement (D1, D22)

  async retirement(): Promise<boolean> {
    const { prisma } = this.deps;
    const now = this.deps.now();
    const filter = orgFilter('a.organization_id', this.deps.organizationIds);
    await prisma.$executeRaw`
      UPDATE ato_accounts a LEFT JOIN users u ON u.id = a.user_id
      SET a.status = 'retired', a.updated_at = ${now}
      WHERE a.kind = 'gateway_user' AND a.status = 'active' AND u.id IS NULL ${filter}`;
    await prisma.$executeRaw`
      UPDATE ato_accounts a LEFT JOIN smtp_connectors c ON c.id = a.connector_id
      SET a.status = 'retired', a.updated_at = ${now}
      WHERE a.kind = 'smtp_connector' AND a.status = 'active' AND c.id IS NULL ${filter}`;
    await prisma.$executeRaw`
      UPDATE ato_accounts a SET a.status = 'retired', a.updated_at = ${now}
      WHERE a.status = 'active' AND a.active_incident_id IS NULL
        AND a.last_seen_at < ${new Date(now.getTime() - ACCOUNT_IDLE_DAYS * DAY_MS)} ${filter}`;
    // Retired accounts without an active incident, incident detail or response are deleted
    // (baselines, identities, overrides and trusted contexts cascade; partitioned history ages out).
    const rows = await prisma.$queryRaw<Array<{ id: bigint | number }>>`
      SELECT a.id FROM ato_accounts a
      WHERE a.status = 'retired' AND a.active_incident_id IS NULL ${filter}
        AND NOT EXISTS (SELECT 1 FROM ato_incident_details d WHERE d.account_id = a.id)
        AND NOT EXISTS (SELECT 1 FROM ato_response_actions r WHERE r.account_id = a.id)
      LIMIT ${PURGE_BATCH}`;
    if (rows.length > 0) {
      await prisma.atoAccount.deleteMany({
        where: { id: { in: rows.map((r) => big(r.id)) }, status: 'retired' },
      });
    }
    return rows.length === PURGE_BATCH;
  }

  // ------------------------------------------------------------------ status, gauges, capabilities

  /**
   * Gauges (active incidents by severity, pending approvals, active restrictions by kind),
   * resolutions since the previous pass (`ato_incidents_resolved_total`) and, every 5 minutes,
   * the capabilities row `system_settings 'ato.worker.capabilities'` (D17).
   */
  async status(): Promise<boolean> {
    const { prisma, metrics } = this.deps;
    const now = this.deps.now();
    const filter = orgFilter('organization_id', this.deps.organizationIds);
    if (metrics) {
      const active = await prisma.$queryRaw<Array<{ severity: string; n: bigint | number }>>`
        SELECT severity, COUNT(*) AS n FROM security_incidents
        WHERE category = 'account_takeover'
          AND status IN ('open', 'investigating', 'confirmed', 'mitigated') ${filter}
        GROUP BY severity`;
      for (const s of SECURITY_INCIDENT_SEVERITIES) {
        metrics.incidentsActive.set(
          { severity: s },
          Number(active.find((r) => r.severity === s)?.n ?? 0),
        );
      }
      const [pending] = await prisma.$queryRaw<Array<{ n: bigint | number }>>`
        SELECT COUNT(*) AS n FROM ato_response_actions WHERE status = 'pending_approval' ${filter}`;
      metrics.responsesPendingApproval.set(Number(pending?.n ?? 0));
      const restrictions = await prisma.$queryRaw<Array<{ kind: string; n: bigint | number }>>`
        SELECT kind, COUNT(*) AS n FROM ato_smtp_restrictions
        WHERE status = 'active' AND expires_at > ${now} ${filter} GROUP BY kind`;
      for (const kind of ['send_block', 'auth_block']) {
        metrics.restrictionsActive.set(
          { kind },
          Number(restrictions.find((r) => r.kind === kind)?.n ?? 0),
        );
      }
      if (this.resolvedSince !== null) {
        const resolved = await prisma.$queryRaw<Array<{ code: string | null; n: bigint | number }>>`
          SELECT resolution_code AS code, COUNT(*) AS n FROM security_incidents
          WHERE category = 'account_takeover' AND status IN ('false_positive', 'resolved')
            AND resolved_at > ${this.resolvedSince} AND resolved_at <= ${now} ${filter}
          GROUP BY resolution_code`;
        for (const r of resolved) {
          const code = (SECURITY_INCIDENT_RESOLUTION_CODES as readonly string[]).includes(
            r.code ?? '',
          )
            ? r.code!
            : 'other';
          metrics.incidentsResolved.inc({ resolution: code }, Number(r.n));
        }
      }
      this.resolvedSince = now;
    }
    if (now.getTime() - this.lastCapabilitiesAt >= CAPABILITIES_INTERVAL_MS) {
      await this.writeCapabilities(now);
      this.lastCapabilitiesAt = now.getTime();
    }
    return false;
  }

  /** The number of platform breach indicators (`email`, unexpired) for the T4 capability. */
  async breachIndicatorCount(now: Date): Promise<number> {
    return this.deps.prisma.threatIndicator.count({
      where: {
        orgScope: 0n,
        indicatorType: 'email',
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
    });
  }

  async writeCapabilities(now: Date): Promise<Record<string, unknown>> {
    const status = this.deps.geo.status();
    const breach = await this.breachIndicatorCount(now);
    this.deps.capabilities.breachIndicators = breach;
    const geo = (db: (typeof GEOIP_DATABASES)[number]) => ({
      loaded: status[db].loaded,
      buildEpoch: status[db].buildEpoch,
      stale: status[db].stale,
    });
    const value = {
      geoipCity: geo('city'),
      geoipAsn: geo('asn'),
      geoipAnonymous: geo('anonymous'),
      dnsblZones: this.deps.reputation.dnsblZones,
      breachIndicators: breach,
      // 8.4 meaning kept: the singleton adapters (the fake). The step 8.5 integrations carry
      // their own effective capabilities (`ato_provider_integrations.capabilities`, D6).
      providers: this.deps.registry.singletonKinds(),
      updatedAt: now.toISOString(),
    };
    await this.deps.prisma.systemSetting.upsert({
      where: { key: CAPABILITIES_KEY },
      create: {
        key: CAPABILITIES_KEY,
        value,
        description: 'Account takeover worker capabilities (step 8.4 D17), written every 5 minutes',
      },
      update: { value },
    });
    return value;
  }
}

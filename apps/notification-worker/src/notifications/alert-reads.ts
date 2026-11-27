import type { Prisma } from '@email-gateway/database';
import {
  ALERT_SCOPE_NONE,
  parseStoredEnvelope,
  type ResolvedNotificationSettings,
  resolveNotificationSettings,
  type WebhookEnvelope,
} from '@email-gateway/webhooks';
import type { SecurityAlertKind } from './alert-templates';
import {
  findPermissionHolders,
  InconsistentNotificationReadError,
  type NoticeUser,
} from './notification-reads';

type Tx = Prisma.TransactionClient;

/**
 * How far before `window.from` (and after `window.to`) the stored public event of an alert is
 * looked up. The producer derives the window from the source envelope's `occurredAt`, which is
 * also `webhook_events.occurred_at`, so the row normally lies inside the window; the margin
 * tolerates a producer that floors a later clock and keeps the lookup on ≤ 2 monthly partitions.
 */
export const ALERT_EVENT_LOOKUP_MARGIN_MS = 24 * 3_600_000;

export interface AlertOrganization {
  id: bigint;
  publicId: string;
  name: string;
  /** `organization_settings.notification_email` (raw; validated by the handler). */
  notificationEmail: string | null;
}

export interface StoredAlertEvent {
  eventId: string;
  eventType: string;
  occurredAt: Date;
  severity: 'info' | 'low' | 'medium' | 'high';
  messageId: bigint | null;
  messageReceivedAt: Date | null;
  domainId: bigint | null;
  envelope: WebhookEnvelope;
}

export interface AlertDomain {
  id: bigint;
  publicId: string;
  name: string;
  status: string;
}

export interface AlertSubscription {
  publicId: string;
  name: string;
  status: string;
  consecutiveFailures: number;
  failingSince: Date | null;
  disabledAt: Date | null;
  disabledReason: string | null;
}

/** A provider connection of the organization (step 8.2 D12): display fields only. */
export interface AlertProviderConnection {
  publicId: string;
  displayName: string;
  provider: string;
  healthStatus: string;
}

/** A journal intake source of the organization (step 8.6 D9): display and health fields only. */
export interface AlertIntakeSource {
  publicId: string;
  displayName: string;
  kind: string;
  healthStatus: string;
  lastAcceptedAt: Date | null;
  silenceAlertMinutes: number | null;
}

/** An API-mode connection of the organization (step API-1 D11.3): display and health only. */
export interface AlertApiModeConnection {
  publicId: string;
  provider: string;
  healthStatus: string;
  /** The 8.2 provider connection's display name. */
  displayName: string;
  /** `api-mode-health/1` codes of the stored checks with status `warn` or `fail` (≤ 16). */
  failingChecks: string[];
}

/** A clawback of the organization (step API-3 C6): state, counts and approval fields only. */
export interface AlertClawback {
  publicId: string;
  trigger: string;
  status: string;
  /** Explicit action of an admin purge (null in policy mode). */
  action: string | null;
  mailboxesEligible: number;
  targetsEligible: number;
  approvalStatus: string | null;
  /** Codes (`mailbox_threshold`, `hard_delete`, `auto_cap`) from the stored JSON array. */
  approvalReasons: string[];
  approvalExpiresAt: Date | null;
}

/** The organization's user report counts (step API-3 C13), each capped at `REPORT_COUNT_CAP`. */
export interface AlertReportCounts {
  pendingTriage: number;
  inReview: number;
  /** Reports received since the start of the alert's window. */
  receivedInWindow: number;
  /** Received time of the oldest report waiting for triage (null: none). */
  oldestPendingAt: string | null;
}

/** Bounded live counts of the report alert (C13: counters capped at 10 000). */
export const REPORT_COUNT_CAP = 10_000;

const APPROVAL_REASON_CODES: ReadonlySet<string> = new Set([
  'mailbox_threshold',
  'hard_delete',
  'auto_cap',
]);

/** The known approval reason codes of a stored `approval_reasons` JSON array (pure). */
export function approvalReasonCodes(value: unknown): string[] {
  const parsed: unknown = typeof value === 'string' ? safeJson(value) : value;
  if (!Array.isArray(parsed)) return [];
  const out: string[] = [];
  for (const item of parsed) {
    if (typeof item === 'string' && APPROVAL_REASON_CODES.has(item) && !out.includes(item)) {
      out.push(item);
    }
  }
  return out;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/** Bound of the stored `api-mode-health/1` checks read for an alert. */
const MAX_API_MODE_CHECKS = 16;
const API_MODE_CHECK_CODE = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/;

/**
 * The codes of the checks that warn or fail in a stored `api-mode-health/1` document
 * (`{ v: 1, checks: [{ code, status, evidence? }] }`), in stored order; anything malformed is
 * ignored (never evidence text: it is not rendered). Pure.
 */
export function failingApiModeChecks(document: unknown): string[] {
  if (typeof document !== 'object' || document === null) return [];
  const checks = (document as { checks?: unknown }).checks;
  if (!Array.isArray(checks)) return [];
  const out: string[] = [];
  for (const check of checks.slice(0, MAX_API_MODE_CHECKS)) {
    if (typeof check !== 'object' || check === null) continue;
    const { code, status } = check as { code?: unknown; status?: unknown };
    if (typeof code !== 'string' || code.length > 64 || !API_MODE_CHECK_CODE.test(code)) continue;
    if ((status === 'warn' || status === 'fail') && !out.includes(code)) out.push(code);
  }
  return out;
}

/**
 * The writer reads of the security alerts (step 6.2 N3, N4), inside the consumer's idempotency
 * transaction, each scoped to the envelope's organization and echo-checked (4.2 §6, D15 of 6.1):
 * the organization (name, public id, notification contact), its notification settings, the
 * throttle window's event count, the stored public event the alert refers to, the message
 * identity, the tenant's domain and its failing records, the webhook subscription (name and
 * failure counters only: never its URL or secrets).
 */
export class SecurityAlertReads {
  async organization(tx: Tx, organizationId: bigint): Promise<AlertOrganization | null> {
    const org = await tx.organization.findFirst({
      where: { id: organizationId },
      select: { id: true, publicId: true, name: true },
    });
    if (org === null) return null;
    if (org.id !== organizationId) throw new InconsistentNotificationReadError('organization');
    const settings = await tx.organizationSetting.findFirst({
      where: { organizationId },
      select: { organizationId: true, notificationEmail: true },
    });
    if (settings !== null && settings.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('organization_settings');
    }
    return { ...org, notificationEmail: settings?.notificationEmail ?? null };
  }

  /** One page of the users holding `permission` (N3), sorted by id, after `afterId`, ≤ `take`. */
  holders(
    tx: Tx,
    organizationId: bigint,
    permission: string,
    take: number,
    afterId: bigint | null,
  ): Promise<NoticeUser[]> {
    return findPermissionHolders(tx, organizationId, permission, { take, afterId });
  }

  /** Effective settings (§6.3): the stored document over the defaults (invalid → defaults). */
  async settings(
    tx: Tx,
    organizationId: bigint,
  ): Promise<{ settings: ResolvedNotificationSettings; invalidStored: boolean }> {
    const row = await tx.notificationSettings.findFirst({
      where: { organizationId },
      select: { organizationId: true, settings: true },
    });
    if (row !== null && row.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('notification_settings');
    }
    return resolveNotificationSettings(row?.settings ?? null);
  }

  /** `event_count` of the alert's throttle window so far, or null when the row is gone. */
  async windowEventCount(
    tx: Tx,
    organizationId: bigint,
    kind: SecurityAlertKind,
    scopeKey: string,
    windowStart: Date,
  ): Promise<number | null> {
    const row = await tx.notificationAlertWindow.findFirst({
      where: { organizationId, kind, scopeKey, windowStart },
      select: { organizationId: true, kind: true, scopeKey: true, eventCount: true },
    });
    if (row === null) return null;
    if (row.organizationId !== organizationId || row.kind !== kind || row.scopeKey !== scopeKey) {
      throw new InconsistentNotificationReadError('notification_alert_window');
    }
    return row.eventCount;
  }

  /** The stored public event (`webhook_events`) of the organization by id near the window. */
  async webhookEvent(
    tx: Tx,
    organizationId: bigint,
    eventId: string,
    window: { from: Date; to: Date },
  ): Promise<StoredAlertEvent | null> {
    const row = await tx.webhookEvent.findFirst({
      where: {
        eventId,
        organizationId,
        occurredAt: {
          gte: new Date(window.from.getTime() - ALERT_EVENT_LOOKUP_MARGIN_MS),
          lte: new Date(window.to.getTime() + ALERT_EVENT_LOOKUP_MARGIN_MS),
        },
      },
      select: {
        eventId: true,
        organizationId: true,
        eventType: true,
        occurredAt: true,
        severity: true,
        messageId: true,
        messageReceivedAt: true,
        domainId: true,
        payloadJson: true,
      },
    });
    if (row === null) return null;
    if (row.eventId !== eventId || row.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('webhook_event');
    }
    return {
      eventId: row.eventId,
      eventType: row.eventType,
      occurredAt: row.occurredAt,
      severity: row.severity,
      messageId: row.messageId,
      messageReceivedAt: row.messageReceivedAt,
      domainId: row.domainId,
      envelope: parseStoredEnvelope(row.payloadJson),
    };
  }

  /** The message identity of the organization (public id, received time). */
  async messageIdentity(
    tx: Tx,
    organizationId: bigint,
    id: bigint,
  ): Promise<{ publicId: string; receivedAt: Date } | null> {
    const row = await tx.messageIdentity.findFirst({
      where: { id, organizationId },
      select: { id: true, organizationId: true, publicId: true, receivedAt: true },
    });
    if (row === null) return null;
    if (row.id !== id || row.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('message_identity');
    }
    return { publicId: row.publicId, receivedAt: row.receivedAt };
  }

  /** A domain of the organization by internal id (any status: the alert reports the failure). */
  async domain(tx: Tx, organizationId: bigint, id: bigint): Promise<AlertDomain | null> {
    const row = await tx.domain.findFirst({
      where: { id, organizationId },
      select: { id: true, organizationId: true, publicId: true, name: true, status: true },
    });
    if (row === null) return null;
    if (row.id !== id || row.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('domain');
    }
    return { id: row.id, publicId: row.publicId, name: row.name, status: row.status };
  }

  /** Purposes of the domain's records whose stored status is `invalid` or `missing` now. */
  async failingRecordPurposes(tx: Tx, organizationId: bigint, domainId: bigint): Promise<string[]> {
    const rows = await tx.domainDnsRecord.findMany({
      where: { organizationId, domainId, status: { in: ['invalid', 'missing'] } },
      select: { organizationId: true, domainId: true, purpose: true },
      orderBy: { id: 'asc' },
    });
    for (const r of rows) {
      if (r.organizationId !== organizationId || r.domainId !== domainId) {
        throw new InconsistentNotificationReadError('domain_dns_record');
      }
    }
    return [...new Set(rows.map((r) => r.purpose))];
  }

  /** A webhook subscription of the organization by public id: name and failure counters only. */
  async subscription(
    tx: Tx,
    organizationId: bigint,
    publicId: string,
  ): Promise<AlertSubscription | null> {
    const row = await tx.webhookSubscription.findFirst({
      where: { publicId, organizationId },
      select: {
        publicId: true,
        organizationId: true,
        name: true,
        status: true,
        consecutiveFailures: true,
        failingSince: true,
        disabledAt: true,
        disabledReason: true,
      },
    });
    if (row === null) return null;
    if (row.publicId !== publicId || row.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('webhook_subscription');
    }
    return {
      publicId: row.publicId,
      name: row.name,
      status: row.status,
      consecutiveFailures: row.consecutiveFailures,
      failingSince: row.failingSince,
      disabledAt: row.disabledAt,
      disabledReason: row.disabledReason,
    };
  }

  /**
   * An API-mode connection of the organization by public id (step API-1 D11.3): provider, health
   * now, the failing check codes and its provider connection's display name — never the tenant
   * id, grants, cursors or mailbox addresses.
   */
  async apiModeConnection(
    tx: Tx,
    organizationId: bigint,
    publicId: string,
  ): Promise<AlertApiModeConnection | null> {
    const row = await tx.apiModeConnection.findFirst({
      where: { publicId, organizationId },
      select: {
        publicId: true,
        organizationId: true,
        provider: true,
        healthStatus: true,
        healthChecks: true,
        providerConnection: { select: { organizationId: true, displayName: true } },
      },
    });
    if (row === null) return null;
    if (
      row.publicId !== publicId ||
      row.organizationId !== organizationId ||
      row.providerConnection.organizationId !== organizationId
    ) {
      throw new InconsistentNotificationReadError('api_mode_connection');
    }
    return {
      publicId: row.publicId,
      provider: row.provider,
      healthStatus: row.healthStatus,
      displayName: row.providerConnection.displayName,
      failingChecks: failingApiModeChecks(row.healthChecks),
    };
  }

  /**
   * A clawback of the organization by public id (step API-3 C6): trigger, status, action, the
   * eligible counts and the approval state — never criteria, signal documents or operator text.
   */
  async clawback(tx: Tx, organizationId: bigint, publicId: string): Promise<AlertClawback | null> {
    const row = await tx.apiClawback.findFirst({
      where: { publicId, organizationId },
      select: {
        publicId: true,
        organizationId: true,
        trigger: true,
        status: true,
        action: true,
        mailboxesEligible: true,
        targetsEligible: true,
        approvalStatus: true,
        approvalReasons: true,
        approvalExpiresAt: true,
      },
    });
    if (row === null) return null;
    if (row.publicId !== publicId || row.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('api_clawback');
    }
    return {
      publicId: row.publicId,
      trigger: row.trigger,
      status: row.status,
      action: row.action,
      mailboxesEligible: row.mailboxesEligible,
      targetsEligible: row.targetsEligible,
      approvalStatus: row.approvalStatus,
      approvalReasons: approvalReasonCodes(row.approvalReasons),
      approvalExpiresAt: row.approvalExpiresAt,
    };
  }

  /**
   * The organization's report counts (step API-3 C13): waiting for triage, in review, received
   * since `since`, and the oldest waiting report's time. Bounded (`REPORT_COUNT_CAP`), index
   * `(organization_id, status, reported_at, id)` / `(organization_id, reported_at, id)`.
   */
  async reportCounts(tx: Tx, organizationId: bigint, since: Date): Promise<AlertReportCounts> {
    const bounded = (where: Prisma.ApiUserReportWhereInput): Promise<number> =>
      tx.apiUserReport.count({ where: { organizationId, ...where }, take: REPORT_COUNT_CAP });
    const pendingTriage = await bounded({ status: 'pending_triage' });
    const inReview = await bounded({ status: 'in_review' });
    const receivedInWindow = await bounded({ reportedAt: { gte: since } });
    const oldest = await tx.apiUserReport.findFirst({
      where: { organizationId, status: 'pending_triage' },
      orderBy: [{ reportedAt: 'asc' }, { id: 'asc' }],
      select: { organizationId: true, status: true, reportedAt: true },
    });
    if (
      oldest !== null &&
      (oldest.organizationId !== organizationId || oldest.status !== 'pending_triage')
    ) {
      throw new InconsistentNotificationReadError('api_user_report');
    }
    return {
      pendingTriage,
      inReview,
      receivedInWindow,
      oldestPendingAt: oldest?.reportedAt.toISOString() ?? null,
    };
  }

  /** A journal intake source of the organization by public id (step 8.6 D9). */
  intakeSource(
    tx: Tx,
    organizationId: bigint,
    publicId: string,
  ): Promise<AlertIntakeSource | null> {
    return readIntakeSource(tx, organizationId, publicId);
  }

  /**
   * A provider connection of the organization by public id (step 8.2 D12): its name, provider and
   * current health only — never the tenant id, grants, credentials or attestations.
   */
  async providerConnection(
    tx: Tx,
    organizationId: bigint,
    publicId: string,
  ): Promise<AlertProviderConnection | null> {
    const row = await tx.providerConnection.findFirst({
      where: { publicId, organizationId },
      select: {
        publicId: true,
        organizationId: true,
        displayName: true,
        provider: true,
        healthStatus: true,
      },
    });
    if (row === null) return null;
    if (row.publicId !== publicId || row.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('provider_connection');
    }
    return {
      publicId: row.publicId,
      displayName: row.displayName,
      provider: row.provider,
      healthStatus: row.healthStatus,
    };
  }
}

/**
 * A journal intake source of the organization by public id (step 8.6 D9): display name, kind and
 * health only — never its address hash, header token hash, networks or attestations.
 */
export async function readIntakeSource(
  tx: Tx,
  organizationId: bigint,
  publicId: string,
): Promise<AlertIntakeSource | null> {
  const row = await tx.journalIntakeSource.findFirst({
    where: { publicId, organizationId },
    select: {
      publicId: true,
      organizationId: true,
      displayName: true,
      kind: true,
      healthStatus: true,
      lastAcceptedAt: true,
      silenceAlertMinutes: true,
    },
  });
  if (row === null) return null;
  if (row.publicId !== publicId || row.organizationId !== organizationId) {
    throw new InconsistentNotificationReadError('journal_intake_source');
  }
  return {
    publicId: row.publicId,
    displayName: row.displayName,
    kind: row.kind,
    healthStatus: row.healthStatus,
    lastAcceptedAt: row.lastAcceptedAt,
    silenceAlertMinutes: row.silenceAlertMinutes,
  };
}

/** `notification_alert_windows.scope_key` of an alert (N2). */
export function alertScopeKey(
  kind: SecurityAlertKind,
  scope: {
    domainPublicId?: string;
    subscriptionPublicId?: string;
    connectionPublicId?: string;
    intakeSourcePublicId?: string;
    apiModeConnectionPublicId?: string;
    clawbackPublicId?: string;
  },
): string {
  switch (kind) {
    case 'threat_detected':
      return ALERT_SCOPE_NONE;
    case 'domain_dns_failed':
      return scope.domainPublicId ?? ALERT_SCOPE_NONE;
    case 'webhook_disabled':
      return scope.subscriptionPublicId ?? ALERT_SCOPE_NONE;
    case 'integration_unhealthy':
      return scope.connectionPublicId ?? ALERT_SCOPE_NONE;
    // Step 8.6 D9: one window per journal intake source (the archive-worker's scope key).
    case 'journal_intake_silent':
      return scope.intakeSourcePublicId ?? ALERT_SCOPE_NONE;
    // Step API-1 D11.3: one window per API-mode connection (the mailbox-worker's scope key).
    case 'api_mode_unhealthy':
      return scope.apiModeConnectionPublicId ?? ALERT_SCOPE_NONE;
    // Step API-3 C6: one window per clawback (the api / mailbox-worker scope key).
    case 'api_mode_purge_approval':
      return scope.clawbackPublicId ?? ALERT_SCOPE_NONE;
    // Step API-3 C13: one window per organization.
    case 'api_mode_report_received':
      return ALERT_SCOPE_NONE;
  }
}

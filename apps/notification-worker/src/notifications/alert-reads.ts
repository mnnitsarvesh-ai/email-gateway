import type { Prisma } from '@email-gateway/database';
import {
  type AlertKind,
  ALERT_SCOPE_NONE,
  parseStoredEnvelope,
  type ResolvedNotificationSettings,
  resolveNotificationSettings,
  type WebhookEnvelope,
} from '@email-gateway/webhooks';
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
    kind: AlertKind,
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
}

/** `notification_alert_windows.scope_key` of an alert (N2). */
export function alertScopeKey(
  kind: AlertKind,
  scope: { domainPublicId?: string; subscriptionPublicId?: string },
): string {
  switch (kind) {
    case 'threat_detected':
      return ALERT_SCOPE_NONE;
    case 'domain_dns_failed':
      return scope.domainPublicId ?? ALERT_SCOPE_NONE;
    case 'webhook_disabled':
      return scope.subscriptionPublicId ?? ALERT_SCOPE_NONE;
  }
}

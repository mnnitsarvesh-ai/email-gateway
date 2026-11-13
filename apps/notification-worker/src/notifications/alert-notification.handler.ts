import { NonRetryableError } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type { EventEnvelope, NotificationAlertRequestedV1 } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  ALERT_RECIPIENT_PERMISSION,
  alertKindSettings,
  type ResolvedNotificationSettings,
  severityRank,
  type WebhookEventData,
} from '@email-gateway/webhooks';
import {
  type AlertOrganization,
  alertScopeKey,
  type SecurityAlertReads,
  type StoredAlertEvent,
} from './alert-reads';
import { type AlertFacts, renderSecurityAlert, securityAlertMessageId } from './alert-templates';
import type { NoticeMailer } from './mailer';
import type { AlertResult, NotificationMetrics } from './notification-metrics';
import { addressDomain } from './policy-notification.handler';
import type { PreferenceFilter } from './preference-filter';

export type AlertKind = NotificationAlertRequestedV1['kind'];

export interface AlertNotificationOptions {
  maxRecipients: number;
  portalUrl: string;
}

type Tx = Prisma.TransactionClient;
/** The per-kind part of `AlertFacts` (distributive: keeps the union of the three kinds). */
type KindFacts = AlertFacts extends infer F
  ? F extends AlertFacts
    ? Omit<F, 'organizationName' | 'window' | 'eventsInWindow' | 'portalUrl'>
    : never
  : never;

/**
 * Handles one `notification.alert_requested.v1` (step 6.2 N2–N4, ADR-0056) inside the consumer's
 * idempotency transaction (ledger `notification-worker.policy`). Throttling and de-duplication
 * happened at the producer (one alert per organization, kind, scope and window); this handler
 * decides at **send time** on the writer, scoped to the envelope's organization:
 *
 * 1. the tenant settings (`notification_settings`, §6.3): a kind switched off — or, for threats,
 *    a `minSeverity` raised above the alert's severity — since the request → `disabled`;
 * 2. the facts (each row echo-checked; a missing or foreign reference is dead-lettered):
 *    threat → the stored public event (verdict, stage, severity) and the message identity;
 *    DNS → the stored public event (failure kind, reason, record purposes), the tenant's domain
 *    and its records still failing; webhook disabled → the subscription's name and counters
 *    (never its URL or secret); plus the throttle window's event count;
 * 3. the recipients (N3): active, verified users holding `ALERT_RECIPIENT_PERMISSION[kind]`,
 *    minus opt-outs (`PreferenceFilter`), sorted by id, ≤ `NOTIFICATION_MAX_RECIPIENTS`; plus
 *    `organization_settings.notification_email` with `alerts.includeOrganizationContact`;
 * 4. one plain-text mail, Bcc, `Message-ID: <security-alert.<eventId>@<From domain>>`, sent
 *    before the ledger commits (at least once; a redelivery after commit sends nothing).
 */
export class AlertNotificationHandler {
  constructor(
    private readonly reads: SecurityAlertReads,
    private readonly mailer: NoticeMailer,
    private readonly metrics: NotificationMetrics,
    private readonly logger: Logger,
    private readonly options: AlertNotificationOptions,
    private readonly preferences: PreferenceFilter,
  ) {}

  async handle(event: EventEnvelope<NotificationAlertRequestedV1>, tx: Tx): Promise<AlertResult> {
    const p = event.payload;
    const kind = p.kind;
    const organizationId = BigInt(event.organizationId);
    const log = this.logger.child({
      eventId: event.eventId,
      organizationId: event.organizationId,
      kind,
    });
    const organization = await this.reads.organization(tx, organizationId);
    if (organization === null) return this.deadLetter(kind, 'organization_not_found');
    const { settings, invalidStored } = await this.reads.settings(tx, organizationId);
    if (invalidStored) {
      log.warn({ message: 'stored notification settings do not validate; defaults apply' });
    }
    if (!this.enabled(settings, p)) {
      this.count(kind, 'disabled');
      this.metrics.alertsSuppressed.inc({ kind, reason: 'disabled' });
      log.info({ message: 'security alert not sent: disabled by the tenant settings' });
      return 'disabled';
    }
    const window = { from: new Date(p.window.from), to: new Date(p.window.to) };
    const kindFacts = await this.facts(tx, organization, p, window);
    const recipients = await this.recipients(tx, organization, kind, settings);
    if (recipients.length === 0) {
      this.count(kind, 'no_recipients');
      log.info({ message: 'security alert has no recipient' });
      return 'no_recipients';
    }
    if (!this.mailer.configured || this.mailer.from === null) {
      this.count(kind, 'disabled');
      log.warn({ message: 'security alert not sent: no relay configured (NOTIFY_SMTP_HOST)' });
      return 'disabled';
    }
    const eventsInWindow = await this.reads.windowEventCount(
      tx,
      organizationId,
      kind,
      kindFacts.scopeKey,
      window.from,
    );
    const notice = renderSecurityAlert({
      ...kindFacts.facts,
      organizationName: organization.name,
      window: { from: window.from.toISOString(), to: window.to.toISOString() },
      eventsInWindow,
      portalUrl: this.options.portalUrl,
    });
    const stop = this.metrics.sendDuration.startTimer({ kind });
    try {
      await this.mailer.send({
        recipients,
        subject: notice.subject,
        text: notice.text,
        messageId: securityAlertMessageId(event.eventId, this.mailer.from),
      });
    } catch (error) {
      this.count(kind, 'failed');
      log.warn({
        message: 'security alert send failed (retried)',
        responseCode: (error as { responseCode?: number }).responseCode,
      });
      throw error;
    } finally {
      stop();
    }
    this.count(kind, 'sent');
    log.info({ message: 'security alert sent', recipientCount: recipients.length });
    return 'sent';
  }

  /** The kind is still enabled (and, for threats, the severity still reaches `minSeverity`). */
  private enabled(
    settings: ResolvedNotificationSettings,
    p: NotificationAlertRequestedV1,
  ): boolean {
    if (!alertKindSettings(settings, p.kind).enabled) return false;
    if (p.kind === 'threat_detected') {
      return severityRank(p.severity) >= severityRank(settings.alerts.threatDetected.minSeverity);
    }
    return true;
  }

  private async facts(
    tx: Tx,
    organization: AlertOrganization,
    p: NotificationAlertRequestedV1,
    window: { from: Date; to: Date },
  ): Promise<{ facts: KindFacts; scopeKey: string }> {
    const organizationId = organization.id;
    const counts = { suppressedBefore: p.counts.suppressedBefore };
    switch (p.kind) {
      case 'threat_detected': {
        const { webhookEventId, messageId, receivedAt } = p.refs;
        if (!webhookEventId || !messageId || !receivedAt) {
          return this.deadLetter(p.kind, 'alert_refs_missing');
        }
        const stored = await this.storedEvent(
          tx,
          organization,
          webhookEventId,
          window,
          'email.threat.detected',
          p.kind,
        );
        if (stored.messageId === null || stored.messageId !== BigInt(messageId)) {
          return this.deadLetter(p.kind, 'webhook_event_mismatch');
        }
        const identity = await this.reads.messageIdentity(tx, organizationId, BigInt(messageId));
        if (identity === null) return this.deadLetter(p.kind, 'message_not_found');
        if (identity.receivedAt.getTime() !== Date.parse(receivedAt)) {
          return this.deadLetter(p.kind, 'message_mismatch');
        }
        const data = stored.envelope.data as WebhookEventData<'email.threat.detected'>;
        if (data.message.id !== identity.publicId) {
          return this.deadLetter(p.kind, 'webhook_event_mismatch');
        }
        return {
          scopeKey: alertScopeKey(p.kind, {}),
          facts: {
            kind: p.kind,
            severity: stored.severity,
            ...counts,
            threat: {
              verdict: data.detection.verdict,
              stage: data.detection.stage,
              messagePublicId: identity.publicId,
              receivedAt: identity.receivedAt.toISOString(),
            },
          },
        };
      }
      case 'domain_dns_failed': {
        const { webhookEventId, domainId } = p.refs;
        if (!webhookEventId || !domainId) return this.deadLetter(p.kind, 'alert_refs_missing');
        const stored = await this.storedEvent(
          tx,
          organization,
          webhookEventId,
          window,
          'domain.dns.failed',
          p.kind,
        );
        if (stored.domainId === null || stored.domainId !== BigInt(domainId)) {
          return this.deadLetter(p.kind, 'webhook_event_mismatch');
        }
        const domain = await this.reads.domain(tx, organizationId, BigInt(domainId));
        if (domain === null) return this.deadLetter(p.kind, 'domain_not_found');
        const data = stored.envelope.data as WebhookEventData<'domain.dns.failed'>;
        if (data.domain.id !== domain.publicId) {
          return this.deadLetter(p.kind, 'webhook_event_mismatch');
        }
        const stillFailing = await this.reads.failingRecordPurposes(tx, organizationId, domain.id);
        return {
          scopeKey: alertScopeKey(p.kind, { domainPublicId: domain.publicId }),
          facts: {
            kind: p.kind,
            severity: stored.severity,
            ...counts,
            dns: {
              domainPublicId: domain.publicId,
              domainName: domain.name,
              failureKind: data.failure.kind,
              reason: data.failure.reason,
              purposes: [...new Set(data.failure.records.map((r) => r.purpose))],
              stillFailing,
            },
          },
        };
      }
      case 'webhook_disabled': {
        const { subscriptionId } = p.refs;
        if (!subscriptionId) return this.deadLetter(p.kind, 'alert_refs_missing');
        const subscription = await this.reads.subscription(tx, organizationId, subscriptionId);
        if (subscription === null) return this.deadLetter(p.kind, 'subscription_not_found');
        return {
          scopeKey: alertScopeKey(p.kind, { subscriptionPublicId: subscription.publicId }),
          facts: {
            kind: p.kind,
            severity: p.severity,
            ...counts,
            webhook: {
              subscriptionPublicId: subscription.publicId,
              name: subscription.name,
              status: subscription.status,
              consecutiveFailures: subscription.consecutiveFailures,
              failingSince: subscription.failingSince?.toISOString() ?? null,
              disabledAt: subscription.disabledAt?.toISOString() ?? null,
              disabledReason: subscription.disabledReason,
            },
          },
        };
      }
    }
  }

  /** The stored public event of the alert, of the expected type and organization. */
  private async storedEvent(
    tx: Tx,
    organization: AlertOrganization,
    eventId: string,
    window: { from: Date; to: Date },
    type: 'email.threat.detected' | 'domain.dns.failed',
    kind: AlertKind,
  ): Promise<StoredAlertEvent> {
    const stored = await this.reads.webhookEvent(tx, organization.id, eventId, window);
    if (stored === null) return this.deadLetter(kind, 'webhook_event_not_found');
    if (
      stored.eventType !== type ||
      stored.envelope.type !== type ||
      stored.envelope.id !== eventId ||
      stored.envelope.organizationId !== organization.publicId
    ) {
      return this.deadLetter(kind, 'webhook_event_mismatch');
    }
    return stored;
  }

  private async recipients(
    tx: Tx,
    organization: AlertOrganization,
    kind: AlertKind,
    settings: ResolvedNotificationSettings,
  ): Promise<string[]> {
    const permission = ALERT_RECIPIENT_PERMISSION[kind];
    const { emails } = await this.preferences.collect(
      tx,
      organization.id,
      kind,
      (afterId, take) => this.reads.holders(tx, organization.id, permission, take, afterId),
      this.options.maxRecipients,
    );
    if (settings.alerts.includeOrganizationContact && organization.notificationEmail) {
      const contact = addressDomain(organization.notificationEmail);
      if (contact === null) {
        this.metrics.alertsSuppressed.inc({ kind, reason: 'invalid_contact' });
      } else if (!emails.includes(contact.address)) {
        emails.push(contact.address);
      }
    }
    return emails;
  }

  private deadLetter(kind: AlertKind, code: string): never {
    this.count(kind, 'failed');
    throw new NonRetryableError(code);
  }

  private count(kind: AlertKind, result: AlertResult): void {
    this.metrics.alertMessages.inc({ kind, result });
  }
}

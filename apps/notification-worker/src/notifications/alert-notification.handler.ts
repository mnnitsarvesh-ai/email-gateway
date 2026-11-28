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
  DETECT_ONLY_MAX_PERIOD_MS,
  type SecurityAlertReads,
  type StoredAlertEvent,
} from './alert-reads';
import {
  type AlertFacts,
  renderSecurityAlert,
  type SecurityAlertKind,
  securityAlertMessageId,
} from './alert-templates';
import type { NoticeMailer } from './mailer';
import type { AlertResult, NotificationMetrics } from './notification-metrics';
import { addressDomain } from './policy-notification.handler';
import type { PreferenceFilter } from './preference-filter';

export type AlertKind = NotificationAlertRequestedV1['kind'];

/**
 * Permission a user must hold to receive an alert kind (N3): the shared map plus the step 8.6
 * `journal_intake_silent` → `journal:manage` (the users who can fix a journal rule or source),
 * the step API-1 `api_mode_unhealthy` → `remediation:read` (D11.3: the users who see the
 * API-mode coverage and health page) and the step API-3 `api_mode_purge_approval` →
 * `remediation:purge` (C6: the users who may approve a purge) and `api_mode_report_received` →
 * `remediation:write` (C13: the users who triage reports), and the step API-4 (B7)
 * `api_mode_detect_only_ended` → `remediation:write` (the users who may switch the policy to
 * enforce). `dlp_detected` → `dlp:read` comes from the shared map (A9.2).
 */
export const SECURITY_ALERT_RECIPIENT_PERMISSION: Readonly<Record<SecurityAlertKind, string>> =
  Object.freeze({
    ...ALERT_RECIPIENT_PERMISSION,
    journal_intake_silent: 'journal:manage',
    api_mode_unhealthy: 'remediation:read',
    api_mode_purge_approval: 'remediation:purge',
    api_mode_report_received: 'remediation:write',
    api_mode_detect_only_ended: 'remediation:write',
  });

/** Public types an alert may refer to (`webhook_events.event_type`). */
type StoredAlertType =
  | 'email.threat.detected'
  | 'mailbox.threat.detected'
  | 'mailbox.dlp.detected'
  | 'domain.dns.failed'
  | 'integration.health_changed';

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
    // Step 8.6 D9: `journal_intake_silent` has no tenant setting (always on, like
    // `integration_unhealthy`; throttled per source by the producer). Step API-1 D11.3: nor has
    // `api_mode_unhealthy` (throttled per API-mode connection by the mailbox-worker), nor the
    // step API-3 kinds (C6, C13), nor the step API-4 detect-only end (B7, once per period).
    if (
      p.kind === 'journal_intake_silent' ||
      p.kind === 'api_mode_unhealthy' ||
      p.kind === 'api_mode_purge_approval' ||
      p.kind === 'api_mode_report_received' ||
      p.kind === 'api_mode_detect_only_ended'
    ) {
      return true;
    }
    if (!alertKindSettings(settings, p.kind).enabled) return false;
    if (p.kind === 'threat_detected') {
      return severityRank(p.severity) >= severityRank(settings.alerts.threatDetected.minSeverity);
    }
    if (p.kind === 'dlp_detected') {
      // Step API-4 A9.2: `alerts.dlpDetected.minSeverity` (default medium).
      return severityRank(p.severity) >= severityRank(settings.alerts.dlpDetected.minSeverity);
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
        // Step API-4 A9.2: the stored event is `email.threat.detected` (gateway message) or
        // `mailbox.threat.detected` (an API-mode copy, detected after delivery).
        const stored = await this.storedEvent(
          tx,
          organization,
          webhookEventId,
          window,
          ['email.threat.detected', 'mailbox.threat.detected'],
          p.kind,
        );
        const identity = await this.messageOf(
          tx,
          p.kind,
          organizationId,
          stored,
          messageId,
          receivedAt,
        );
        if (identity === null) return this.deadLetter(p.kind, 'message_not_found');
        const copyEvent = stored.eventType === 'mailbox.threat.detected';
        await this.assertIngest(tx, organizationId, p.kind, messageId, receivedAt, copyEvent);
        const base = {
          kind: p.kind,
          severity: stored.severity,
          ...counts,
        } as const;
        if (copyEvent) {
          const data = stored.envelope.data as WebhookEventData<'mailbox.threat.detected'>;
          if (data.message.id !== identity.publicId) {
            return this.deadLetter(p.kind, 'webhook_event_mismatch');
          }
          return {
            scopeKey: alertScopeKey(p.kind, {}),
            facts: {
              ...base,
              threat: {
                verdict: data.detection.verdict,
                stage: data.detection.stage,
                messagePublicId: identity.publicId,
                receivedAt: identity.receivedAt.toISOString(),
                copy: {
                  protectionMode: data.detection.protectionMode,
                  mailboxCount: data.detection.mailboxCount,
                },
              },
            },
          };
        }
        const data = stored.envelope.data as WebhookEventData<'email.threat.detected'>;
        if (data.message.id !== identity.publicId) {
          return this.deadLetter(p.kind, 'webhook_event_mismatch');
        }
        return {
          scopeKey: alertScopeKey(p.kind, {}),
          facts: {
            ...base,
            threat: {
              verdict: data.detection.verdict,
              stage: data.detection.stage,
              messagePublicId: identity.publicId,
              receivedAt: identity.receivedAt.toISOString(),
              copy: null,
            },
          },
        };
      }
      case 'dlp_detected': {
        // Step API-4 A9.2: the stored `mailbox.dlp.detected` event (codes and counts only).
        const { webhookEventId, messageId, receivedAt } = p.refs;
        if (!webhookEventId || !messageId || !receivedAt) {
          return this.deadLetter(p.kind, 'alert_refs_missing');
        }
        const stored = await this.storedEvent(
          tx,
          organization,
          webhookEventId,
          window,
          ['mailbox.dlp.detected'],
          p.kind,
        );
        const identity = await this.messageOf(
          tx,
          p.kind,
          organizationId,
          stored,
          messageId,
          receivedAt,
        );
        if (identity === null) return this.deadLetter(p.kind, 'message_not_found');
        await this.assertIngest(tx, organizationId, p.kind, messageId, receivedAt, true);
        const data = stored.envelope.data as WebhookEventData<'mailbox.dlp.detected'>;
        if (data.message.id !== identity.publicId) {
          return this.deadLetter(p.kind, 'webhook_event_mismatch');
        }
        return {
          scopeKey: alertScopeKey(p.kind, {}),
          facts: {
            kind: p.kind,
            severity: stored.severity,
            ...counts,
            dlp: {
              action: data.dlp.action,
              direction: data.dlp.direction,
              categories: [...data.dlp.categories],
              protectionMode: data.dlp.protectionMode,
              mailboxCount: data.dlp.mailboxCount,
              messagePublicId: identity.publicId,
              receivedAt: identity.receivedAt.toISOString(),
            },
          },
        };
      }
      case 'api_mode_detect_only_ended': {
        // Step API-4 B7: the remediation policy at send time (scope, mode, period) and the
        // simulated actions of its scope; never the policy document.
        const { remediationPolicyId } = p.refs;
        if (!remediationPolicyId) return this.deadLetter(p.kind, 'alert_refs_missing');
        const policy = await this.reads.remediationPolicy(tx, organizationId, remediationPolicyId);
        if (policy === null) return this.deadLetter(p.kind, 'remediation_policy_not_found');
        const endedAt = policy.detectOnlyUntil ?? policy.detectOnlyNotifiedAt;
        // `enforce` clears the period columns (B7): the start is then unknown, so the count
        // covers the longest possible period before the end.
        const since =
          policy.detectOnlyStartedAt ??
          new Date((endedAt ?? window.from).getTime() - DETECT_ONLY_MAX_PERIOD_MS);
        const simulated = await this.reads.simulatedActions(
          tx,
          organizationId,
          policy.domainId,
          since,
        );
        // The severity names what happened (A9.2: low = remind, medium = enforce).
        const then =
          policy.detectOnlyThen ??
          (p.severity === 'medium' || policy.mode === 'enforce' ? 'enforce' : 'remind');
        return {
          scopeKey: alertScopeKey(p.kind, { remediationPolicyPublicId: policy.publicId }),
          facts: {
            kind: p.kind,
            severity: p.severity,
            ...counts,
            policy: {
              remediationPolicyPublicId: policy.publicId,
              domainName: policy.domainName,
              then,
              modeNow: policy.mode,
              endedAt: endedAt?.toISOString() ?? null,
              simulated: simulated.count,
              simulatedCapped: simulated.capped,
              simulatedSince: since.toISOString(),
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
      case 'integration_unhealthy': {
        // Step 8.2 D12: the stored `integration.health_changed` event and the connection row.
        const { webhookEventId, connectionId } = p.refs;
        if (!webhookEventId || !connectionId) return this.deadLetter(p.kind, 'alert_refs_missing');
        const stored = await this.storedEvent(
          tx,
          organization,
          webhookEventId,
          window,
          'integration.health_changed',
          p.kind,
        );
        const data = stored.envelope.data as WebhookEventData<'integration.health_changed'>;
        if (data.connection.id !== connectionId) {
          return this.deadLetter(p.kind, 'webhook_event_mismatch');
        }
        const connection = await this.reads.providerConnection(tx, organizationId, connectionId);
        if (connection === null) return this.deadLetter(p.kind, 'connection_not_found');
        return {
          scopeKey: alertScopeKey(p.kind, { connectionPublicId: connection.publicId }),
          facts: {
            kind: p.kind,
            severity: stored.severity,
            ...counts,
            integration: {
              connectionPublicId: connection.publicId,
              name: connection.displayName,
              provider: data.connection.provider,
              previousStatus: data.previousStatus,
              status: data.status,
              statusNow: connection.healthStatus,
              failingChecks: [...data.failingChecks],
              changedAt: data.changedAt,
            },
          },
        };
      }
      case 'journal_intake_silent': {
        // Step 8.6 D9: the source row at send time (name, kind, health); never its address.
        const { intakeSourceId } = p.refs;
        if (!intakeSourceId) return this.deadLetter(p.kind, 'alert_refs_missing');
        const source = await this.reads.intakeSource(tx, organizationId, intakeSourceId);
        if (source === null) return this.deadLetter(p.kind, 'intake_source_not_found');
        return {
          scopeKey: alertScopeKey(p.kind, { intakeSourcePublicId: source.publicId }),
          facts: {
            kind: p.kind,
            severity: p.severity,
            ...counts,
            intake: {
              sourcePublicId: source.publicId,
              name: source.displayName,
              sourceKind: source.kind,
              healthNow: source.healthStatus,
              lastAcceptedAt: source.lastAcceptedAt?.toISOString() ?? null,
              silenceAlertMinutes: source.silenceAlertMinutes,
            },
          },
        };
      }
      case 'api_mode_unhealthy': {
        // Step API-1 D11.3: the API-mode connection at send time (provider, name, health, the
        // checks failing now); never a mailbox address.
        const { apiModeConnectionId } = p.refs;
        if (!apiModeConnectionId) return this.deadLetter(p.kind, 'alert_refs_missing');
        const connection = await this.reads.apiModeConnection(
          tx,
          organizationId,
          apiModeConnectionId,
        );
        if (connection === null) return this.deadLetter(p.kind, 'api_mode_connection_not_found');
        return {
          scopeKey: alertScopeKey(p.kind, { apiModeConnectionPublicId: connection.publicId }),
          facts: {
            kind: p.kind,
            severity: p.severity,
            ...counts,
            apiMode: {
              connectionPublicId: connection.publicId,
              name: connection.displayName,
              provider: connection.provider,
              healthNow: connection.healthStatus,
              failingChecks: connection.failingChecks,
            },
          },
        };
      }
      case 'api_mode_purge_approval': {
        // Step API-3 C6: the clawback at send time (trigger, status, eligible mailboxes, the
        // approval state and expiry); never an address, subject or criteria value.
        const { clawbackId } = p.refs;
        if (!clawbackId) return this.deadLetter(p.kind, 'alert_refs_missing');
        const clawback = await this.reads.clawback(tx, organizationId, clawbackId);
        if (clawback === null) return this.deadLetter(p.kind, 'clawback_not_found');
        return {
          scopeKey: alertScopeKey(p.kind, { clawbackPublicId: clawback.publicId }),
          facts: {
            kind: p.kind,
            severity: p.severity,
            ...counts,
            clawback: {
              clawbackPublicId: clawback.publicId,
              trigger: clawback.trigger,
              status: clawback.status,
              action: clawback.action,
              mailboxesEligible: clawback.mailboxesEligible,
              targetsEligible: clawback.targetsEligible,
              approvalStatus: clawback.approvalStatus,
              approvalReasons: clawback.approvalReasons,
              approvalExpiresAt: clawback.approvalExpiresAt?.toISOString() ?? null,
            },
          },
        };
      }
      case 'api_mode_report_received': {
        // Step API-3 C13: the organization's report counts at send time; never a reporter
        // address, subject or sender.
        const reportCounts = await this.reads.reportCounts(tx, organizationId, window.from);
        return {
          scopeKey: alertScopeKey(p.kind, {}),
          facts: { kind: p.kind, severity: p.severity, ...counts, reports: reportCounts },
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

  /**
   * The message identity of a message alert, echo-checked against the stored event's message id
   * and the refs' received time; null when the identity is gone.
   */
  private async messageOf(
    tx: Tx,
    kind: AlertKind,
    organizationId: bigint,
    stored: StoredAlertEvent,
    messageId: string,
    receivedAt: string,
  ): Promise<{ publicId: string; receivedAt: Date } | null> {
    if (stored.messageId === null || stored.messageId !== BigInt(messageId)) {
      return this.deadLetter(kind, 'webhook_event_mismatch');
    }
    const identity = await this.reads.messageIdentity(tx, organizationId, BigInt(messageId));
    if (identity === null) return null;
    if (identity.receivedAt.getTime() !== Date.parse(receivedAt)) {
      return this.deadLetter(kind, 'message_mismatch');
    }
    return identity;
  }

  /**
   * Step API-4 A9.2: the message's `ingest_source` agrees with the stored public type (a copy
   * ⇔ `mailbox.*`). A purged message row cannot be checked and is accepted on the stored type.
   */
  private async assertIngest(
    tx: Tx,
    organizationId: bigint,
    kind: AlertKind,
    messageId: string,
    receivedAt: string,
    copyEvent: boolean,
  ): Promise<void> {
    const ingest = await this.reads.messageIngestSource(
      tx,
      organizationId,
      BigInt(messageId),
      new Date(receivedAt),
    );
    if (ingest !== null && (ingest !== 'gateway') !== copyEvent) {
      this.deadLetter(kind, 'webhook_event_mismatch');
    }
  }

  /** The stored public event of the alert, of an expected type and the organization. */
  private async storedEvent(
    tx: Tx,
    organization: AlertOrganization,
    eventId: string,
    window: { from: Date; to: Date },
    type: StoredAlertType | readonly StoredAlertType[],
    kind: AlertKind,
  ): Promise<StoredAlertEvent> {
    const types: readonly string[] = typeof type === 'string' ? [type] : type;
    const stored = await this.reads.webhookEvent(tx, organization.id, eventId, window);
    if (stored === null) return this.deadLetter(kind, 'webhook_event_not_found');
    if (
      !types.includes(stored.eventType) ||
      stored.envelope.type !== stored.eventType ||
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
    const permission = SECURITY_ALERT_RECIPIENT_PERMISSION[kind];
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

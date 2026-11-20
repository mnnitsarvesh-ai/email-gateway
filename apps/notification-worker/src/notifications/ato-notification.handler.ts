import { NonRetryableError } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type { AtoNotificationRequestedV1, EventEnvelope } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { PreferenceKind } from '@email-gateway/webhooks';
import {
  type AtoNotificationReads,
  type AtoNotificationSettings,
  type AtoOrganization,
  atoSeverityRank,
} from './ato-reads';
import {
  type AtoAudience,
  type AtoNoticeFacts,
  type AtoNoticeKind,
  atoNoticeMessageId,
  renderAtoNotice,
} from './ato-templates';
import type { NoticeMailer } from './mailer';
import type { NotificationMetrics } from './notification-metrics';
import { addressDomain } from './policy-notification.handler';
import type { PreferenceFilter } from './preference-filter';

type Tx = Prisma.TransactionClient;

/** `sent`, `no_recipients`, `disabled` (feature/mode/kind/audience off or no relay), `not_applicable`, `failed`. */
export type AtoNoticeResult = 'sent' | 'no_recipients' | 'disabled' | 'not_applicable' | 'failed';

export interface AtoNotificationOptions {
  maxRecipients: number;
  portalUrl: string;
  /** `NOTIFY_ATO_PLATFORM_SOC_EMAIL` (lower-cased; empty = the platform SOC audience is off). */
  platformSocEmail: string;
}

/** Recipient permission per kind (D16): responders for alerts, approvals, failures; readers for digests. */
export const ATO_RECIPIENT_PERMISSION: Readonly<Record<AtoNoticeKind, string>> = Object.freeze({
  incident_alert: 'ato:respond',
  approval_requested: 'ato:respond',
  response_failed: 'ato:respond',
  digest: 'ato:read',
  // Step 8.5 (D11, PQ16): the people who configure identity-provider integrations.
  provider_unhealthy: 'ato:configure',
});

/** Opt-out kind per notice kind (`PREFERENCE_KINDS`, D16). */
export const ATO_PREFERENCE_KIND: Readonly<Record<AtoNoticeKind, PreferenceKind>> = Object.freeze({
  incident_alert: 'ato_incident',
  response_failed: 'ato_incident',
  approval_requested: 'ato_approval_requested',
  digest: 'ato_digest',
  provider_unhealthy: 'ato_provider_health',
});

/** `notification_alert_windows.kind` of each notice kind (the producer's throttle windows). */
export const ATO_WINDOW_KIND: Readonly<Record<AtoNoticeKind, string>> = Object.freeze({
  incident_alert: 'ato_incident',
  response_failed: 'ato_incident',
  approval_requested: 'ato_approval',
  digest: 'ato_digest',
  provider_unhealthy: 'ato_provider_health',
});

type KindFacts = AtoNoticeFacts extends infer F
  ? F extends AtoNoticeFacts
    ? Omit<
        F,
        | 'organizationName'
        | 'organizationSlug'
        | 'audience'
        | 'portalUrl'
        | 'window'
        | 'eventsInWindow'
        | 'suppressedBefore'
      >
    : never
  : never;

/**
 * Handles one `ato.notification.requested.v1` (step 8.4 D16) inside the consumer's idempotency
 * transaction (ledger `notification-worker.policy`). Throttling happened at the producer (the ATO
 * store writes one request per throttle window: `ato_incident` per `notifications.throttleMinutes`,
 * `ato_approval` per action, `ato_digest` once per period); this handler decides at **send time**
 * on the writer, scoped to the envelope's organization:
 *
 * 1. `ato_detection` still enabled and the tenant's ATO mode not `off`, else `disabled`;
 * 2. the facts (echo-checked; a reference that is missing or another organization's is
 *    dead-lettered): incident (category `account_takeover`), account, action, digest counts;
 *    an incident alert below `notifications.incidentMinSeverity` (raised since), an approval
 *    no longer pending, a digest period switched off → `not_applicable` / `disabled`;
 * 3. the recipients per audience (`provider_unhealthy`, step 8.5 D11: `tenant` only, users with
 *    `ato:configure` minus `ato_provider_health` opt-outs, no organization contact): `tenant` → active, verified users holding
 *    `ATO_RECIPIENT_PERMISSION[kind]` minus opt-outs (`ATO_PREFERENCE_KIND[kind]`), sorted by id,
 *    ≤ `NOTIFICATION_MAX_RECIPIENTS`, plus `organization_settings.notification_email` with
 *    `notifications.includeOrganizationContact`; `soc` → `notifications.socEmails`;
 *    `platform_soc` → `NOTIFY_ATO_PLATFORM_SOC_EMAIL` (critical incident alerts only; off when
 *    empty);
 * 4. one plain-text mail (Bcc), `Message-ID: <ato-notice.<eventId>.<audience>@…>`, sent before the
 *    ledger commits (at least once).
 */
export class AtoNotificationHandler {
  constructor(
    private readonly reads: AtoNotificationReads,
    private readonly mailer: NoticeMailer,
    private readonly metrics: NotificationMetrics,
    private readonly logger: Logger,
    private readonly options: AtoNotificationOptions,
    private readonly preferences: PreferenceFilter,
  ) {}

  async handle(event: EventEnvelope<AtoNotificationRequestedV1>, tx: Tx): Promise<AtoNoticeResult> {
    const p = event.payload;
    const kind: AtoNoticeKind = p.kind;
    const { audience } = p;
    const organizationId = BigInt(event.organizationId);
    const log = this.logger.child({
      eventId: event.eventId,
      organizationId: event.organizationId,
      kind,
      audience,
    });
    const organization = await this.reads.organization(tx, organizationId);
    if (organization === null) return this.deadLetter(kind, audience, 'organization_not_found');
    const state = await this.reads.state(tx, organizationId);
    if (!state.featureEnabled || state.settings.mode === 'off') {
      log.info({ message: 'ATO notice not sent: ATO is not enabled for the organization' });
      return this.count(kind, audience, 'disabled');
    }
    if (audience === 'platform_soc' && this.options.platformSocEmail === '') {
      return this.count(kind, audience, 'disabled');
    }
    const facts = await this.facts(tx, organization, p, state.settings);
    if (facts === 'disabled' || facts === 'not_applicable') {
      log.info({ message: `ATO notice not sent: ${facts}` });
      return this.count(kind, audience, facts);
    }
    const recipients = await this.recipients(tx, organization, kind, audience, state.settings);
    if (recipients.length === 0) {
      log.info({ message: 'ATO notice has no recipient' });
      return this.count(kind, audience, 'no_recipients');
    }
    if (!this.mailer.configured || this.mailer.from === null) {
      log.warn({ message: 'ATO notice not sent: no relay configured (NOTIFY_SMTP_HOST)' });
      return this.count(kind, audience, 'disabled');
    }
    const window = { from: new Date(p.window.from), to: new Date(p.window.to) };
    const eventsInWindow = await this.reads.windowEventCount(
      tx,
      organizationId,
      ATO_WINDOW_KIND[kind],
      this.scopeOf(p),
      window.from,
    );
    const notice = renderAtoNotice({
      ...facts,
      organizationName: organization.name,
      organizationSlug: organization.slug,
      audience,
      portalUrl: this.options.portalUrl,
      window: { from: window.from.toISOString(), to: window.to.toISOString() },
      eventsInWindow,
      suppressedBefore: p.counts.suppressedBefore,
    });
    const stop = this.metrics.sendDuration.startTimer({ kind: `ato_${kind}` });
    try {
      await this.mailer.send({
        recipients,
        subject: notice.subject,
        text: notice.text,
        messageId: atoNoticeMessageId(event.eventId, audience, this.mailer.from),
      });
    } catch (error) {
      this.count(kind, audience, 'failed');
      log.warn({
        message: 'ATO notice send failed (retried)',
        responseCode: (error as { responseCode?: number }).responseCode,
      });
      throw error;
    } finally {
      stop();
    }
    log.info({ message: 'ATO notice sent', recipientCount: recipients.length });
    return this.count(kind, audience, 'sent');
  }

  /** The throttle scope the producer used (`-` for incidents, the action id, the period). */
  private scopeOf(p: AtoNotificationRequestedV1): string {
    switch (p.kind) {
      case 'approval_requested':
        return p.refs.actionPublicId ?? '-';
      case 'digest':
        return p.digestPeriod ?? '-';
      case 'provider_unhealthy':
        return p.refs.integrationPublicId ?? '-';
      default:
        return '-';
    }
  }

  private async facts(
    tx: Tx,
    organization: AtoOrganization,
    p: AtoNotificationRequestedV1,
    settings: AtoNotificationSettings,
  ): Promise<KindFacts | 'disabled' | 'not_applicable'> {
    const organizationId = organization.id;
    switch (p.kind) {
      case 'incident_alert': {
        const ref = p.refs.incidentPublicId;
        if (!ref) return this.deadLetter(p.kind, p.audience, 'notice_refs_missing');
        const incident = await this.reads.incident(tx, organizationId, ref);
        if (incident === null) return this.deadLetter(p.kind, p.audience, 'incident_not_found');
        // The tenant may have raised the minimum since the request; the platform SOC receives
        // critical incidents only (the contract guarantees the requested severity).
        if (atoSeverityRank(incident.severity) < atoSeverityRank(settings.incidentMinSeverity)) {
          return 'disabled';
        }
        if (p.audience === 'platform_soc' && incident.severity !== 'critical') {
          return 'not_applicable';
        }
        const account = await this.reads.account(tx, organizationId, {
          id: incident.subjectRefId,
        });
        return {
          kind: 'incident_alert',
          incident: {
            publicId: incident.publicId,
            severity: incident.severity,
            status: incident.status,
            detectedAt: incident.detectedAt.toISOString(),
            titleCode: incident.titleCode,
            reasonCodes: incident.reasonCodes,
          },
          account,
        };
      }
      case 'approval_requested':
      case 'response_failed': {
        const ref = p.refs.actionPublicId;
        if (!ref) return this.deadLetter(p.kind, p.audience, 'notice_refs_missing');
        const action = await this.reads.action(tx, organizationId, ref);
        if (action === null) return this.deadLetter(p.kind, p.audience, 'action_not_found');
        if (p.kind === 'approval_requested' && action.status !== 'pending_approval') {
          return 'not_applicable';
        }
        if (
          p.kind === 'response_failed' &&
          action.status !== 'failed' &&
          action.status !== 'rollback_failed'
        ) {
          return 'not_applicable';
        }
        const account = await this.reads.account(tx, organizationId, { id: action.accountId });
        const incidentPublicId = p.refs.incidentPublicId ?? null;
        if (incidentPublicId !== null) {
          const incident = await this.reads.incident(tx, organizationId, incidentPublicId);
          if (incident === null || incident.id !== action.incidentId) {
            return this.deadLetter(p.kind, p.audience, 'incident_mismatch');
          }
        }
        return p.kind === 'approval_requested'
          ? {
              kind: 'approval_requested',
              action: {
                publicId: action.publicId,
                actionType: action.actionType,
                impact: action.impact,
                status: action.status,
                approvalExpiresAt: action.approvalExpiresAt?.toISOString() ?? null,
              },
              account,
              incidentPublicId,
            }
          : {
              kind: 'response_failed',
              action: {
                publicId: action.publicId,
                actionType: action.actionType,
                status: action.status,
                provider: action.provider,
                resultCode: action.resultCode,
              },
              account,
              incidentPublicId,
            };
      }
      case 'digest': {
        const period = p.digestPeriod;
        if (period === null) return this.deadLetter(p.kind, p.audience, 'digest_period_missing');
        if (!settings.digest[period]) return 'disabled';
        const counts = await this.reads.digest(
          tx,
          organizationId,
          new Date(p.window.from),
          new Date(p.window.to),
        );
        return { kind: 'digest', period, counts };
      }
      case 'provider_unhealthy': {
        // Step 8.5 (D11): sent only while the integration is still unhealthy and bound.
        const ref = p.refs.integrationPublicId;
        if (!ref) return this.deadLetter(p.kind, p.audience, 'notice_refs_missing');
        const integration = await this.reads.integration(tx, organizationId, ref);
        if (integration === null)
          return this.deadLetter(p.kind, p.audience, 'integration_not_found');
        if (integration.status === 'disabled' || integration.healthStatus !== 'unhealthy') {
          return 'not_applicable';
        }
        return { kind: 'provider_unhealthy', integration };
      }
    }
  }

  private async recipients(
    tx: Tx,
    organization: AtoOrganization,
    kind: AtoNoticeKind,
    audience: AtoAudience,
    settings: AtoNotificationSettings,
  ): Promise<string[]> {
    if (audience === 'platform_soc') return [this.options.platformSocEmail];
    if (audience === 'soc') {
      const out: string[] = [];
      for (const email of settings.socEmails) {
        const parsed = addressDomain(email);
        if (parsed !== null && !out.includes(parsed.address)) out.push(parsed.address);
      }
      return out;
    }
    const permission = ATO_RECIPIENT_PERMISSION[kind];
    const { emails } = await this.preferences.collect(
      tx,
      organization.id,
      ATO_PREFERENCE_KIND[kind],
      (afterId, take) => this.reads.holders(tx, organization.id, permission, take, afterId),
      this.options.maxRecipients,
    );
    // The provider-health notice goes to the integration administrators only (D11).
    if (
      kind !== 'provider_unhealthy' &&
      settings.includeOrganizationContact &&
      organization.notificationEmail
    ) {
      const contact = addressDomain(organization.notificationEmail);
      if (contact === null) {
        this.metrics.alertsSuppressed.inc({
          kind: ATO_PREFERENCE_KIND[kind],
          reason: 'invalid_contact',
        });
      } else if (!emails.includes(contact.address)) {
        emails.push(contact.address);
      }
    }
    return emails;
  }

  private deadLetter(kind: AtoNoticeKind, audience: AtoAudience, code: string): never {
    this.count(kind, audience, 'failed');
    throw new NonRetryableError(code);
  }

  private count(
    kind: AtoNoticeKind,
    audience: AtoAudience,
    result: AtoNoticeResult,
  ): AtoNoticeResult {
    this.metrics.atoMessages.inc({ kind, audience, result });
    return result;
  }
}

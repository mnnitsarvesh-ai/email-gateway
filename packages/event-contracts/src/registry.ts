import type { z } from 'zod';
import {
  assistantReportEmailRequestedV1,
  assistantReportGenerateRequestedV1,
} from './assistant-events';
import {
  atoAccountRiskUpdatedV1,
  atoNotificationRequestedV1,
  atoResponseCompletedV1,
  atoResponseRequestedV1,
  atoRestrictionChangedV1,
  authAccountChangedV1,
  authLoginRecordedV1,
  securityIncidentCreatedV1,
  securityIncidentUpdatedV1,
  smtpAuthRecordedV1,
  smtpSubmissionRecordedV1,
} from './ato-events';
import {
  attachmentSandboxCompletedV1,
  attachmentSandboxRequestedV1,
  deliveryApprovedV1,
  deliveryStatusChangedV1,
  domainDnsRecordsChangedV1,
  domainRoutingChangedV1,
  domainStatusChangedV1,
  EventTypes,
  integrationHealthChangedV1,
  messageArchiveRequestedV1,
  messageCopyDetectedV1,
  messageCopyScannedV1,
  messageDlpIncidentV1,
  messageParsedV1,
  messageParseFailedV1,
  messageReceivedV1,
  messageRescanRequestedV1,
  messageScannedV1,
  messageScanStageReadyV1,
  messageStateChangedV1,
  notificationAlertRequestedV1,
  policyDecidedV1,
  policyNotificationRequestedV1,
  quarantineNotificationRequestedV1,
  quarantineReleaseRequestedV1,
  reportFeedbackRequestedV1,
  sandboxTaskCompletedV1,
  sandboxTaskRequestedV1,
  threatLateSignalV1,
  urlClickedV1,
  urlInspectionCompletedV1,
  urlInspectionRequestedV1,
} from './events';
import type { ExchangeName } from './topology';

/**
 * The event registry (step 3.2 Q1, Q3): every concrete event type `<name>.vN`, the exchange the
 * relay publishes it to, its payload schema and the outbox `aggregate_type` its producers write.
 * The relay validates a stored payload with this schema before publishing; consumers accept only
 * the registered version of each type they declare.
 */

/**
 * Outbox `aggregate_type` values of registered events. `attachment` (step 4.2 A2): the aggregate
 * is a sandbox submission (`aggregate_id` = `sandbox_submissions.id`). `sandbox_analysis` (step
 * 4.6 X11): the aggregate is a sandbox analysis (`aggregate_id` = `sandbox_analyses.id`;
 * `message_outbox.aggregate_type` is VARCHAR(64), no DDL). `quarantine` (step 5.3 Q20): a
 * quarantine notification of an organization (`aggregate_id` = the decimal organization id).
 * `organization` (step 6.2 §4.1): a security alert request of an organization (`aggregate_id` =
 * the decimal organization id).
 *
 * Step 8.4 (D2): own aggregate types keep ATO and incident rows out of the ordering chains of
 * messages and organizations (a nacked publish blocks only its aggregate): `login`
 * (`login_audit_logs.id`), `audit` (`audit_logs.id`), `smtp_telemetry` (the organization id of a
 * telemetry batch), `ato_account` (`ato_accounts.id`), `security_incident`
 * (`security_incidents.id`), `ato_response` (`ato_response_actions.id`), `ato_restriction`
 * (`ato_smtp_restrictions.id`), `ato_notification` (the organization id).
 *
 * `provider_connection` (step 8.2 §4.2): a provider connection's health transition
 * (`aggregate_id` = the decimal `provider_connections.id`).
 *
 * `assistant_report_delivery` (step AI-R D8, §4.3): a confirmed assistant report email
 * (`aggregate_id` = the `ai_chat_report_deliveries.public_id`).
 *
 * `assistant_report_job` (step AI-6 D5, §4.2): an asynchronous assistant report job
 * (`aggregate_id` = the `ai_chat_report_jobs.public_id`).
 */
export type AggregateType =
  | 'message'
  | 'domain'
  | 'attachment'
  | 'sandbox_analysis'
  | 'quarantine'
  | 'organization'
  | 'login'
  | 'audit'
  | 'smtp_telemetry'
  | 'ato_account'
  | 'security_incident'
  | 'ato_response'
  | 'ato_restriction'
  | 'ato_notification'
  | 'provider_connection'
  | 'assistant_report_delivery'
  | 'assistant_report_job';

export interface EventDefinition<S extends z.ZodType = z.ZodType> {
  type: string;
  /** The `N` of `.vN`; carried in `x-eg-schema-version`. */
  version: number;
  exchange: ExchangeName;
  schema: S;
  aggregateType: AggregateType;
}

/** A routable event type without a schema yet: bound in the topology, never published. */
export interface ReservedEventDefinition {
  type: string;
  version: number;
  exchange: ExchangeName;
  aggregateType: AggregateType;
  /** The step that defines the schema. */
  definedBy: string;
}

const EVENT_TYPE_PATTERN = /^[a-z]+(\.[a-z_]+)+\.v([1-9][0-9]{0,5})$/;

/** `N` of a `<name>.vN` event type. Throws on anything else. */
export function schemaVersionOf(type: string): number {
  const match = EVENT_TYPE_PATTERN.exec(type);
  if (!match?.[2]) throw new Error('Malformed event type: expected <name>.v<N>');
  return Number(match[2]);
}

function define<S extends z.ZodType>(
  type: string,
  exchange: ExchangeName,
  schema: S,
  aggregateType: AggregateType,
): EventDefinition<S> {
  return { type, version: schemaVersionOf(type), exchange, schema, aggregateType };
}

export const EVENT_REGISTRY = {
  [EventTypes.MessageReceived]: define(
    EventTypes.MessageReceived,
    'email.ingestion',
    messageReceivedV1,
    'message',
  ),
  [EventTypes.MessageParsed]: define(
    EventTypes.MessageParsed,
    'email.ingestion',
    messageParsedV1,
    'message',
  ),
  [EventTypes.MessageParseFailed]: define(
    EventTypes.MessageParseFailed,
    'email.ingestion',
    messageParseFailedV1,
    'message',
  ),
  [EventTypes.MessageStateChanged]: define(
    EventTypes.MessageStateChanged,
    'email.events',
    messageStateChangedV1,
    'message',
  ),
  [EventTypes.MessageRescanRequested]: define(
    EventTypes.MessageRescanRequested,
    'email.security',
    messageRescanRequestedV1,
    'message',
  ),
  [EventTypes.MessageScanned]: define(
    EventTypes.MessageScanned,
    'email.security',
    messageScannedV1,
    'message',
  ),
  // Step 5.2 P15: redefined in place; producer policy-engine through the outbox. Topology v10
  // (step 5.3 Q2, Q27): no work-queue binding (analytics firehose only).
  [EventTypes.PolicyDecided]: define(
    EventTypes.PolicyDecided,
    'email.policy',
    policyDecidedV1,
    'message',
  ),
  // Step 5.2 P15: producer policy-engine through the outbox; bound to email.archive (consumer:
  // the archive-worker since topology v12, step 8.1).
  [EventTypes.MessageArchiveRequested]: define(
    EventTypes.MessageArchiveRequested,
    'email.archive',
    messageArchiveRequestedV1,
    'message',
  ),
  // Step 5.2 P15: producer policy-engine through the outbox; bound to email.notifications
  // (consumer: notification-worker).
  [EventTypes.PolicyNotificationRequested]: define(
    EventTypes.PolicyNotificationRequested,
    'email.policy',
    policyNotificationRequestedV1,
    'message',
  ),
  // Step 5.3 Q13, Q27: producer api through the outbox; bound to email.quarantine (consumer:
  // policy-engine release executor, ledger policy-engine.quarantine).
  [EventTypes.QuarantineReleaseRequested]: define(
    EventTypes.QuarantineReleaseRequested,
    'email.policy',
    quarantineReleaseRequestedV1,
    'message',
  ),
  // Step 5.3 Q20, Q27: producers policy-engine and api through the outbox; bound to
  // email.notifications (consumer: notification-worker).
  [EventTypes.QuarantineNotificationRequested]: define(
    EventTypes.QuarantineNotificationRequested,
    'email.policy',
    quarantineNotificationRequestedV1,
    'quarantine',
  ),
  [EventTypes.DeliveryApproved]: define(
    EventTypes.DeliveryApproved,
    'email.delivery',
    deliveryApprovedV1,
    'message',
  ),
  [EventTypes.DeliveryStatusChanged]: define(
    EventTypes.DeliveryStatusChanged,
    'email.delivery',
    deliveryStatusChangedV1,
    'message',
  ),
  [EventTypes.DomainStatusChanged]: define(
    EventTypes.DomainStatusChanged,
    'email.events',
    domainStatusChangedV1,
    'domain',
  ),
  [EventTypes.DomainRoutingChanged]: define(
    EventTypes.DomainRoutingChanged,
    'email.events',
    domainRoutingChangedV1,
    'domain',
  ),
  // Step 4.2 A2: reserved since step 3.2, registered with its schema; producer email-worker.
  [EventTypes.AttachmentSandboxRequested]: define(
    EventTypes.AttachmentSandboxRequested,
    'email.security',
    attachmentSandboxRequestedV1,
    'attachment',
  ),
  // Step 4.3 U2: producer email-worker (URL engine) through the outbox; bound to scan.url.inspect.
  [EventTypes.UrlInspectionRequested]: define(
    EventTypes.UrlInspectionRequested,
    'email.security',
    urlInspectionRequestedV1,
    'message',
  ),
  // Step 4.3 U2: producer url-browser-worker by direct publish with publisher confirms (no
  // outbox: the worker has no database); bound to scan.url.results.
  [EventTypes.UrlInspectionCompleted]: define(
    EventTypes.UrlInspectionCompleted,
    'email.security',
    urlInspectionCompletedV1,
    'message',
  ),
  // Step 4.3 U2: producer click-service through the outbox; no queue binding (analytics only).
  [EventTypes.UrlClicked]: define(EventTypes.UrlClicked, 'email.security', urlClickedV1, 'message'),
  // Step 4.4 B2: producer email-worker (scan stage) through the outbox; bound to the stage-2
  // engine queue scan.bec (topology v6).
  [EventTypes.MessageScanStageReady]: define(
    EventTypes.MessageScanStageReady,
    'email.security',
    messageScanStageReadyV1,
    'message',
  ),
  // Step 4.5 D14: producer email-worker (dlp engine finalize) through the outbox; no queue
  // binding in topology v7 (analytics firehose only; the notification-worker binds it in 6.2).
  [EventTypes.MessageDlpIncident]: define(
    EventTypes.MessageDlpIncident,
    'email.security',
    messageDlpIncidentV1,
    'message',
  ),
  // Step 4.6 X11: producer email-worker (sandbox dispatcher) through the outbox; bound to the
  // controller's queue scan.sandbox (topology v8).
  [EventTypes.SandboxTaskRequested]: define(
    EventTypes.SandboxTaskRequested,
    'email.security',
    sandboxTaskRequestedV1,
    'sandbox_analysis',
  ),
  // Step 4.6 X11: producer sandbox-controller by direct publish with publisher confirms (no
  // outbox: the controller has no database); bound to scan.sandbox.results.
  [EventTypes.SandboxTaskCompleted]: define(
    EventTypes.SandboxTaskCompleted,
    'email.security',
    sandboxTaskCompletedV1,
    'sandbox_analysis',
  ),
  // Step 4.6 X15: producer email-worker (sandbox finalizer) through the outbox; no queue binding
  // in topology v8 (analytics firehose only; policy 5.x binds it).
  [EventTypes.AttachmentSandboxCompleted]: define(
    EventTypes.AttachmentSandboxCompleted,
    'email.security',
    attachmentSandboxCompletedV1,
    'attachment',
  ),
  // Step 6.2 §4.1: producer api (domains check transaction) through the outbox, only on stored
  // record status transitions; bound to email.webhooks (consumer: webhook-worker fanout).
  [EventTypes.DomainDnsRecordsChanged]: define(
    EventTypes.DomainDnsRecordsChanged,
    'email.events',
    domainDnsRecordsChangedV1,
    'domain',
  ),
  // Step 6.2 N2, §4.1: producer webhook-worker through the outbox (first event of a throttle
  // window); bound to email.notifications (consumer: notification-worker).
  [EventTypes.NotificationAlertRequested]: define(
    EventTypes.NotificationAlertRequested,
    'email.policy',
    notificationAlertRequestedV1,
    'organization',
  ),
  // Step 8.4 D2, D5: producer api (LoginAuditRepository, same transaction as the
  // login_audit_logs row) through the outbox; bound to ato.events (topology v13).
  [EventTypes.AuthLoginRecorded]: define(
    EventTypes.AuthLoginRecorded,
    'email.events',
    authLoginRecordedV1,
    'login',
  ),
  // Step 8.4 D2, D5: producer api (AuditService, same client as the audit_logs row) for
  // ATO_ACCOUNT_CHANGE_ACTIONS; bound to ato.events.
  [EventTypes.AuthAccountChanged]: define(
    EventTypes.AuthAccountChanged,
    'email.events',
    authAccountChangedV1,
    'audit',
  ),
  // Step 8.4 D4: producer smtp-adapter (telemetry flusher, after the SMTP reply); bound to
  // ato.events.
  [EventTypes.SmtpAuthRecorded]: define(
    EventTypes.SmtpAuthRecorded,
    'email.events',
    smtpAuthRecordedV1,
    'smtp_telemetry',
  ),
  [EventTypes.SmtpSubmissionRecorded]: define(
    EventTypes.SmtpSubmissionRecorded,
    'email.events',
    smtpSubmissionRecordedV1,
    'smtp_telemetry',
  ),
  // Step 8.4 D11: producer ATO store (worker or api) when the level changes; bound to
  // email.webhooks (webhook-worker fanout).
  [EventTypes.AtoAccountRiskUpdated]: define(
    EventTypes.AtoAccountRiskUpdated,
    'email.security',
    atoAccountRiskUpdatedV1,
    'ato_account',
  ),
  // Step 8.4 D24: producer the shared IncidentStore (every category); bound to email.webhooks.
  [EventTypes.SecurityIncidentCreated]: define(
    EventTypes.SecurityIncidentCreated,
    'email.security',
    securityIncidentCreatedV1,
    'security_incident',
  ),
  [EventTypes.SecurityIncidentUpdated]: define(
    EventTypes.SecurityIncidentUpdated,
    'email.security',
    securityIncidentUpdatedV1,
    'security_incident',
  ),
  // Step 8.4 D13, D15: producer ATO store, provider actions only; bound to ato.responses
  // (consumer: ato-worker respond role).
  [EventTypes.AtoResponseRequested]: define(
    EventTypes.AtoResponseRequested,
    'email.security',
    atoResponseRequestedV1,
    'ato_response',
  ),
  // Step 8.4 D13: producer ATO store on every terminal state; bound to email.webhooks.
  [EventTypes.AtoResponseCompleted]: define(
    EventTypes.AtoResponseCompleted,
    'email.security',
    atoResponseCompletedV1,
    'ato_response',
  ),
  // Step 8.4 D14: producer ATO store and the expiry sweeper; no queue binding (smtp-adapter
  // outbox tail for cache invalidation; analytics firehose).
  [EventTypes.AtoRestrictionChanged]: define(
    EventTypes.AtoRestrictionChanged,
    'email.security',
    atoRestrictionChangedV1,
    'ato_restriction',
  ),
  // Step 8.4 D16: producer ATO store (first event of a throttle window); bound to
  // email.notifications (consumer: notification-worker).
  [EventTypes.AtoNotificationRequested]: define(
    EventTypes.AtoNotificationRequested,
    'email.security',
    atoNotificationRequestedV1,
    'ato_notification',
  ),
  // Step 8.2 D12, §4.2: producer integration-worker (health role) through the outbox, only on
  // health transitions; bound to email.webhooks (consumer: webhook-worker fanout, topology v14).
  [EventTypes.IntegrationHealthChanged]: define(
    EventTypes.IntegrationHealthChanged,
    'email.events',
    integrationHealthChangedV1,
    'provider_connection',
  ),
  // Step AI-R D8: producer api (ReportDeliveryService, confirm transaction) through the outbox;
  // bound to email.notifications (consumer: notification-worker).
  [EventTypes.AssistantReportEmailRequested]: define(
    EventTypes.AssistantReportEmailRequested,
    'email.policy',
    assistantReportEmailRequestedV1,
    'assistant_report_delivery',
  ),
  // Step AI-6 D5: producer api (turn engine, the report_generate transaction) through the
  // outbox; bound to assistant.reports (consumer: the api-assistant ReportJobConsumer, v16).
  [EventTypes.AssistantReportGenerateRequested]: define(
    EventTypes.AssistantReportGenerateRequested,
    'email.policy',
    assistantReportGenerateRequestedV1,
    'assistant_report_job',
  ),
  // Step API-1 D8 (§5, ADR-0100): producer email-worker (E30–E32 transaction of a non-gateway
  // copy) through the outbox, on the exchange of mail.message.scanned.v1; bound to email.mailbox
  // (consumer: mailbox-worker copies role, topology v17).
  [EventTypes.MessageCopyScanned]: define(
    EventTypes.MessageCopyScanned,
    'email.security',
    messageCopyScannedV1,
    'message',
  ),
  // Step API-3 C2.1 (§5, ADR-0103): producer email-worker (sandbox risk revision / late URL
  // dynamic verdict transaction) through the outbox, on the exchange of
  // mail.message.copy_scanned.v1; bound to email.mailbox (consumer: mailbox-worker copies role,
  // topology v18).
  [EventTypes.ThreatLateSignal]: define(
    EventTypes.ThreatLateSignal,
    'email.security',
    threatLateSignalV1,
    'message',
  ),
  // Step API-3 C12 (§5, ADR-0104): producers api (triage) and mailbox-worker (reports role)
  // through the outbox, on the exchange of the quarantine notifications; bound to
  // email.notifications (consumer: notification-worker, topology v18).
  [EventTypes.ReportFeedbackRequested]: define(
    EventTypes.ReportFeedbackRequested,
    'email.policy',
    reportFeedbackRequestedV1,
    'organization',
  ),
  // Step API-4 A8 (§6, ADR-0106): producer mailbox-worker (copies role, the copy_scanned ledger
  // transaction) through the outbox, on the exchange of mail.message.copy_scanned.v1; bound to
  // email.webhooks (consumer: webhook-worker fanout, topology v19).
  [EventTypes.MessageCopyDetected]: define(
    EventTypes.MessageCopyDetected,
    'email.security',
    messageCopyDetectedV1,
    'message',
  ),
} as const satisfies Record<string, EventDefinition>;

export type RegisteredEventType = keyof typeof EVENT_REGISTRY;

/**
 * Reserved types: routed (bindings exist) but without a schema; the relay refuses them. Empty
 * since step 4.2 registered `mail.attachment.sandbox_requested.v1` (A2); kept for future
 * reservations.
 */
export const RESERVED_EVENT_TYPES: Readonly<Record<string, ReservedEventDefinition>> =
  Object.freeze({});

export type ReservedEventType = keyof typeof RESERVED_EVENT_TYPES;

export function isRegisteredEventType(type: string): type is RegisteredEventType {
  return Object.prototype.hasOwnProperty.call(EVENT_REGISTRY, type);
}

export function isReservedEventType(type: string): type is ReservedEventType {
  return Object.prototype.hasOwnProperty.call(RESERVED_EVENT_TYPES, type);
}

/** The registered definition of `type`, or `undefined` for unknown and reserved types. */
export function eventDefinition(type: string): EventDefinition | undefined {
  return isRegisteredEventType(type) ? EVENT_REGISTRY[type] : undefined;
}

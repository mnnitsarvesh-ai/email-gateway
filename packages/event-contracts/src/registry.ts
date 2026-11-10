import type { z } from 'zod';
import {
  attachmentSandboxCompletedV1,
  attachmentSandboxRequestedV1,
  deliveryApprovedV1,
  deliveryStatusChangedV1,
  domainRoutingChangedV1,
  domainStatusChangedV1,
  EventTypes,
  messageDlpIncidentV1,
  messageParsedV1,
  messageParseFailedV1,
  messageReceivedV1,
  messageRescanRequestedV1,
  messageScannedV1,
  messageScanStageReadyV1,
  messageStateChangedV1,
  policyDecidedV1,
  sandboxTaskCompletedV1,
  sandboxTaskRequestedV1,
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
 * `message_outbox.aggregate_type` is VARCHAR(64), no DDL).
 */
export type AggregateType = 'message' | 'domain' | 'attachment' | 'sandbox_analysis';

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
  [EventTypes.PolicyDecided]: define(
    EventTypes.PolicyDecided,
    'email.policy',
    policyDecidedV1,
    'message',
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

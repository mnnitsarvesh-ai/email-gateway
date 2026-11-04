import type { z } from 'zod';
import {
  deliveryApprovedV1,
  deliveryStatusChangedV1,
  domainRoutingChangedV1,
  domainStatusChangedV1,
  EventTypes,
  messageParsedV1,
  messageParseFailedV1,
  messageReceivedV1,
  messageRescanRequestedV1,
  messageScannedV1,
  messageStateChangedV1,
  policyDecidedV1,
} from './events';
import type { ExchangeName } from './topology';

/**
 * The event registry (step 3.2 Q1, Q3): every concrete event type `<name>.vN`, the exchange the
 * relay publishes it to, its payload schema and the outbox `aggregate_type` its producers write.
 * The relay validates a stored payload with this schema before publishing; consumers accept only
 * the registered version of each type they declare.
 */

/** Outbox `aggregate_type` values of registered events. */
export type AggregateType = 'message' | 'domain';

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
} as const satisfies Record<string, EventDefinition>;

export type RegisteredEventType = keyof typeof EVENT_REGISTRY;

/** Reserved types: routed (bindings exist) but without a schema; the relay refuses them. */
export const RESERVED_EVENT_TYPES = {
  'mail.attachment.sandbox_requested.v1': {
    type: 'mail.attachment.sandbox_requested.v1',
    version: 1,
    exchange: 'email.security',
    aggregateType: 'message',
    definedBy: 'step 4.6',
  },
} as const satisfies Record<string, ReservedEventDefinition>;

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

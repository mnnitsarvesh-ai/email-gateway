import {
  assertMetadataOnly,
  baseHeaders,
  decodeDelivery,
  HEADERS,
  integerHeader,
  stringHeader,
} from '@email-gateway/common';
import {
  eventDefinition,
  eventTypesBoundTo,
  type EventEnvelope,
  type QueueName,
  queueDefinition,
  retryRoutingKey,
  TOPOLOGY,
} from '@email-gateway/event-contracts';
import type { ZodType } from 'zod';

/** The dead-letter queue of topology v1 (Q1); no consumer, operators replay through the api. */
export const DEAD_LETTER_QUEUE = 'email.dead-letter';
/** One replay at a time platform-wide (Q9): Redis `SET dlq:replay:lock <replayId> NX PX 300000`. */
export const REPLAY_LOCK_KEY = 'dlq:replay:lock';
export const REPLAY_LOCK_TTL_SECONDS = 300;
/** Event ids kept in the audit row (Q9 step 5). */
export const AUDIT_EVENT_IDS_MAX = 100;

/** Queues whose dead letters can be replayed: the work queues of the topology (Q9). */
export const REPLAYABLE_QUEUES: readonly QueueName[] = TOPOLOGY.queues
  .filter((q) => q.role === 'work')
  .map((q) => q.name);

/**
 * The structural subset of an amqplib `GetMessage` the replay reads (the fake channel of the unit
 * tests implements the same shape).
 */
export interface DeadLetterMessage {
  content: Buffer;
  fields: { deliveryTag: number; routingKey: string; exchange?: string; redelivered?: boolean };
  properties: {
    headers?: Record<string, unknown>;
    messageId?: unknown;
    correlationId?: unknown;
    type?: unknown;
    timestamp?: unknown;
    appId?: unknown;
    contentType?: unknown;
    contentEncoding?: unknown;
  };
}

export interface ReplayFilters {
  sourceQueue: QueueName;
  eventType?: string;
  /** Internal decimal organization id (resolved from the public id). */
  organizationId?: string;
  failureReason?: string;
}

/** The first `x-death` entry of a broker dead letter, when the header has the AMQP shape. */
function firstDeath(headers: Record<string, unknown> | undefined): Record<string, unknown> | null {
  const deaths = headers?.['x-death'];
  if (!Array.isArray(deaths) || deaths.length === 0) return null;
  const first: unknown = deaths[0];
  return typeof first === 'object' && first !== null ? (first as Record<string, unknown>) : null;
}

function text(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  return undefined;
}

/**
 * Source queue of a dead letter (Q9 step 2): `x-eg-source-queue` (consumer-published), else
 * `x-first-death-queue`, else the first `x-death[].queue` (broker-published, delivery limit).
 */
export function sourceQueueOf(msg: DeadLetterMessage): string | undefined {
  const headers = msg.properties.headers;
  return (
    stringHeader(headers, HEADERS.sourceQueue) ??
    stringHeader(headers, 'x-first-death-queue') ??
    text(firstDeath(headers)?.queue)
  );
}

/** Event type of a dead letter: `x-eg-event-type`, else the `type` property. */
export function eventTypeOf(msg: DeadLetterMessage): string | undefined {
  return stringHeader(msg.properties.headers, HEADERS.eventType) ?? text(msg.properties.type);
}

/** Internal organization id of a dead letter (`x-eg-organization-id`, decimal). */
export function organizationIdOf(msg: DeadLetterMessage): string | undefined {
  const value: unknown = msg.properties.headers?.[HEADERS.organizationId];
  if (typeof value === 'number' || typeof value === 'bigint') return String(value);
  return stringHeader(msg.properties.headers, HEADERS.organizationId);
}

/** Failure reason: `x-eg-failure-reason`, else `x-first-death-reason` / `x-death[0].reason`. */
export function failureReasonOf(msg: DeadLetterMessage): string | undefined {
  const headers = msg.properties.headers;
  return (
    stringHeader(headers, HEADERS.failureReason) ??
    stringHeader(headers, 'x-first-death-reason') ??
    text(firstDeath(headers)?.reason)
  );
}

/** Q9 step 2: the source queue and every optional filter must match. */
export function matchesFilters(msg: DeadLetterMessage, filters: ReplayFilters): boolean {
  if (sourceQueueOf(msg) !== filters.sourceQueue) return false;
  if (filters.eventType !== undefined && eventTypeOf(msg) !== filters.eventType) return false;
  if (filters.organizationId !== undefined && organizationIdOf(msg) !== filters.organizationId) {
    return false;
  }
  if (filters.failureReason !== undefined && failureReasonOf(msg) !== filters.failureReason) {
    return false;
  }
  return true;
}

/**
 * Q9 step 3: decodes a matching dead letter with the schemas of the event types bound to its
 * source queue (envelope, registry schema, schema version, tenant agreement of header, routing
 * key and envelope) and runs the content guard on it. `null` = invalid (left in the queue).
 */
export function decodeForReplay(
  msg: DeadLetterMessage,
  sourceQueue: QueueName,
): EventEnvelope | null {
  const accepted = new Map<string, ZodType>();
  for (const type of eventTypesBoundTo(sourceQueue)) {
    const definition = eventDefinition(type);
    if (definition) accepted.set(type, definition.schema);
  }
  const decoded = decodeDelivery(msg as Parameters<typeof decodeDelivery>[0], accepted);
  if (!decoded.ok) return null;
  try {
    // The guard runs on the bytes that would be republished, not only on the decoded payload
    // (a schema strips unknown keys; the copy keeps them).
    assertMetadataOnly(JSON.parse(msg.content.toString('utf8')));
  } catch {
    return null;
  }
  return decoded.event;
}

/**
 * Headers of a replayed copy (Q9 step 3): the Q2 base headers of the envelope, fresh retry state
 * (`x-eg-attempt` 0, `x-eg-transient-retries` 0, no first-failed-at), no failure headers, no
 * `x-death` / `x-first-death-*` / `x-last-death-*`, plus `x-eg-replay-id`, `x-eg-replay-count`
 * (previous + 1) and `x-eg-replayed-at`. Other headers of the dead letter are not copied.
 */
export function replayHeaders(
  msg: DeadLetterMessage,
  envelope: EventEnvelope,
  replay: { replayId: string; replayedAt: Date },
): Record<string, string | number> {
  return {
    ...baseHeaders(envelope),
    [HEADERS.attempt]: 0,
    [HEADERS.transientRetries]: 0,
    [HEADERS.replayId]: replay.replayId,
    [HEADERS.replayCount]: integerHeader(msg.properties.headers, HEADERS.replayCount) + 1,
    [HEADERS.replayedAt]: replay.replayedAt.toISOString(),
  };
}

/** Where a replayed copy goes: the source queue's home exchange, `retry.<queue>.org.<id>.<type>`. */
export function replayTarget(
  sourceQueue: QueueName,
  envelope: EventEnvelope,
): { exchange: string; routingKey: string } {
  return {
    exchange: queueDefinition(sourceQueue).homeExchange,
    routingKey: retryRoutingKey(sourceQueue, envelope.organizationId, envelope.eventType),
  };
}

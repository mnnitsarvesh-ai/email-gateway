import { crc32 } from 'node:zlib';
import { assertMetadataOnly, ContentGuardError, encodeEvent } from '@email-gateway/common';
import {
  eventDefinition,
  type EventEnvelope,
  eventEnvelopeSchema,
} from '@email-gateway/event-contracts';
import type { OutboxRow } from './relay-store';

/** Shard of an aggregate: the TypeScript twin of the SQL `MOD(CRC32(CONCAT(t, ':', id)), n)`. */
export function shardOf(aggregateType: string, aggregateId: string, count: number): number {
  return crc32(Buffer.from(`${aggregateType}:${aggregateId}`, 'utf8')) % count;
}

/** Lock name of relay shard `index` of `count` (≤ 64 characters: `er:relay#63/64` is 14). */
export function relayLockName(prefix: string, index: number, count: number): string {
  return `${prefix}:relay#${index}/${count}`;
}

export type BuiltEnvelope = { ok: true; envelope: EventEnvelope } | { ok: false; code: string };

/**
 * The envelope of an outbox row (Q2): `occurredAt` = `created_at` (ISO), `organizationId` the
 * decimal id, `correlationId` and `eventId` from the row, the payload validated with the
 * registry schema (Q3). A row that can never be published is classified (Q11 step 5):
 *
 * - unknown or reserved event type → `unknown_event_type`;
 * - payload or envelope schema failure → `contract_invalid`;
 * - content guard on the stored payload or the envelope → the guard code (`forbidden_field`,
 *   `mime_content`, …): a stored payload with content is refused even when the schema would
 *   strip the offending key;
 * - encoded size over `maxMessageBytes` → `message_too_large`.
 */
export function buildEnvelope(
  row: OutboxRow,
  options: { appId: string; maxMessageBytes: number },
): BuiltEnvelope {
  const definition = eventDefinition(row.eventType);
  if (!definition) return { ok: false, code: 'unknown_event_type' };
  const stored = typeof row.payload === 'string' ? parseJson(row.payload) : row.payload;
  if (stored === undefined) return { ok: false, code: 'contract_invalid' };
  const guard = guardCode(stored);
  if (guard) return { ok: false, code: guard };
  const payload = definition.schema.safeParse(stored);
  if (!payload.success) return { ok: false, code: 'contract_invalid' };
  const envelope = eventEnvelopeSchema.safeParse({
    eventId: row.eventId,
    eventType: row.eventType,
    occurredAt: row.createdAt.toISOString(),
    correlationId: row.correlationId,
    organizationId: row.organizationId.toString(),
    payload: payload.data,
  });
  if (!envelope.success) return { ok: false, code: 'contract_invalid' };
  const value: EventEnvelope = { ...envelope.data, payload: payload.data };
  const envelopeGuard = guardCode(value);
  if (envelopeGuard) return { ok: false, code: envelopeGuard };
  if (encodeEvent(value, options.appId).content.length > options.maxMessageBytes) {
    return { ok: false, code: 'message_too_large' };
  }
  return { ok: true, envelope: value };
}

function guardCode(value: unknown): string | undefined {
  try {
    assertMetadataOnly(value);
    return undefined;
  } catch (error) {
    if (error instanceof ContentGuardError) return error.code;
    throw error;
  }
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

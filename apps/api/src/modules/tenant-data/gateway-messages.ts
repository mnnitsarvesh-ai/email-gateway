import { Prisma } from '@email-gateway/database';

/**
 * Step 8.6 D5 (ADR-0087 decision 6): journal intake messages (`email_messages.ingest_source =
 * 'journal_intake'`) are registry messages kept for the archive only. Every gateway-facing view
 * — the Email Explorer list drivers and saved views, the message detail and its sub-routes,
 * lifecycle operations (rescan, release), reports, usage and incident message links — reads
 * gateway messages only; an intake message's id answers `404 message_not_found` there. This is
 * the one predicate those reads share.
 */
export const GATEWAY_INGEST_SOURCE = 'gateway' as const;

/** The Prisma `where` fragment of a gateway message (`email_messages`). */
export const GATEWAY_MESSAGE_WHERE = Object.freeze({ ingestSource: GATEWAY_INGEST_SOURCE });

/** The SQL predicate of a gateway message on alias `m` (a code constant; no input). */
export const GATEWAY_MESSAGE_SQL = Prisma.sql`m.ingest_source = 'gateway'`;

/** The same predicate on another alias (code constants only). */
export function gatewayMessageSql(alias: 'm' | 'em' | 'msg'): Prisma.Sql {
  return Prisma.raw(`${alias}.ingest_source = 'gateway'`);
}

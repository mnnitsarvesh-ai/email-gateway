import { Prisma } from '@email-gateway/database';
import type { ClawbackCriteria, ClawbackMatchKey } from '@email-gateway/mailbox-api';
import { big, type Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

/** One recorded copy a search matched (ids only) and the keys that matched it. */
export interface MatchedCopy {
  id: bigint;
  receivedAt: Date;
  apiConnectionId: bigint;
  mailboxId: bigint;
  messageId: bigint;
  matchKeys: Set<ClawbackMatchKey>;
}

export type SearchResult =
  { kind: 'ok'; copies: MatchedCopy[] } | { kind: 'too_broad'; matched: number };

export interface SearchOptions {
  /** `API_MODE_CLAWBACK_MAX_TARGETS`: more matches → `too_broad` (C4.3). */
  maxTargets: number;
  /** Stop at the first match (the TI sweep's existence check, C2.2). */
  firstOnly?: boolean;
}

interface CopyRow {
  id: bigint | number;
  received_at: Date;
  organization_id: bigint | number;
  api_connection_id: bigint | number;
  mailbox_id: bigint | number;
  message_id: bigint | number;
}

const keyOf = (id: bigint, receivedAt: Date): string => `${id.toString()}:${receivedAt.getTime()}`;

/**
 * C4.2: the recorded copies of an organization matched by `api-clawback-criteria/1` — every key an
 * indexed lookup with the organization first and `received_at` bounded to the window (partition
 * pruning on the partitioned tables): Message-ID → `api_message_copies (organization_id,
 * message_id_hash)`; attachment → `email_attachments (organization_id, sha256, received_at)`; URL
 * → `message_urls (organization_id, url_sha256)`; URL domain → `message_urls (organization_id,
 * registrable_domain)`; sender → `email_messages` header From / envelope From indexes; sender
 * domain → `sender_domain`; sender + subject → header From filtered by `subject_key`. Registry
 * messages reach their copies through UNIQUE (message_id, received_at, mailbox_id); gateway-only
 * messages have none. Copies of report mailboxes (C9.3) and of deleted mailboxes are excluded,
 * and only the criteria's directions match. Keys combine with OR; `matchKeys` records which keys
 * matched each copy. Every row is organization echo-checked.
 */
export async function searchCopies(
  db: Db,
  organizationId: bigint,
  criteria: ClawbackCriteria,
  options: SearchOptions,
): Promise<SearchResult> {
  const from = new Date(criteria.window.from);
  const to = new Date(criteria.window.to);
  const limit = options.firstOnly ? 1 : options.maxTargets + 1;
  const directions = Prisma.join([...criteria.directions]);
  const matched = new Map<string, MatchedCopy>();
  const k = criteria.keys;

  /** Copy filter shared by every lookup (window, directions, mailbox eligibility). */
  const copyFilter = Prisma.sql`
    c.organization_id = ${organizationId}
    AND c.received_at >= ${from} AND c.received_at <= ${to}
    AND c.direction IN (${directions})
    AND EXISTS (
      SELECT 1 FROM api_mailboxes m
      WHERE m.id = c.mailbox_id AND m.organization_id = c.organization_id
        AND m.report_mailbox = 0 AND m.status <> 'deleted')`;

  const add = (rows: CopyRow[], key: ClawbackMatchKey): boolean => {
    for (const r of rows) {
      if (big(r.organization_id) !== organizationId) {
        throw new InconsistentReadError('api_message_copies');
      }
      const id = big(r.id);
      const k2 = keyOf(id, r.received_at);
      const known = matched.get(k2);
      if (known) {
        known.matchKeys.add(key);
        continue;
      }
      matched.set(k2, {
        id,
        receivedAt: r.received_at,
        apiConnectionId: big(r.api_connection_id),
        mailboxId: big(r.mailbox_id),
        messageId: big(r.message_id),
        matchKeys: new Set([key]),
      });
    }
    // Stop early: the first match (existence check), or already more than the target limit.
    return options.firstOnly === true ? matched.size > 0 : matched.size > options.maxTargets;
  };

  /** Copies of the registry messages a sub-select (`message_id`, `received_at`) yields. */
  const viaMessages = (messages: Prisma.Sql): Promise<CopyRow[]> =>
    db.$queryRaw<CopyRow[]>`
      SELECT c.id, c.received_at, c.organization_id, c.api_connection_id, c.mailbox_id,
             c.message_id
      FROM (${messages}) AS hit
      JOIN api_message_copies c
        ON c.message_id = hit.message_id AND c.received_at = hit.received_at
      WHERE ${copyFilter}
      LIMIT ${limit}`;

  if (k.messageIdHashes) {
    const rows = await db.$queryRaw<CopyRow[]>`
      SELECT c.id, c.received_at, c.organization_id, c.api_connection_id, c.mailbox_id,
             c.message_id
      FROM api_message_copies c
      WHERE c.message_id_hash IN (${Prisma.join(k.messageIdHashes)}) AND ${copyFilter}
      LIMIT ${limit}`;
    if (add(rows, 'message_id')) return done(matched, options);
  }
  if (k.attachmentSha256) {
    const rows = await viaMessages(Prisma.sql`
      SELECT DISTINCT a.message_id, a.received_at FROM email_attachments a
      WHERE a.organization_id = ${organizationId}
        AND a.sha256 IN (${Prisma.join(k.attachmentSha256)})
        AND a.received_at >= ${from} AND a.received_at <= ${to}`);
    if (add(rows, 'attachment')) return done(matched, options);
  }
  if (k.urlSha256) {
    const rows = await viaMessages(Prisma.sql`
      SELECT DISTINCT u.message_id, u.received_at FROM message_urls u
      WHERE u.organization_id = ${organizationId}
        AND u.url_sha256 IN (${Prisma.join(k.urlSha256)})
        AND u.received_at >= ${from} AND u.received_at <= ${to}`);
    if (add(rows, 'url')) return done(matched, options);
  }
  if (k.urlDomains) {
    const rows = await viaMessages(Prisma.sql`
      SELECT DISTINCT u.message_id, u.received_at FROM message_urls u
      WHERE u.organization_id = ${organizationId}
        AND u.registrable_domain IN (${Prisma.join(k.urlDomains)})
        AND u.received_at >= ${from} AND u.received_at <= ${to}`);
    if (add(rows, 'url_domain')) return done(matched, options);
  }
  if (k.senders) {
    for (const column of ['header_from', 'envelope_from'] as const) {
      const rows = await viaMessages(Prisma.sql`
        SELECT e.id AS message_id, e.received_at FROM email_messages e
        WHERE e.organization_id = ${organizationId}
          AND e.${Prisma.raw(column)} IN (${Prisma.join(k.senders)})
          AND e.received_at >= ${from} AND e.received_at <= ${to}`);
      if (add(rows, 'sender')) return done(matched, options);
    }
  }
  if (k.senderDomains) {
    const rows = await viaMessages(Prisma.sql`
      SELECT e.id AS message_id, e.received_at FROM email_messages e
      WHERE e.organization_id = ${organizationId}
        AND e.sender_domain IN (${Prisma.join(k.senderDomains)})
        AND e.received_at >= ${from} AND e.received_at <= ${to}`);
    if (add(rows, 'sender_domain')) return done(matched, options);
  }
  if (k.senderSubject) {
    const rows = await viaMessages(Prisma.sql`
      SELECT e.id AS message_id, e.received_at FROM email_messages e
      WHERE e.organization_id = ${organizationId}
        AND e.header_from = ${k.senderSubject.sender}
        AND e.received_at >= ${from} AND e.received_at <= ${to}
        AND e.subject_key = ${k.senderSubject.subjectKey}`);
    if (add(rows, 'sender_subject')) return done(matched, options);
  }
  return done(matched, options);
}

function done(matched: Map<string, MatchedCopy>, options: SearchOptions): SearchResult {
  if (!options.firstOnly && matched.size > options.maxTargets) {
    return { kind: 'too_broad', matched: matched.size };
  }
  const copies = [...matched.values()].sort((a, b) =>
    a.receivedAt.getTime() === b.receivedAt.getTime()
      ? a.id < b.id
        ? -1
        : 1
      : a.receivedAt.getTime() - b.receivedAt.getTime(),
  );
  return { kind: 'ok', copies };
}

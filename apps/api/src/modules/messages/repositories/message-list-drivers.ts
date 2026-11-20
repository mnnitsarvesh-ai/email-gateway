import { Prisma } from '@email-gateway/database';
import type { CursorDirection } from '../../../http/cursor/cursor-codec';
import type { ParsedFilter } from '../../../http/listing/list-query';
import { boundaryOffset } from '../../../http/listing/scan-budget';
import { GATEWAY_MESSAGE_SQL } from '../../tenant-data/gateway-messages';
import { clampTake } from '../../tenant-data/page';
import type { FilterDriver, MessageListDriver } from '../domain/message-list-plan';
import type { TimeIdKey } from '../domain/v1-list';
import { afterKey, allOf, column, keysetOrder, upToKey } from './keyset-sql';

/**
 * SQL of the `GET /messages` search drivers (step 7.2 §2 E1, §3.2, ADR-0061), exported for the
 * EXPLAIN checks (integration/messages-explain.test.ts). Every statement starts with
 * `organization_id = ?`, ranges over `received_at` (partition pruning), names its index with
 * `FORCE INDEX` (step 6.1 found that MySQL 8.4 picks another index otherwise) and reads it in
 * keyset order `(received_at, id)`. Identifiers are code constants (`column`, `Prisma.raw` of a
 * literal); every value is a bound parameter (6.1 D4).
 *
 * Every served statement also selects a bound per-statement `echo_nonce`: the repository checks
 * it on every row together with the organization, the range and (for exact-valued keys: verdict,
 * delivery and quarantine states) the key (6.1 D15). The nonce proves a result belongs to this
 * statement (the Prisma wrong-read defect returns another statement's result), which is the
 * exact form of the key echo for the case- and accent-insensitive keys (`utf8mb4_unicode_ci`:
 * addresses, domains, subjects, Message-IDs) that TypeScript cannot re-compare exactly.
 */

/** Index names (code constants: step 1.1 baseline, 6.1 `rest_api`, 7.2 `email_explorer_search`). */
export const MESSAGE_INDEXES = {
  orgReceived: 'email_messages_organization_id_received_at_id_idx',
  orgVerdict: 'email_messages_org_verdict_received_idx',
  recipientAddress: 'email_recipients_organization_id_address_received_at_idx',
  envelopeFrom: 'email_messages_org_envelope_from_received_idx',
  headerFrom: 'email_messages_org_header_from_received_idx',
  senderDomain: 'email_messages_org_sender_domain_received_idx',
  subjectKey: 'email_messages_org_subject_key_received_idx',
  messageIdKey: 'email_messages_org_message_id_key_received_idx',
  recipientDomain: 'email_recipients_org_address_domain_received_idx',
  deliveryStatus: 'email_deliveries_org_status_received_message_idx',
  quarantineStatus: 'quarantine_messages_org_status_received_message_idx',
} as const;

const forceIndex = (name: string) => Prisma.raw(`FORCE INDEX (${name})`);

/** The list item columns of `email_messages m` (no content, no S3 key). */
export const MESSAGE_COLUMNS = Prisma.sql`m.id, m.received_at, m.organization_id, m.domain_id,
  m.direction, m.status, m.status_changed_at, m.subject, m.envelope_from, m.header_from,
  m.recipient_count, m.attachment_count, m.size_bytes, m.final_verdict, m.final_action,
  m.risk_score`;

const M_RECEIVED_AT = column('m.received_at');
const M_ID = column('m.id');

/** The drivers read from an `email_messages` index (`none`/`scan`: the 6.1 plans 1 and 4). */
export type MessagesTableDriver = Extract<
  MessageListDriver,
  | 'none'
  | 'scan'
  | 'internetMessageId'
  | 'sender'
  | 'headerFrom'
  | 'subject'
  | 'senderDomain'
  | 'verdict'
>;

/** Index and key column of each `email_messages` driver (code constants). */
export const MESSAGES_DRIVERS: Readonly<
  Record<MessagesTableDriver, { index: string; key: string | null }>
> = Object.freeze({
  none: { index: MESSAGE_INDEXES.orgReceived, key: null },
  scan: { index: MESSAGE_INDEXES.orgReceived, key: null },
  internetMessageId: { index: MESSAGE_INDEXES.messageIdKey, key: 'm.message_id_key' },
  sender: { index: MESSAGE_INDEXES.envelopeFrom, key: 'm.envelope_from' },
  headerFrom: { index: MESSAGE_INDEXES.headerFrom, key: 'm.header_from' },
  subject: { index: MESSAGE_INDEXES.subjectKey, key: 'm.subject_key' },
  senderDomain: { index: MESSAGE_INDEXES.senderDomain, key: 'm.sender_domain' },
  verdict: { index: MESSAGE_INDEXES.orgVerdict, key: 'm.final_verdict' },
});

/** The drivers read from another table's index, grouped by message. */
export type ForeignDriver = Extract<
  FilterDriver,
  'recipientDomain' | 'deliveryStatus' | 'quarantineStatus'
>;

/** Table, index, key, time and message columns of each foreign driver (code constants). */
export const FOREIGN_DRIVERS: Readonly<
  Record<
    ForeignDriver,
    { table: string; index: string; key: string; time: string; message: string }
  >
> = Object.freeze({
  recipientDomain: {
    table: 'email_recipients',
    index: MESSAGE_INDEXES.recipientDomain,
    key: 't.address_domain',
    time: 't.received_at',
    message: 't.message_id',
  },
  deliveryStatus: {
    table: 'email_deliveries',
    index: MESSAGE_INDEXES.deliveryStatus,
    key: 't.status',
    time: 't.received_at',
    message: 't.message_id',
  },
  quarantineStatus: {
    table: 'quarantine_messages',
    index: MESSAGE_INDEXES.quarantineStatus,
    key: 't.status',
    time: 't.message_received_at',
    message: 't.message_id',
  },
});

/** What every driver statement reads: scope, window, keyset position, order and the nonce. */
export interface DriverWindow {
  organizationId: bigint;
  range: { from: Date; to: Date };
  after?: TimeIdKey | undefined;
  direction: CursorDirection;
  /** Per-statement value echoed on every row (see the file comment). */
  nonce: string;
}

/**
 * Residual filters of a search, resolved: the normalized search keys, the domain's row id, the
 * LIKE pattern of a subject prefix. Each maps to one fixed SQL fragment on `email_messages m`
 * or one correlated `EXISTS` on the foreign tables (§3.2).
 */
export interface ResolvedResiduals {
  direction?: readonly string[];
  status?: readonly string[];
  verdict?: readonly string[];
  action?: readonly string[];
  domainId?: bigint;
  sender?: string;
  headerFrom?: string;
  messageIdKey?: string;
  subjectKey?: string;
  subjectPrefixPattern?: string;
  senderDomain?: string;
  riskScore?: ParsedFilter<number>;
  hasAttachments?: boolean;
  recipient?: string;
  recipientDomain?: string;
  deliveryStatus?: string;
  quarantineStatus?: string;
}

/** The residual predicates on `email_messages m`; columns from code constants, values bound. */
export function residualSql(organizationId: bigint, r: ResolvedResiduals): Prisma.Sql[] {
  const parts: Prisma.Sql[] = [];
  const inList = (col: string, values: readonly string[] | undefined) => {
    if (values && values.length > 0) {
      parts.push(Prisma.sql`${column(col)} IN (${Prisma.join([...values])})`);
    }
  };
  inList('m.direction', r.direction);
  inList('m.status', r.status);
  inList('m.final_verdict', r.verdict);
  inList('m.final_action', r.action);
  if (r.domainId !== undefined) parts.push(Prisma.sql`m.domain_id = ${r.domainId}`);
  if (r.sender !== undefined) parts.push(Prisma.sql`m.envelope_from = ${r.sender}`);
  if (r.headerFrom !== undefined) parts.push(Prisma.sql`m.header_from = ${r.headerFrom}`);
  if (r.messageIdKey !== undefined) parts.push(Prisma.sql`m.message_id_key = ${r.messageIdKey}`);
  if (r.subjectKey !== undefined) parts.push(Prisma.sql`m.subject_key = ${r.subjectKey}`);
  if (r.subjectPrefixPattern !== undefined) {
    parts.push(Prisma.sql`m.subject_key LIKE ${r.subjectPrefixPattern} ESCAPE '!'`);
  }
  if (r.senderDomain !== undefined) parts.push(Prisma.sql`m.sender_domain = ${r.senderDomain}`);
  const risk = r.riskScore;
  if (risk) {
    if (risk.values && risk.values.length > 0) {
      parts.push(Prisma.sql`m.risk_score IN (${Prisma.join(risk.values)})`);
    }
    if (risk.gte !== undefined) parts.push(Prisma.sql`m.risk_score >= ${risk.gte}`);
    if (risk.gt !== undefined) parts.push(Prisma.sql`m.risk_score > ${risk.gt}`);
    if (risk.lte !== undefined) parts.push(Prisma.sql`m.risk_score <= ${risk.lte}`);
    if (risk.lt !== undefined) parts.push(Prisma.sql`m.risk_score < ${risk.lt}`);
  }
  if (r.hasAttachments !== undefined) {
    parts.push(
      r.hasAttachments ? Prisma.sql`m.attachment_count > 0` : Prisma.sql`m.attachment_count = 0`,
    );
  }
  // Correlated on the message's (id, received_at): the recipients' unique key, the deliveries'
  // (message_id, received_at) index, the quarantine entries' (message_id, …) unique key.
  if (r.recipient !== undefined) {
    parts.push(Prisma.sql`EXISTS (SELECT 1 FROM email_recipients r
      WHERE r.organization_id = ${organizationId} AND r.message_id = m.id
        AND r.received_at = m.received_at AND r.address = ${r.recipient})`);
  }
  if (r.recipientDomain !== undefined) {
    parts.push(Prisma.sql`EXISTS (SELECT 1 FROM email_recipients r
      WHERE r.organization_id = ${organizationId} AND r.message_id = m.id
        AND r.received_at = m.received_at AND r.address_domain = ${r.recipientDomain})`);
  }
  if (r.deliveryStatus !== undefined) {
    parts.push(Prisma.sql`EXISTS (SELECT 1 FROM email_deliveries d
      WHERE d.organization_id = ${organizationId} AND d.message_id = m.id
        AND d.received_at = m.received_at AND d.status = ${r.deliveryStatus})`);
  }
  if (r.quarantineStatus !== undefined) {
    parts.push(Prisma.sql`EXISTS (SELECT 1 FROM quarantine_messages q
      WHERE q.organization_id = ${organizationId} AND q.message_id = m.id
        AND q.message_received_at = m.received_at AND q.status = ${r.quarantineStatus})`);
  }
  return parts;
}

const range = (time: Prisma.Sql, input: DriverWindow) =>
  Prisma.sql`${time} >= ${input.range.from} AND ${time} < ${input.range.to}`;

/** `organization_id = ? [AND <key> = ?] AND <range> AND <after cursor>` of an `m` driver. */
function messagesWhere(
  input: DriverWindow & { driver: MessagesTableDriver; key?: string | undefined },
): Prisma.Sql {
  const spec = MESSAGES_DRIVERS[input.driver];
  if ((spec.key === null) !== (input.key === undefined)) {
    throw new Error(`message-list-drivers: driver ${input.driver} key mismatch`);
  }
  const keyPart =
    spec.key === null ? Prisma.empty : Prisma.sql` AND ${column(spec.key)} = ${input.key}`;
  return Prisma.sql`m.organization_id = ${input.organizationId}${keyPart}
      AND ${range(M_RECEIVED_AT, input)}
      AND ${afterKey(M_RECEIVED_AT, M_ID, input.after, input.direction)}`;
}

/**
 * A page of an `email_messages` driver: exact without residuals (`LIMIT limit + 1` in index
 * order); with residuals (budgeted) between the cursor and the step 1 boundary (inclusive). The
 * 6.1 index plan is `none`, its scan plan `scan`, its verdict plan `verdict`.
 */
export function messagesPageSql(
  input: DriverWindow & {
    driver: MessagesTableDriver;
    key?: string | undefined;
    take: number;
    boundary?: TimeIdKey | null;
    residuals?: readonly Prisma.Sql[];
  },
): Prisma.Sql {
  const spec = MESSAGES_DRIVERS[input.driver];
  const extra = [
    ...(input.boundary ? [upToKey(M_RECEIVED_AT, M_ID, input.boundary, input.direction)] : []),
    ...(input.residuals ?? []),
  ];
  return Prisma.sql`SELECT ${input.nonce} AS echo_nonce, ${MESSAGE_COLUMNS}
    FROM email_messages m ${forceIndex(spec.index)}
    WHERE ${messagesWhere(input)} AND ${GATEWAY_MESSAGE_SQL}${extra.length > 0 ? Prisma.sql` AND ${allOf(extra)}` : Prisma.empty}
    ${keysetOrder(M_RECEIVED_AT, M_ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

/**
 * Budget step 1 of an `email_messages` driver (6.1 D6 over the driver's index): the key of the
 * `budget`-th entry after the cursor (index-only); none when fewer entries are left.
 */
export function messagesBoundarySql(
  input: DriverWindow & { driver: MessagesTableDriver; key?: string | undefined; budget: number },
): Prisma.Sql {
  const spec = MESSAGES_DRIVERS[input.driver];
  return Prisma.sql`SELECT ${input.nonce} AS echo_nonce, m.organization_id, m.received_at, m.id
    FROM email_messages m ${forceIndex(spec.index)}
    WHERE ${messagesWhere(input)}
    ${keysetOrder(M_RECEIVED_AT, M_ID, input.direction)} LIMIT 1 OFFSET ${boundaryOffset(input.budget)}`;
}

const R_RECEIVED_AT = column('r.received_at');
const R_ID = column('r.id');

/** The recipient rows of one address (6.1 plan 3 step 1; the exact `recipient` driver). */
export function recipientRowsSql(
  input: DriverWindow & { address: string; take: number },
): Prisma.Sql {
  return Prisma.sql`SELECT ${input.nonce} AS echo_nonce, r.id, r.received_at, r.message_id,
      r.organization_id
    FROM email_recipients r ${forceIndex(MESSAGE_INDEXES.recipientAddress)}
    WHERE r.organization_id = ${input.organizationId} AND r.address = ${input.address}
      AND ${range(R_RECEIVED_AT, input)}
      AND ${afterKey(R_RECEIVED_AT, R_ID, input.after, input.direction)}
    ${keysetOrder(R_RECEIVED_AT, R_ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

/** Budget step 1 of the `recipient` driver: keyset `(received_at, recipient row id)`. */
export function recipientBoundarySql(
  input: DriverWindow & { address: string; budget: number },
): Prisma.Sql {
  return Prisma.sql`SELECT ${input.nonce} AS echo_nonce, r.organization_id, r.received_at, r.id
    FROM email_recipients r ${forceIndex(MESSAGE_INDEXES.recipientAddress)}
    WHERE r.organization_id = ${input.organizationId} AND r.address = ${input.address}
      AND ${range(R_RECEIVED_AT, input)}
      AND ${afterKey(R_RECEIVED_AT, R_ID, input.after, input.direction)}
    ${keysetOrder(R_RECEIVED_AT, R_ID, input.direction)} LIMIT 1 OFFSET ${boundaryOffset(input.budget)}`;
}

/**
 * Budgeted page of the `recipient` driver (§3.2): the recipient rows between the cursor and the
 * boundary (at most the budget), joined to their messages (`STRAIGHT_JOIN`: recipients first),
 * the residuals applied, ordered by the recipient keyset (a sort over at most the budget). The
 * recipient row id comes back as `rid` for the next cursor; a message repeated on one page is
 * collapsed by the service (6.1 rule).
 */
export function recipientPageSql(
  input: DriverWindow & {
    address: string;
    take: number;
    boundary: TimeIdKey | null;
    residuals: readonly Prisma.Sql[];
  },
): Prisma.Sql {
  const K_RECEIVED_AT = column('k.received_at');
  const K_ID = column('k.id');
  return Prisma.sql`SELECT ${input.nonce} AS echo_nonce, ${MESSAGE_COLUMNS}, k.id AS rid
    FROM (SELECT r.id, r.received_at, r.message_id
          FROM email_recipients r ${forceIndex(MESSAGE_INDEXES.recipientAddress)}
          WHERE r.organization_id = ${input.organizationId} AND r.address = ${input.address}
            AND ${range(R_RECEIVED_AT, input)}
            AND ${afterKey(R_RECEIVED_AT, R_ID, input.after, input.direction)}
            AND ${upToKey(R_RECEIVED_AT, R_ID, input.boundary, input.direction)}) k
    STRAIGHT_JOIN email_messages m ON m.id = k.message_id AND m.received_at = k.received_at
    WHERE m.organization_id = ${input.organizationId} AND ${range(M_RECEIVED_AT, input)}
      AND ${GATEWAY_MESSAGE_SQL} AND ${allOf(input.residuals)}
    ${keysetOrder(K_RECEIVED_AT, K_ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

function foreignWhere(
  input: DriverWindow & { driver: ForeignDriver; key: string },
  boundary?: TimeIdKey | null,
): Prisma.Sql {
  const spec = FOREIGN_DRIVERS[input.driver];
  const time = column(spec.time);
  const message = column(spec.message);
  return Prisma.sql`t.organization_id = ${input.organizationId} AND ${column(spec.key)} = ${input.key}
      AND ${range(time, input)}
      AND ${afterKey(time, message, input.after, input.direction)}${
        boundary === undefined
          ? Prisma.empty
          : Prisma.sql` AND ${upToKey(time, message, boundary, input.direction)}`
      }`;
}

/**
 * Exact page of a foreign driver (§3.2): the `(time, message_id)` keys of the driver's index,
 * grouped (one row per message, in index order: a message never appears on two pages), `LIMIT
 * limit + 1`; the messages are then read by primary key (`messagesByKeysSql`).
 */
export function foreignKeysSql(
  input: DriverWindow & { driver: ForeignDriver; key: string; take: number },
): Prisma.Sql {
  const spec = FOREIGN_DRIVERS[input.driver];
  const time = column(spec.time);
  const message = column(spec.message);
  return Prisma.sql`SELECT ${input.nonce} AS echo_nonce, t.organization_id,
      ${column(spec.key)} AS driver_key, ${time} AS received_at, ${message} AS id
    FROM ${Prisma.raw(spec.table)} t ${forceIndex(spec.index)}
    WHERE ${foreignWhere(input)}
    GROUP BY t.organization_id, ${column(spec.key)}, ${time}, ${message}
    ${keysetOrder(time, message, input.direction)} LIMIT ${clampTake(input.take)}`;
}

/** Budget step 1 of a foreign driver: the `budget`-th raw index entry after the cursor. */
export function foreignBoundarySql(
  input: DriverWindow & { driver: ForeignDriver; key: string; budget: number },
): Prisma.Sql {
  const spec = FOREIGN_DRIVERS[input.driver];
  const time = column(spec.time);
  const message = column(spec.message);
  return Prisma.sql`SELECT ${input.nonce} AS echo_nonce, t.organization_id,
      ${time} AS received_at, ${message} AS id
    FROM ${Prisma.raw(spec.table)} t ${forceIndex(spec.index)}
    WHERE ${foreignWhere(input)}
    ${keysetOrder(time, message, input.direction)} LIMIT 1 OFFSET ${boundaryOffset(input.budget)}`;
}

/**
 * Budgeted page of a foreign driver (§3.2): the grouped keys between the cursor and the
 * boundary (at most the budget entries) joined to `email_messages` (`STRAIGHT_JOIN`), the
 * residuals applied, `ORDER BY` the message keyset (a sort over at most the budget).
 */
export function foreignPageSql(
  input: DriverWindow & {
    driver: ForeignDriver;
    key: string;
    take: number;
    boundary: TimeIdKey | null;
    residuals: readonly Prisma.Sql[];
  },
): Prisma.Sql {
  const spec = FOREIGN_DRIVERS[input.driver];
  const time = column(spec.time);
  const message = column(spec.message);
  return Prisma.sql`SELECT ${input.nonce} AS echo_nonce, ${MESSAGE_COLUMNS}
    FROM (SELECT ${time} AS received_at, ${message} AS message_id
          FROM ${Prisma.raw(spec.table)} t ${forceIndex(spec.index)}
          WHERE ${foreignWhere(input, input.boundary)}
          GROUP BY ${time}, ${message}) k
    STRAIGHT_JOIN email_messages m ON m.id = k.message_id AND m.received_at = k.received_at
    WHERE m.organization_id = ${input.organizationId} AND ${range(M_RECEIVED_AT, input)}
      AND ${GATEWAY_MESSAGE_SQL} AND ${allOf(input.residuals)}
    ${keysetOrder(M_RECEIVED_AT, M_ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

/**
 * The messages of a page of keys by `(id, received_at)` (primary key, one partition each). An
 * OR of `(id = ? AND received_at = ?)` terms: MySQL 8.4 answered the equivalent row-constructor
 * `(id, received_at) IN ((?, ?), …)` with an empty result on the first execution of a new
 * prepared statement with several pairs (observed locally, 2026-11-12).
 */
export function messagesByKeysSql(
  organizationId: bigint,
  keys: ReadonlyArray<{ id: bigint; receivedAt: Date }>,
): Prisma.Sql {
  if (keys.length === 0) throw new Error('messagesByKeysSql: at least one key is required');
  const terms = Prisma.join(
    keys.map((k) => Prisma.sql`(m.id = ${k.id} AND m.received_at = ${k.receivedAt})`),
    ' OR ',
  );
  return Prisma.sql`SELECT ${MESSAGE_COLUMNS} FROM email_messages m
    WHERE m.organization_id = ${organizationId} AND ${GATEWAY_MESSAGE_SQL} AND (${terms})`;
}

/** `/*+ MAX_EXECUTION_TIME(n) *\/` of the subject prefix statements (integer from config). */
export function maxExecutionTime(timeoutMs: number): Prisma.Sql {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error('MAX_EXECUTION_TIME must be a positive integer');
  }
  return Prisma.raw(`/*+ MAX_EXECUTION_TIME(${timeoutMs}) */`);
}

/**
 * Probe of the capped subject-prefix driver (§2 E1): the `(cap + 1)`-th subject-key index entry
 * of the window (after the cursor) that starts with the prefix (`LIMIT 1 OFFSET cap`, no ORDER
 * BY, index-only: at most `cap + 1` entries are read, the read pattern of a budget boundary). A
 * row means more than `cap` matches: `422 message_search_too_broad`.
 */
export function prefixProbeSql(
  input: DriverWindow & { pattern: string; cap: number; timeoutMs: number },
): Prisma.Sql {
  if (!Number.isSafeInteger(input.cap) || input.cap < 1) {
    throw new Error('prefixProbeSql: the cap must be a positive integer');
  }
  return Prisma.sql`SELECT ${maxExecutionTime(input.timeoutMs)} ${input.nonce} AS echo_nonce,
      m.organization_id, m.received_at, m.id
    FROM email_messages m ${forceIndex(MESSAGE_INDEXES.subjectKey)}
    WHERE m.organization_id = ${input.organizationId}
      AND m.subject_key LIKE ${input.pattern} ESCAPE '!'
      AND ${range(M_RECEIVED_AT, input)}
      AND ${afterKey(M_RECEIVED_AT, M_ID, input.after, input.direction)}
    LIMIT 1 OFFSET ${input.cap}`;
}

/** Page of the subject-prefix driver: the probe's predicate plus residuals, sorted (≤ cap rows). */
export function prefixPageSql(
  input: DriverWindow & {
    pattern: string;
    take: number;
    timeoutMs: number;
    residuals: readonly Prisma.Sql[];
  },
): Prisma.Sql {
  return Prisma.sql`SELECT ${maxExecutionTime(input.timeoutMs)} ${input.nonce} AS echo_nonce,
      ${MESSAGE_COLUMNS}
    FROM email_messages m ${forceIndex(MESSAGE_INDEXES.subjectKey)}
    WHERE m.organization_id = ${input.organizationId}
      AND m.subject_key LIKE ${input.pattern} ESCAPE '!'
      AND ${range(M_RECEIVED_AT, input)}
      AND ${afterKey(M_RECEIVED_AT, M_ID, input.after, input.direction)}
      AND ${GATEWAY_MESSAGE_SQL} AND ${allOf(input.residuals)}
    ${keysetOrder(M_RECEIVED_AT, M_ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

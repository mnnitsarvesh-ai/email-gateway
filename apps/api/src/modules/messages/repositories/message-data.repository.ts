import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { CursorDirection } from '../../../http/cursor/cursor-codec';
import { assertEcho, InconsistentReadError } from '../../../http/listing/echo-check';
import { boundaryOffset } from '../../../http/listing/scan-budget';
import { MessagesRepository } from '../../tenant-data/messages.repository';
import { clampTake } from '../../tenant-data/page';
import type { TimeIdKey } from '../domain/v1-list';
import type { MessageListFilters } from '../dto/message-data.schemas';
import { afterKey, allOf, column, keysetOrder, upToKey } from './keyset-sql';

/**
 * Reads of the step 6.1 message data routes (WP2, D5, D15) on the replica
 * (`PrismaReadService`): the four plans of `GET /messages`, the detail, the recipients with
 * their latest delivery, and the public ids of the domains and users the rows reference. Every
 * query matches the scope's organization first and every partitioned table is read with its
 * `received_at`; every returned row is echo-checked (organization and queried key) and a
 * mismatch is `503 inconsistent_read`. SQL identifiers are code constants; values are bound.
 * The SQL builders are exported for the EXPLAIN checks (integration/messages-explain.test.ts).
 */

/** Index names (code constants, step 1.1 baseline and the step 6.1 `rest_api` migration). */
export const MESSAGE_INDEXES = {
  orgReceived: 'email_messages_organization_id_received_at_id_idx',
  orgVerdict: 'email_messages_org_verdict_received_idx',
  recipientAddress: 'email_recipients_organization_id_address_received_at_idx',
} as const;

const RECEIVED_AT = column('received_at');
const ID = column('id');

const MESSAGE_COLUMNS = Prisma.sql`id, received_at, organization_id, domain_id, direction, status,
  status_changed_at, subject, envelope_from, header_from, recipient_count, attachment_count,
  size_bytes, final_verdict, final_action, risk_score`;

interface RawMessageRow {
  id: bigint;
  received_at: Date;
  organization_id: bigint;
  domain_id: bigint | null;
  direction: string;
  status: string;
  status_changed_at: Date;
  subject: string | null;
  envelope_from: string;
  header_from: string | null;
  recipient_count: number;
  attachment_count: number;
  size_bytes: number;
  final_verdict: string | null;
  final_action: string | null;
  risk_score: number | null;
}

/** The columns of a message list item (no content, no S3 key). */
export interface MessageListRow {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  domainId: bigint | null;
  direction: string;
  status: string;
  statusChangedAt: Date;
  subject: string | null;
  envelopeFrom: string;
  headerFrom: string | null;
  recipientCount: number;
  attachmentCount: number;
  sizeBytes: number;
  finalVerdict: string | null;
  finalAction: string | null;
  riskScore: number | null;
}

const toRow = (raw: RawMessageRow): MessageListRow => ({
  id: BigInt(raw.id),
  receivedAt: raw.received_at,
  organizationId: BigInt(raw.organization_id),
  domainId: raw.domain_id === null ? null : BigInt(raw.domain_id),
  direction: raw.direction,
  status: raw.status,
  statusChangedAt: raw.status_changed_at,
  subject: raw.subject,
  envelopeFrom: raw.envelope_from,
  headerFrom: raw.header_from,
  recipientCount: Number(raw.recipient_count),
  attachmentCount: Number(raw.attachment_count),
  sizeBytes: Number(raw.size_bytes),
  finalVerdict: raw.final_verdict,
  finalAction: raw.final_action,
  riskScore: raw.risk_score === null ? null : Number(raw.risk_score),
});

/** What every plan reads: the scope, the resolved window and the keyset position. */
export interface MessagePlanInput {
  organizationId: bigint;
  range: { from: Date; to: Date };
  after?: TimeIdKey | undefined;
  direction: CursorDirection;
  /** limit + 1 */
  take: number;
}

/** A filter of the scan plan, resolved (the domain public id already turned into its row id). */
export interface ResolvedMessageFilters extends Omit<MessageListFilters, 'domainId'> {
  domainId?: bigint;
}

const forceIndex = (name: string) => Prisma.raw(`FORCE INDEX (${name})`);

/**
 * Plan 1 (D5): no filter, keyset `(received_at, id)` over `(organization_id, received_at, id)`;
 * the statement shape of MessagesRepository.listRecent (Q1) with the index named. Without the
 * hint MySQL 8.4 picks `email_messages_org_verdict_received_idx` for that statement and sorts
 * (EXPLAIN in integration/messages-explain.test.ts), so the list states the index.
 */
export function indexPlanSql(input: MessagePlanInput): Prisma.Sql {
  return Prisma.sql`SELECT ${MESSAGE_COLUMNS} FROM email_messages ${forceIndex(MESSAGE_INDEXES.orgReceived)}
    WHERE organization_id = ${input.organizationId}
      AND received_at >= ${input.range.from} AND received_at < ${input.range.to}
      AND ${afterKey(RECEIVED_AT, ID, input.after, input.direction)}
    ${keysetOrder(RECEIVED_AT, ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

/** Plan 2 (D5): one verdict over `email_messages_org_verdict_received_idx`. */
export function verdictPlanSql(input: MessagePlanInput & { verdict: string }): Prisma.Sql {
  return Prisma.sql`SELECT ${MESSAGE_COLUMNS} FROM email_messages ${forceIndex(MESSAGE_INDEXES.orgVerdict)}
    WHERE organization_id = ${input.organizationId} AND final_verdict = ${input.verdict}
      AND received_at >= ${input.range.from} AND received_at < ${input.range.to}
      AND ${afterKey(RECEIVED_AT, ID, input.after, input.direction)}
    ${keysetOrder(RECEIVED_AT, ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

/** Plan 3 (D5), step 1: the recipient rows of one address (keyset `(received_at, id)`). */
export function recipientPlanSql(input: MessagePlanInput & { address: string }): Prisma.Sql {
  return Prisma.sql`SELECT id, received_at, message_id, organization_id
    FROM email_recipients ${forceIndex(MESSAGE_INDEXES.recipientAddress)}
    WHERE organization_id = ${input.organizationId} AND address = ${input.address}
      AND received_at >= ${input.range.from} AND received_at < ${input.range.to}
      AND ${afterKey(RECEIVED_AT, ID, input.after, input.direction)}
    ${keysetOrder(RECEIVED_AT, ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

/**
 * Plan 3, step 2: the messages of the recipient rows by `(id, received_at)` (primary key, one
 * partition each). An OR of `(id = ? AND received_at = ?)` terms: MySQL 8.4 answered the
 * equivalent row-constructor `(id, received_at) IN ((?, ?), …)` with an empty result on the
 * first execution of a new prepared statement with several pairs (observed locally, 2026-11-12).
 */
export function messagesByKeysSql(
  organizationId: bigint,
  keys: ReadonlyArray<{ id: bigint; receivedAt: Date }>,
): Prisma.Sql {
  const terms = Prisma.join(
    keys.map((k) => Prisma.sql`(id = ${k.id} AND received_at = ${k.receivedAt})`),
    ' OR ',
  );
  return Prisma.sql`SELECT ${MESSAGE_COLUMNS} FROM email_messages
    WHERE organization_id = ${organizationId} AND (${terms})`;
}

/**
 * Plan 4 (D5, D6), step 1: the key of the `budget`-th index entry after the cursor
 * (index-only on `(organization_id, received_at, id)`); none when fewer entries are left.
 */
export function scanBoundarySql(input: MessagePlanInput & { budget: number }): Prisma.Sql {
  return Prisma.sql`SELECT received_at, id FROM email_messages ${forceIndex(MESSAGE_INDEXES.orgReceived)}
    WHERE organization_id = ${input.organizationId}
      AND received_at >= ${input.range.from} AND received_at < ${input.range.to}
      AND ${afterKey(RECEIVED_AT, ID, input.after, input.direction)}
    ${keysetOrder(RECEIVED_AT, ID, input.direction)} LIMIT 1 OFFSET ${boundaryOffset(input.budget)}`;
}

/** The filter predicates of the scan plan; columns from code constants, values bound. */
export function messageFilterSql(
  organizationId: bigint,
  filters: ResolvedMessageFilters,
): Prisma.Sql[] {
  const parts: Prisma.Sql[] = [];
  const inList = (col: string, values: readonly string[] | undefined) => {
    if (values && values.length > 0)
      parts.push(Prisma.sql`${column(col)} IN (${Prisma.join(values)})`);
  };
  inList('direction', filters.direction?.values);
  inList('status', filters.status?.values);
  inList('final_verdict', filters.verdict?.values);
  inList('final_action', filters.action?.values);
  if (filters.domainId !== undefined) parts.push(Prisma.sql`domain_id = ${filters.domainId}`);
  const sender = filters.sender?.values?.[0];
  if (sender !== undefined) parts.push(Prisma.sql`envelope_from = ${sender}`);
  const headerFrom = filters.headerFrom?.values?.[0];
  if (headerFrom !== undefined) parts.push(Prisma.sql`header_from = ${headerFrom}`);
  const internetMessageId = filters.internetMessageId?.values?.[0];
  if (internetMessageId !== undefined) {
    parts.push(Prisma.sql`internet_message_id = ${internetMessageId}`);
  }
  const risk = filters.riskScore;
  if (risk) {
    if (risk.values && risk.values.length > 0) {
      parts.push(Prisma.sql`risk_score IN (${Prisma.join(risk.values)})`);
    }
    if (risk.gte !== undefined) parts.push(Prisma.sql`risk_score >= ${risk.gte}`);
    if (risk.gt !== undefined) parts.push(Prisma.sql`risk_score > ${risk.gt}`);
    if (risk.lte !== undefined) parts.push(Prisma.sql`risk_score <= ${risk.lte}`);
    if (risk.lt !== undefined) parts.push(Prisma.sql`risk_score < ${risk.lt}`);
  }
  const hasAttachments = filters.hasAttachments?.values?.[0];
  if (hasAttachments !== undefined) {
    parts.push(
      hasAttachments ? Prisma.sql`attachment_count > 0` : Prisma.sql`attachment_count = 0`,
    );
  }
  const recipient = filters.recipient?.values?.[0];
  if (recipient !== undefined) {
    parts.push(Prisma.sql`EXISTS (SELECT 1 FROM email_recipients r
      WHERE r.organization_id = ${organizationId} AND r.message_id = email_messages.id
        AND r.received_at = email_messages.received_at AND r.address = ${recipient})`);
  }
  return parts;
}

/** Plan 4, step 2: the filtered rows between the cursor and the boundary (inclusive). */
export function scanPageSql(
  input: MessagePlanInput & { boundary: TimeIdKey | null; filters: ResolvedMessageFilters },
): Prisma.Sql {
  return Prisma.sql`SELECT ${MESSAGE_COLUMNS} FROM email_messages ${forceIndex(MESSAGE_INDEXES.orgReceived)}
    WHERE organization_id = ${input.organizationId}
      AND received_at >= ${input.range.from} AND received_at < ${input.range.to}
      AND ${afterKey(RECEIVED_AT, ID, input.after, input.direction)}
      AND ${upToKey(RECEIVED_AT, ID, input.boundary, input.direction)}
      AND ${allOf(messageFilterSql(input.organizationId, input.filters))}
    ${keysetOrder(RECEIVED_AT, ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

/** A recipient row of plan 3 (keyset and message key). */
export interface RecipientKeyRow {
  id: bigint;
  receivedAt: Date;
  messageId: bigint;
  organizationId: bigint;
}

const detailSelect = {
  id: true,
  receivedAt: true,
  organizationId: true,
  domainId: true,
  direction: true,
  status: true,
  statusChangedAt: true,
  subject: true,
  envelopeFrom: true,
  headerFrom: true,
  recipientCount: true,
  attachmentCount: true,
  sizeBytes: true,
  finalVerdict: true,
  finalAction: true,
  riskScore: true,
  internetMessageId: true,
  lifecycleRound: true,
  version: true,
  statusReason: true,
  clientIp: true,
  clientHelo: true,
  mtaQueueId: true,
} satisfies Prisma.EmailMessageSelect;

export type MessageDetailRow = Prisma.EmailMessageGetPayload<{ select: typeof detailSelect }> & {
  publicId: string;
};

/** The partition key of a message of the scope (identity + `email_messages` row exist). */
export interface MessageRef {
  id: bigint;
  publicId: string;
  receivedAt: Date;
  organizationId: bigint;
}

const recipientSelect = {
  id: true,
  organizationId: true,
  messageId: true,
  receivedAt: true,
  rcptSeq: true,
  address: true,
  status: true,
  finalAction: true,
  direction: true,
  userId: true,
} satisfies Prisma.EmailRecipientSelect;

export type RecipientRow = Prisma.EmailRecipientGetPayload<{ select: typeof recipientSelect }>;

const deliverySelect = {
  organizationId: true,
  messageId: true,
  recipientId: true,
  deliverySeq: true,
  status: true,
  finalSmtpCode: true,
  deliveredAt: true,
} satisfies Prisma.EmailDeliverySelect;

export type DeliveryRow = Prisma.EmailDeliveryGetPayload<{ select: typeof deliverySelect }>;

/** Most delivery rows read for one recipients page (≤ 100 recipients × delivery sequences). */
const MAX_DELIVERY_ROWS = 2_000;

@Injectable()
export class MessageDataRepository {
  constructor(
    private readonly reader: PrismaReadService,
    private readonly messages: MessagesRepository,
  ) {}

  private get db() {
    return this.reader.client;
  }

  /** Plan 1 (D5). */
  async indexPlan(scope: TenantScope, input: MessagePlanInput): Promise<MessageListRow[]> {
    const rows = await this.messageRows(
      input.range,
      indexPlanSql({ ...input, organizationId: scope.organizationId }),
    );
    assertEcho('messages.indexPlan', rows, { organizationId: scope.organizationId });
    return rows;
  }

  /** Registry public ids of the scope's messages (a row without one is never served). */
  publicIds(scope: TenantScope, ids: readonly bigint[]): Promise<Map<bigint, string>> {
    return this.messages.publicIdMap(scope, ids);
  }

  /** Plan 2. */
  async verdictPlan(
    scope: TenantScope,
    input: MessagePlanInput & { verdict: string },
  ): Promise<MessageListRow[]> {
    const rows = await this.messageRows(
      input.range,
      verdictPlanSql({ ...input, organizationId: scope.organizationId }),
    );
    assertEcho('messages.verdictPlan', rows, {
      organizationId: scope.organizationId,
      finalVerdict: input.verdict,
    });
    return rows;
  }

  /** Plan 3, step 1: recipient rows of the address (keyset order). */
  async recipientRows(
    scope: TenantScope,
    input: MessagePlanInput & { address: string },
  ): Promise<RecipientKeyRow[]> {
    const raw = await this.db.$queryRaw<
      Array<{ id: bigint; received_at: Date; message_id: bigint; organization_id: bigint }>
    >(recipientPlanSql({ ...input, organizationId: scope.organizationId }));
    const rows = raw.map((r) => ({
      id: BigInt(r.id),
      receivedAt: r.received_at,
      messageId: BigInt(r.message_id),
      organizationId: BigInt(r.organization_id),
    }));
    assertEcho('messages.recipientPlan', rows, { organizationId: scope.organizationId });
    this.assertInRange('messages.recipientPlan', rows, input.range);
    return rows;
  }

  /** Plan 3, step 2: the messages of recipient rows (one query by `(id, received_at)`). */
  async messagesByKeys(
    scope: TenantScope,
    range: { from: Date; to: Date },
    keys: ReadonlyArray<{ id: bigint; receivedAt: Date }>,
  ): Promise<MessageListRow[]> {
    if (keys.length === 0) return [];
    const rows = await this.messageRows(range, messagesByKeysSql(scope.organizationId, keys));
    assertEcho('messages.byKeys', rows, {
      organizationId: scope.organizationId,
      id: keys.map((k) => k.id),
    });
    return rows;
  }

  /** Plan 4, step 1. */
  async scanBoundary(
    scope: TenantScope,
    input: MessagePlanInput & { budget: number },
  ): Promise<TimeIdKey | null> {
    const raw = await this.db.$queryRaw<Array<{ received_at: Date; id: bigint }>>(
      scanBoundarySql({ ...input, organizationId: scope.organizationId }),
    );
    const row = raw[0];
    if (!row) return null;
    const key = { at: row.received_at, id: BigInt(row.id) };
    this.assertInRange('messages.scanBoundary', [{ receivedAt: key.at }], input.range);
    return key;
  }

  /** Plan 4, step 2. */
  async scanPage(
    scope: TenantScope,
    input: MessagePlanInput & { boundary: TimeIdKey | null; filters: ResolvedMessageFilters },
  ): Promise<MessageListRow[]> {
    const rows = await this.messageRows(
      input.range,
      scanPageSql({ ...input, organizationId: scope.organizationId }),
    );
    assertEcho('messages.scanPage', rows, { organizationId: scope.organizationId });
    return rows;
  }

  /** Public ids of the scope's domains by internal id (any status: the message's domain). */
  async domainPublicIds(scope: TenantScope, ids: readonly bigint[]): Promise<Map<bigint, string>> {
    const unique = [...new Set(ids)];
    if (unique.length === 0) return new Map();
    const rows = await this.db.domain.findMany({
      where: tenantWhere(scope, { id: { in: unique } }),
      select: { id: true, publicId: true, organizationId: true },
    });
    assertEcho('messages.domainPublicIds', rows, {
      organizationId: scope.organizationId,
      id: unique,
    });
    return new Map(rows.map((r) => [r.id, r.publicId]));
  }

  /**
   * The message of the scope with this registry public id (identity, then one partition by
   * `(id, received_at)`), or null; another tenant's id is null.
   */
  async findRef(scope: TenantScope, publicId: string): Promise<MessageRef | null> {
    const detail = await this.findDetail(scope, publicId);
    return detail
      ? {
          id: detail.id,
          publicId: detail.publicId,
          receivedAt: detail.receivedAt,
          organizationId: detail.organizationId,
        }
      : null;
  }

  async findDetail(scope: TenantScope, publicId: string): Promise<MessageDetailRow | null> {
    const identity = await this.db.messageIdentity.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, publicId: true, receivedAt: true, organizationId: true },
    });
    if (!identity) return null;
    assertEcho('messages.identity', [identity], {
      organizationId: scope.organizationId,
      publicId,
    });
    const message = await this.db.emailMessage.findFirst({
      where: tenantWhere(scope, { id: identity.id, receivedAt: identity.receivedAt }),
      select: detailSelect,
    });
    if (!message) return null;
    assertEcho('messages.detail', [message], {
      organizationId: scope.organizationId,
      id: identity.id,
      receivedAt: identity.receivedAt,
    });
    return { ...message, publicId: identity.publicId };
  }

  /** Recipients of the message with `rcpt_seq` after `afterSeq`, ascending. */
  async recipients(
    scope: TenantScope,
    message: MessageRef,
    page: { take: number; afterSeq?: number | undefined },
  ): Promise<RecipientRow[]> {
    const rows = await this.db.emailRecipient.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        ...(page.afterSeq !== undefined && { rcptSeq: { gt: page.afterSeq } }),
      }),
      select: recipientSelect,
      orderBy: { rcptSeq: 'asc' },
      take: clampTake(page.take),
    });
    assertEcho('messages.recipients', rows, {
      organizationId: scope.organizationId,
      messageId: message.id,
      receivedAt: message.receivedAt,
    });
    return rows;
  }

  /** Every delivery row of the given recipients (`(message_id, received_at)` index). */
  async deliveries(
    scope: TenantScope,
    message: MessageRef,
    recipientIds: readonly bigint[],
  ): Promise<DeliveryRow[]> {
    if (recipientIds.length === 0) return [];
    const rows = await this.db.emailDelivery.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        recipientId: { in: [...recipientIds] },
      }),
      select: deliverySelect,
      orderBy: [{ recipientId: 'asc' }, { deliverySeq: 'desc' }],
      take: MAX_DELIVERY_ROWS,
    });
    assertEcho('messages.deliveries', rows, {
      organizationId: scope.organizationId,
      messageId: message.id,
      recipientId: [...recipientIds],
    });
    return rows;
  }

  /** Lifecycle rounds of the message's scans by scan id (`email_scans`, pruned). */
  async scanRounds(
    scope: TenantScope,
    message: MessageRef,
    scanIds: readonly bigint[],
  ): Promise<Map<bigint, number>> {
    const ids = [...new Set(scanIds)];
    if (ids.length === 0) return new Map();
    const rows = await this.db.emailScan.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        id: { in: ids },
      }),
      select: { id: true, lifecycleRound: true, organizationId: true, messageId: true },
    });
    assertEcho('messages.scanRounds', rows, {
      organizationId: scope.organizationId,
      messageId: message.id,
      id: ids,
    });
    return new Map(rows.map((r) => [r.id, r.lifecycleRound]));
  }

  /** Public ids of the scope's users by internal id. */
  async userPublicIds(scope: TenantScope, ids: readonly bigint[]): Promise<Map<bigint, string>> {
    const unique = [...new Set(ids)];
    if (unique.length === 0) return new Map();
    const rows = await this.db.user.findMany({
      where: tenantWhere(scope, { id: { in: unique } }),
      select: { id: true, publicId: true, organizationId: true },
    });
    assertEcho('messages.userPublicIds', rows, {
      organizationId: scope.organizationId,
      id: unique,
    });
    return new Map(rows.map((r) => [r.id, r.publicId]));
  }

  private async messageRows(
    range: { from: Date; to: Date },
    sql: Prisma.Sql,
  ): Promise<MessageListRow[]> {
    const rows = (await this.db.$queryRaw<RawMessageRow[]>(sql)).map(toRow);
    this.assertInRange('messages.rows', rows, range);
    return rows;
  }

  private assertInRange(
    read: string,
    rows: ReadonlyArray<{ receivedAt: Date }>,
    range: { from: Date; to: Date },
  ): void {
    const outside = rows.some(
      (r) =>
        r.receivedAt.getTime() < range.from.getTime() ||
        r.receivedAt.getTime() >= range.to.getTime(),
    );
    if (outside) throw new InconsistentReadError(read);
  }
}

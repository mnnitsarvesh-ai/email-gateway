import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { CursorDirection } from '../../../http/cursor/cursor-codec';
import { assertEcho, InconsistentReadError } from '../../../http/listing/echo-check';
import { isQueryTimeout } from '../../reports/domain/report-errors';
import { MessagesRepository } from '../../tenant-data/messages.repository';
import { clampTake } from '../../tenant-data/page';
import type { TimeIdKey } from '../domain/v1-list';
import { messageSearchTimeout } from '../messages.errors';
import {
  type ForeignDriver,
  foreignBoundarySql,
  foreignKeysSql,
  foreignPageSql,
  messagesBoundarySql,
  messagesByKeysSql,
  type MessagesTableDriver,
  messagesPageSql,
  prefixPageSql,
  prefixProbeSql,
  recipientBoundarySql,
  recipientPageSql,
  recipientRowsSql,
  type ResolvedResiduals,
  residualSql,
} from './message-list-drivers';

export { MESSAGE_INDEXES } from './message-list-drivers';

/**
 * Reads of the message data routes (step 6.1 WP2, D5, D15; the step 7.2 search drivers, §2 E1,
 * §3.2) on the replica (`PrismaReadService`): the driver statements of `GET /messages` (SQL in
 * `message-list-drivers.ts`), the detail, the recipients with their latest delivery, and the
 * public ids of the domains and users the rows reference. Every query matches the scope's
 * organization first and every partitioned table is read with its `received_at`. Every returned
 * row is echo-checked (D15): the organization, the range, the per-statement `echo_nonce` of the
 * driver statements and, where the key is exact-valued (verdict, delivery and quarantine
 * states), the key; a mismatch is `503 inconsistent_read`. The subject-prefix statements carry
 * `MAX_EXECUTION_TIME`; a timeout is `503 message_search_timeout`.
 */

interface RawMessageRow {
  echo_nonce?: string;
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

/** What every driver reads: the resolved window, the keyset position and the order. */
export interface MessagePlanInput {
  organizationId: bigint;
  range: { from: Date; to: Date };
  after?: TimeIdKey | undefined;
  direction: CursorDirection;
  /** limit + 1 */
  take: number;
}

/** A page of the `recipient` driver with residuals: message rows with their recipient row id. */
export interface RecipientPageRow extends MessageListRow {
  rid: bigint;
}

/** A grouped key of a foreign driver: the message's `(received_at, id)`. */
export interface ForeignKeyRow {
  receivedAt: Date;
  id: bigint;
}

/** A key row of a boundary or foreign statement. */
interface KeyRow {
  echo_nonce: string;
  organization_id: bigint;
  received_at: Date;
  id: bigint;
}

/** A recipient row of the exact `recipient` driver (keyset and message key). */
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

  /** Registry public ids of the scope's messages (a row without one is never served). */
  publicIds(scope: TenantScope, ids: readonly bigint[]): Promise<Map<bigint, string>> {
    return this.messages.publicIdMap(scope, ids);
  }

  /**
   * A page of an `email_messages` driver (`none`, `scan`, `verdict`, `internetMessageId`,
   * `sender`, `headerFrom`, `subject`, `senderDomain`): exact without a boundary and residuals,
   * budgeted with them.
   */
  async messagesPage(
    scope: TenantScope,
    input: MessagePlanInput & {
      driver: MessagesTableDriver;
      key?: string | undefined;
      boundary?: TimeIdKey | null;
      residuals?: ResolvedResiduals;
    },
  ): Promise<MessageListRow[]> {
    const nonce = randomUUID();
    const { residuals, ...rest } = input;
    const raw = await this.db.$queryRaw<RawMessageRow[]>(
      messagesPageSql({
        ...rest,
        organizationId: scope.organizationId,
        nonce,
        ...(residuals && { residuals: residualSql(scope.organizationId, residuals) }),
      }),
    );
    const read = `messages.${input.driver}`;
    const rows = this.messageRows(read, raw, nonce, input.range);
    if (input.driver === 'verdict') {
      assertEcho(read, rows, { organizationId: scope.organizationId, finalVerdict: input.key! });
    }
    return rows;
  }

  /** Budget step 1 of an `email_messages` driver (index-only). */
  async messagesBoundary(
    scope: TenantScope,
    input: Omit<MessagePlanInput, 'take'> & {
      driver: MessagesTableDriver;
      key?: string | undefined;
      budget: number;
    },
  ): Promise<TimeIdKey | null> {
    const nonce = randomUUID();
    const raw = await this.db.$queryRaw<KeyRow[]>(
      messagesBoundarySql({ ...input, organizationId: scope.organizationId, nonce }),
    );
    return this.boundaryOf(`messages.${input.driver}.boundary`, raw, nonce, scope, input.range);
  }

  /** The exact `recipient` driver (6.1 plan 3 step 1): recipient rows of the address. */
  async recipientRows(
    scope: TenantScope,
    input: MessagePlanInput & { address: string },
  ): Promise<RecipientKeyRow[]> {
    const nonce = randomUUID();
    const raw = await this.db.$queryRaw<
      Array<{
        echo_nonce: string;
        id: bigint;
        received_at: Date;
        message_id: bigint;
        organization_id: bigint;
      }>
    >(recipientRowsSql({ ...input, organizationId: scope.organizationId, nonce }));
    this.assertNonce('messages.recipient', raw, nonce);
    const rows = raw.map((r) => ({
      id: BigInt(r.id),
      receivedAt: r.received_at,
      messageId: BigInt(r.message_id),
      organizationId: BigInt(r.organization_id),
    }));
    assertEcho('messages.recipient', rows, { organizationId: scope.organizationId });
    this.assertInRange('messages.recipient', rows, input.range);
    return rows;
  }

  /** Budget step 1 of the `recipient` driver (keyset `(received_at, recipient row id)`). */
  async recipientBoundary(
    scope: TenantScope,
    input: Omit<MessagePlanInput, 'take'> & { address: string; budget: number },
  ): Promise<TimeIdKey | null> {
    const nonce = randomUUID();
    const raw = await this.db.$queryRaw<KeyRow[]>(
      recipientBoundarySql({ ...input, organizationId: scope.organizationId, nonce }),
    );
    return this.boundaryOf('messages.recipient.boundary', raw, nonce, scope, input.range);
  }

  /** Budgeted page of the `recipient` driver: message rows with their recipient row id. */
  async recipientPage(
    scope: TenantScope,
    input: MessagePlanInput & {
      address: string;
      boundary: TimeIdKey | null;
      residuals: ResolvedResiduals;
    },
  ): Promise<RecipientPageRow[]> {
    const nonce = randomUUID();
    const raw = await this.db.$queryRaw<Array<RawMessageRow & { rid: bigint }>>(
      recipientPageSql({
        ...input,
        organizationId: scope.organizationId,
        nonce,
        residuals: residualSql(scope.organizationId, input.residuals),
      }),
    );
    const rows = this.messageRows('messages.recipient.page', raw, nonce, input.range);
    return rows.map((row, i) => ({ ...row, rid: BigInt(raw[i]!.rid) }));
  }

  /** Exact page of a foreign driver: grouped `(received_at, message id)` keys. */
  async foreignKeys(
    scope: TenantScope,
    input: MessagePlanInput & { driver: ForeignDriver; key: string },
  ): Promise<ForeignKeyRow[]> {
    const nonce = randomUUID();
    const read = `messages.${input.driver}`;
    const raw = await this.db.$queryRaw<Array<KeyRow & { driver_key: string }>>(
      foreignKeysSql({ ...input, organizationId: scope.organizationId, nonce }),
    );
    this.assertNonce(read, raw, nonce);
    const rows = raw.map((r) => ({
      organizationId: BigInt(r.organization_id),
      driverKey: r.driver_key,
      receivedAt: r.received_at,
      id: BigInt(r.id),
    }));
    assertEcho(read, rows, {
      organizationId: scope.organizationId,
      // Delivery and quarantine states are exact enum values; a recipient domain is compared
      // under the column collation (the nonce binds the rows to this statement).
      ...(input.driver !== 'recipientDomain' && { driverKey: input.key }),
    });
    this.assertInRange(read, rows, input.range);
    return rows.map((r) => ({ receivedAt: r.receivedAt, id: r.id }));
  }

  /** Budget step 1 of a foreign driver (raw index entries). */
  async foreignBoundary(
    scope: TenantScope,
    input: Omit<MessagePlanInput, 'take'> & { driver: ForeignDriver; key: string; budget: number },
  ): Promise<TimeIdKey | null> {
    const nonce = randomUUID();
    const raw = await this.db.$queryRaw<KeyRow[]>(
      foreignBoundarySql({ ...input, organizationId: scope.organizationId, nonce }),
    );
    return this.boundaryOf(`messages.${input.driver}.boundary`, raw, nonce, scope, input.range);
  }

  /** Budgeted page of a foreign driver: the messages of the grouped keys, residuals applied. */
  async foreignPage(
    scope: TenantScope,
    input: MessagePlanInput & {
      driver: ForeignDriver;
      key: string;
      boundary: TimeIdKey | null;
      residuals: ResolvedResiduals;
    },
  ): Promise<MessageListRow[]> {
    const nonce = randomUUID();
    const raw = await this.db.$queryRaw<RawMessageRow[]>(
      foreignPageSql({
        ...input,
        organizationId: scope.organizationId,
        nonce,
        residuals: residualSql(scope.organizationId, input.residuals),
      }),
    );
    return this.messageRows(`messages.${input.driver}.page`, raw, nonce, input.range);
  }

  /** The messages of a page of keys (one query by `(id, received_at)`). */
  async messagesByKeys(
    scope: TenantScope,
    range: { from: Date; to: Date },
    keys: ReadonlyArray<{ id: bigint; receivedAt: Date }>,
  ): Promise<MessageListRow[]> {
    if (keys.length === 0) return [];
    const raw = await this.db.$queryRaw<RawMessageRow[]>(
      messagesByKeysSql(scope.organizationId, keys),
    );
    const rows = raw.map(toRow);
    this.assertInRange('messages.byKeys', rows, range);
    assertEcho('messages.byKeys', rows, {
      organizationId: scope.organizationId,
      id: keys.map((k) => k.id),
    });
    const wanted = new Set(keys.map((k) => `${k.id}:${k.receivedAt.getTime()}`));
    if (rows.some((r) => !wanted.has(`${r.id}:${r.receivedAt.getTime()}`))) {
      throw new InconsistentReadError('messages.byKeys');
    }
    return rows;
  }

  /**
   * Probe of the subject-prefix driver: true when more than `cap` subject keys of the window
   * (after the cursor) start with the prefix (the `(cap + 1)`-th entry exists). A
   * `MAX_EXECUTION_TIME` timeout is `503 message_search_timeout`.
   */
  async prefixProbe(
    scope: TenantScope,
    input: Omit<MessagePlanInput, 'take'> & { pattern: string; cap: number; timeoutMs: number },
  ): Promise<boolean> {
    const nonce = randomUUID();
    const raw = await this.timed(() =>
      this.db.$queryRaw<KeyRow[]>(
        prefixProbeSql({ ...input, organizationId: scope.organizationId, nonce }),
      ),
    );
    if (raw.length > 1) throw new InconsistentReadError('messages.subjectPrefix.probe');
    return this.boundaryOf('messages.subjectPrefix.probe', raw, nonce, scope, input.range) !== null;
  }

  /** Page of the subject-prefix driver (sorted within the cap, residuals applied). */
  async prefixPage(
    scope: TenantScope,
    input: MessagePlanInput & { pattern: string; timeoutMs: number; residuals: ResolvedResiduals },
  ): Promise<MessageListRow[]> {
    const nonce = randomUUID();
    const raw = await this.timed(() =>
      this.db.$queryRaw<RawMessageRow[]>(
        prefixPageSql({
          ...input,
          organizationId: scope.organizationId,
          nonce,
          residuals: residualSql(scope.organizationId, input.residuals),
        }),
      ),
    );
    return this.messageRows('messages.subjectPrefix.page', raw, nonce, input.range);
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

  /** Rows of a driver statement: nonce, organization and range checked (D15). */
  private messageRows(
    read: string,
    raw: readonly RawMessageRow[],
    nonce: string,
    range: { from: Date; to: Date },
  ): MessageListRow[] {
    this.assertNonce(read, raw, nonce);
    const rows = raw.map(toRow);
    this.assertInRange(read, rows, range);
    return rows;
  }

  /** The boundary key of a budget step 1, checked like a row. */
  private boundaryOf(
    read: string,
    raw: readonly KeyRow[],
    nonce: string,
    scope: TenantScope,
    range: { from: Date; to: Date },
  ): TimeIdKey | null {
    const row = raw[0];
    if (!row) return null;
    this.assertNonce(read, raw, nonce);
    const key = { organizationId: BigInt(row.organization_id), receivedAt: row.received_at };
    assertEcho(read, [key], { organizationId: scope.organizationId });
    this.assertInRange(read, [key], range);
    return { at: row.received_at, id: BigInt(row.id) };
  }

  /** Every row carries this statement's nonce (the result is not another statement's). */
  private assertNonce(read: string, rows: ReadonlyArray<{ echo_nonce?: string }>, nonce: string) {
    if (rows.some((r) => r.echo_nonce !== nonce)) throw new InconsistentReadError(read);
  }

  /** `MAX_EXECUTION_TIME` interruptions (MySQL 3024) as `503 message_search_timeout`. */
  private async timed<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (err) {
      if (isQueryTimeout(err)) throw messageSearchTimeout();
      throw err;
    }
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

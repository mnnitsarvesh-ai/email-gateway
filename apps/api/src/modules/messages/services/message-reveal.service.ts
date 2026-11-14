import { Injectable, Logger } from '@nestjs/common';
import { MetricsService } from '@email-gateway/common';
import { type AuditEntry, AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import { isRevealableHeader, MASKED_HEADER_NAMES } from '../domain/sensitive-masking';
import { decodeListCursor, encodeListCursor, intKey, listBinding } from '../domain/v1-list';
import {
  MESSAGE_RECIPIENTS_REVEAL_RESOURCE,
  MESSAGE_REVEAL_DEFAULT_RECIPIENTS,
  type RevealBody,
  type RevealManyBody,
  type RevealManyResponse,
  type RevealResponse,
} from '../dto/message-sensitive.schemas';
import { messageNotFound, revealNotRecorded } from '../messages.errors';
import { MessageDataRepository, type MessageRef } from '../repositories/message-data.repository';
import { MessageHeadersRepository } from '../repositories/message-headers.repository';
import { MessageRevealRepository } from '../repositories/message-reveal.repository';
import { MessageRevealMetrics } from './message-reveal-metrics';

const MAX_RCPT_SEQ = 65_535;

/** The audit action of every reveal (§2 E6). */
export const MESSAGE_REVEALED = 'message.revealed';

/** What a single reveal returned, for the audit metadata (counts and positions, never values). */
export interface RevealAuditInput {
  fields: readonly string[];
  bulk?: boolean;
  headerCount?: number;
  recipients?: { count: number; firstRcptSeq: number | null; lastRcptSeq: number | null };
}

/** The audit metadata of one revealed message (§2 E6): fields and counts, never values. */
export function revealMetadata(input: RevealAuditInput): Record<string, unknown> {
  return {
    fields: [...input.fields],
    ...(input.bulk === true && { bulk: true }),
    ...(input.headerCount !== undefined && { headerCount: input.headerCount }),
    ...(input.recipients !== undefined && { recipients: { ...input.recipients } }),
  };
}

/**
 * The audited reveal operations (step 7.2 §2 E6, ADR-0062): the only way the api returns a clear
 * subject, recipient address, matched user id or To/Cc/Subject header value of the message
 * surface. Values are read from the replica; then **one writer transaction** commits one
 * `message.revealed` audit row per revealed message (resource `message`/`<public id>`, fields and
 * counts only, the override metadata of an override session through `AuditService.actorFrom`);
 * only after that commit is the response built. A failed audit write is `503
 * service_unavailable` and returns no value. Unknown and foreign ids look alike: omitted (bulk)
 * or `404 message_not_found` (single). The recipients of a single reveal page with a v1 cursor
 * (`message_recipients_reveal`) bound to the message and the organization.
 */
@Injectable()
export class MessageRevealService {
  private readonly logger = new Logger(MessageRevealService.name);
  private readonly metrics: MessageRevealMetrics;

  constructor(
    private readonly reveals: MessageRevealRepository,
    private readonly data: MessageDataRepository,
    private readonly headers: MessageHeadersRepository,
    private readonly codec: CursorCodec,
    private readonly audit: AuditService,
    private readonly transactions: TransactionRunner,
    metricsService: MetricsService,
  ) {
    this.metrics = new MessageRevealMetrics(metricsService);
  }

  now(): Date {
    return new Date();
  }

  /** `POST /messages/reveal`: the subjects of up to 100 messages, in request order. */
  async revealMany(
    principal: Principal,
    scope: TenantScope,
    body: RevealManyBody,
    sourceIp: string | null,
  ): Promise<RevealManyResponse> {
    const refs = await this.reveals.refs(scope, body.messageIds);
    const rows = await this.reveals.subjects(scope, refs);
    const byPublicId = new Map(rows.map((row) => [row.ref.publicId, row]));
    const revealed = body.messageIds.flatMap((id) => {
      const row = byPublicId.get(id);
      return row ? [row] : [];
    });
    const revealedAt = this.now();
    await this.record(
      revealed.map((row) =>
        this.entry(principal, scope, row.ref.publicId, sourceIp, {
          fields: ['subject'],
          bulk: true,
        }),
      ),
    );
    this.metrics.reveals.inc({ kind: 'bulk' });
    if (revealed.length > 0) this.metrics.values.inc({ field: 'subject' }, revealed.length);
    return {
      revealedAt: revealedAt.toISOString(),
      data: revealed.map((row) => ({ id: row.ref.publicId, subject: row.subject })),
    };
  }

  /** `POST /messages/{messageId}/reveal`: subject, To/Cc/Subject rows, a page of recipients. */
  async reveal(
    principal: Principal,
    scope: TenantScope,
    messageId: string,
    body: RevealBody,
    sourceIp: string | null,
  ): Promise<RevealResponse> {
    const fields = new Set(body.fields);
    const wantsRecipients = fields.has('recipients');
    // The cursor is checked before anything is read (400 cursor_invalid, like the lists).
    const binding = listBinding({
      resource: MESSAGE_RECIPIENTS_REVEAL_RESOURCE,
      principal,
      filters: { messageId: { values: [messageId] } },
      sort: 'rcptSeq',
    });
    const decoded = wantsRecipients
      ? decodeListCursor(this.codec, binding, body.recipientsCursor, 1)
      : undefined;
    const afterSeq = decoded ? intKey(decoded.keys[0], MAX_RCPT_SEQ) : undefined;

    const detail = await this.data.findDetail(scope, messageId);
    if (!detail) throw messageNotFound();
    const message: MessageRef = {
      id: detail.id,
      publicId: detail.publicId,
      receivedAt: detail.receivedAt,
      organizationId: detail.organizationId,
    };
    const limit = body.recipientsLimit ?? MESSAGE_REVEAL_DEFAULT_RECIPIENTS;
    const [headerRows, recipients] = await Promise.all([
      fields.has('headers')
        ? this.headers.headers(scope, message, MASKED_HEADER_NAMES)
        : Promise.resolve(undefined),
      wantsRecipients
        ? this.recipientsPage(scope, message, limit, afterSeq)
        : Promise.resolve(undefined),
    ]);
    // Defence in depth: only the masked names, whatever the SQL collation matched.
    const headers = headerRows?.filter((row) => isRevealableHeader(row.name));

    const revealedAt = this.now();
    await this.record([
      this.entry(principal, scope, message.publicId, sourceIp, {
        fields: body.fields,
        ...(headers !== undefined && { headerCount: headers.length }),
        ...(recipients !== undefined && {
          recipients: {
            count: recipients.rows.length,
            firstRcptSeq: recipients.rows[0]?.rcptSeq ?? null,
            lastRcptSeq: recipients.rows.at(-1)?.rcptSeq ?? null,
          },
        }),
      }),
    ]);
    this.metrics.reveals.inc({ kind: 'message' });
    if (fields.has('subject')) this.metrics.values.inc({ field: 'subject' });
    if (headers && headers.length > 0)
      this.metrics.values.inc({ field: 'headers' }, headers.length);
    if (recipients && recipients.rows.length > 0) {
      this.metrics.values.inc({ field: 'recipients' }, recipients.rows.length);
    }

    return {
      messageId: message.publicId,
      revealedAt: revealedAt.toISOString(),
      ...(fields.has('subject') && { subject: detail.subject }),
      ...(headers !== undefined && {
        headers: headers.map((row) => ({ seq: row.seq, name: row.name, value: row.value })),
      }),
      ...(recipients !== undefined && {
        recipients: {
          data: recipients.rows,
          nextCursor:
            recipients.next === null
              ? null
              : encodeListCursor(this.codec, binding, [String(recipients.next)]),
        },
      }),
    };
  }

  /** One page of recipients (keyset `rcptSeq`) with their matched users' public ids. */
  private async recipientsPage(
    scope: TenantScope,
    message: MessageRef,
    limit: number,
    afterSeq: number | undefined,
  ): Promise<{
    rows: Array<{ rcptSeq: number; address: string; userId: string | null }>;
    next: number | null;
  }> {
    const fetched = await this.data.recipients(scope, message, { take: limit + 1, afterSeq });
    const decision = decideKeysetPage({ fetched, limit, keyOf: (r) => r.rcptSeq });
    const page = fetched.slice(0, decision.rows);
    const users = await this.data.userPublicIds(
      scope,
      page.flatMap((r) => (r.userId === null ? [] : [r.userId])),
    );
    return {
      rows: page.map((r) => ({
        rcptSeq: r.rcptSeq,
        address: r.address,
        userId: r.userId === null ? null : (users.get(r.userId) ?? null),
      })),
      next: decision.next,
    };
  }

  private entry(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    sourceIp: string | null,
    input: RevealAuditInput,
  ): AuditEntry {
    return {
      organizationId: scope.organizationId,
      actor: this.audit.actorFrom(principal),
      action: MESSAGE_REVEALED,
      resourceType: 'message',
      resourceId: publicId,
      sourceIp,
      metadata: revealMetadata(input),
    };
  }

  /**
   * Commits the audit rows in one writer transaction before any value is returned; a failure is
   * `503 service_unavailable` (logged without values).
   */
  private async record(entries: readonly AuditEntry[]): Promise<void> {
    if (entries.length === 0) return;
    try {
      await this.transactions.run(async (tx) => {
        for (const entry of entries) await this.audit.record(entry, tx);
      });
    } catch (err) {
      this.logger.error({
        message: 'message.revealed audit write failed: no value returned',
        err,
        rows: entries.length,
      });
      throw revealNotRecorded();
    }
  }
}

import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { ApiConventionMetrics } from '../../../http/api-metrics';
import { CursorCodec, cursorInvalid } from '../../../http/cursor/cursor-codec';
import { rangeWindow, resolveRange } from '../../../http/listing/range';
import { decideKeysetPage, decideScanPage } from '../../../http/listing/scan-budget';
import { DomainsRepository } from '../../tenant-data/domains.repository';
import {
  identifyingFilters,
  type MessageListPlan,
  presentFilters,
  selectMessagePlan,
} from '../domain/message-list-plan';
import {
  decodeListCursor,
  encodeListCursor,
  intKey,
  listBinding,
  sha256Hex,
  type TimeIdKey,
  timeIdKeyOf,
  timeIdKeys,
} from '../domain/v1-list';
import {
  MESSAGE_RECIPIENTS_RESOURCE,
  MESSAGES_RESOURCE,
  type MessageDetail,
  type MessageListItem,
  type MessageListPage,
  type MessageListQuery,
  type MessageRecipientItem,
  type MessageRecipientsPage,
  type MessageRecipientsQuery,
} from '../dto/message-data.schemas';
import { domainNotFound, messageNotFound } from '../messages.errors';
import {
  type DeliveryRow,
  MessageDataRepository,
  type MessageDetailRow,
  type MessageListRow,
  type MessagePlanInput,
  type MessageRef,
  type RecipientRow,
} from '../repositories/message-data.repository';

const DAY_MS = 86_400_000;
const MAX_RCPT_SEQ = 65_535;

type Config = Pick<ApiConfig, 'API_MESSAGES_MAX_RANGE_DAYS' | 'API_LIST_SCAN_BUDGET_ROWS'>;

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

/** A list row as the API item (the domain public id resolved by the caller). */
export function toMessageItem(
  row: MessageListRow,
  publicId: string,
  domainPublicId: string | null,
): MessageListItem {
  return {
    id: publicId,
    receivedAt: row.receivedAt.toISOString(),
    direction: row.direction as MessageListItem['direction'],
    status: row.status as MessageListItem['status'],
    statusChangedAt: row.statusChangedAt.toISOString(),
    subject: row.subject,
    envelopeFrom: row.envelopeFrom,
    headerFrom: row.headerFrom,
    recipientCount: row.recipientCount,
    attachmentCount: row.attachmentCount,
    sizeBytes: row.sizeBytes,
    finalVerdict: row.finalVerdict as MessageListItem['finalVerdict'],
    finalAction: row.finalAction as MessageListItem['finalAction'],
    riskScore: row.riskScore,
    domainId: domainPublicId,
  };
}

export function toMessageDetail(
  row: MessageDetailRow,
  domainPublicId: string | null,
): MessageDetail {
  return {
    ...toMessageItem(row, row.publicId, domainPublicId),
    internetMessageId: row.internetMessageId,
    lifecycleRound: row.lifecycleRound,
    version: row.version,
    statusReason: row.statusReason,
    clientIp: row.clientIp,
    clientHelo: row.clientHelo,
    mtaQueueId: row.mtaQueueId,
  };
}

/** The delivery with the highest `delivery_seq` per recipient id. */
export function latestDeliveries(rows: readonly DeliveryRow[]): Map<bigint, DeliveryRow> {
  const latest = new Map<bigint, DeliveryRow>();
  for (const row of rows) {
    const current = latest.get(row.recipientId);
    if (!current || row.deliverySeq > current.deliverySeq) latest.set(row.recipientId, row);
  }
  return latest;
}

export function toRecipientItem(
  row: RecipientRow,
  delivery: DeliveryRow | undefined,
  userPublicId: string | null,
): MessageRecipientItem {
  return {
    rcptSeq: row.rcptSeq,
    address: row.address,
    status: row.status,
    finalAction: row.finalAction,
    direction: row.direction,
    userId: userPublicId,
    latestDelivery: delivery
      ? {
          deliverySeq: delivery.deliverySeq,
          status: delivery.status,
          finalSmtpCode: delivery.finalSmtpCode,
          deliveredAt: iso(delivery.deliveredAt),
        }
      : null,
  };
}

/** One page of a plan: the rows to serve (keyset order) and the next keyset position. */
interface PlanPage {
  rows: MessageListRow[];
  next: TimeIdKey | null;
  budgetExhausted: boolean;
}

const keyOfMessage = (row: MessageListRow): TimeIdKey => ({ at: row.receivedAt, id: row.id });

/**
 * `GET /messages`, `GET /messages/{messageId}` and `GET /messages/{messageId}/recipients`
 * (step 6.1 WP2, D3–D6, D11): message metadata of the caller's organization from the read
 * replica, through the plan D5 chooses from the filters, with the signed v1 cursor (bound to the
 * filters, sort, organization and the first page's window). Searches by a person- or
 * message-identifying filter are audited on their first page (`message.searched`, values only as
 * SHA-256). Content, S3 keys and internal ids are never returned.
 */
@Injectable()
export class MessageDataService {
  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly repository: MessageDataRepository,
    private readonly domains: DomainsRepository,
    private readonly codec: CursorCodec,
    private readonly audit: AuditService,
    private readonly metrics: ApiConventionMetrics,
  ) {}

  now(): Date {
    return new Date();
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    query: MessageListQuery,
    sourceIp: string | null = null,
  ): Promise<MessageListPage> {
    const binding = listBinding({
      resource: MESSAGES_RESOURCE,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    if (decoded && !decoded.window) throw cursorInvalid();
    const range = resolveRange(query, {
      defaultMs: DAY_MS,
      maxDays: this.config.API_MESSAGES_MAX_RANGE_DAYS,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const domainPublicId = query.filters.domainId?.values?.[0];
    let domainId: bigint | undefined;
    if (domainPublicId !== undefined) {
      const domain = await this.domains.findByPublicId(scope, domainPublicId);
      if (!domain) throw domainNotFound();
      domainId = domain.id;
    }
    const plan = selectMessagePlan(query.filters);
    const input: MessagePlanInput = {
      organizationId: scope.organizationId,
      range,
      after: timeIdKeyOf(decoded),
      direction: binding.direction,
      take: query.limit + 1,
    };
    const page = await this.runPlan(scope, plan, input, query, domainId);
    if (page.budgetExhausted) this.metrics.scanBudgetExhausted.inc({ resource: MESSAGES_RESOURCE });

    const [publicIds, domainIds] = await Promise.all([
      this.repository.publicIds(
        scope,
        page.rows.map((r) => r.id),
      ),
      this.repository.domainPublicIds(
        scope,
        page.rows.flatMap((r) => (r.domainId === null ? [] : [r.domainId])),
      ),
    ]);
    const data = page.rows.flatMap((row) => {
      const publicId = publicIds.get(row.id);
      if (!publicId) return [];
      return [
        toMessageItem(
          row,
          publicId,
          row.domainId === null ? null : (domainIds.get(row.domainId) ?? null),
        ),
      ];
    });

    const identifying = identifyingFilters(query.filters);
    if (query.cursor === undefined && identifying.length > 0) {
      await this.audit.record({
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action: 'message.searched',
        resourceType: 'message',
        resourceId: null,
        sourceIp,
        metadata: {
          filters: presentFilters(query.filters),
          filterHash: binding.filterHash,
          plan,
          valueSha256: Object.fromEntries(
            identifying.map((name) => [name, sha256Hex(String(query.filters[name]?.values?.[0]))]),
          ),
          range: { from: range.from.toISOString(), to: range.to.toISOString() },
          resultCount: data.length,
        },
      });
    }

    return {
      data,
      nextCursor: page.next
        ? encodeListCursor(this.codec, binding, timeIdKeys(page.next), rangeWindow(range))
        : null,
    };
  }

  private async runPlan(
    scope: TenantScope,
    plan: MessageListPlan,
    input: MessagePlanInput,
    query: MessageListQuery,
    domainId: bigint | undefined,
  ): Promise<PlanPage> {
    const limit = query.limit;
    switch (plan) {
      case 'index':
      case 'verdict': {
        const fetched =
          plan === 'index'
            ? await this.repository.indexPlan(scope, input)
            : await this.repository.verdictPlan(scope, {
                ...input,
                verdict: query.filters.verdict!.values![0]!,
              });
        const decision = decideKeysetPage({ fetched, limit, keyOf: keyOfMessage });
        return {
          rows: fetched.slice(0, decision.rows),
          next: decision.next,
          budgetExhausted: false,
        };
      }
      case 'recipient': {
        const recipients = await this.repository.recipientRows(scope, {
          ...input,
          address: query.filters.recipient!.values![0]!,
        });
        const decision = decideKeysetPage({
          fetched: recipients,
          limit,
          keyOf: (r) => ({ at: r.receivedAt, id: r.id }),
        });
        const onPage = recipients.slice(0, decision.rows);
        // One message per page even when the address is several recipients of it (collapse).
        const keys = new Map<bigint, { id: bigint; receivedAt: Date }>();
        for (const r of onPage) {
          if (!keys.has(r.messageId))
            keys.set(r.messageId, { id: r.messageId, receivedAt: r.receivedAt });
        }
        const messages = await this.repository.messagesByKeys(scope, input.range, [
          ...keys.values(),
        ]);
        const byId = new Map(messages.map((m) => [m.id, m]));
        const rows = [...keys.keys()].flatMap((id) => {
          const row = byId.get(id);
          return row ? [row] : [];
        });
        return { rows, next: decision.next, budgetExhausted: false };
      }
      case 'scan': {
        const boundary = await this.repository.scanBoundary(scope, {
          ...input,
          budget: this.config.API_LIST_SCAN_BUDGET_ROWS,
        });
        const { domainId: _publicDomainId, ...filters } = query.filters;
        const fetched = await this.repository.scanPage(scope, {
          ...input,
          boundary,
          filters: { ...filters, ...(domainId !== undefined && { domainId }) },
        });
        const decision = decideScanPage({ fetched, limit, boundary, keyOf: keyOfMessage });
        return {
          rows: fetched.slice(0, decision.rows),
          next: decision.next,
          budgetExhausted: decision.budgetExhausted,
        };
      }
    }
  }

  async detail(scope: TenantScope, messageId: string): Promise<MessageDetail> {
    const row = await this.repository.findDetail(scope, messageId);
    if (!row) throw messageNotFound();
    const domains =
      row.domainId === null
        ? new Map<bigint, string>()
        : await this.repository.domainPublicIds(scope, [row.domainId]);
    return toMessageDetail(row, row.domainId === null ? null : (domains.get(row.domainId) ?? null));
  }

  /** The scope's message or `404 message_not_found` (shared by the message sub-resources). */
  async messageRef(scope: TenantScope, messageId: string): Promise<MessageRef> {
    const ref = await this.repository.findRef(scope, messageId);
    if (!ref) throw messageNotFound();
    return ref;
  }

  async recipients(
    principal: Principal,
    scope: TenantScope,
    messageId: string,
    query: MessageRecipientsQuery,
  ): Promise<MessageRecipientsPage> {
    const binding = listBinding({
      resource: MESSAGE_RECIPIENTS_RESOURCE,
      principal,
      filters: { messageId: { values: [messageId] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const afterSeq = decoded ? intKey(decoded.keys[0], MAX_RCPT_SEQ) : undefined;
    const message = await this.messageRef(scope, messageId);
    const fetched = await this.repository.recipients(scope, message, {
      take: query.limit + 1,
      afterSeq,
    });
    const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf: (r) => r.rcptSeq });
    const rows = fetched.slice(0, decision.rows);
    const [deliveries, users] = await Promise.all([
      this.repository.deliveries(
        scope,
        message,
        rows.map((r) => r.id),
      ),
      this.repository.userPublicIds(
        scope,
        rows.flatMap((r) => (r.userId === null ? [] : [r.userId])),
      ),
    ]);
    const latest = latestDeliveries(deliveries);
    return {
      data: rows.map((row) =>
        toRecipientItem(
          row,
          latest.get(row.id),
          row.userId === null ? null : (users.get(row.userId) ?? null),
        ),
      ),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [String(decision.next)]),
    };
  }
}

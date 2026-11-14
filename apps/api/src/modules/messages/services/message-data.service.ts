import { Inject, Injectable } from '@nestjs/common';
import { MetricsService } from '@email-gateway/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { ApiConventionMetrics } from '../../../http/api-metrics';
import { CodedHttpException } from '../../../http/coded-exception';
import { CursorCodec, cursorInvalid } from '../../../http/cursor/cursor-codec';
import { rangeWindow, resolveRange } from '../../../http/listing/range';
import { decideKeysetPage, decideScanPage } from '../../../http/listing/scan-budget';
import { DomainsRepository } from '../../tenant-data/domains.repository';
import {
  DRIVER_KIND,
  driverBinding,
  forbiddenFilter,
  identifyingFilters,
  identifyingValue,
  type MessageListFilterName,
  type MessageListPlan,
  presentFilters,
  selectMessagePlan,
} from '../domain/message-list-plan';
import {
  normalizeMessageIdKey,
  normalizeSubjectKey,
  normalizeSubjectPrefix,
  subjectPrefixPattern,
} from '../domain/search-keys';
import { maskAddress } from '../domain/sensitive-masking';
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
  type MessageListFilters,
  type MessageListItem,
  type MessageListPage,
  type MessageListQuery,
  type MessageRecipientItem,
  type MessageRecipientsPage,
  type MessageRecipientsQuery,
} from '../dto/message-data.schemas';
import {
  domainNotFound,
  MESSAGE_SEARCH_TIMEOUT,
  messageFilterForbidden,
  messageNotFound,
  messageSearchTooBroad,
} from '../messages.errors';
import {
  type DeliveryRow,
  MessageDataRepository,
  type MessageDetailRow,
  type MessageListRow,
  type MessagePlanInput,
  type MessageRef,
  type RecipientRow,
} from '../repositories/message-data.repository';
import type {
  ForeignDriver,
  MessagesTableDriver,
  ResolvedResiduals,
} from '../repositories/message-list-drivers';
import { MessageSearchMetrics } from '../search-metrics';

const DAY_MS = 86_400_000;
const MAX_RCPT_SEQ = 65_535;

type Config = Pick<
  ApiConfig,
  | 'API_MESSAGES_MAX_RANGE_DAYS'
  | 'API_LIST_SCAN_BUDGET_ROWS'
  | 'API_MESSAGES_SEARCH_MAX_MATCHES'
  | 'API_MESSAGES_SEARCH_TIMEOUT_MS'
>;

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

/**
 * A list row as the API item (the domain public id resolved by the caller). Step 7.2 (§2 E5): the
 * subject is withheld for every caller (`subject: null`, `subjectMasked` when one exists).
 */
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
    subject: null,
    subjectMasked: row.subject !== null,
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

/**
 * A recipient row as the API item. Step 7.2 (§2 E5): the address is masked and the matched user
 * withheld for every caller (`POST /messages/{messageId}/reveal` returns both).
 */
export function toRecipientItem(
  row: RecipientRow,
  delivery: DeliveryRow | undefined,
): MessageRecipientItem {
  return {
    rcptSeq: row.rcptSeq,
    address: maskAddress(row.address),
    addressMasked: true,
    status: row.status,
    finalAction: row.finalAction,
    direction: row.direction,
    userId: null,
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

/**
 * The search values of a request in the form the SQL compares (§2 E1): the normalized subject
 * key, the LIKE pattern of the normalized prefix, the Message-ID key; addresses and domains as
 * the query schema parsed them (lower-cased); the domain filter as its row id.
 */
export interface SearchValues {
  internetMessageId?: string;
  sender?: string;
  headerFrom?: string;
  recipient?: string;
  subject?: string;
  senderDomain?: string;
  recipientDomain?: string;
  subjectPrefix?: string;
  quarantineStatus?: string;
  deliveryStatus?: string;
  verdict?: string[];
}

const one = <T>(filter: { values?: T[] | undefined } | undefined): T | undefined =>
  filter?.values?.[0];

export function searchValuesOf(filters: MessageListFilters): SearchValues {
  const out: SearchValues = {};
  const messageId = one(filters.internetMessageId);
  if (messageId !== undefined) out.internetMessageId = normalizeMessageIdKey(messageId);
  const subject = one(filters.subject);
  if (subject !== undefined) out.subject = normalizeSubjectKey(subject);
  const prefix = one(filters.subjectPrefix);
  if (prefix !== undefined)
    out.subjectPrefix = subjectPrefixPattern(normalizeSubjectPrefix(prefix));
  for (const name of [
    'sender',
    'headerFrom',
    'recipient',
    'senderDomain',
    'recipientDomain',
    'quarantineStatus',
    'deliveryStatus',
  ] as const) {
    const value = one<string>(filters[name]);
    if (value !== undefined) out[name] = value;
  }
  if (filters.verdict?.values) out.verdict = [...filters.verdict.values];
  return out;
}

/** The residual predicates of a plan (its residual filter names), resolved for the SQL. */
export function residualsOf(
  names: readonly MessageListFilterName[],
  filters: MessageListFilters,
  values: SearchValues,
  domainId: bigint | undefined,
): ResolvedResiduals {
  const r: ResolvedResiduals = {};
  for (const name of names) {
    switch (name) {
      case 'direction':
      case 'status':
      case 'action':
        r[name] = [...(filters[name]?.values ?? [])];
        break;
      case 'verdict':
        r.verdict = values.verdict ?? [];
        break;
      case 'domainId':
        if (domainId !== undefined) r.domainId = domainId;
        break;
      case 'riskScore':
        if (filters.riskScore) r.riskScore = filters.riskScore;
        break;
      case 'hasAttachments': {
        const value = one(filters.hasAttachments);
        if (value !== undefined) r.hasAttachments = value;
        break;
      }
      case 'internetMessageId':
        r.messageIdKey = values.internetMessageId!;
        break;
      case 'subject':
        r.subjectKey = values.subject!;
        break;
      case 'subjectPrefix':
        r.subjectPrefixPattern = values.subjectPrefix!;
        break;
      case 'sender':
      case 'headerFrom':
      case 'recipient':
      case 'senderDomain':
      case 'recipientDomain':
      case 'deliveryStatus':
      case 'quarantineStatus':
        r[name] = values[name]!;
        break;
    }
  }
  return r;
}

/** The value the driver's index is searched with (undefined for `none`/`scan`). */
export function driverKeyOf(plan: MessageListPlan, values: SearchValues): string | undefined {
  switch (plan.driver) {
    case 'none':
    case 'scan':
      return undefined;
    case 'verdict':
      return values.verdict?.[0];
    default:
      return values[plan.driver];
  }
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
 * (step 6.1 WP2, D3–D6, D11; step 7.2 §2 E1, E2, E5): message metadata of the caller's
 * organization from the read replica, with the subject withheld and recipient addresses masked
 * for every caller (ADR-0062; clear values only through MessageRevealService). The list checks the filter-level permissions first (`403
 * message_filter_forbidden`), then runs the search driver the filters select (§3.2), with the
 * signed v1 cursor bound to the filters, the driver, the sort, the organization and the first
 * page's window. Searches by a person-, message- or content-identifying filter are audited on
 * their first page (`message.searched`, values only as SHA-256, subjects normalized first).
 * Content, S3 keys and internal ids are never returned.
 */
@Injectable()
export class MessageDataService {
  private readonly searchMetrics: MessageSearchMetrics;

  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly repository: MessageDataRepository,
    private readonly domains: DomainsRepository,
    private readonly codec: CursorCodec,
    private readonly audit: AuditService,
    private readonly metrics: ApiConventionMetrics,
    metricsService: MetricsService,
  ) {
    this.searchMetrics = new MessageSearchMetrics(metricsService);
  }

  now(): Date {
    return new Date();
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    query: MessageListQuery,
    sourceIp: string | null = null,
  ): Promise<MessageListPage> {
    // Filter-level permissions (§2 E2) before any read.
    const forbidden = forbiddenFilter(query.filters, principal.permissions);
    if (forbidden) throw messageFilterForbidden(forbidden.filter, forbidden.permission);
    const plan = selectMessagePlan(query.filters);
    // The cursor is bound to the plan's driver too (§2 E1 "Cursor binding").
    const binding = listBinding({
      resource: MESSAGES_RESOURCE,
      principal,
      filters: { ...query.filters, ...driverBinding(plan.driver) },
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
    const input: MessagePlanInput = {
      organizationId: scope.organizationId,
      range,
      after: timeIdKeyOf(decoded),
      direction: binding.direction,
      take: query.limit + 1,
    };
    this.searchMetrics.plans.inc({ driver: plan.driver, budgeted: String(plan.budgeted) });
    const values = searchValuesOf(query.filters);
    const residuals = residualsOf(plan.residuals, query.filters, values, domainId);
    const page = await this.runPlan(scope, plan, input, query.limit, values, residuals);
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
          plan: plan.driver,
          budgeted: plan.budgeted,
          valueSha256: Object.fromEntries(
            identifying.map((name) => [name, sha256Hex(identifyingValue(name, query.filters))]),
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

  /** Runs the plan's driver (§3.2): exact, budgeted, grouped foreign keys or the capped prefix. */
  private async runPlan(
    scope: TenantScope,
    plan: MessageListPlan,
    input: MessagePlanInput,
    limit: number,
    values: SearchValues,
    residuals: ResolvedResiduals,
  ): Promise<PlanPage> {
    const key = driverKeyOf(plan, values);
    const budget = this.config.API_LIST_SCAN_BUDGET_ROWS;
    switch (DRIVER_KIND[plan.driver]) {
      case 'messages': {
        const driver = plan.driver as MessagesTableDriver;
        if (!plan.budgeted) {
          const fetched = await this.repository.messagesPage(scope, { ...input, driver, key });
          const decision = decideKeysetPage({ fetched, limit, keyOf: keyOfMessage });
          return {
            rows: fetched.slice(0, decision.rows),
            next: decision.next,
            budgetExhausted: false,
          };
        }
        const boundary = await this.repository.messagesBoundary(scope, {
          ...input,
          driver,
          key,
          budget,
        });
        const fetched = await this.repository.messagesPage(scope, {
          ...input,
          driver,
          key,
          boundary,
          residuals,
        });
        const decision = decideScanPage({ fetched, limit, boundary, keyOf: keyOfMessage });
        return {
          rows: fetched.slice(0, decision.rows),
          next: decision.next,
          budgetExhausted: decision.budgetExhausted,
        };
      }
      case 'recipient':
        return plan.budgeted
          ? this.recipientBudgeted(scope, input, limit, key!, residuals)
          : this.recipientExact(scope, input, limit, key!);
      case 'foreign': {
        const driver = plan.driver as ForeignDriver;
        if (!plan.budgeted) {
          const keys = await this.repository.foreignKeys(scope, { ...input, driver, key: key! });
          const decision = decideKeysetPage({
            fetched: keys,
            limit,
            keyOf: (k) => ({ at: k.receivedAt, id: k.id }),
          });
          const onPage = keys.slice(0, decision.rows);
          const messages = await this.repository.messagesByKeys(scope, input.range, onPage);
          const byId = new Map(messages.map((m) => [m.id, m]));
          const rows = onPage.flatMap((k) => {
            const row = byId.get(k.id);
            return row ? [row] : [];
          });
          return { rows, next: decision.next, budgetExhausted: false };
        }
        const boundary = await this.repository.foreignBoundary(scope, {
          ...input,
          driver,
          key: key!,
          budget,
        });
        const fetched = await this.repository.foreignPage(scope, {
          ...input,
          driver,
          key: key!,
          boundary,
          residuals,
        });
        const decision = decideScanPage({ fetched, limit, boundary, keyOf: keyOfMessage });
        return {
          rows: fetched.slice(0, decision.rows),
          next: decision.next,
          budgetExhausted: decision.budgetExhausted,
        };
      }
      case 'prefix':
        return this.prefix(scope, input, limit, key!, residuals);
    }
  }

  /** The exact `recipient` driver (6.1 plan 3): recipient keyset, collapse per page. */
  private async recipientExact(
    scope: TenantScope,
    input: MessagePlanInput,
    limit: number,
    address: string,
  ): Promise<PlanPage> {
    const recipients = await this.repository.recipientRows(scope, { ...input, address });
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
    const messages = await this.repository.messagesByKeys(scope, input.range, [...keys.values()]);
    const byId = new Map(messages.map((m) => [m.id, m]));
    const rows = [...keys.keys()].flatMap((id) => {
      const row = byId.get(id);
      return row ? [row] : [];
    });
    return { rows, next: decision.next, budgetExhausted: false };
  }

  /** The budgeted `recipient` driver: keyset `(received_at, recipient row id)`, collapse. */
  private async recipientBudgeted(
    scope: TenantScope,
    input: MessagePlanInput,
    limit: number,
    address: string,
    residuals: ResolvedResiduals,
  ): Promise<PlanPage> {
    const boundary = await this.repository.recipientBoundary(scope, {
      ...input,
      address,
      budget: this.config.API_LIST_SCAN_BUDGET_ROWS,
    });
    const fetched = await this.repository.recipientPage(scope, {
      ...input,
      address,
      boundary,
      residuals,
    });
    const decision = decideScanPage({
      fetched,
      limit,
      boundary,
      keyOf: (r) => ({ at: r.receivedAt, id: r.rid }),
    });
    const seen = new Set<bigint>();
    const rows = fetched.slice(0, decision.rows).filter((row) => {
      if (seen.has(row.id)) return false;
      seen.add(row.id);
      return true;
    });
    return { rows, next: decision.next, budgetExhausted: decision.budgetExhausted };
  }

  /**
   * The capped subject-prefix driver (§2 E1): the probe reads at most cap + 1 matching index
   * entries of the window after the cursor; more than cap is `422 message_search_too_broad`;
   * else the page sorts the
   * matches with the residuals applied (exact page). Timeouts are `503 message_search_timeout`.
   */
  private async prefix(
    scope: TenantScope,
    input: MessagePlanInput,
    limit: number,
    pattern: string,
    residuals: ResolvedResiduals,
  ): Promise<PlanPage> {
    const cap = this.config.API_MESSAGES_SEARCH_MAX_MATCHES;
    const timeoutMs = this.config.API_MESSAGES_SEARCH_TIMEOUT_MS;
    try {
      const tooBroad = await this.repository.prefixProbe(scope, {
        ...input,
        pattern,
        cap,
        timeoutMs,
      });
      if (tooBroad) {
        this.searchMetrics.refused.inc({ reason: 'too_broad' });
        throw messageSearchTooBroad(cap);
      }
      const fetched = await this.repository.prefixPage(scope, {
        ...input,
        pattern,
        timeoutMs,
        residuals,
      });
      const decision = decideKeysetPage({ fetched, limit, keyOf: keyOfMessage });
      return { rows: fetched.slice(0, decision.rows), next: decision.next, budgetExhausted: false };
    } catch (err) {
      if (err instanceof CodedHttpException && err.code === MESSAGE_SEARCH_TIMEOUT) {
        this.searchMetrics.refused.inc({ reason: 'timeout' });
      }
      throw err;
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
    const deliveries = await this.repository.deliveries(
      scope,
      message,
      rows.map((r) => r.id),
    );
    const latest = latestDeliveries(deliveries);
    return {
      data: rows.map((row) => toRecipientItem(row, latest.get(row.id))),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [String(decision.next)]),
    };
  }
}

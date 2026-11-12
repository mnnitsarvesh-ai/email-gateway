import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../../api-config.token';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import { ApiConventionMetrics } from '../../http/api-metrics';
import { CursorCodec, cursorInvalid } from '../../http/cursor/cursor-codec';
import { rangeWindow, resolveRange } from '../../http/listing/range';
import { decideKeysetPage, decideScanPage } from '../../http/listing/scan-budget';
import { sourcesOf, urlCodes } from '../messages/domain/message-scans';
import {
  decodeListCursor,
  encodeListCursor,
  intKey,
  listBinding,
  type TimeIdKey,
  timeIdKeyOf,
  timeIdKeys,
} from '../messages/domain/v1-list';
import { MessageDataRepository } from '../messages/repositories/message-data.repository';
import { MessageDataService } from '../messages/services/message-data.service';
import { MessagesRepository } from '../tenant-data/messages.repository';
import {
  type ClickCountRow,
  type ClickFilters,
  type ClickRow,
  type MessageUrlFullRow,
  UrlProtectionRepository,
  type UrlLatestRow,
} from './url-protection.repository';
import {
  CLICKS_MAX_RANGE_DAYS,
  MESSAGE_URLS_RESOURCE,
  type MessageUrlItem,
  type MessageUrlsPage,
  type MessageUrlsQuery,
  URL_CLICKS_RESOURCE,
  type UrlClickItem,
  type UrlClicksPage,
  type UrlClicksQuery,
} from './url-protection.schemas';

const DAY_MS = 86_400_000;
const MAX_URL_SEQ = 65_535;

type Config = Pick<ApiConfig, 'API_LIST_SCAN_BUDGET_ROWS'>;

/** The newest round's result per URL seq (highest scan id). */
export function latestUrlResults(rows: readonly UrlLatestRow[]): Map<number, UrlLatestRow> {
  const latest = new Map<number, UrlLatestRow>();
  for (const row of rows) {
    const current = latest.get(row.urlSeq);
    if (!current || row.scanId > current.scanId) latest.set(row.urlSeq, row);
  }
  return latest;
}

/** `{ total, byDecision }` per URL seq. */
export function clickSummaries(
  rows: readonly ClickCountRow[],
): Map<number, MessageUrlItem['clicks']> {
  const out = new Map<number, MessageUrlItem['clicks']>();
  for (const row of rows) {
    const summary = out.get(row.urlSeq) ?? { total: 0, byDecision: {} };
    summary.total += row.count;
    const decision = row.decision as keyof MessageUrlItem['clicks']['byDecision'];
    summary.byDecision[decision] = (summary.byDecision[decision] ?? 0) + row.count;
    out.set(row.urlSeq, summary);
  }
  return out;
}

/**
 * One URL of a message: the `message_urls` fields of the tenant URL view (sources and flags
 * through the scans view mappers), the newest result (a result whose hash names another URL is
 * not shown, as in the scans view), the latest rewrite and the click counts.
 */
export function toUrlItem(
  url: MessageUrlFullRow,
  latest: UrlLatestRow | undefined,
  round: number | undefined,
  rewrite: MessageUrlItem['rewrite'],
  clicks: MessageUrlItem['clicks'] | undefined,
): MessageUrlItem {
  const result =
    latest && latest.urlSha256 === url.urlSha256 && round !== undefined ? latest : null;
  return {
    urlSeq: url.urlSeq,
    url: url.url,
    host: url.host,
    unicodeHost: url.unicodeHost,
    registrableDomain: url.registrableDomain,
    hostKind: url.hostKind,
    sources: sourcesOf(url.sources),
    flags: urlCodes(url.flags, 32),
    latest: result
      ? {
          round: round!,
          verdict: result.verdict as NonNullable<MessageUrlItem['latest']>['verdict'],
          reasonCodes: urlCodes(result.reasonCodes, 32),
          rewritten: result.rewritten,
        }
      : null,
    rewrite,
    clicks: clicks ?? { total: 0, byDecision: {} },
  };
}

export function toClickItem(
  click: ClickRow,
  messagePublicId: string | null,
  host: { host: string; registrableDomain: string | null } | undefined,
): UrlClickItem {
  return {
    id: click.publicId,
    clickedAt: click.clickedAt.toISOString(),
    decision: click.decision as UrlClickItem['decision'],
    verdict: click.verdict as UrlClickItem['verdict'],
    reasonCodes: urlCodes(click.reasonCodes, 16),
    messageId: messagePublicId,
    urlSeq: click.urlSeq,
    host: host?.host ?? null,
    registrableDomain: host?.registrableDomain ?? null,
    clientNetwork: click.clientNetwork,
  };
}

/**
 * URL protection data (step 6.1 WP2, §3.3) of the caller's organization from the read replica:
 * the URLs of a message and the click log (scan-bounded when filtered, D6).
 */
@Injectable()
export class UrlProtectionService {
  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly repository: UrlProtectionRepository,
    private readonly messages: MessageDataService,
    private readonly messageData: MessageDataRepository,
    private readonly identities: MessagesRepository,
    private readonly codec: CursorCodec,
    private readonly metrics: ApiConventionMetrics,
  ) {}

  now(): Date {
    return new Date();
  }

  async ofMessage(
    principal: Principal,
    scope: TenantScope,
    messageId: string,
    query: MessageUrlsQuery,
  ): Promise<MessageUrlsPage> {
    const binding = listBinding({
      resource: MESSAGE_URLS_RESOURCE,
      principal,
      filters: { messageId: { values: [messageId] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const afterSeq = decoded ? intKey(decoded.keys[0], MAX_URL_SEQ) : undefined;
    const message = await this.messages.messageRef(scope, messageId);
    const fetched = await this.repository.messageUrls(scope, message, {
      take: query.limit + 1,
      afterSeq,
    });
    const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf: (u) => u.urlSeq });
    const urls = fetched.slice(0, decision.rows);
    const seqs = urls.map((u) => u.urlSeq);
    const [results, rewriteRow, counts] = await Promise.all([
      this.repository.results(scope, message, seqs),
      this.repository.latestRewrite(scope, message),
      this.repository.clickCounts(scope, message, seqs),
    ]);
    const latest = latestUrlResults(results);
    const rounds = await this.messageData.scanRounds(
      scope,
      message,
      [...latest.values()].map((r) => r.scanId),
    );
    const rewrite: MessageUrlItem['rewrite'] = rewriteRow
      ? {
          round: rewriteRow.lifecycleRound,
          status: rewriteRow.status,
          skipReason: rewriteRow.skipReason as NonNullable<MessageUrlItem['rewrite']>['skipReason'],
        }
      : null;
    const clicks = clickSummaries(counts);
    return {
      data: urls.map((url) => {
        const result = latest.get(url.urlSeq);
        return toUrlItem(
          url,
          result,
          result ? rounds.get(result.scanId) : undefined,
          rewrite,
          clicks.get(url.urlSeq),
        );
      }),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [String(decision.next)]),
    };
  }

  async clicks(
    principal: Principal,
    scope: TenantScope,
    query: UrlClicksQuery,
  ): Promise<UrlClicksPage> {
    const binding = listBinding({
      resource: URL_CLICKS_RESOURCE,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    if (decoded && !decoded.window) throw cursorInvalid();
    const range = resolveRange(query, {
      defaultMs: DAY_MS,
      maxDays: CLICKS_MAX_RANGE_DAYS,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const messagePublicId = query.filters.messageId?.values?.[0];
    const message =
      messagePublicId === undefined
        ? undefined
        : await this.messages.messageRef(scope, messagePublicId);
    const filters: ClickFilters = {
      decisions: query.filters.decision?.values,
      verdicts: query.filters.verdict?.values,
      ...(message && { message: { id: message.id, receivedAt: message.receivedAt } }),
    };
    const filtered =
      (filters.decisions?.length ?? 0) > 0 || (filters.verdicts?.length ?? 0) > 0 || !!message;
    const base = {
      range,
      after: timeIdKeyOf(decoded),
      direction: binding.direction,
      take: query.limit + 1,
    };
    const keyOf = (c: ClickRow): TimeIdKey => ({ at: c.clickedAt, id: c.id });
    let rows: ClickRow[];
    let next: TimeIdKey | null;
    if (!filtered) {
      const fetched = await this.repository.clicks(scope, base);
      const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf });
      rows = fetched.slice(0, decision.rows);
      next = decision.next;
    } else {
      const boundary = await this.repository.clicksBoundary(scope, {
        ...base,
        budget: this.config.API_LIST_SCAN_BUDGET_ROWS,
      });
      const fetched = await this.repository.clicks(scope, { ...base, boundary, filters });
      const decision = decideScanPage({ fetched, limit: query.limit, boundary, keyOf });
      if (decision.budgetExhausted) {
        this.metrics.scanBudgetExhausted.inc({ resource: URL_CLICKS_RESOURCE });
      }
      rows = fetched.slice(0, decision.rows);
      next = decision.next;
    }
    const [publicIds, hosts] = await Promise.all([
      this.identities.publicIdMap(
        scope,
        rows.map((r) => r.messageId),
      ),
      this.repository.clickHosts(scope, rows),
    ]);
    return {
      data: rows.map((row) =>
        toClickItem(
          row,
          publicIds.get(row.messageId) ?? null,
          hosts.get(`${row.messageId}:${row.urlSeq}`),
        ),
      ),
      nextCursor: next
        ? encodeListCursor(this.codec, binding, timeIdKeys(next), rangeWindow(range))
        : null,
    };
  }
}

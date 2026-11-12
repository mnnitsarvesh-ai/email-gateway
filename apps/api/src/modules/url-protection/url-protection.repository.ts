import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';
import type { CursorDirection } from '../../http/cursor/cursor-codec';
import { assertEcho, InconsistentReadError } from '../../http/listing/echo-check';
import { boundaryOffset } from '../../http/listing/scan-budget';
import type { TimeIdKey } from '../messages/domain/v1-list';
import type { MessageRef } from '../messages/repositories/message-data.repository';
import { afterKey, allOf, column, keysetOrder, upToKey } from '../messages/repositories/keyset-sql';
import { messageUrlSelect } from '../messages/repositories/message-scans-read.repository';
import { clampTake } from '../tenant-data/page';

/**
 * URL protection reads (step 6.1 WP2, D15) on the replica: the URLs of a message with their
 * latest result, rewrite and click counts, and the organization's clicks. Never `token_kid`,
 * token material, `recheck` or durations. Every query matches the scope's organization and the
 * partition key (`received_at` / `clicked_at`); rows are echo-checked.
 */

export const CLICKS_INDEX = 'url_click_events_organization_id_clicked_at_idx';

const CLICKED_AT = column('clicked_at');
const ID = column('id');

const CLICK_COLUMNS = Prisma.sql`id, clicked_at, public_id, organization_id, message_id,
  message_received_at, url_seq, decision, verdict, reason_codes, client_network`;

export interface ClickFilters {
  decisions?: readonly string[] | undefined;
  verdicts?: readonly string[] | undefined;
  message?: { id: bigint; receivedAt: Date } | undefined;
}

export interface ClickPlanInput {
  organizationId: bigint;
  range: { from: Date; to: Date };
  after?: TimeIdKey | undefined;
  direction: CursorDirection;
  take: number;
}

const forceClicksIndex = () => Prisma.raw(`FORCE INDEX (${CLICKS_INDEX})`);

export function clickFilterSql(filters: ClickFilters): Prisma.Sql[] {
  const parts: Prisma.Sql[] = [];
  if (filters.decisions && filters.decisions.length > 0) {
    parts.push(Prisma.sql`decision IN (${Prisma.join(filters.decisions)})`);
  }
  if (filters.verdicts && filters.verdicts.length > 0) {
    parts.push(Prisma.sql`verdict IN (${Prisma.join(filters.verdicts)})`);
  }
  if (filters.message) {
    parts.push(
      Prisma.sql`message_id = ${filters.message.id} AND message_received_at = ${filters.message.receivedAt}`,
    );
  }
  return parts;
}

/** Unfiltered clicks: keyset `(clicked_at, id)` over `(organization_id, clicked_at)`. */
export function clicksPageSql(
  input: ClickPlanInput & { boundary?: TimeIdKey | null; filters?: ClickFilters },
): Prisma.Sql {
  return Prisma.sql`SELECT ${CLICK_COLUMNS} FROM url_click_events ${forceClicksIndex()}
    WHERE organization_id = ${input.organizationId}
      AND clicked_at >= ${input.range.from} AND clicked_at < ${input.range.to}
      AND ${afterKey(CLICKED_AT, ID, input.after, input.direction)}
      AND ${upToKey(CLICKED_AT, ID, input.boundary ?? null, input.direction)}
      AND ${allOf(clickFilterSql(input.filters ?? {}))}
    ${keysetOrder(CLICKED_AT, ID, input.direction)} LIMIT ${clampTake(input.take)}`;
}

/** Scan-bounded clicks, step 1: the key of the `budget`-th index entry after the cursor. */
export function clicksBoundarySql(input: ClickPlanInput & { budget: number }): Prisma.Sql {
  return Prisma.sql`SELECT clicked_at, id FROM url_click_events ${forceClicksIndex()}
    WHERE organization_id = ${input.organizationId}
      AND clicked_at >= ${input.range.from} AND clicked_at < ${input.range.to}
      AND ${afterKey(CLICKED_AT, ID, input.after, input.direction)}
    ${keysetOrder(CLICKED_AT, ID, input.direction)} LIMIT 1 OFFSET ${boundaryOffset(input.budget)}`;
}

export interface ClickRow {
  id: bigint;
  clickedAt: Date;
  publicId: string;
  organizationId: bigint;
  messageId: bigint;
  messageReceivedAt: Date;
  urlSeq: number;
  decision: string;
  verdict: string | null;
  reasonCodes: unknown;
  clientNetwork: string | null;
}

interface RawClickRow {
  id: bigint;
  clicked_at: Date;
  public_id: string;
  organization_id: bigint;
  message_id: bigint;
  message_received_at: Date;
  url_seq: number;
  decision: string;
  verdict: string | null;
  reason_codes: unknown;
  client_network: string | null;
}

/** A JSON column as returned by `$queryRaw` (parsed, or a JSON string on some drivers). */
function json(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

const toClick = (r: RawClickRow): ClickRow => ({
  id: BigInt(r.id),
  clickedAt: r.clicked_at,
  publicId: r.public_id,
  organizationId: BigInt(r.organization_id),
  messageId: BigInt(r.message_id),
  messageReceivedAt: r.message_received_at,
  urlSeq: Number(r.url_seq),
  decision: r.decision,
  verdict: r.verdict,
  reasonCodes: json(r.reason_codes),
  clientNetwork: r.client_network,
});

const urlRowSelect = { ...messageUrlSelect, organizationId: true, messageId: true } as const;
export type MessageUrlFullRow = Prisma.MessageUrlGetPayload<{ select: typeof urlRowSelect }>;

export interface UrlLatestRow {
  scanId: bigint;
  urlSeq: number;
  urlSha256: string;
  verdict: string;
  reasonCodes: unknown;
  rewritten: boolean;
}

export interface ClickCountRow {
  urlSeq: number;
  decision: string;
  count: number;
}

/** Most result rows one URL page reads (≤ 100 URLs × rounds). */
const MAX_RESULT_ROWS = 4_000;

@Injectable()
export class UrlProtectionRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  /** The message's URLs with `url_seq` after `afterSeq`, ascending. */
  async messageUrls(
    scope: TenantScope,
    message: MessageRef,
    page: { take: number; afterSeq?: number | undefined },
  ): Promise<MessageUrlFullRow[]> {
    const rows = await this.db.messageUrl.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        ...(page.afterSeq !== undefined && { urlSeq: { gt: page.afterSeq } }),
      }),
      select: urlRowSelect,
      orderBy: { urlSeq: 'asc' },
      take: clampTake(page.take),
    });
    assertEcho('urls.messageUrls', rows, {
      organizationId: scope.organizationId,
      messageId: message.id,
    });
    return rows;
  }

  /** Every `url_scan_results` row of the given URL seqs of the message (all rounds). */
  async results(
    scope: TenantScope,
    message: MessageRef,
    seqs: readonly number[],
  ): Promise<UrlLatestRow[]> {
    if (seqs.length === 0) return [];
    const rows = await this.db.urlScanResult.findMany({
      where: tenantWhere(scope, {
        messageId: message.id,
        receivedAt: message.receivedAt,
        urlSeq: { in: [...seqs] },
      }),
      select: {
        scanId: true,
        urlSeq: true,
        urlSha256: true,
        verdict: true,
        reasonCodes: true,
        rewritten: true,
        organizationId: true,
        messageId: true,
      },
      orderBy: [{ scanId: 'desc' }, { urlSeq: 'asc' }],
      take: MAX_RESULT_ROWS,
    });
    assertEcho('urls.results', rows, {
      organizationId: scope.organizationId,
      messageId: message.id,
      urlSeq: [...seqs],
    });
    return rows;
  }

  /** The rewrite of the message's newest rewrite round (`url_rewrites`), or null. */
  async latestRewrite(scope: TenantScope, message: MessageRef) {
    const row = await this.db.urlRewrite.findFirst({
      where: tenantWhere(scope, { messageId: message.id, receivedAt: message.receivedAt }),
      select: {
        status: true,
        skipReason: true,
        lifecycleRound: true,
        organizationId: true,
        messageId: true,
      },
      orderBy: [{ lifecycleRound: 'desc' }, { id: 'desc' }],
    });
    if (!row) return null;
    assertEcho('urls.latestRewrite', [row], {
      organizationId: scope.organizationId,
      messageId: message.id,
    });
    return row;
  }

  /**
   * Click counts per URL seq and decision (`url_click_events`, `(message_id,
   * message_received_at)` index; a click never precedes its message, so `clicked_at >=
   * received_at` bounds the partitions).
   */
  async clickCounts(
    scope: TenantScope,
    message: MessageRef,
    seqs: readonly number[],
  ): Promise<ClickCountRow[]> {
    if (seqs.length === 0) return [];
    const raw = await this.db.$queryRaw<
      Array<{ organization_id: bigint; url_seq: number; decision: string; n: bigint }>
    >(Prisma.sql`SELECT organization_id, url_seq, decision, COUNT(*) AS n FROM url_click_events
      WHERE organization_id = ${scope.organizationId} AND message_id = ${message.id}
        AND message_received_at = ${message.receivedAt} AND clicked_at >= ${message.receivedAt}
        AND url_seq IN (${Prisma.join([...seqs])})
      GROUP BY organization_id, url_seq, decision`);
    const rows = raw.map((r) => ({
      organizationId: BigInt(r.organization_id),
      urlSeq: Number(r.url_seq),
      decision: r.decision,
      count: Number(r.n),
    }));
    assertEcho('urls.clickCounts', rows, {
      organizationId: scope.organizationId,
      urlSeq: [...seqs],
    });
    return rows;
  }

  /** One page of clicks (with the scan boundary and filters of the scan-bounded plan). */
  async clicks(
    scope: TenantScope,
    input: Omit<ClickPlanInput, 'organizationId'> & {
      boundary?: TimeIdKey | null;
      filters?: ClickFilters;
    },
  ): Promise<ClickRow[]> {
    const rows = (
      await this.db.$queryRaw<RawClickRow[]>(
        clicksPageSql({ ...input, organizationId: scope.organizationId }),
      )
    ).map(toClick);
    assertEcho('urls.clicks', rows, {
      organizationId: scope.organizationId,
      ...(input.filters?.decisions && { decision: [...input.filters.decisions] }),
      ...(input.filters?.message && { messageId: input.filters.message.id }),
    });
    this.assertInRange(rows, input.range);
    return rows;
  }

  async clicksBoundary(
    scope: TenantScope,
    input: Omit<ClickPlanInput, 'organizationId'> & { budget: number },
  ): Promise<TimeIdKey | null> {
    const raw = await this.db.$queryRaw<Array<{ clicked_at: Date; id: bigint }>>(
      clicksBoundarySql({ ...input, organizationId: scope.organizationId }),
    );
    const row = raw[0];
    if (!row) return null;
    this.assertInRange([{ clickedAt: row.clicked_at }], input.range);
    return { at: row.clicked_at, id: BigInt(row.id) };
  }

  /** Host and registrable domain per `(message_id, url_seq)` of the clicks (one query). */
  async clickHosts(
    scope: TenantScope,
    clicks: readonly ClickRow[],
  ): Promise<Map<string, { host: string; registrableDomain: string | null }>> {
    if (clicks.length === 0) return new Map();
    const keys = new Map<string, { messageId: bigint; receivedAt: Date; urlSeq: number }>();
    for (const c of clicks) {
      keys.set(`${c.messageId}:${c.urlSeq}`, {
        messageId: c.messageId,
        receivedAt: c.messageReceivedAt,
        urlSeq: c.urlSeq,
      });
    }
    const rows = await this.db.messageUrl.findMany({
      where: tenantWhere(scope, { OR: [...keys.values()] }),
      select: {
        organizationId: true,
        messageId: true,
        urlSeq: true,
        host: true,
        registrableDomain: true,
      },
    });
    assertEcho('urls.clickHosts', rows, {
      organizationId: scope.organizationId,
      messageId: [...new Set(clicks.map((c) => c.messageId))],
    });
    return new Map(
      rows.map((r) => [
        `${r.messageId}:${r.urlSeq}`,
        { host: r.host, registrableDomain: r.registrableDomain },
      ]),
    );
  }

  private assertInRange(
    rows: ReadonlyArray<{ clickedAt: Date }>,
    range: { from: Date; to: Date },
  ): void {
    if (
      rows.some(
        (r) =>
          r.clickedAt.getTime() < range.from.getTime() ||
          r.clickedAt.getTime() >= range.to.getTime(),
      )
    ) {
      throw new InconsistentReadError('urls.clicks');
    }
  }
}

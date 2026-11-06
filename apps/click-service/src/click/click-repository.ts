import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import type { FeedRow, ReputationKind } from '@email-gateway/url-security';

/**
 * Data access of the click-service (U14) through its own MySQL account `gateway_click` on the
 * writer: SELECT on `message_urls`, `url_scan_results`, `url_dynamic_inspections`,
 * `scan_engine_settings`, `threat_indicators`, `domains`; INSERT on `url_click_events` and
 * `message_outbox` — nothing else (the account cannot read `email_messages` or write anywhere
 * else). Every read whose result decides something selects its identifying columns and is
 * echo-checked (step 4.2 §6 wrong-read mitigation): a mismatch throws `InconsistentReadError`.
 * Writes use `createMany` (a plain INSERT: the account has no SELECT on the written tables).
 */

/** The key of a click: organization from the verified token, never from the request. */
export interface UrlKey {
  organizationId: bigint;
  messageId: bigint;
  receivedAt: Date;
  urlSeq: number;
}

export interface UrlRow extends UrlKey {
  url: string;
  urlSha256: string;
  host: string;
  unicodeHost: string | null;
  registrableDomain: string | null;
  hostKind: 'domain' | 'ipv4' | 'ipv6';
  truncated: boolean;
  flags: unknown;
}

export interface ScanResultRow {
  scanId: bigint;
  urlSha256: string;
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  reasonCodes: unknown;
  lookalike: unknown;
  fetchStatus: 'not_attempted' | 'completed' | 'error' | 'blocked';
  fetchError: string | null;
  redirectChain: unknown;
  finalUrl: string | null;
  finalStatus: number | null;
  landing: unknown;
}

export interface DynamicRow {
  scanId: bigint;
  urlSha256: string;
  status: 'completed' | 'failed';
  signals: unknown;
}

export interface ClickEventRecord {
  publicId: string;
  clickedAt: Date;
  organizationId: bigint;
  messageId: bigint;
  messageReceivedAt: Date;
  urlSeq: number;
  decision: 'allowed' | 'warned' | 'blocked' | 'continued' | 'expired' | 'not_found';
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown' | null;
  reasonCodes: string[] | null;
  recheck: Record<string, string> | null;
  tokenKid: number;
  clientNetwork: string | null;
  durationMs: number;
}

export interface OutboxRecord {
  eventId: string;
  organizationId: bigint;
  eventType: string;
  aggregateId: string;
  correlationId: string;
  payload: Record<string, unknown>;
}

/** A read returned a row whose identifying columns differ from the request (4.2 §6). */
export class InconsistentReadError extends Error {
  override readonly name = 'InconsistentReadError';
  constructor(readonly read: string) {
    super(`inconsistent read (${read})`);
  }
}

/** Abstract so tests can substitute an in-memory store (the e2e suite). */
export abstract class ClickRepository {
  abstract findUrl(key: UrlKey): Promise<UrlRow | null>;
  abstract latestScanResult(key: UrlKey, urlSha256: string): Promise<ScanResultRow | null>;
  abstract latestDynamic(key: UrlKey, urlSha256: string): Promise<DynamicRow | null>;
  /** `scan_engine_settings.settings` of engine `url`, or null without an override. */
  abstract tenantUrlSettings(organizationId: bigint): Promise<unknown>;
  abstract activeDomains(organizationId: bigint): Promise<string[]>;
  abstract feedRows(kind: ReputationKind, hashes: readonly string[]): Promise<FeedRow[]>;
  abstract writeClick(
    event: ClickEventRecord,
    outbox: OutboxRecord,
    options: { timeoutMs: number; maxWaitMs: number },
  ): Promise<void>;
}

/** Tenant domains taken into the lookalike recomputation (U7 b), bounded. */
export const MAX_ACTIVE_DOMAINS = 1000;

const sameKey = (row: UrlKey, key: UrlKey): boolean =>
  row.organizationId === key.organizationId &&
  row.messageId === key.messageId &&
  row.receivedAt.getTime() === key.receivedAt.getTime() &&
  row.urlSeq === key.urlSeq;

@Injectable()
export class PrismaClickRepository extends ClickRepository {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async findUrl(key: UrlKey): Promise<UrlRow | null> {
    const row = await this.prisma.messageUrl.findFirst({
      where: {
        organizationId: key.organizationId,
        messageId: key.messageId,
        receivedAt: key.receivedAt,
        urlSeq: key.urlSeq,
      },
      select: {
        organizationId: true,
        messageId: true,
        receivedAt: true,
        urlSeq: true,
        url: true,
        urlSha256: true,
        host: true,
        unicodeHost: true,
        registrableDomain: true,
        hostKind: true,
        truncated: true,
        flags: true,
      },
    });
    if (row === null) return null;
    if (!sameKey(row, key)) throw new InconsistentReadError('message_urls');
    return row;
  }

  async latestScanResult(key: UrlKey, urlSha256: string): Promise<ScanResultRow | null> {
    const row = await this.prisma.urlScanResult.findFirst({
      where: {
        organizationId: key.organizationId,
        messageId: key.messageId,
        receivedAt: key.receivedAt,
        urlSeq: key.urlSeq,
      },
      orderBy: { scanId: 'desc' },
      select: {
        organizationId: true,
        messageId: true,
        receivedAt: true,
        urlSeq: true,
        scanId: true,
        urlSha256: true,
        verdict: true,
        reasonCodes: true,
        lookalike: true,
        fetchStatus: true,
        fetchError: true,
        redirectChain: true,
        finalUrl: true,
        finalStatus: true,
        landing: true,
      },
    });
    if (row === null) return null;
    if (!sameKey(row, key) || row.urlSha256 !== urlSha256)
      throw new InconsistentReadError('url_scan_results');
    return row;
  }

  async latestDynamic(key: UrlKey, urlSha256: string): Promise<DynamicRow | null> {
    const row = await this.prisma.urlDynamicInspection.findFirst({
      where: {
        organizationId: key.organizationId,
        messageId: key.messageId,
        receivedAt: key.receivedAt,
        urlSeq: key.urlSeq,
        status: { in: ['completed', 'failed'] },
      },
      orderBy: { scanId: 'desc' },
      select: {
        organizationId: true,
        messageId: true,
        receivedAt: true,
        urlSeq: true,
        scanId: true,
        urlSha256: true,
        status: true,
        signals: true,
      },
    });
    if (row === null) return null;
    if (
      !sameKey(row, key) ||
      row.urlSha256 !== urlSha256 ||
      (row.status !== 'completed' && row.status !== 'failed')
    ) {
      throw new InconsistentReadError('url_dynamic_inspections');
    }
    return {
      scanId: row.scanId,
      urlSha256: row.urlSha256,
      status: row.status,
      signals: row.signals,
    };
  }

  async tenantUrlSettings(organizationId: bigint): Promise<unknown> {
    const row = await this.prisma.scanEngineSetting.findFirst({
      where: { organizationId, engine: 'url' },
      select: { organizationId: true, engine: true, settings: true },
    });
    if (row === null) return null;
    if (row.organizationId !== organizationId || row.engine !== 'url')
      throw new InconsistentReadError('scan_engine_settings');
    return row.settings;
  }

  async activeDomains(organizationId: bigint): Promise<string[]> {
    const rows = await this.prisma.domain.findMany({
      where: { organizationId, status: 'active' },
      select: { organizationId: true, status: true, name: true },
      orderBy: { id: 'asc' },
      take: MAX_ACTIVE_DOMAINS,
    });
    if (rows.some((r) => r.organizationId !== organizationId || r.status !== 'active'))
      throw new InconsistentReadError('domains');
    return rows.map((r) => r.name);
  }

  /**
   * The platform feed (`org_scope = 0`, not expired), never cached (U6). Rows are checked against
   * the request (kind, platform scope, a requested hash): a shifted read throws (→ provider error).
   */
  async feedRows(kind: ReputationKind, hashes: readonly string[]): Promise<FeedRow[]> {
    if (hashes.length === 0) return [];
    const now = new Date();
    const rows = await this.prisma.threatIndicator.findMany({
      where: {
        orgScope: 0n,
        indicatorType: kind,
        valueSha256: { in: [...hashes] },
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      select: {
        orgScope: true,
        indicatorType: true,
        valueSha256: true,
        severity: true,
        category: true,
      },
    });
    const requested = new Set(hashes);
    for (const row of rows) {
      if (row.orgScope !== 0n || row.indicatorType !== kind || !requested.has(row.valueSha256))
        throw new InconsistentReadError('threat_indicators');
    }
    return rows.map((r) => ({
      valueSha256: r.valueSha256,
      severity: r.severity,
      category: r.category,
    }));
  }

  /**
   * One interactive transaction: the click event row and its `mail.url.clicked.v1` outbox row
   * (U14 step 7; budget CLICK_DB_TX_TIMEOUT_MS, maxWait 10 s, no socket timeout).
   */
  async writeClick(
    event: ClickEventRecord,
    outbox: OutboxRecord,
    options: { timeoutMs: number; maxWaitMs: number },
  ): Promise<void> {
    await this.prisma.$transaction(
      async (tx) => {
        await tx.urlClickEvent.createMany({
          data: [
            {
              clickedAt: event.clickedAt,
              publicId: event.publicId,
              organizationId: event.organizationId,
              messageId: event.messageId,
              messageReceivedAt: event.messageReceivedAt,
              urlSeq: event.urlSeq,
              decision: event.decision,
              verdict: event.verdict,
              reasonCodes: event.reasonCodes ?? Prisma.DbNull,
              recheck: event.recheck ?? Prisma.DbNull,
              tokenKid: event.tokenKid,
              clientNetwork: event.clientNetwork,
              durationMs: event.durationMs,
            },
          ],
        });
        await tx.messageOutbox.createMany({
          data: [
            {
              eventId: outbox.eventId,
              organizationId: outbox.organizationId,
              eventType: outbox.eventType,
              aggregateType: 'message',
              aggregateId: outbox.aggregateId,
              correlationId: outbox.correlationId,
              payload: outbox.payload as Prisma.InputJsonValue,
            },
          ],
        });
      },
      { timeout: options.timeoutMs, maxWait: options.maxWaitMs },
    );
  }
}

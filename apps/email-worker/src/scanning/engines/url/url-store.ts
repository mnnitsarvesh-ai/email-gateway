import type { PrismaClient } from '@email-gateway/database';
import type { FeedQuery, FeedRow, ReputationKind } from '@email-gateway/url-security';
import type { UrlRead } from './url-metrics';

/**
 * The writer reads of the url engine (step 4.3 U3 step 1): the message's parse row (status,
 * limits, body keys/hashes/sizes/charsets, `structure`), its attachment rows (html/text extra
 * parts, U4), the `message_urls` rows of earlier rounds (stable seqs on rescans), the tenant's
 * active domains (LRU, 60 s per organization) and the platform threat feed (`local_feed`,
 * `org_scope = 0`, not expired; the provider sends chunks of 500 hashes).
 *
 * Every read selects and verifies its identifying columns (message, organization and
 * `received_at`; seq/hash uniqueness; returned hashes among the requested ones). A result that
 * does not belong to the request throws `InconsistentUrlReadError` (the Prisma 6.19 wrong-read
 * defect, step 4.2 §6): the engine turns it into the retryable attempt failure
 * `error`/`inconsistent_read`, never into a verdict.
 */

export class InconsistentUrlReadError extends Error {
  override readonly name = 'InconsistentUrlReadError';

  constructor(
    readonly read: UrlRead,
    readonly check: string,
  ) {
    super(`inconsistent ${read} read: ${check}`);
  }
}

const sameTime = (a: Date, b: Date): boolean => a.getTime() === b.getTime();

const stringArray = (value: unknown): string[] => {
  const parsed: unknown = typeof value === 'string' ? JSON.parse(value) : value;
  return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : [];
};

/** A stored body of the parse row (UTF-8, step 3.1 M8). `key` null: not stored or absent. */
export interface BodyRef {
  key: string | null;
  sha256: string | null;
  sizeBytes: number | null;
  charset: string | null;
}

/** One `structure` node as the url engine needs it (step 3.1 M13). */
export interface StructureEntry {
  index: number;
  contentType: string;
  charset: string | null;
}

export interface UrlParseRow {
  status: string;
  limitsExceeded: string[];
  attachmentCount: number | null;
  textBody: BodyRef;
  htmlBody: BodyRef;
  /** Null when absent or not an array of nodes (rewriting is then skipped). */
  structure: StructureEntry[] | null;
}

export interface UrlAttachmentRow {
  partIndex: number;
  filename: string | null;
  declaredContentType: string | null;
  detectedContentType: string | null;
  sizeBytes: number;
  sha256: string;
  objectKey: string | null;
}

export interface StoredUrlRow {
  urlSeq: number;
  urlSha256: string;
}

export interface UrlStore {
  loadParse(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
  ): Promise<UrlParseRow | null>;
  /** At most `limit` rows ordered by part index. */
  loadAttachments(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
    limit: number,
  ): Promise<UrlAttachmentRow[]>;
  loadMessageUrls(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
  ): Promise<StoredUrlRow[]>;
  activeDomains(organizationId: bigint): Promise<string[]>;
  /** The `local_feed` query (U6), injected into `LocalFeedProvider`. */
  readonly feedQuery: FeedQuery;
}

function parseStructure(value: unknown): StructureEntry[] | null {
  let parsed: unknown = value;
  if (typeof value === 'string') {
    try {
      parsed = JSON.parse(value);
    } catch {
      return null;
    }
  }
  if (!Array.isArray(parsed)) return null;
  const out: StructureEntry[] = [];
  for (const [position, node] of parsed.entries()) {
    if (typeof node !== 'object' || node === null) return null;
    const n = node as { index?: unknown; contentType?: unknown; charset?: unknown };
    if (typeof n.contentType !== 'string') return null;
    out.push({
      index: typeof n.index === 'number' ? n.index : position,
      contentType: n.contentType.toLowerCase(),
      charset: typeof n.charset === 'string' ? n.charset : null,
    });
  }
  return out;
}

/** Most `message_urls` rows of one message read back (200 per round, stable across rescans). */
export const MAX_STORED_URLS = 10_000;
/** Most active domains of a tenant used as protected entries. */
export const MAX_TENANT_DOMAINS = 1_000;

/** A small LRU with a time-to-live (active domains per organization, 60 s). */
export class TtlLru<K, V> {
  private readonly entries = new Map<K, { value: V; expires: number }>();

  constructor(
    private readonly max: number,
    private readonly ttlMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  get(key: K): V | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expires <= this.now()) {
      this.entries.delete(key);
      return undefined;
    }
    // Refresh recency.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  set(key: K, value: V): void {
    this.entries.delete(key);
    this.entries.set(key, { value, expires: this.now() + this.ttlMs });
    while (this.entries.size > this.max) {
      const oldest = this.entries.keys().next().value as K;
      this.entries.delete(oldest);
    }
  }

  get size(): number {
    return this.entries.size;
  }
}

export class PrismaUrlStore implements UrlStore {
  private readonly domains: TtlLru<string, string[]>;
  readonly feedQuery: FeedQuery;

  constructor(
    private readonly prisma: PrismaClient,
    options: { domainTtlMs?: number; domainCacheSize?: number; now?: () => Date } = {},
  ) {
    const now = options.now ?? (() => new Date());
    this.domains = new TtlLru(options.domainCacheSize ?? 1_000, options.domainTtlMs ?? 60_000, () =>
      now().getTime(),
    );
    this.feedQuery = (kind, hashes) => this.feed(kind, hashes, now());
  }

  async loadParse(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
  ): Promise<UrlParseRow | null> {
    const row = await this.prisma.emailMessageParse.findFirst({
      where: { messageId, receivedAt, organizationId },
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        status: true,
        limitsExceeded: true,
        attachmentCount: true,
        textBodyObjectKey: true,
        textBodySha256: true,
        textBodySizeBytes: true,
        textBodyCharset: true,
        htmlBodyObjectKey: true,
        htmlBodySha256: true,
        htmlBodySizeBytes: true,
        htmlBodyCharset: true,
        structure: true,
      },
    });
    if (!row) return null;
    if (
      row.messageId !== messageId ||
      row.organizationId !== organizationId ||
      !(row.receivedAt instanceof Date) ||
      !sameTime(row.receivedAt, receivedAt)
    ) {
      throw new InconsistentUrlReadError('parse', 'identity echo');
    }
    return {
      status: row.status,
      limitsExceeded: stringArray(row.limitsExceeded),
      attachmentCount: row.attachmentCount,
      textBody: {
        key: row.textBodyObjectKey,
        sha256: row.textBodySha256,
        sizeBytes: row.textBodySizeBytes,
        charset: row.textBodyCharset,
      },
      htmlBody: {
        key: row.htmlBodyObjectKey,
        sha256: row.htmlBodySha256,
        sizeBytes: row.htmlBodySizeBytes,
        charset: row.htmlBodyCharset,
      },
      structure: parseStructure(row.structure),
    };
  }

  async loadAttachments(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
    limit: number,
  ): Promise<UrlAttachmentRow[]> {
    const rows = await this.prisma.emailAttachment.findMany({
      where: { messageId, receivedAt, organizationId },
      orderBy: { partIndex: 'asc' },
      take: limit,
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        partIndex: true,
        filename: true,
        declaredContentType: true,
        detectedContentType: true,
        sizeBytes: true,
        sha256: true,
        objectKey: true,
      },
    });
    let previous = -1;
    for (const r of rows) {
      if (
        r.messageId !== messageId ||
        r.organizationId !== organizationId ||
        !(r.receivedAt instanceof Date) ||
        !sameTime(r.receivedAt, receivedAt)
      ) {
        throw new InconsistentUrlReadError('attachments', 'identity echo');
      }
      if (r.partIndex <= previous) throw new InconsistentUrlReadError('attachments', 'part order');
      previous = r.partIndex;
    }
    return rows.map((r) => ({
      partIndex: r.partIndex,
      filename: r.filename,
      declaredContentType: r.declaredContentType,
      detectedContentType: r.detectedContentType,
      sizeBytes: r.sizeBytes,
      sha256: r.sha256,
      objectKey: r.objectKey,
    }));
  }

  async loadMessageUrls(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
  ): Promise<StoredUrlRow[]> {
    const rows = await this.prisma.messageUrl.findMany({
      where: { messageId, receivedAt, organizationId },
      orderBy: { urlSeq: 'asc' },
      take: MAX_STORED_URLS,
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        urlSeq: true,
        urlSha256: true,
      },
    });
    const hashes = new Set<string>();
    let previous = -1;
    for (const r of rows) {
      if (
        r.messageId !== messageId ||
        r.organizationId !== organizationId ||
        !(r.receivedAt instanceof Date) ||
        !sameTime(r.receivedAt, receivedAt)
      ) {
        throw new InconsistentUrlReadError('message_urls', 'identity echo');
      }
      if (r.urlSeq <= previous || hashes.has(r.urlSha256)) {
        throw new InconsistentUrlReadError('message_urls', 'seq/hash uniqueness');
      }
      previous = r.urlSeq;
      hashes.add(r.urlSha256);
    }
    return rows.map((r) => ({ urlSeq: r.urlSeq, urlSha256: r.urlSha256 }));
  }

  async activeDomains(organizationId: bigint): Promise<string[]> {
    const key = organizationId.toString();
    const cached = this.domains.get(key);
    if (cached) return cached;
    const rows = await this.prisma.domain.findMany({
      where: { organizationId, status: 'active', deletedAt: null },
      orderBy: { id: 'asc' },
      take: MAX_TENANT_DOMAINS,
      select: { organizationId: true, name: true, status: true },
    });
    for (const r of rows) {
      if (r.organizationId !== organizationId || r.status !== 'active') {
        throw new InconsistentUrlReadError('domains', 'organization echo');
      }
    }
    const names = rows.map((r) => r.name.toLowerCase());
    this.domains.set(key, names);
    return names;
  }

  /**
   * Platform indicators (`org_scope = 0`, i.e. `organization_id` NULL), not expired, of one kind
   * whose `value_sha256` is in `hashes` (the provider sends at most 500 per call). Never cached.
   */
  private async feed(
    kind: ReputationKind,
    hashes: readonly string[],
    now: Date,
  ): Promise<FeedRow[]> {
    if (hashes.length === 0) return [];
    const rows = await this.prisma.threatIndicator.findMany({
      where: {
        orgScope: 0n,
        indicatorType: kind,
        valueSha256: { in: [...hashes] },
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      select: {
        orgScope: true,
        organizationId: true,
        indicatorType: true,
        valueSha256: true,
        severity: true,
        category: true,
        expiresAt: true,
      },
    });
    const requested = new Set(hashes);
    for (const r of rows) {
      if (
        r.indicatorType !== kind ||
        r.organizationId !== null ||
        (r.orgScope !== null && r.orgScope !== 0n) ||
        !requested.has(r.valueSha256) ||
        (r.expiresAt !== null && r.expiresAt.getTime() <= now.getTime())
      ) {
        throw new InconsistentUrlReadError('feed', 'indicator echo');
      }
    }
    return rows.map((r) => ({
      valueSha256: r.valueSha256,
      severity: r.severity,
      category: r.category,
    }));
  }
}

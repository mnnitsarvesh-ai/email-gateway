import type { PrismaClient } from '@email-gateway/database';
import type { KnownHashHit } from './verdict-mapper';

/**
 * The writer reads of the attachment engine (step 4.2 A3 steps 1 and 3): the message's parse row,
 * its attachment rows (organization from the trusted envelope, ordered by `part_index`,
 * bounded) and the known-threat hash catalog (`malware_signatures`, platform-wide, never cached,
 * expired rows ignored, `IN` lists in chunks of 500).
 *
 * Every read selects and verifies its identifying columns (the message, organization and
 * `received_at` echo; part indexes strictly ascending; returned hashes among the requested
 * ones). A result that does not belong to the request throws `InconsistentAttachmentReadError`
 * (the Prisma 6.19 wrong-read defect after a writer stall, step 4.2 §6 and §13.1.4): the engine
 * turns it into a retryable attempt failure, never into `skipped` or `clean`.
 */

/**
 * Parse limits that never hide an attachment (A6 E1): `body_size` only (a text/HTML body part
 * that is not stored; the parse goes on and no attachment row is affected). Every other limit,
 * including any limit added later, makes the attachment list possibly incomplete: the
 * structural stops (`message_size`, `nesting_depth`, `part_count`, `header_count`,
 * `header_line_length`, `header_block_size`, `attachment_count`, `decoded_ratio`,
 * `total_decoded_size`, `parse_timeout`) end the parse, so later parts have no row, and
 * `attachment_size` is kept for E1 as designed (the part is not stored).
 */
export const NON_HIDING_PARSE_LIMITS: ReadonlySet<string> = new Set(['body_size']);

/** Whether a breached parse limit may hide attachments (A6 E1). */
export const limitMayHideAttachments = (limit: string): boolean =>
  !NON_HIDING_PARSE_LIMITS.has(limit);

/** Which read returned rows that do not belong to the request. */
export type AttachmentRead = 'parse' | 'attachments' | 'known_hashes';

/** A writer read returned rows of another request (see the file comment); transient. */
export class InconsistentAttachmentReadError extends Error {
  override readonly name = 'InconsistentAttachmentReadError';

  constructor(
    readonly read: AttachmentRead,
    readonly check: string,
  ) {
    super(`inconsistent ${read} read: ${check}`);
  }
}

const sameTime = (a: Date, b: Date): boolean => a.getTime() === b.getTime();

export const HASH_LOOKUP_CHUNK = 500;

export interface ParseRow {
  status: string;
  limitsExceeded: string[];
  /** Attachment rows the parse wrote (`email_message_parses.attachment_count`); null when not final. */
  attachmentCount: number | null;
}

export interface AttachmentRow {
  id: bigint;
  partIndex: number;
  filename: string | null;
  declaredContentType: string | null;
  sizeBytes: number;
  sha256: string;
  objectKey: string | null;
  flags: string[];
}

export interface AttachmentStore {
  loadParse(messageId: bigint, receivedAt: Date, organizationId: bigint): Promise<ParseRow | null>;
  /** At most `limit` rows ordered by part index. */
  loadAttachments(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
    limit: number,
  ): Promise<AttachmentRow[]>;
  knownHashes(sha256s: readonly string[], now: Date): Promise<Map<string, KnownHashHit>>;
}

const stringArray = (value: unknown): string[] => {
  const parsed: unknown = typeof value === 'string' ? JSON.parse(value) : value;
  return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : [];
};

export class PrismaAttachmentStore implements AttachmentStore {
  constructor(private readonly prisma: PrismaClient) {}

  async loadParse(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
  ): Promise<ParseRow | null> {
    const row = await this.prisma.emailMessageParse.findFirst({
      where: { messageId, receivedAt, organizationId },
      select: {
        messageId: true,
        receivedAt: true,
        organizationId: true,
        status: true,
        limitsExceeded: true,
        attachmentCount: true,
      },
    });
    if (!row) return null;
    if (
      row.messageId !== messageId ||
      row.organizationId !== organizationId ||
      !(row.receivedAt instanceof Date) ||
      !sameTime(row.receivedAt, receivedAt)
    ) {
      throw new InconsistentAttachmentReadError('parse', 'identity echo');
    }
    return {
      status: row.status,
      limitsExceeded: stringArray(row.limitsExceeded),
      attachmentCount: row.attachmentCount,
    };
  }

  async loadAttachments(
    messageId: bigint,
    receivedAt: Date,
    organizationId: bigint,
    limit: number,
  ): Promise<AttachmentRow[]> {
    const rows = await this.prisma.emailAttachment.findMany({
      where: { messageId, receivedAt, organizationId },
      orderBy: { partIndex: 'asc' },
      take: limit,
      select: {
        id: true,
        messageId: true,
        receivedAt: true,
        organizationId: true,
        partIndex: true,
        filename: true,
        declaredContentType: true,
        sizeBytes: true,
        sha256: true,
        objectKey: true,
        flags: true,
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
        throw new InconsistentAttachmentReadError('attachments', 'identity echo');
      }
      if (r.partIndex <= previous) {
        throw new InconsistentAttachmentReadError('attachments', 'part order');
      }
      previous = r.partIndex;
    }
    return rows.map((r) => ({
      id: r.id,
      partIndex: r.partIndex,
      filename: r.filename,
      declaredContentType: r.declaredContentType,
      sizeBytes: r.sizeBytes,
      sha256: r.sha256,
      objectKey: r.objectKey,
      flags: stringArray(r.flags),
    }));
  }

  async knownHashes(sha256s: readonly string[], now: Date): Promise<Map<string, KnownHashHit>> {
    const unique = [...new Set(sha256s)];
    const hits = new Map<string, KnownHashHit>();
    for (let i = 0; i < unique.length; i += HASH_LOOKUP_CHUNK) {
      const chunk = unique.slice(i, i + HASH_LOOKUP_CHUNK);
      const rows = await this.prisma.malwareSignature.findMany({
        where: { sha256: { in: chunk }, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
        select: { sha256: true, severity: true, family: true },
      });
      const requested = new Set(chunk);
      for (const row of rows) {
        if (!requested.has(row.sha256)) {
          throw new InconsistentAttachmentReadError('known_hashes', 'hash echo');
        }
        hits.set(row.sha256, { severity: row.severity, family: row.family });
      }
    }
    return hits;
  }
}

import { createHash, type KeyObject } from 'node:crypto';
import { PassThrough, Transform, type TransformCallback } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import {
  archivePartiesSchema,
  assertKeyOfOrganization,
  buildSignedExportManifest,
  canonicalJsonBytes,
  createArchiveDecryptStream,
  createArchiveEncryptStream,
  EDISCOVERY_REVIEW_TAGS,
  type EdiscoveryReviewTag,
  EXPORT_MALICIOUS_README_PATH,
  EXPORT_MALICIOUS_README_TEXT,
  EXPORT_MANIFEST_PATH,
  EXPORT_OBJECT_TAG,
  EXPORT_README_PATH,
  EXPORT_README_TEXT,
  EXPORT_SIGNATURE_PATH,
  exportEntryPath,
  exportObjectKey,
  generateDataKey,
  sha256Hex,
  signManifest,
  wrapExportKey,
} from '@email-gateway/archive';
import { type EmailArchive, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { ZipFile } from 'yazl';
import type { TenantKeyService } from '../keys/tenant-keys';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { big, orgFilter, systemAudit } from '../shared/db';
import { errorCode, errorFields } from '../shared/errors';
import type { ArchiveStorage, StoredVersion } from '../storage/archive-storage';
import { type RecordObjects, RecordShreddedError } from '../storage/record-objects';
import { mergedCopiesOf } from '../storage/record-versions';

/** Step 8.6 D7: the signed supplement of merged records (variants and merged parties). */
export const EXPORT_MERGED_PATH = 'merged.json';
export const EXPORT_MERGED_SIGNATURE_PATH = 'merged.sig';
export const EXPORT_MERGED_VERSION = 'archive-export-merged/1';

/** `<item path without .eml>.variant-<n>.eml` (n from 1, in `objects.merged` order). */
export function variantEntryPath(itemPath: string, n: number): string {
  return `${itemPath.replace(/\.eml$/, '')}.variant-${String(n)}.eml`;
}

/** One stored content variant of an exported record. */
interface ExportVariant {
  record: EmailArchive;
  messagePublicId: string;
  path: string;
  sha256: string;
  sizeBytes: number;
}

export class ExportError extends Error {
  constructor(readonly code: string) {
    super(`export failed: ${code}`);
    this.name = 'ExportError';
  }
}

/** SHA-256 and byte count of the plaintext ZIP while it streams. */
class Measure extends Transform {
  private readonly hash = createHash('sha256');
  bytes = 0;
  sha256: string | null = null;

  override _transform(chunk: Buffer, _e: BufferEncoding, cb: TransformCallback): void {
    this.hash.update(chunk);
    this.bytes += chunk.length;
    cb(null, chunk);
  }

  override _flush(cb: TransformCallback): void {
    this.sha256 = this.hash.digest('hex');
    cb();
  }
}

interface ClaimedExport {
  id: bigint;
  publicId: string;
  caseId: bigint;
  searchId: bigint;
  organizationId: bigint;
  reviewTags: unknown;
  acknowledgeMalicious: boolean;
  createdAt: Date;
}

export interface ExportItem {
  record: EmailArchive;
  malicious: boolean;
}

const SELECTION_PAGE = 1_000;

/**
 * eDiscovery exports (A18, `ediscovery` role): claims a `queued` export (→ `building`; a
 * `building` export not updated for a day is taken over), re-checks that its search is
 * `completed`, selects the search's hits by review tags joined to live records on the writer,
 * enforces `ARCHIVE_EXPORT_MAX_ITEMS` / `_MAX_BYTES` (`ediscovery_export_too_large`) and the
 * malicious acknowledgement (`ediscovery_export_malicious_ack_required`), then streams a ZIP
 * (yazl): `messages/<receivedAt>_<messageId>.eml` (decrypted originals; record status and DEK
 * re-read on the writer per item; plaintext SHA-256 re-verified), malicious items under
 * `malicious/` with a warning README, `manifest.json` (`archive-export-manifest/1`),
 * `manifest.sig` (Ed25519) and `README.txt`. The ZIP stream is encrypted (`archive-object/1`,
 * kind `export`, an export DEK wrapped under the tenant key) and uploaded to
 * `org/<org>/exports/<yyyy>/<mm>/<exportId>.bin` with tag `eg-object=archive-export` (never
 * locked). The row records the plaintext package SHA-256 and size, the manifest SHA-256, counts,
 * the signing key id, the wrapped DEK, key version, object key/version and `expires_at`; system
 * audit `ediscovery.export_completed|failed`.
 */
export class ExportBuilder {
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      storage: ArchiveStorage;
      objects: RecordObjects;
      keys: TenantKeyService;
      metrics: ArchiveMetrics;
      logger: Logger;
      signingKey: KeyObject;
      signingKeyId: string;
      maxItems: number;
      maxBytes: number;
      ttlHours: number;
      chunkBytes: number;
      organizationIds?: readonly bigint[];
      now?: () => Date;
    },
  ) {
    this.now = options.now ?? (() => new Date());
  }

  async runOnce(): Promise<boolean> {
    const claimed = await this.claim();
    if (claimed === null) return false;
    await this.build(claimed);
    return true;
  }

  private async claim(): Promise<ClaimedExport | null> {
    const now = this.now();
    const stale = new Date(now.getTime() - 86_400_000);
    return this.prisma.$transaction(async (tx) => {
      const [row] = await tx.$queryRaw<
        Array<{
          id: bigint | number;
          public_id: string;
          case_id: bigint | number;
          search_id: bigint | number;
          organization_id: bigint | number;
          review_tags: unknown;
          acknowledge_malicious: number | boolean;
          created_at: Date;
        }>
      >`
        SELECT id, public_id, case_id, search_id, organization_id, review_tags,
          acknowledge_malicious, created_at
        FROM ediscovery_exports
        WHERE (status = 'queued' OR (status = 'building' AND updated_at < ${stale}))
          ${orgFilter('organization_id', this.options.organizationIds)}
        ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED`;
      if (row === undefined) return null;
      await tx.$executeRaw`
        UPDATE ediscovery_exports SET status = 'building', error_code = NULL, updated_at = NOW(3)
        WHERE id = ${big(row.id)}`;
      return {
        id: big(row.id),
        publicId: row.public_id,
        caseId: big(row.case_id),
        searchId: big(row.search_id),
        organizationId: big(row.organization_id),
        reviewTags:
          typeof row.review_tags === 'string'
            ? (JSON.parse(row.review_tags) as unknown)
            : row.review_tags,
        acknowledgeMalicious: Boolean(Number(row.acknowledge_malicious)),
        createdAt: row.created_at,
      };
    });
  }

  /** The selected items (review tags), bounded; refused before anything is written. */
  async select(e: ClaimedExport): Promise<{ items: ExportItem[]; tags: EdiscoveryReviewTag[] }> {
    const search = await this.prisma.ediscoverySearch.findUnique({
      where: { id: e.searchId },
      select: { organizationId: true, caseId: true, status: true },
    });
    if (
      search === null ||
      search.organizationId !== e.organizationId ||
      search.caseId !== e.caseId
    ) {
      throw new ExportError('ediscovery_search_not_found');
    }
    if (search.status !== 'completed') throw new ExportError('ediscovery_search_not_completed');
    const tags = Array.isArray(e.reviewTags)
      ? (e.reviewTags as unknown[]).filter((t): t is EdiscoveryReviewTag =>
          (EDISCOVERY_REVIEW_TAGS as readonly unknown[]).includes(t),
        )
      : [];
    if (tags.length === 0) throw new ExportError('review_tags_invalid');
    const items: ExportItem[] = [];
    let bytes = 0;
    let after = 0n;
    for (;;) {
      const hits = await this.prisma.ediscoverySearchHit.findMany({
        where: {
          searchId: e.searchId,
          organizationId: e.organizationId,
          reviewTag: { in: tags },
          id: { gt: after },
        },
        orderBy: { id: 'asc' },
        take: SELECTION_PAGE,
        select: { id: true, messageId: true, messageReceivedAt: true },
      });
      if (hits.length === 0) break;
      const records = await this.prisma.emailArchive.findMany({
        where: {
          organizationId: e.organizationId,
          status: { in: ['active', 'expiry_review'] },
          wrappedDek: { not: null },
          OR: hits.map((h) => ({ messageId: h.messageId, receivedAt: h.messageReceivedAt })),
        },
      });
      for (const r of records) {
        if (r.organizationId !== e.organizationId) continue;
        items.push({ record: r, malicious: r.malicious });
        bytes += r.sizeBytes;
      }
      if (items.length > this.options.maxItems || bytes > this.options.maxBytes) {
        throw new ExportError('ediscovery_export_too_large');
      }
      after = hits[hits.length - 1]!.id;
      if (hits.length < SELECTION_PAGE) break;
    }
    if (items.some((i) => i.malicious) && !e.acknowledgeMalicious) {
      throw new ExportError('ediscovery_export_malicious_ack_required');
    }
    items.sort(
      (a, b) =>
        a.record.receivedAt.getTime() - b.record.receivedAt.getTime() ||
        a.record.messagePublicId.localeCompare(b.record.messagePublicId),
    );
    return { items, tags };
  }

  async build(e: ClaimedExport): Promise<'completed' | 'failed'> {
    let uploaded: StoredVersion | null = null;
    try {
      const { items, tags } = await this.select(e);
      const [org, kase, search] = await Promise.all([
        this.prisma.organization.findUnique({
          where: { id: e.organizationId },
          select: { publicId: true },
        }),
        this.prisma.ediscoveryCase.findUnique({
          where: { id: e.caseId },
          select: { publicId: true, organizationId: true },
        }),
        this.prisma.ediscoverySearch.findUnique({
          where: { id: e.searchId },
          select: { publicId: true },
        }),
      ]);
      if (
        org === null ||
        kase === null ||
        search === null ||
        kase.organizationId !== e.organizationId
      ) {
        throw new ExportError('ediscovery_case_not_found');
      }
      const now = this.now();
      const manifest = buildSignedExportManifest(
        {
          exportId: e.publicId,
          caseId: kase.publicId,
          searchId: search.publicId,
          organizationId: org.publicId,
          generatedAt: now,
          signingKeyId: this.options.signingKeyId,
          reviewTags: tags,
          items: items.map((i) => ({
            messageId: i.record.messagePublicId,
            receivedAt: i.record.receivedAt,
            internetMessageId: i.record.internetMessageId,
            sha256: i.record.sha256,
            sizeBytes: i.record.sizeBytes,
            verdict: i.record.finalVerdict ?? null,
            malicious: i.malicious,
          })),
        },
        this.options.signingKey,
      );
      const tenantKey = await this.options.keys.active(e.organizationId);
      const dek = generateDataKey();
      const wrappedDek = wrapExportKey(
        tenantKey.key,
        {
          organizationId: e.organizationId,
          exportPublicId: e.publicId,
          keyVersion: tenantKey.version,
        },
        dek,
      );
      const key = assertKeyOfOrganization(
        exportObjectKey({
          organizationId: e.organizationId,
          createdAt: e.createdAt,
          exportPublicId: e.publicId,
        }),
        e.organizationId,
        'exports',
      );
      const zip = new ZipFile();
      const mtime = now;
      const merged = await this.mergedSupplement(e, items);
      for (const item of items) {
        const path = exportEntryPath({
          receivedAt: item.record.receivedAt,
          messageId: item.record.messagePublicId,
          malicious: item.malicious,
        });
        zip.addReadStreamLazy(path, { mtime, compress: true }, (cb) => {
          this.itemStream(item.record).then(
            (stream) => {
              // yazl does not watch its input streams: an integrity or S3 error of an item must
              // fail the whole package (never a ZIP with a truncated entry).
              stream.once('error', (error: unknown) => zip.emit('error', error));
              cb(null, stream);
            },
            (error: unknown) => cb(error, undefined as never),
          );
        });
        // Step 8.6 D7: the record's content variants as additional files of the item.
        for (const v of merged.variants.filter((x) => x.record.id === item.record.id)) {
          zip.addReadStreamLazy(v.path, { mtime, compress: true }, (cb) => {
            this.variantStream(v).then(
              (stream) => {
                stream.once('error', (error: unknown) => zip.emit('error', error));
                cb(null, stream);
              },
              (error: unknown) => cb(error, undefined as never),
            );
          });
        }
      }
      if (merged.document !== null) {
        const bytes = canonicalJsonBytes(merged.document);
        zip.addBuffer(bytes, EXPORT_MERGED_PATH, { mtime });
        zip.addBuffer(
          Buffer.from(signManifest(bytes, this.options.signingKey), 'utf8'),
          EXPORT_MERGED_SIGNATURE_PATH,
          { mtime },
        );
      }
      if (items.some((i) => i.malicious)) {
        zip.addBuffer(
          Buffer.from(EXPORT_MALICIOUS_README_TEXT, 'utf8'),
          EXPORT_MALICIOUS_README_PATH,
          { mtime },
        );
      }
      zip.addBuffer(manifest.bytes, EXPORT_MANIFEST_PATH, { mtime });
      zip.addBuffer(Buffer.from(manifest.signature, 'utf8'), EXPORT_SIGNATURE_PATH, { mtime });
      zip.addBuffer(Buffer.from(EXPORT_README_TEXT, 'utf8'), EXPORT_README_PATH, { mtime });
      zip.end();
      const measure = new Measure();
      const encrypt = createArchiveEncryptStream({
        dek,
        kind: 'export',
        organizationId: e.organizationId,
        subjectId: e.publicId,
        chunkBytes: this.options.chunkBytes,
      });
      const body = new PassThrough();
      const zipError = new Promise<never>((_, reject) => zip.once('error', reject));
      zipError.catch(() => undefined);
      const uploading = this.options.storage.uploadStream({
        key,
        body,
        lock: null,
        tagging: `${EXPORT_OBJECT_TAG.key}=${EXPORT_OBJECT_TAG.value}`,
      });
      // A failed upload stops reading its body: end the pipeline too, or it waits forever.
      uploading.catch((error: unknown) => body.destroy(error as Error));
      zipError.catch((error: unknown) => body.destroy(error as Error));
      const [piped, stored] = await Promise.allSettled([
        Promise.race([pipeline(zip.outputStream, measure, encrypt, body), zipError]),
        uploading,
      ]);
      dek.fill(0);
      if (stored.status === 'fulfilled') uploaded = stored.value;
      if (piped.status === 'rejected') {
        body.destroy();
        (zip.outputStream as unknown as { destroy?: () => void }).destroy?.();
        throw piped.reason;
      }
      if (stored.status === 'rejected') throw stored.reason;
      if (measure.sha256 === null) throw new ExportError('package_incomplete');
      const expiresAt = new Date(now.getTime() + this.options.ttlHours * 3_600_000);
      const maliciousCount = items.filter((i) => i.malicious).length;
      await this.prisma.$transaction(async (tx) => {
        const done = await tx.$executeRaw`
          UPDATE ediscovery_exports SET status = 'completed', item_count = ${items.length},
            malicious_count = ${maliciousCount}, package_bytes = ${BigInt(measure.bytes)},
            package_sha256 = ${measure.sha256}, manifest_sha256 = ${manifest.sha256},
            signing_key_id = ${this.options.signingKeyId}, object_key = ${key},
            object_version_id = ${uploaded!.versionId}, key_version = ${tenantKey.version},
            wrapped_dek = ${wrappedDek}, expires_at = ${expiresAt}, completed_at = ${this.now()},
            error_code = NULL, updated_at = NOW(3)
          WHERE id = ${e.id} AND status = 'building'`;
        if (done !== 1) throw new ExportError('export_changed');
        await systemAudit(tx, {
          organizationId: e.organizationId,
          action: 'ediscovery.export_completed',
          resourceType: 'ediscovery_export',
          resourceId: e.publicId,
          correlationId: `ediscovery-export:${e.publicId}`,
          metadata: {
            caseId: kase.publicId,
            searchId: search.publicId,
            items: items.length,
            malicious: maliciousCount,
            packageBytes: measure.bytes,
            packageSha256: measure.sha256,
            manifestSha256: manifest.sha256,
            signingKeyId: this.options.signingKeyId,
            reviewTags: tags,
          },
        });
      });
      this.options.metrics.exports.inc({ result: 'completed' });
      this.options.metrics.exportBytes.inc(measure.bytes);
      return 'completed';
    } catch (error) {
      const code =
        error instanceof ExportError
          ? error.code
          : error instanceof RecordShreddedError
            ? 'archive_content_unavailable'
            : (error as { reason?: unknown }).reason === 'integrity'
              ? 'archive_integrity_failed'
              : errorCode(error, 'export_failed');
      if (code === 'archive_integrity_failed') this.options.metrics.integrityFailures.inc();
      this.options.logger.warn(
        { exportId: e.publicId, failureCode: code, ...errorFields(error) },
        'eDiscovery export failed',
      );
      if (uploaded?.versionId) {
        await this.options.storage
          .deleteVersion(this.options.storage.buckets.archive, uploaded.key, uploaded.versionId)
          .catch(() => undefined);
      }
      await this.prisma.$transaction(async (tx) => {
        await tx.$executeRaw`
          UPDATE ediscovery_exports SET status = 'failed', error_code = ${code.slice(0, 64)},
            wrapped_dek = NULL, updated_at = NOW(3)
          WHERE id = ${e.id} AND status = 'building'`;
        await systemAudit(tx, {
          organizationId: e.organizationId,
          action: 'ediscovery.export_failed',
          resourceType: 'ediscovery_export',
          resourceId: e.publicId,
          correlationId: `ediscovery-export:${e.publicId}`,
          metadata: { errorCode: code.slice(0, 64) },
        });
      });
      this.options.metrics.exports.inc({ result: 'failed' });
      return 'failed';
    }
  }

  /** One item: the record and its DEK re-read on the writer, then the verified plaintext stream. */
  private async itemStream(record: EmailArchive): Promise<NodeJS.ReadableStream> {
    const fresh = await this.prisma.emailArchive.findUnique({
      where: { id_receivedAt: { id: record.id, receivedAt: record.receivedAt } },
    });
    if (
      fresh === null ||
      fresh.organizationId !== record.organizationId ||
      fresh.wrappedDek === null ||
      (fresh.status !== 'active' && fresh.status !== 'expiry_review')
    ) {
      throw new RecordShreddedError();
    }
    return this.options.objects.emlStream(fresh);
  }

  /**
   * The step 8.6 supplement of an export (D7, ADR-0088): for every selected record with merged
   * copies or a journal intake source, `merged.json` (`archive-export-merged/1`, canonical JSON,
   * signed like the manifest into `merged.sig`): the record's sources, its merged parties
   * (addresses with their envelope field and sources) and its merged copies (public id, received
   * time, source, whether the body is a stored variant and then its ZIP path, plaintext SHA-256
   * and size from `archive_record_sources`). The signed `archive-export-manifest/1` itself is
   * unchanged (strict schema); variants are listed here.
   */
  private async mergedSupplement(
    e: ClaimedExport,
    items: readonly ExportItem[],
  ): Promise<{ document: Record<string, unknown> | null; variants: ExportVariant[] }> {
    const variants: ExportVariant[] = [];
    const records: Array<Record<string, unknown>> = [];
    for (const item of items) {
      const r = item.record;
      const copies = mergedCopiesOf(r.objects);
      if (copies.length === 0 && !r.sourceJournalIntake) continue;
      const sources =
        copies.length === 0
          ? []
          : await this.prisma.archiveRecordSource.findMany({
              where: {
                organizationId: e.organizationId,
                archiveId: r.id,
                archiveReceivedAt: r.receivedAt,
              },
              select: {
                organizationId: true,
                messagePublicId: true,
                emlSha256: true,
                sizeBytes: true,
                bodySha256: true,
              },
            });
      const itemPath = exportEntryPath({
        receivedAt: r.receivedAt,
        messageId: r.messagePublicId,
        malicious: item.malicious,
      });
      let n = 0;
      const mergedCopies = copies.map((c) => {
        const row = sources.find(
          (x) => x.messagePublicId === c.messageId && x.organizationId === e.organizationId,
        );
        if (c.eml === null || row === undefined) {
          return {
            messageId: c.messageId,
            receivedAt: c.receivedAt,
            source: c.source,
            contentVariant: false,
            path: null,
            sha256: row?.emlSha256 ?? null,
            sizeBytes: row?.sizeBytes ?? null,
          };
        }
        n += 1;
        const path = variantEntryPath(itemPath, n);
        variants.push({
          record: r,
          messagePublicId: c.messageId,
          path,
          sha256: row.emlSha256,
          sizeBytes: row.sizeBytes,
        });
        return {
          messageId: c.messageId,
          receivedAt: c.receivedAt,
          source: c.source,
          contentVariant: true,
          path,
          sha256: row.emlSha256,
          sizeBytes: row.sizeBytes,
        };
      });
      const parties = archivePartiesSchema.safeParse(r.parties);
      records.push({
        messageId: r.messagePublicId,
        path: itemPath,
        sources: [
          ...(r.sourceGateway ? ['gateway'] : []),
          ...(r.sourceJournalIntake ? ['journal_intake'] : []),
        ],
        parties: parties.success
          ? {
              from: parties.data.from,
              headerFrom: parties.data.headerFrom,
              recipients: parties.data.recipients.map((p) => ({
                address: p.address,
                direction: p.direction,
                status: p.status,
                ...(p.field !== undefined ? { field: p.field } : {}),
                ...(p.sources !== undefined ? { sources: p.sources } : {}),
              })),
            }
          : null,
        mergedCopies,
      });
    }
    if (records.length === 0) return { document: null, variants };
    const document = {
      version: EXPORT_MERGED_VERSION,
      exportId: e.publicId,
      records,
      counts: {
        records: records.length,
        variants: variants.length,
        variantBytes: variants.reduce((sum, v) => sum + v.sizeBytes, 0),
      },
    };
    return { document: { ...document, sha256: sha256Hex(canonicalJsonBytes(document)) }, variants };
  }

  /**
   * One content variant: the record (status, DEK) re-read on the writer, the variant decrypted
   * under the record's DEK with the merged message's public id as subject and its plaintext
   * SHA-256 (`archive_record_sources.eml_sha256`) re-verified while it streams.
   */
  private async variantStream(v: ExportVariant): Promise<NodeJS.ReadableStream> {
    const fresh = await this.prisma.emailArchive.findUnique({
      where: { id_receivedAt: { id: v.record.id, receivedAt: v.record.receivedAt } },
    });
    if (
      fresh === null ||
      fresh.organizationId !== v.record.organizationId ||
      fresh.wrappedDek === null ||
      (fresh.status !== 'active' && fresh.status !== 'expiry_review')
    ) {
      throw new RecordShreddedError();
    }
    const copy = mergedCopiesOf(fresh.objects).find((c) => c.messageId === v.messagePublicId);
    if (copy === undefined || copy.eml === null) throw new RecordShreddedError();
    const key = assertKeyOfOrganization(copy.eml.key, fresh.organizationId, 'archive');
    const { dek } = await this.options.objects.dek(fresh);
    const storage = this.options.storage;
    let sealed: NodeJS.ReadableStream;
    try {
      sealed = await storage.getStream(storage.buckets.archive, key, copy.eml.versionId);
    } catch (error) {
      dek.fill(0);
      throw error;
    }
    const decrypt = createArchiveDecryptStream({
      dek,
      kind: 'eml',
      organizationId: fresh.organizationId,
      subjectId: v.messagePublicId,
      expectedSha256: v.sha256.toLowerCase(),
    });
    decrypt.once('close', () => dek.fill(0));
    sealed.once('error', (error: unknown) => decrypt.destroy(error as Error));
    return sealed.pipe(decrypt);
  }

  /**
   * Export expiry (A18): completed exports past `expires_at` lose their object (the recorded
   * version, under `org/<org>/exports/` only) and their wrapped DEK; status `expired`.
   */
  async expire(limit = 100): Promise<number> {
    const now = this.now();
    const due = await this.prisma.ediscoveryExport.findMany({
      where: {
        status: 'completed',
        expiresAt: { lte: now },
        ...(this.options.organizationIds
          ? { organizationId: { in: [...this.options.organizationIds] } }
          : {}),
      },
      select: {
        id: true,
        organizationId: true,
        objectKey: true,
        objectVersionId: true,
        publicId: true,
      },
      orderBy: { expiresAt: 'asc' },
      take: limit,
    });
    let expired = 0;
    for (const x of due) {
      try {
        if (x.objectKey !== null && x.objectVersionId !== null) {
          const key = assertKeyOfOrganization(x.objectKey, x.organizationId, 'exports');
          await this.options.storage.deleteVersion(
            this.options.storage.buckets.archive,
            key,
            x.objectVersionId,
          );
        }
        await this.prisma.$executeRaw`
          UPDATE ediscovery_exports SET status = 'expired', wrapped_dek = NULL, updated_at = NOW(3)
          WHERE id = ${x.id} AND status = 'completed'`;
        expired += 1;
        this.options.metrics.exports.inc({ result: 'expired' });
      } catch (error) {
        this.options.logger.warn(
          { exportId: x.publicId, ...errorFields(error) },
          'export expiry failed',
        );
      }
    }
    return expired;
  }
}

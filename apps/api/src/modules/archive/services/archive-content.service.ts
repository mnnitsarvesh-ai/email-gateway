import { PassThrough, type Readable } from 'node:stream';
import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  ARCHIVE_TENANT_KEY_ALGORITHM,
  ArchiveCryptoError,
  type ArchiveJournal,
  archiveJournalSchema,
  type ArchiveRecordObjects,
  archiveRecordObjectsSchema,
  createArchiveDecryptStream,
  decryptArchiveObject,
  generateDataKey,
  LocalRootKeyProvider,
  parseScanSnapshot,
  type ScanSnapshot,
  unwrapExportKey,
  unwrapRecordKey,
  unwrapTenantKey,
  wrapTenantKey,
} from '@email-gateway/archive';
import { API_CONFIG } from '../../../api-config.token';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ArchiveConfig } from '../archive.constants';
import { archiveContentUnavailable, archiveIntegrityFailed } from '../archive.errors';
import { ArchiveConfigRepository } from '../repositories/archive-config.repository';
import type { RecordRow } from '../repositories/archive-records.repository';
import { ArchiveMetrics } from './archive-metrics';
import { ArchiveObjectError, ArchiveObjectStore } from './archive-object-store';

/** Bound of the small objects read into memory (journal reports, scan snapshots). */
const MAX_SMALL_OBJECT_BYTES = 64 * 1024 * 1024;
/** Bound of a streamed object (EML originals and export packages are streamed, never buffered). */
const MAX_STREAM_BYTES = Number.MAX_SAFE_INTEGER;

/** The export columns a download reads (writer). */
export interface ExportContentRow {
  publicId: string;
  objectKey: string | null;
  objectVersionId: string | null;
  keyVersion: number | null;
  wrappedDek: string | null;
  packageSha256: string | null;
  packageBytes: bigint | null;
}

/**
 * Archive content access of the api (step 8.1 A8, A19, ADR-0065): the root key provider, tenant
 * key unwrapping (writer reads of `archive_encryption_keys`), record and export DEK unwrapping
 * with their AADs, and decryption of the `archive-object/1` objects: the journal report and scan
 * snapshots into memory (bounded), the original EML and export packages as constant-memory
 * streams whose plaintext SHA-256 is verified at the end. Callers re-read the record on the
 * writer first (A14) and commit their audit row before calling. A crypto or integrity failure is
 * `500 archive_integrity_failed` (counted, logged by reason code only); a missing key, DEK or
 * object is `410 archive_content_unavailable`.
 */
@Injectable()
export class ArchiveContentService {
  private readonly logger = new Logger(ArchiveContentService.name);
  private readonly provider: LocalRootKeyProvider;

  constructor(
    @Inject(API_CONFIG)
    config: Pick<
      ArchiveConfig,
      | 'ARCHIVE_ROOT_KEY'
      | 'ARCHIVE_ROOT_KEY_ID'
      | 'ARCHIVE_ROOT_KEY_PREVIOUS'
      | 'ARCHIVE_ROOT_KEY_PREVIOUS_ID'
    >,
    private readonly configs: ArchiveConfigRepository,
    private readonly objects: ArchiveObjectStore,
    private readonly metrics: ArchiveMetrics,
  ) {
    this.provider = LocalRootKeyProvider.fromConfig({
      ARCHIVE_ROOT_KEY: config.ARCHIVE_ROOT_KEY,
      ARCHIVE_ROOT_KEY_ID: config.ARCHIVE_ROOT_KEY_ID,
      ARCHIVE_ROOT_KEY_PREVIOUS: config.ARCHIVE_ROOT_KEY_PREVIOUS,
      ARCHIVE_ROOT_KEY_PREVIOUS_ID: config.ARCHIVE_ROOT_KEY_PREVIOUS_ID,
    });
  }

  /** Counts one content access (no tenant, principal or id labels, A27). */
  count(kind: string, result: string): void {
    this.metrics.contentAccess.inc({ kind, result });
  }

  /** A fresh tenant key version wrapped under the current root key (rotation, A9). */
  async newTenantKey(
    organizationId: bigint,
    version: number,
  ): Promise<{ wrappedKey: string; rootKeyId: string; algorithm: string }> {
    const key = generateDataKey();
    try {
      const wrappedKey = await wrapTenantKey(this.provider, { organizationId, version }, key);
      return {
        wrappedKey,
        rootKeyId: this.provider.currentKeyId,
        algorithm: ARCHIVE_TENANT_KEY_ALGORITHM,
      };
    } finally {
      key.fill(0);
    }
  }

  /** The unwrapped tenant key of a version (writer); destroyed or missing → content unavailable. */
  private async tenantKey(scope: TenantScope, version: number): Promise<Buffer> {
    const row = await this.configs.wrappedKey(scope, version);
    if (row === null || row.status === 'destroyed' || row.wrappedKey === null) {
      throw archiveContentUnavailable();
    }
    const result = await this.guard('tenant_key', () =>
      unwrapTenantKey(this.provider, row.wrappedKey!, {
        organizationId: scope.organizationId,
        version,
      }),
    );
    return result.key;
  }

  /** The record's objects and its DEK (writer facts; `wrapped_dek` NULL = crypto-shredded). */
  async recordKey(
    scope: TenantScope,
    record: RecordRow,
  ): Promise<{ dek: Buffer; objects: ArchiveRecordObjects }> {
    if (record.status === 'disposing' || record.wrappedDek === null || record.deletedAt !== null) {
      throw archiveContentUnavailable();
    }
    const parsed = archiveRecordObjectsSchema.safeParse(record.objects);
    if (!parsed.success) {
      this.integrity('objects', 'malformed');
      throw archiveIntegrityFailed();
    }
    const tenantKey = await this.tenantKey(scope, record.keyVersion);
    const dek = await this.guard('record_key', () =>
      unwrapRecordKey(tenantKey, record.wrappedDek!, {
        organizationId: scope.organizationId,
        messagePublicId: record.messagePublicId,
        captureId: parsed.data.captureId,
        keyVersion: record.keyVersion,
      }),
    );
    tenantKey.fill(0);
    return { dek, objects: parsed.data };
  }

  /** The decrypted `archive-journal/1` report of a record (bound to the record's ids). */
  async journal(scope: TenantScope, record: RecordRow): Promise<ArchiveJournal> {
    const { dek, objects } = await this.recordKey(scope, record);
    try {
      const plain = await this.decryptSmall(scope, record, dek, 'journal', objects.journal);
      let json: unknown;
      try {
        json = JSON.parse(plain.toString('utf8'));
      } catch {
        json = null;
      }
      const parsed = archiveJournalSchema.safeParse(json);
      if (
        !parsed.success ||
        parsed.data.organizationId !== scope.organizationId.toString() ||
        parsed.data.messageId !== record.messagePublicId
      ) {
        this.integrity('journal', 'document');
        throw archiveIntegrityFailed();
      }
      return parsed.data;
    } finally {
      dek.fill(0);
    }
  }

  /** Every linked scan snapshot of a record, decrypted and decoded (rounds ascending). */
  async scanSnapshots(
    scope: TenantScope,
    record: RecordRow,
    options: { latestOnly?: boolean } = {},
  ): Promise<Array<{ round: number; revision: number; snapshot: ScanSnapshot }>> {
    const { dek, objects } = await this.recordKey(scope, record);
    try {
      const out: Array<{ round: number; revision: number; snapshot: ScanSnapshot }> = [];
      const ordered = [...objects.scans].sort(
        (a, b) => a.round - b.round || a.revision - b.revision,
      );
      const refs = options.latestOnly === true ? ordered.slice(-1) : ordered;
      for (const ref of refs) {
        const plain = await this.decryptSmall(scope, record, dek, 'scan', ref);
        let snapshot: ScanSnapshot;
        try {
          snapshot = parseScanSnapshot(plain);
        } catch {
          this.integrity('scan', 'document');
          throw archiveIntegrityFailed();
        }
        if (
          snapshot.messageId !== record.messagePublicId ||
          snapshot.organizationId !== scope.organizationId.toString()
        ) {
          this.integrity('scan', 'binding');
          throw archiveIntegrityFailed();
        }
        out.push({ round: ref.round, revision: ref.revision, snapshot });
      }
      return out.sort((a, b) => a.round - b.round || a.revision - b.revision);
    } finally {
      dek.fill(0);
    }
  }

  /**
   * The original EML as a decrypting stream: the plaintext SHA-256 must equal
   * `email_archives.sha256` at the end of the stream, else the stream errors (the response is
   * aborted, `archive_integrity_failures_total` counts it).
   */
  async openEml(scope: TenantScope, record: RecordRow): Promise<Readable> {
    const { dek, objects } = await this.recordKey(scope, record);
    const opened = await this.openObject(scope, 'archive', objects.eml.key, objects.eml.versionId);
    const decrypt = createArchiveDecryptStream({
      dek,
      kind: 'eml',
      organizationId: scope.organizationId,
      subjectId: record.messagePublicId,
      expectedSha256: record.sha256,
    });
    // The DEK stays with the stream: it derives the object key when the header arrives.
    return this.pipe(opened, decrypt, 'eml');
  }

  /**
   * Step 8.6 D7: a stored content variant (the EML of a merged copy whose body differed) as a
   * decrypting stream: encrypted under the record's DEK with the merged copy's public id as the
   * subject; its plaintext SHA-256 must equal `archive_record_sources.eml_sha256`.
   */
  async openVariantEml(
    scope: TenantScope,
    record: RecordRow,
    variant: { messagePublicId: string; emlSha256: string },
  ): Promise<Readable> {
    const { dek, objects } = await this.recordKey(scope, record);
    const copy = (objects.merged ?? []).find((m) => m.messageId === variant.messagePublicId);
    if (copy === undefined || copy.eml === null) {
      dek.fill(0);
      throw archiveContentUnavailable();
    }
    const opened = await this.openObject(scope, 'archive', copy.eml.key, copy.eml.versionId);
    const decrypt = createArchiveDecryptStream({
      dek,
      kind: 'eml',
      organizationId: scope.organizationId,
      subjectId: variant.messagePublicId,
      expectedSha256: variant.emlSha256,
    });
    return this.pipe(opened, decrypt, 'eml');
  }

  /** An export package (ZIP) as a decrypting stream verified against `package_sha256`. */
  async openExport(scope: TenantScope, row: ExportContentRow): Promise<Readable> {
    if (
      row.objectKey === null ||
      row.keyVersion === null ||
      row.wrappedDek === null ||
      row.packageSha256 === null
    ) {
      throw archiveContentUnavailable();
    }
    const tenantKey = await this.tenantKey(scope, row.keyVersion);
    const dek = await this.guard('export_key', () =>
      unwrapExportKey(tenantKey, row.wrappedDek!, {
        organizationId: scope.organizationId,
        exportPublicId: row.publicId,
        keyVersion: row.keyVersion!,
      }),
    );
    tenantKey.fill(0);
    const opened = await this.openObject(scope, 'exports', row.objectKey, row.objectVersionId);
    const decrypt = createArchiveDecryptStream({
      dek,
      kind: 'export',
      organizationId: scope.organizationId,
      subjectId: row.publicId,
      expectedSha256: row.packageSha256,
    });
    // The DEK stays with the stream: it derives the object key when the header arrives.
    return this.pipe(opened, decrypt, 'export');
  }

  private pipe(source: Readable, decrypt: NodeJS.ReadWriteStream, what: string): Readable {
    const out = new PassThrough();
    const fail = (error: unknown) => {
      const reason = error instanceof ArchiveCryptoError ? error.reason : 'storage_error';
      this.integrity(what, reason);
      out.destroy(new Error(`archive ${what} stream failed (${reason})`));
    };
    source.on('error', fail);
    decrypt.on('error', fail);
    source.pipe(decrypt).pipe(out);
    return out;
  }

  private async openObject(
    scope: TenantScope,
    area: 'archive' | 'exports',
    key: string,
    versionId: string | null,
  ): Promise<Readable> {
    try {
      const opened = await this.objects.open(
        scope.organizationId,
        area,
        key,
        versionId,
        MAX_STREAM_BYTES,
      );
      return opened.body;
    } catch (error) {
      throw this.objectError(error, area);
    }
  }

  private async decryptSmall(
    scope: TenantScope,
    record: RecordRow,
    dek: Buffer,
    kind: 'journal' | 'scan',
    ref: { key: string; versionId: string | null },
  ): Promise<Buffer> {
    let cipher: Buffer;
    try {
      cipher = await this.objects.read(
        scope.organizationId,
        ref.key,
        ref.versionId,
        MAX_SMALL_OBJECT_BYTES,
      );
    } catch (error) {
      throw this.objectError(error, kind);
    }
    return this.guard(kind, () =>
      decryptArchiveObject(cipher, {
        dek,
        kind,
        organizationId: scope.organizationId,
        subjectId: record.messagePublicId,
      }),
    );
  }

  private objectError(error: unknown, what: string): Error {
    if (error instanceof ArchiveObjectError) {
      if (error.why === 'not_found') {
        this.logger.warn({ message: 'archive object missing', what });
        return archiveContentUnavailable();
      }
      this.integrity(what, error.why);
      return archiveIntegrityFailed();
    }
    return error instanceof Error ? error : new Error('archive object read failed');
  }

  private async guard<T>(what: string, fn: () => T | Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      if (error instanceof ArchiveCryptoError) {
        this.integrity(what, error.reason);
        throw archiveIntegrityFailed();
      }
      throw error;
    }
  }

  private integrity(what: string, reason: string): void {
    this.metrics.contentAccess.inc({ kind: 'integrity', result: reason });
    this.logger.error({ message: 'archive integrity failure', what, reason });
  }
}

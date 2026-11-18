import type { Readable } from 'node:stream';
import {
  type ArchiveJournal,
  archiveJournalSchema,
  type ArchiveRecordObjects,
  archiveRecordObjectsSchema,
  assertKeyOfOrganization,
  createArchiveDecryptStream,
  decryptArchiveObject,
  parseScanSnapshot,
  type ScanSnapshot,
  unwrapRecordKey,
} from '@email-gateway/archive';
import type { TenantKeyService } from '../keys/tenant-keys';
import type { ArchiveStorage } from './archive-storage';

/** The columns of an `email_archives` row needed to open its objects. */
export interface OpenableRecord {
  organizationId: bigint;
  messagePublicId: string;
  keyVersion: number;
  wrappedDek: string | null;
  objects: unknown;
  sha256: string;
}

export class RecordShreddedError extends Error {
  readonly code = 'archive_content_unavailable';
  constructor() {
    super('record content unavailable');
    this.name = 'RecordShreddedError';
  }
}

/**
 * Opens the objects of an archive record (A8): the record DEK is unwrapped under its tenant key
 * version (AAD binds organization, message, capture and version), every key is checked against
 * `org/<organizationId>/archive/`, and every object is read by its recorded version id.
 * A shredded record (`wrapped_dek` NULL) has no readable content.
 */
export class RecordObjects {
  constructor(
    private readonly storage: ArchiveStorage,
    private readonly keys: TenantKeyService,
  ) {}

  async dek(record: OpenableRecord): Promise<{ dek: Buffer; objects: ArchiveRecordObjects }> {
    if (record.wrappedDek === null) throw new RecordShreddedError();
    const objects = archiveRecordObjectsSchema.parse(record.objects);
    const tenantKey = await this.keys.version(record.organizationId, record.keyVersion);
    const dek = unwrapRecordKey(tenantKey.key, record.wrappedDek, {
      organizationId: record.organizationId,
      messagePublicId: record.messagePublicId,
      captureId: objects.captureId,
      keyVersion: record.keyVersion,
    });
    return { dek, objects };
  }

  async journal(record: OpenableRecord): Promise<ArchiveJournal> {
    const { dek, objects } = await this.dek(record);
    try {
      const key = assertKeyOfOrganization(objects.journal.key, record.organizationId, 'archive');
      const sealed = await this.storage.getBuffer(
        this.storage.buckets.archive,
        key,
        objects.journal.versionId,
      );
      const plain = decryptArchiveObject(sealed, {
        dek,
        kind: 'journal',
        organizationId: record.organizationId,
        subjectId: record.messagePublicId,
      });
      return archiveJournalSchema.parse(JSON.parse(plain.toString('utf8')));
    } finally {
      dek.fill(0);
    }
  }

  /** The newest linked scan snapshot (null when the record links none). */
  async latestScan(record: OpenableRecord): Promise<ScanSnapshot | null> {
    const { dek, objects } = await this.dek(record);
    try {
      const ref = [...objects.scans]
        .sort((a, b) => a.round - b.round || a.revision - b.revision)
        .pop();
      if (ref === undefined) return null;
      const key = assertKeyOfOrganization(ref.key, record.organizationId, 'archive');
      const sealed = await this.storage.getBuffer(this.storage.buckets.archive, key, ref.versionId);
      const plain = decryptArchiveObject(sealed, {
        dek,
        kind: 'scan',
        organizationId: record.organizationId,
        subjectId: record.messagePublicId,
      });
      return parseScanSnapshot(plain);
    } finally {
      dek.fill(0);
    }
  }

  /**
   * The decrypted original as a stream; the plaintext SHA-256 is re-verified against the
   * record's `sha256` while streaming (the stream errors `integrity` at its end, A6).
   */
  async emlStream(record: OpenableRecord): Promise<Readable> {
    const { dek, objects } = await this.dek(record);
    const key = assertKeyOfOrganization(objects.eml.key, record.organizationId, 'archive');
    const sealed = await this.storage.getStream(
      this.storage.buckets.archive,
      key,
      objects.eml.versionId,
    );
    const decrypt = createArchiveDecryptStream({
      dek,
      kind: 'eml',
      organizationId: record.organizationId,
      subjectId: record.messagePublicId,
      expectedSha256: record.sha256.toLowerCase(),
    });
    decrypt.once('close', () => dek.fill(0));
    sealed.once('error', (error) => decrypt.destroy(error));
    return sealed.pipe(decrypt);
  }
}

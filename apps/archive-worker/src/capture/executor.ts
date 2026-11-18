import { createHash } from 'node:crypto';
import { PassThrough, type Readable, Transform, type TransformCallback } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import {
  ARCHIVE_OBJECT_FORMAT,
  type ArchiveCategory,
  type ArchiveRecordObjects,
  type ArchiveScanRounds,
  archiveObjectKey,
  assertKeyOfOrganization,
  buildScanSnapshot,
  computeRetainUntil,
  createArchiveEncryptStream,
  encryptArchiveObject,
  generateDataKey,
  isKeyOfOrganization,
  type ObjectLockMode,
  wrapRecordKey,
} from '@email-gateway/archive';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { TenantKeyService } from '../keys/tenant-keys';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import {
  DeterministicCaptureError,
  errorFields,
  isUniqueViolation,
  LeaseLostError,
  ObjectLockUnknownError,
  OriginalMissingError,
} from '../shared/errors';
import {
  type ArchiveStorage,
  isMissing,
  LOCK_FLOOR_MS,
  type ObjectLockSpec,
  type ObjectLockState,
  type StoredVersion,
} from '../storage/archive-storage';
import { FactsReader, isMalicious, type MessageFacts, partiesOf, type RoundRef } from './facts';
import { buildJournal, readBodies } from './journal';
import type { OrgArchiveContext } from './org-context';
import { selectRetention } from './retention';

/** Plaintext SHA-256 check of the original while it streams (A5 step 3, A6). */
export class Sha256Verify extends Transform {
  private readonly hash = createHash('sha256');
  mismatch = false;
  bytes = 0;

  constructor(private readonly expected: string) {
    super();
  }

  override _transform(chunk: Buffer, _enc: BufferEncoding, cb: TransformCallback): void {
    this.hash.update(chunk);
    this.bytes += chunk.length;
    cb(null, chunk);
  }

  override _flush(cb: TransformCallback): void {
    const actual = this.hash.digest('hex');
    if (actual !== this.expected.toLowerCase()) {
      this.mismatch = true;
      // Erroring before the end aborts the upload: no object is completed from this stream.
      cb(new DeterministicCaptureError('integrity_mismatch'));
      return;
    }
    cb();
  }
}

/** The lease a claim holds on an intent (A2, A6). */
export interface ClaimedIntent {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  messageId: bigint;
  leaseUntil: Date;
  sourceJournal: boolean;
  sourcePolicy: boolean;
  policyRuleRef: string | null;
}

/** Test-only fault hooks (integration suites inject them; never reachable from configuration). */
export interface CaptureFaults {
  /** After the EML object was uploaded, before the journal object. */
  afterEmlUpload?: () => Promise<void>;
  /** After every object was uploaded, inside nothing (before the commit transaction). */
  beforeCommit?: () => Promise<void>;
}

export type CaptureResult =
  { status: 'captured'; archiveId: bigint; storedBytes: number } | { status: 'lost_race' };

const s3Lock = (mode: ObjectLockMode, until: Date): ObjectLockSpec | null =>
  mode === 'none' ? null : { mode, until };

/** Snapshot objects of one round written for a record (shared with the outcome refresh). */
export async function writeScanSnapshot(input: {
  storage: ArchiveStorage;
  reader: FactsReader;
  db: Prisma.TransactionClient | PrismaClient;
  facts: MessageFacts;
  round: RoundRef;
  dek: Buffer;
  captureId: string;
  frozenAt: Date;
  lock: ObjectLockSpec | null;
  chunkBytes: number;
}): Promise<{
  ref: ArchiveRecordObjects['scans'][number];
  link: ArchiveScanRounds[number];
  rows: Awaited<ReturnType<FactsReader['roundRows']>>;
}> {
  const m = input.facts.message;
  const rows = await input.reader.roundRows(input.db, m, input.round);
  const snapshot = buildScanSnapshot({
    organizationId: m.organizationId.toString(),
    messageId: m.publicId,
    round: input.round.round,
    revision: input.round.revision,
    frozenAt: input.frozenAt,
    rows,
  });
  const encrypted = encryptArchiveObject(snapshot.bytes, {
    dek: input.dek,
    kind: 'scan',
    organizationId: m.organizationId,
    subjectId: m.publicId,
    chunkBytes: input.chunkBytes,
  });
  const key = archiveObjectKey({
    organizationId: m.organizationId,
    receivedAt: m.receivedAt,
    messagePublicId: m.publicId,
    captureId: input.captureId,
    kind: 'scan',
    round: input.round.round,
    revision: input.round.revision,
  });
  const stored = await input.storage.putBuffer({ key, body: encrypted.object, lock: input.lock });
  return {
    ref: {
      key,
      versionId: stored.versionId,
      sha256: encrypted.summary.ciphertextSha256,
      bytes: encrypted.summary.ciphertextBytes,
      round: input.round.round,
      revision: input.round.revision,
    },
    link: {
      round: input.round.round,
      revision: input.round.revision,
      frozenAt: input.frozenAt.toISOString(),
    },
    rows,
  };
}

/**
 * The capture executor (A5, ADR-0064/0065/0066), strictly in this order: writer facts (echo-
 * checked), the tenant key and a fresh DEK, `captureId` (UUIDv7), the original EML streamed from
 * the mail bucket through `archive-object/1` encryption into a multipart upload (Object Lock
 * headers for locked tenants; refused with `object_lock_unavailable` when the tenant needs a lock
 * and the bucket has none), the plaintext SHA-256 checked against `email_messages.eml_sha256`
 * (mismatch → `integrity_mismatch`, upload aborted, nothing committed), the journal object, one
 * scan snapshot per linked round/revision, the retention policy and `retain_until`, then ONE
 * writer transaction: the `email_archives` row, the intent `captured_open` (CAS on the lease) and
 * an index upsert. A lost unique race deletes its own just-written versions (locked ones are left
 * to the orphan reconciliation, A15).
 */
export class CaptureExecutor {
  private readonly reader = new FactsReader();

  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      storage: ArchiveStorage;
      lockState: ObjectLockState;
      keys: TenantKeyService;
      metrics: ArchiveMetrics;
      logger: Logger;
      chunkBytes: number;
      previewPartMaxBytes: number;
      daySeconds: number;
      faults?: CaptureFaults;
      now?: () => Date;
    },
  ) {}

  private now(): Date {
    return this.options.now?.() ?? new Date();
  }

  async capture(input: {
    intent: ClaimedIntent;
    facts: MessageFacts;
    ctx: OrgArchiveContext;
    category: ArchiveCategory;
    sources: { journal: boolean; policy: boolean };
    recheckAt: Date;
  }): Promise<CaptureResult> {
    const { facts, ctx } = input;
    const m = facts.message;
    const org = m.organizationId;
    const storage = this.options.storage;
    const lockMode = ctx.objectLockMode;
    if (lockMode !== 'none' && this.options.lockState.available !== true) {
      // Not probed yet (S3 unreachable at start): retried; probed and absent: refused (A10).
      if (this.options.lockState.available === null) throw new ObjectLockUnknownError();
      this.options.metrics.objectLock.inc({ op: 'upload', result: 'unavailable' });
      throw new DeterministicCaptureError('object_lock_unavailable');
    }
    if (!isKeyOfOrganization(m.emlObjectKey, org, 'eml') || !/^[0-9a-f]{64}$/i.test(m.emlSha256)) {
      throw new DeterministicCaptureError('facts_invalid');
    }

    // 1. Facts (journal inputs, linked round) on the writer.
    const inputs = await this.reader.journalInputs(this.prisma, facts);
    const rounds = await this.reader.terminalRounds(this.prisma, m);
    const latest = rounds[0] ?? null;

    // Retention (A11) before any upload: a missing default is retried, never stored unretained.
    const selection = await selectRetention(this.prisma, {
      facts,
      category: input.category,
      sources: input.sources,
      policyRuleRef: input.intent.policyRuleRef,
      defaultPolicyId: ctx.defaultRetentionPolicyId,
    });
    const now = this.now();
    const retainUntil = computeRetainUntil(
      m.receivedAt,
      selection.policy.retentionDays,
      this.options.daySeconds,
    );
    // A lock date must lie in the future; a late capture with a short policy keeps a short lock.
    const lockUntil =
      lockMode === 'none'
        ? null
        : new Date(Math.max(retainUntil.getTime(), now.getTime() + LOCK_FLOOR_MS));
    const lock = lockUntil === null ? null : s3Lock(lockMode, lockUntil);

    // 2. Keys.
    const tenantKey = await this.options.keys.active(org);
    const dek = generateDataKey();
    const captureId = uuidv7(now.getTime());
    const wrappedDek = wrapRecordKey(
      tenantKey.key,
      {
        organizationId: org,
        messagePublicId: m.publicId,
        captureId,
        keyVersion: tenantKey.version,
      },
      dek,
    );
    const written: StoredVersion[] = [];
    try {
      // 3. EML object.
      const emlKey = archiveObjectKey({
        organizationId: org,
        receivedAt: m.receivedAt,
        messagePublicId: m.publicId,
        captureId,
        kind: 'eml',
      });
      const eml = await this.uploadEml({
        sourceKey: assertKeyOfOrganization(m.emlObjectKey, org, 'eml'),
        expectedSha256: m.emlSha256,
        dek,
        organizationId: org,
        subjectId: m.publicId,
        key: emlKey,
        lock,
      });
      written.push(eml.stored);
      if (lock) this.options.metrics.objectLock.inc({ op: 'upload', result: 'ok' });
      await this.options.faults?.afterEmlUpload?.();

      // 4. Journal object.
      const bodies = await readBodies(storage, org, inputs.parse, this.options.previewPartMaxBytes);
      const journal = buildJournal({
        facts,
        inputs,
        bodies,
        captureId,
        capturedAt: now,
        category: input.category,
        sources: input.sources,
        policyRuleRef: input.intent.policyRuleRef,
        settingsGeneration: ctx.generation,
      });
      const journalEnc = encryptArchiveObject(Buffer.from(JSON.stringify(journal), 'utf8'), {
        dek,
        kind: 'journal',
        organizationId: org,
        subjectId: m.publicId,
        chunkBytes: this.options.chunkBytes,
      });
      const journalKey = archiveObjectKey({
        organizationId: org,
        receivedAt: m.receivedAt,
        messagePublicId: m.publicId,
        captureId,
        kind: 'journal',
      });
      const journalStored = await storage.putBuffer({
        key: journalKey,
        body: journalEnc.object,
        lock,
      });
      written.push(journalStored);

      // 5. Scan snapshot of the linked round (never a rescan).
      const scans: ArchiveRecordObjects['scans'] = [];
      const links: ArchiveScanRounds = [];
      let rows: Awaited<ReturnType<FactsReader['roundRows']>> | null = null;
      if (latest !== null) {
        const snap = await writeScanSnapshot({
          storage,
          reader: this.reader,
          db: this.prisma,
          facts,
          round: latest,
          dek,
          captureId,
          frozenAt: now,
          lock,
          chunkBytes: this.options.chunkBytes,
        });
        written.push({ key: snap.ref.key, versionId: snap.ref.versionId });
        scans.push(snap.ref);
        links.push(snap.link);
        rows = snap.rows;
      }

      const objects: ArchiveRecordObjects = {
        captureId,
        eml: {
          key: emlKey,
          versionId: eml.stored.versionId,
          sha256: eml.summary.ciphertextSha256,
          bytes: eml.summary.ciphertextBytes,
        },
        journal: {
          key: journalKey,
          versionId: journalStored.versionId,
          sha256: journalEnc.summary.ciphertextSha256,
          bytes: journalEnc.summary.ciphertextBytes,
        },
        scans,
      };
      const storedBytes =
        objects.eml.bytes + objects.journal.bytes + scans.reduce((s, x) => s + x.bytes, 0);
      await this.options.faults?.beforeCommit?.();

      // 6. One writer transaction.
      const archiveId = await this.prisma.$transaction(async (tx) => {
        const record = await tx.emailArchive.create({
          data: {
            receivedAt: m.receivedAt,
            messageId: m.id,
            organizationId: org,
            messagePublicId: m.publicId,
            direction: m.direction,
            capturedByJournal: input.sources.journal,
            capturedByPolicy: input.sources.policy,
            policyRuleRef: input.intent.policyRuleRef?.slice(0, 128) ?? null,
            category: input.category,
            status: 'active',
            messageState: m.status,
            messageStateReason: m.statusReason?.slice(0, 64) ?? null,
            envelopeFrom: m.envelopeFrom.slice(0, 320),
            headerFrom: m.headerFrom?.slice(0, 320) ?? null,
            subject: m.subject?.slice(0, 998) ?? null,
            internetMessageId: m.internetMessageId?.slice(0, 998) ?? null,
            parties: partiesOf(facts),
            recipientCount: Math.min(facts.recipients.length, 65_535),
            attachmentCount: m.attachmentCount,
            archiveObjectKey: emlKey,
            sha256: m.emlSha256.toLowerCase(),
            sizeBytes: m.sizeBytes,
            objects: objects,
            storedBytes: BigInt(storedBytes),
            encryptionFormat: ARCHIVE_OBJECT_FORMAT,
            keyVersion: tenantKey.version,
            wrappedDek,
            lockMode,
            lockUntil,
            retentionPolicyId: selection.policy.id,
            retainUntil,
            expiryAction: selection.policy.onExpiry,
            finalVerdict: m.finalVerdict,
            finalAction: m.finalAction,
            riskScore: m.riskScore,
            malicious: isMalicious(m, rows),
            scanRounds: links,
            settingsGeneration: ctx.generation,
            archivedAt: now,
          },
          select: { id: true },
        });
        const claimed = await tx.$executeRaw`
          UPDATE archive_capture_intents
          SET status = 'captured_open', category = ${input.category}, archive_id = ${record.id},
              captured_at = ${now}, next_check_at = ${input.recheckAt}, lease_until = NULL,
              last_error_code = NULL, settings_generation = ${ctx.generation}, updated_at = NOW(3)
          WHERE id = ${input.intent.id} AND received_at = ${input.intent.receivedAt}
            AND lease_until = ${input.intent.leaseUntil}`;
        if (claimed !== 1) throw new LeaseLostError();
        await tx.archiveIndexQueue.create({
          data: {
            organizationId: org,
            messageId: m.id,
            receivedAt: m.receivedAt,
            messagePublicId: m.publicId,
            op: 'upsert',
          },
          select: { id: true },
        });
        return record.id;
      });
      this.options.metrics.captureBytes.inc(storedBytes);
      return { status: 'captured', archiveId, storedBytes };
    } catch (error) {
      if (isUniqueViolation(error)) {
        await this.discard(written, lockMode);
        return { status: 'lost_race' };
      }
      await this.discard(written, lockMode);
      throw error;
    } finally {
      dek.fill(0);
    }
  }

  /**
   * Deletes this attempt's own versions after a failure before (or a lost race at) the commit.
   * Locked versions cannot be deleted now: they stay for the orphan reconciliation (A15).
   */
  private async discard(
    written: readonly StoredVersion[],
    lockMode: ObjectLockMode,
  ): Promise<void> {
    if (lockMode !== 'none') return;
    for (const v of written) {
      if (v.versionId === null) continue;
      try {
        await this.options.storage.deleteVersion(
          this.options.storage.buckets.archive,
          v.key,
          v.versionId,
        );
      } catch (error) {
        this.options.logger.warn(
          { ...errorFields(error) },
          'could not delete an uncommitted archive object; the orphan reconciliation will',
        );
      }
    }
  }

  private async uploadEml(input: {
    sourceKey: string;
    expectedSha256: string;
    dek: Buffer;
    organizationId: bigint;
    subjectId: string;
    key: string;
    lock: ObjectLockSpec | null;
  }) {
    const storage = this.options.storage;
    let source: Readable;
    try {
      source = await storage.getStream(storage.buckets.mail, input.sourceKey);
    } catch (error) {
      if (isMissing(error)) throw new OriginalMissingError();
      throw error;
    }
    const verify = new Sha256Verify(input.expectedSha256);
    const encrypt = createArchiveEncryptStream({
      dek: input.dek,
      kind: 'eml',
      organizationId: input.organizationId,
      subjectId: input.subjectId,
      chunkBytes: this.options.chunkBytes,
    });
    const body = new PassThrough();
    const uploading = storage.uploadStream({ key: input.key, body, lock: input.lock });
    // A failed upload stops reading its body: end the pipeline too, or it waits forever.
    uploading.catch((error: unknown) => body.destroy(error as Error));
    const [piped, uploaded] = await Promise.allSettled([
      pipeline(source, verify, encrypt, body),
      uploading,
    ]);
    if (verify.mismatch) {
      this.options.metrics.integrityFailures.inc();
      // A version can only exist if the upload completed before the error surfaced.
      if (uploaded.status === 'fulfilled' && uploaded.value.versionId !== null) {
        await this.discard([uploaded.value], input.lock === null ? 'none' : input.lock.mode);
      }
      throw new DeterministicCaptureError('integrity_mismatch');
    }
    if (piped.status === 'rejected') {
      if (uploaded.status === 'fulfilled') await this.discard([uploaded.value], 'none');
      throw piped.reason;
    }
    if (uploaded.status === 'rejected') throw uploaded.reason;
    const summary = encrypt.summary;
    if (summary === null) throw new Error('encryption summary missing');
    return { stored: uploaded.value, summary };
  }
}

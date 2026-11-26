import { createHash } from 'node:crypto';
import {
  PassThrough,
  type Readable,
  Transform,
  type TransformCallback,
  Writable,
} from 'node:stream';
import { pipeline } from 'node:stream/promises';
import {
  ARCHIVE_OBJECT_FORMAT,
  type ArchiveCategory,
  type ArchiveMergedCopy,
  type ArchiveParties,
  archivePartiesSchema,
  type ArchiveRecordObjects,
  archiveRecordObjectsSchema,
  type ArchiveScanRounds,
  archiveScanRoundsSchema,
  archiveObjectKey,
  assertKeyOfOrganization,
  BodyHasher,
  buildScanSnapshot,
  computeRetainUntil,
  createArchiveEncryptStream,
  decideMerge,
  encryptArchiveObject,
  generateDataKey,
  type IngestSource,
  isKeyOfOrganization,
  mergeParties,
  type ObjectLockMode,
  unwrapRecordKey,
  wrapRecordKey,
} from '@email-gateway/archive';
import { uuidv7 } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
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
import { recordVersionsWithMerged } from '../storage/record-versions';
import {
  CandidateChangedError,
  type DedupeCandidate,
  type DedupeKey,
  dedupeKeyOf,
  findCandidates,
  insertDedupeRow,
} from './dedupe';
import {
  FactsReader,
  type IntakeFacts,
  isMalicious,
  type MessageFacts,
  partiesOf,
  type RoundRef,
} from './facts';
import { buildJournal, type JournalInputs, readBodies } from './journal';
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
  | { status: 'captured'; archiveId: bigint; storedBytes: number }
  | {
      status: 'merged';
      archiveId: bigint;
      archiveReceivedAt: Date;
      storedBytes: number;
      variant: boolean;
    }
  | { status: 'lost_race' };

/** Cross-source dedupe bounds (step 8.6 D7, §4.4). */
export interface DedupeOptions {
  /** `ARCHIVE_DEDUPE_WINDOW_HOURS`. */
  windowHours: number;
  /** `ARCHIVE_MAX_CONTENT_VARIANTS`. */
  maxContentVariants: number;
  /** `ARCHIVE_MAX_MERGED_COPIES`. */
  maxMergedCopies: number;
}

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
  /**
   * HKDF subject of the snapshot (default the message's public id). A merged gateway copy's
   * snapshot is linked to the record and encrypted under the record's subject (step 8.6 D7), so
   * every reader opens a record's scans the same way.
   */
  subjectId?: string;
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
    subjectId: input.subjectId ?? m.publicId,
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
 *
 * Step 8.6 (D6, D7, ADR-0088): a journal intake message is captured the same way with its sources
 * (`source_gateway`/`source_journal_intake`, `intake_source_id`), the journal `intake` block and
 * the parties' envelope fields. Cross-source dedupe (with `dedupe` options): the message's key
 * (Message-ID hash + header fingerprint) is looked up in `archive_dedupe_keys`; for a live record
 * of the key (window, scope rule: at least one intake copy) the EML is hashed first without an
 * upload and `decideMerge` chooses merge without content, merge with a content variant (the EML
 * under the record's DEK), or a separate record. A merge writes the copy's journal object (and
 * variant) under the record's DEK, then one transaction that locks the record and the key's
 * dedupe rows, re-decides, and writes `archive_record_sources`, the merged record and the intent
 * (`captured_open`, `merged`, the record's `archive_id` / `archive_received_at`). A capture
 * without a candidate adds its dedupe row under the same key lock and is retried as a merge when
 * a mergeable candidate appeared meanwhile.
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
      /** Cross-source dedupe (step 8.6); absent = 8.1 behaviour (no dedupe rows). */
      dedupe?: DedupeOptions;
      faults?: CaptureFaults;
      now?: () => Date;
    },
  ) {}

  private now(): Date {
    return this.options.now?.() ?? new Date();
  }

  /** Refuses (or retries) a capture that needs a lock the bucket cannot give (A10). */
  private assertLockable(lockMode: ObjectLockMode): void {
    if (lockMode !== 'none' && this.options.lockState.available !== true) {
      // Not probed yet (S3 unreachable at start): retried; probed and absent: refused (A10).
      if (this.options.lockState.available === null) throw new ObjectLockUnknownError();
      this.options.metrics.objectLock.inc({ op: 'upload', result: 'unavailable' });
      throw new DeterministicCaptureError('object_lock_unavailable');
    }
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
    this.assertLockable(lockMode);
    if (!isKeyOfOrganization(m.emlObjectKey, org, 'eml') || !/^[0-9a-f]{64}$/i.test(m.emlSha256)) {
      throw new DeterministicCaptureError('facts_invalid');
    }
    const sourceKey = assertKeyOfOrganization(m.emlObjectKey, org, 'eml');
    const dedupe = this.options.dedupe;
    // Step API-1 D7.6: a mailbox API copy is never captured (`decideCapture` skips it with
    // `api_copy`); refuse it here too (defence in depth: never an archive record of it).
    if (m.ingestSource === 'mailbox_api') throw new DeterministicCaptureError('facts_invalid');
    const source: IngestSource = m.ingestSource ?? 'gateway';
    // Step 8.6 D7 (review fix): the copy's trusted facts that a merge must agree with.
    const incomingFacts = { source, direction: m.direction, receivedAt: m.receivedAt };

    // Step 8.6: a message already merged into a record is linked, never captured again.
    if (dedupe !== undefined) {
      const merged = await this.prisma.archiveRecordSource.findFirst({
        where: { messageId: m.id, messageReceivedAt: m.receivedAt, organizationId: org },
        select: { id: true },
      });
      if (merged !== null) return { status: 'lost_race' };
    }

    // 1. Facts (journal inputs, linked round, intake facts) on the writer.
    const inputs = await this.reader.journalInputs(this.prisma, facts);
    const rounds = await this.reader.terminalRounds(this.prisma, m);
    const latest = rounds[0] ?? null;
    const intake = await this.reader.intake(this.prisma, m);

    // Step 8.6 D7: the dedupe key and, for a live candidate record, the merge decision.
    const now = this.now();
    let key: DedupeKey | null = null;
    let bodySha256: string | null = null;
    if (dedupe !== undefined) {
      key = await dedupeKeyOf(storage, m, inputs, sourceKey);
      if (key === null) {
        this.options.metrics.dedupe.inc({ result: 'no_key' });
      } else {
        const since = new Date(now.getTime() - dedupe.windowHours * 3_600_000);
        const candidates = (await findCandidates(this.prisma, org, key, since, false)).filter(
          (c) => c.wrappedDek,
        );
        if (candidates.length === 0) {
          this.options.metrics.dedupe.inc({ result: 'no_candidate' });
        } else {
          bodySha256 = await this.hashEml(sourceKey, m.emlSha256);
          const decisions = candidates.map((candidate) => ({
            candidate,
            decision: decideMerge({
              candidate,
              incoming: { ...incomingFacts, bodySha256: bodySha256! },
              limits: dedupe,
              now,
            }),
          }));
          const pick = decisions.find((d) => d.decision.action === 'merge');
          if (pick !== undefined && pick.decision.action === 'merge') {
            return this.merge({
              ...input,
              candidate: pick.candidate,
              content: pick.decision.content,
              bodySha256,
              key,
              intake,
              inputs,
              latest,
              source,
              sourceKey,
              now,
            });
          }
          const first = decisions[0]!.decision;
          this.options.metrics.dedupe.inc({
            result: first.action === 'separate' ? first.reason : 'no_candidate',
          });
        }
      }
    }

    // Retention (A11) before any upload: a missing default is retried, never stored unretained.
    const selection = await selectRetention(this.prisma, {
      facts,
      category: input.category,
      sources: input.sources,
      policyRuleRef: input.intent.policyRuleRef,
      defaultPolicyId: ctx.defaultRetentionPolicyId,
    });
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
      // 3. EML object (its body hash computed while it streams, step 8.6 D7).
      const emlKey = archiveObjectKey({
        organizationId: org,
        receivedAt: m.receivedAt,
        messagePublicId: m.publicId,
        captureId,
        kind: 'eml',
      });
      const hasher = key === null ? undefined : new BodyHasher();
      const eml = await this.uploadEml({
        sourceKey,
        expectedSha256: m.emlSha256,
        dek,
        organizationId: org,
        subjectId: m.publicId,
        key: emlKey,
        lock,
        ...(hasher ? { hasher } : {}),
      });
      written.push(eml.stored);
      if (lock) this.options.metrics.objectLock.inc({ op: 'upload', result: 'ok' });
      await this.options.faults?.afterEmlUpload?.();
      const body = hasher?.bodySha256 ?? bodySha256;

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
        intake,
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

      // 6. One writer transaction (REPEATABLE READ when it takes the dedupe key lock: the server
      // default READ COMMITTED takes no gap locks, and an empty key range must serialize too).
      const archiveId = await this.prisma.$transaction(
        async (tx) => {
          if (key !== null && body !== null && dedupe !== undefined) {
            // Step 8.6 D7: the key's dedupe rows locked (next-key locks serialize concurrent
            // captures of one key); a candidate this copy would merge into → retry as a merge.
            const since = new Date(now.getTime() - dedupe.windowHours * 3_600_000);
            const locked = await findCandidates(tx, org, key, since, true);
            const mergeable = locked.some(
              (c) =>
                c.wrappedDek &&
                decideMerge({
                  candidate: c,
                  incoming: { ...incomingFacts, bodySha256: body },
                  limits: dedupe,
                  now,
                }).action === 'merge',
            );
            if (mergeable) throw new CandidateChangedError();
          }
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
              parties: partiesOf(facts, intake),
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
              sourceGateway: source === 'gateway',
              sourceJournalIntake: source === 'journal_intake',
              intakeSourceId: intake?.sourceInternalId ?? null,
            },
            select: { id: true },
          });
          if (key !== null && body !== null) {
            await insertDedupeRow(tx, {
              organizationId: org,
              key,
              bodySha256: body,
              archiveId: record.id,
              archiveReceivedAt: m.receivedAt,
              source,
              now,
            });
          }
          const claimed = await tx.$executeRaw`
          UPDATE archive_capture_intents
          SET status = 'captured_open', category = ${input.category}, archive_id = ${record.id},
              archive_received_at = NULL, merged = 0,
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
        },
        key !== null ? DEDUPE_TX : undefined,
      );
      this.options.metrics.captureBytes.inc(storedBytes);
      return { status: 'captured', archiveId, storedBytes };
    } catch (error) {
      if (error instanceof CandidateChangedError) {
        this.options.metrics.dedupe.inc({ result: 'candidate_changed' });
      }
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
   * Merge of a copy into a candidate record (step 8.6 D7 steps 1–3, ADR-0088). Objects first
   * (the copy's journal object and, for `variant`, its EML, both under the record's DEK with the
   * merged message's public id as HKDF subject; a gateway copy merged into a record without one
   * also freezes its newest terminal round, under the record's subject), every recorded version's
   * Object Lock extended when the merged copy's retention is longer, then one writer transaction:
   * the record row and the key's dedupe rows locked (`FOR UPDATE`), the decision re-checked on the
   * locked rows (a change → `CandidateChangedError`, the intent is retried and the written objects
   * are orphans for A15), `archive_record_sources`, the record (sources OR-ed, merged parties,
   * `objects.merged`, `retain_until` / `lock_until` maximum, `merged_count + 1`; a gateway copy's
   * outcome and scan link), the variant's dedupe row, the intent and an index upsert.
   */
  private async merge(args: {
    intent: ClaimedIntent;
    facts: MessageFacts;
    ctx: OrgArchiveContext;
    category: ArchiveCategory;
    sources: { journal: boolean; policy: boolean };
    recheckAt: Date;
    candidate: DedupeCandidate;
    content: 'none' | 'variant';
    bodySha256: string;
    key: DedupeKey;
    intake: IntakeFacts | null;
    inputs: JournalInputs;
    latest: RoundRef | null;
    source: IngestSource;
    sourceKey: string;
    now: Date;
  }): Promise<CaptureResult> {
    const { facts, candidate, now, source } = args;
    const m = facts.message;
    const org = m.organizationId;
    const storage = this.options.storage;
    const dedupe = this.options.dedupe!;
    const record = await this.prisma.emailArchive.findUnique({
      where: {
        id_receivedAt: { id: candidate.archiveId, receivedAt: candidate.archiveReceivedAt },
      },
    });
    if (
      record === null ||
      record.organizationId !== org ||
      record.status !== 'active' ||
      record.wrappedDek === null
    ) {
      this.options.metrics.dedupe.inc({ result: 'candidate_changed' });
      throw new CandidateChangedError();
    }
    const lockMode = record.lockMode;
    this.assertLockable(lockMode);
    const objects = archiveRecordObjectsSchema.parse(record.objects);
    const links = archiveScanRoundsSchema.parse(record.scanRounds);

    // Retention of the merged copy (A11): the record keeps the longest of its copies.
    const selection = await selectRetention(this.prisma, {
      facts,
      category: args.category,
      sources: args.sources,
      policyRuleRef: args.intent.policyRuleRef,
      defaultPolicyId: args.ctx.defaultRetentionPolicyId,
    });
    const copyRetain = computeRetainUntil(
      m.receivedAt,
      selection.policy.retentionDays,
      this.options.daySeconds,
    );
    const retainUntil = new Date(Math.max(record.retainUntil.getTime(), copyRetain.getTime()));
    const lockUntil =
      lockMode === 'none'
        ? null
        : new Date(
            Math.max(
              record.lockUntil?.getTime() ?? 0,
              retainUntil.getTime(),
              now.getTime() + LOCK_FLOOR_MS,
            ),
          );
    const lock = lockUntil === null ? null : s3Lock(lockMode, lockUntil);

    const tenantKey = await this.options.keys.version(org, record.keyVersion);
    const dek = unwrapRecordKey(tenantKey.key, record.wrappedDek, {
      organizationId: org,
      messagePublicId: record.messagePublicId,
      captureId: objects.captureId,
      keyVersion: record.keyVersion,
    });
    const captureId = uuidv7(now.getTime());
    const written: StoredVersion[] = [];
    try {
      // 1. The content variant (a differing body), under the record's DEK.
      let variant: ArchiveMergedCopy['eml'] = null;
      if (args.content === 'variant') {
        const emlKey = archiveObjectKey({
          organizationId: org,
          receivedAt: m.receivedAt,
          messagePublicId: m.publicId,
          captureId,
          kind: 'eml',
        });
        const up = await this.uploadEml({
          sourceKey: args.sourceKey,
          expectedSha256: m.emlSha256,
          dek,
          organizationId: org,
          subjectId: m.publicId,
          key: emlKey,
          lock,
        });
        written.push(up.stored);
        if (lock) this.options.metrics.objectLock.inc({ op: 'upload', result: 'ok' });
        variant = {
          key: emlKey,
          versionId: up.stored.versionId,
          sha256: up.summary.ciphertextSha256,
          bytes: up.summary.ciphertextBytes,
        };
      }

      // 2. The merged copy's journal object (its envelope, intake block or gateway facts).
      const bodies = await readBodies(
        storage,
        org,
        args.inputs.parse,
        this.options.previewPartMaxBytes,
      );
      const journal = buildJournal({
        facts,
        inputs: args.inputs,
        bodies,
        captureId,
        capturedAt: now,
        category: args.category,
        sources: args.sources,
        policyRuleRef: args.intent.policyRuleRef,
        settingsGeneration: args.ctx.generation,
        intake: args.intake,
        mergedFrom: {
          recordMessageId: record.messagePublicId,
          recordReceivedAt: record.receivedAt.toISOString(),
          mergedAt: now.toISOString(),
          source,
          contentVariant: variant !== null,
        },
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

      // 3. A gateway copy is authoritative for the security outcome of a record without one.
      const authoritative = source === 'gateway' && !record.sourceGateway;
      const scansAdded: ArchiveRecordObjects['scans'] = [];
      const linksAdded: ArchiveScanRounds = [];
      let rows: Awaited<ReturnType<FactsReader['roundRows']>> | null = null;
      const latest = args.latest;
      if (
        authoritative &&
        latest !== null &&
        links.length < MAX_SCAN_LINKS_PER_RECORD &&
        !links.some(
          (l) =>
            l.round > latest.round || (l.round === latest.round && l.revision >= latest.revision),
        )
      ) {
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
          subjectId: record.messagePublicId,
        });
        written.push({ key: snap.ref.key, versionId: snap.ref.versionId });
        scansAdded.push(snap.ref);
        linksAdded.push(snap.link);
        rows = snap.rows;
      }

      // 4. Every recorded version keeps the record's (possibly longer) lock.
      if (lock !== null && (record.lockUntil === null || lock.until > record.lockUntil)) {
        for (const v of recordVersionsWithMerged(record)) {
          await storage.putRetention(storage.buckets.archive, v.key, v.versionId, lock);
          this.options.metrics.objectLock.inc({ op: 'extend', result: 'ok' });
        }
      }

      const entry: ArchiveMergedCopy = {
        messageId: m.publicId,
        receivedAt: m.receivedAt.toISOString(),
        source,
        journal: {
          key: journalKey,
          versionId: journalStored.versionId,
          sha256: journalEnc.summary.ciphertextSha256,
          bytes: journalEnc.summary.ciphertextBytes,
        },
        eml: variant,
      };
      const storedBytes =
        entry.journal.bytes + (variant?.bytes ?? 0) + scansAdded.reduce((s, x) => s + x.bytes, 0);
      const incoming = partiesOf(facts, args.intake);
      await this.options.faults?.beforeCommit?.();

      // 5. One writer transaction under the record and key locks.
      await this.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`
          SELECT id FROM email_archives
          WHERE id = ${record.id} AND received_at = ${record.receivedAt} FOR UPDATE`;
        const fresh = await tx.emailArchive.findUnique({
          where: { id_receivedAt: { id: record.id, receivedAt: record.receivedAt } },
        });
        const since = new Date(now.getTime() - dedupe.windowHours * 3_600_000);
        const locked = (await findCandidates(tx, org, args.key, since, true)).find(
          (c) => c.archiveId === record.id,
        );
        const redecided =
          locked === undefined
            ? null
            : decideMerge({
                candidate: locked,
                incoming: {
                  source,
                  direction: m.direction,
                  receivedAt: m.receivedAt,
                  bodySha256: args.bodySha256,
                },
                limits: dedupe,
                now,
              });
        if (
          fresh === null ||
          fresh.organizationId !== org ||
          fresh.status !== 'active' ||
          fresh.wrappedDek === null ||
          // A refresh or another merge changed what this attempt prepared (links, objects).
          fresh.mergedCount !== record.mergedCount ||
          freshScanCount(fresh.objects) !== objects.scans.length ||
          archiveScanRoundsSchema.parse(fresh.scanRounds).length !== links.length ||
          fresh.sourceGateway !== record.sourceGateway ||
          redecided === null ||
          redecided.action !== 'merge' ||
          redecided.content !== args.content
        ) {
          throw new CandidateChangedError();
        }
        const stored = archivePartiesSchema.safeParse(fresh.parties);
        const base: ArchiveParties = stored.success
          ? stored.data
          : { v: 1, from: fresh.envelopeFrom, headerFrom: fresh.headerFrom, recipients: [] };
        const primary: IngestSource =
          fresh.sourceJournalIntake && !fresh.sourceGateway ? 'journal_intake' : 'gateway';
        const merged = mergeParties(base, incoming, { aSource: primary, bSource: source });
        await tx.archiveRecordSource.create({
          data: {
            archiveReceivedAt: record.receivedAt,
            organizationId: org,
            archiveId: record.id,
            messageId: m.id,
            messageReceivedAt: m.receivedAt,
            messagePublicId: m.publicId,
            source,
            intakeSourceId: args.intake?.sourceInternalId ?? null,
            emlSha256: m.emlSha256.toLowerCase(),
            sizeBytes: m.sizeBytes,
            bodySha256: args.bodySha256.toLowerCase(),
            contentVariant: variant !== null,
            recipientsAdded: Math.min(merged.added, 65_535),
            mergedAt: now,
          },
          select: { id: true },
        });
        const freshObjects = archiveRecordObjectsSchema.parse(fresh.objects);
        const nextObjects: ArchiveRecordObjects = {
          ...freshObjects,
          scans: [...freshObjects.scans, ...scansAdded],
          merged: [...(freshObjects.merged ?? []), entry],
        };
        const updated = await tx.emailArchive.updateMany({
          where: {
            id: record.id,
            receivedAt: record.receivedAt,
            organizationId: org,
            status: 'active',
          },
          data: {
            sourceGateway: fresh.sourceGateway || source === 'gateway',
            sourceJournalIntake: fresh.sourceJournalIntake || source === 'journal_intake',
            intakeSourceId: fresh.intakeSourceId ?? args.intake?.sourceInternalId ?? null,
            parties: merged.parties,
            recipientCount: Math.min(merged.parties.recipients.length, 65_535),
            objects: nextObjects,
            retainUntil,
            ...(lockUntil !== null ? { lockUntil } : {}),
            mergedCount: { increment: 1 },
            storedBytes: fresh.storedBytes + BigInt(storedBytes),
            capturedByJournal: fresh.capturedByJournal || args.sources.journal,
            capturedByPolicy: fresh.capturedByPolicy || args.sources.policy,
            ...(authoritative
              ? {
                  messageState: m.status,
                  messageStateReason: m.statusReason?.slice(0, 64) ?? null,
                  finalVerdict: m.finalVerdict,
                  finalAction: m.finalAction,
                  riskScore: m.riskScore,
                  malicious: fresh.malicious || isMalicious(m, rows),
                  ...(linksAdded.length > 0 ? { scanRounds: [...links, ...linksAdded] } : {}),
                }
              : {}),
          },
        });
        if (updated.count !== 1) throw new CandidateChangedError();
        if (variant !== null) {
          await insertDedupeRow(tx, {
            organizationId: org,
            key: args.key,
            bodySha256: args.bodySha256,
            archiveId: record.id,
            archiveReceivedAt: record.receivedAt,
            source,
            now,
          });
        }
        const claimed = await tx.$executeRaw`
          UPDATE archive_capture_intents
          SET status = 'captured_open', category = ${args.category}, archive_id = ${record.id},
              archive_received_at = ${record.receivedAt}, merged = 1,
              captured_at = ${now}, next_check_at = ${args.recheckAt}, lease_until = NULL,
              last_error_code = NULL, settings_generation = ${args.ctx.generation},
              updated_at = NOW(3)
          WHERE id = ${args.intent.id} AND received_at = ${args.intent.receivedAt}
            AND lease_until = ${args.intent.leaseUntil}`;
        if (claimed !== 1) throw new LeaseLostError();
        await tx.archiveIndexQueue.create({
          data: {
            organizationId: org,
            messageId: record.messageId,
            receivedAt: record.receivedAt,
            messagePublicId: record.messagePublicId,
            op: 'upsert',
          },
          select: { id: true },
        });
      }, DEDUPE_TX);
      this.options.metrics.dedupe.inc({ result: variant !== null ? 'merged_variant' : 'merged' });
      this.options.metrics.captureBytes.inc(storedBytes);
      return {
        status: 'merged',
        archiveId: record.id,
        archiveReceivedAt: record.receivedAt,
        storedBytes,
        variant: variant !== null,
      };
    } catch (error) {
      if (error instanceof CandidateChangedError) {
        this.options.metrics.dedupe.inc({ result: 'candidate_changed' });
      }
      await this.discard(written, lockMode);
      if (isUniqueViolation(error)) return { status: 'lost_race' };
      throw error;
    } finally {
      dek.fill(0);
    }
  }

  /**
   * The body hash of the original (step 8.6 D7 step 1): one pass of the EML through the plaintext
   * SHA-256 check and the `BodyHasher`, without an upload.
   */
  private async hashEml(sourceKey: string, expectedSha256: string): Promise<string> {
    const storage = this.options.storage;
    let source: Readable;
    try {
      source = await storage.getStream(storage.buckets.mail, sourceKey);
    } catch (error) {
      if (isMissing(error)) throw new OriginalMissingError();
      throw error;
    }
    const verify = new Sha256Verify(expectedSha256);
    const hasher = new BodyHasher();
    const sink = new Writable({ write: (_chunk, _enc, cb) => cb() });
    try {
      await pipeline(source, verify, hasher, sink);
    } catch (error) {
      if (verify.mismatch) {
        this.options.metrics.integrityFailures.inc();
        throw new DeterministicCaptureError('integrity_mismatch');
      }
      throw error;
    }
    const digest = hasher.bodySha256;
    if (digest === null) throw new Error('body hash missing');
    return digest;
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
    /** Step 8.6: the body hash computed while the EML streams. */
    hasher?: BodyHasher;
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
      input.hasher
        ? pipeline(source, verify, input.hasher, encrypt, body)
        : pipeline(source, verify, encrypt, body),
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

/** Linked rounds/revisions per record (A7; the scheduler's `MAX_SCAN_LINKS`). */
const MAX_SCAN_LINKS_PER_RECORD = 16;

/**
 * Transactions that lock a dedupe key range (step 8.6 D7) run REPEATABLE READ: there the
 * `SELECT … FOR UPDATE` on `(organization_id, message_id_hash, header_fingerprint)` takes next-key
 * (gap) locks, so two captures of a key without rows serialize (one waits or loses a deadlock and
 * is retried as a merge). The server default (READ COMMITTED, ADR-0004) takes record locks only.
 */
const DEDUPE_TX = { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead };

const freshScanCount = (value: unknown): number => {
  const parsed = archiveRecordObjectsSchema.safeParse(value);
  return parsed.success ? parsed.data.scans.length : -1;
};

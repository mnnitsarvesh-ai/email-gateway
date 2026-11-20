import {
  type ArchiveParties,
  dedupeMessageIdHash,
  headerFingerprint,
  type IngestSource,
  type MergeCandidate,
} from '@email-gateway/archive';
import { Prisma } from '@email-gateway/database';
import { big, type Db } from '../shared/db';
import { isMissing } from '../storage/archive-storage';
import type { ArchiveStorage } from '../storage/archive-storage';
import { mergedCopiesOf } from '../storage/record-versions';
import type { JournalInputs } from './journal';
import type { MessageRow } from './facts';

/**
 * Cross-source dedupe of the capture executor (step 8.6 D7, ADR-0088): the key of a message
 * (`archive-dedupe/1` Message-ID hash + `archive-fingerprint/1` header fingerprint), the candidate
 * records of a key on the writer, and the merged-party refresh. Pure decisions live in
 * `@email-gateway/archive` (`decideMerge`, `mergeParties`).
 */

/** Most bytes of the stored EML read for its header block (a bounded Range GET). */
export const DEDUPE_HEADER_MAX_BYTES = 262_144;

/** Parse statuses whose attachment rows are complete enough for a fingerprint. */
const FINGERPRINT_PARSE_STATUSES: ReadonlySet<string> = new Set([
  'parsed',
  'parsed_with_defects',
  'parse_limit_exceeded',
]);

export interface DedupeKey {
  messageIdHash: string;
  fingerprint: string;
}

/** A candidate record of a key (the record must still be checked with `decideMerge`). */
export interface DedupeCandidate extends MergeCandidate {
  archiveId: bigint;
  archiveReceivedAt: Date;
  keyCreatedAt: Date;
  status: string;
  wrappedDek: boolean;
}

/** A retry of the intent: the candidate set of the key changed between the decision and the lock. */
export class CandidateChangedError extends Error {
  readonly code = 'dedupe_candidate_changed';
  constructor() {
    super('dedupe candidate changed');
    this.name = 'CandidateChangedError';
  }
}

/**
 * The header block of a message prefix: the bytes up to the first `CRLF CRLF` or `LF LF`
 * (separator excluded); null when the prefix holds no separator (header larger than the bound).
 */
export function headerBlockOf(prefix: Buffer): Buffer | null {
  const crlf = prefix.indexOf('\r\n\r\n');
  const lf = prefix.indexOf('\n\n');
  const ends = [crlf, lf].filter((i) => i >= 0);
  if (ends.length === 0) return null;
  return prefix.subarray(0, Math.min(...ends));
}

/**
 * The dedupe key of a captured message, or null (no dedupe: no complete parse, no header block
 * within `DEDUPE_HEADER_MAX_BYTES`, no usable Message-ID, Date or From, an attachment without a
 * valid hash). The header block is read from the stored EML in the mail bucket (organization-
 * prefixed key, checked by the caller); attachment hashes come from the parse rows.
 */
export async function dedupeKeyOf(
  storage: ArchiveStorage,
  m: Pick<MessageRow, 'organizationId' | 'emlObjectKey'>,
  inputs: Pick<JournalInputs, 'parse' | 'attachments'>,
  emlKey: string,
): Promise<DedupeKey | null> {
  if (inputs.parse === null || !FINGERPRINT_PARSE_STATUSES.has(inputs.parse.status)) return null;
  let prefix: Buffer;
  try {
    prefix = (await storage.readRange(storage.buckets.mail, emlKey, DEDUPE_HEADER_MAX_BYTES)).bytes;
  } catch (error) {
    // The capture itself reports a missing original (`lost`).
    if (isMissing(error)) return null;
    throw error;
  }
  const header = headerBlockOf(prefix);
  if (header === null) return null;
  const fp = headerFingerprint({
    headerBlock: header,
    attachmentSha256s: inputs.attachments.map((a) => a.sha256),
  });
  if (fp === null) return null;
  const messageIdHash = dedupeMessageIdHash(m.organizationId, fp.messageId);
  if (messageIdHash === null) return null;
  return { messageIdHash, fingerprint: fp.fingerprint };
}

interface KeyRow {
  archive_id: bigint | number;
  archive_received_at: Date;
  body_sha256: string;
  created_at: Date;
}

/**
 * The candidate records of a key, oldest first: every `archive_dedupe_keys` row of `(organization,
 * message_id_hash, header_fingerprint)` (with `lock`: `SELECT … FOR UPDATE`, whose next-key locks
 * serialize concurrent captures of one key), joined to its live record of the organization. A
 * record whose first row of the key is older than `since` (the merge window) is left out; its
 * bodies are every row of the key that names it (primary and variants).
 */
export async function findCandidates(
  db: Db,
  organizationId: bigint,
  key: DedupeKey,
  since: Date,
  lock: boolean,
): Promise<DedupeCandidate[]> {
  const rows = await db.$queryRaw<KeyRow[]>`
    SELECT archive_id, archive_received_at, body_sha256, created_at
    FROM archive_dedupe_keys
    WHERE organization_id = ${organizationId} AND message_id_hash = ${key.messageIdHash}
      AND header_fingerprint = ${key.fingerprint}
    ORDER BY created_at, id
    ${lock ? Prisma.sql`FOR UPDATE` : Prisma.empty}`;
  if (rows.length === 0) return [];
  const byRecord = new Map<string, { id: bigint; at: Date; first: Date; bodies: string[] }>();
  for (const r of rows) {
    const id = big(r.archive_id);
    const k = `${id.toString()}:${r.archive_received_at.getTime()}`;
    const entry = byRecord.get(k) ?? {
      id,
      at: r.archive_received_at,
      first: r.created_at,
      bodies: [],
    };
    if (r.created_at < entry.first) entry.first = r.created_at;
    entry.bodies.push(r.body_sha256.toLowerCase());
    byRecord.set(k, entry);
  }
  const fresh = [...byRecord.values()].filter((e) => e.first >= since);
  if (fresh.length === 0) return [];
  const records = await db.emailArchive.findMany({
    where: {
      organizationId,
      OR: fresh.map((e) => ({ id: e.id, receivedAt: e.at })),
    },
    select: {
      id: true,
      receivedAt: true,
      organizationId: true,
      status: true,
      direction: true,
      sourceGateway: true,
      sourceJournalIntake: true,
      mergedCount: true,
      objects: true,
      wrappedDek: true,
    },
  });
  const out: DedupeCandidate[] = [];
  for (const e of fresh) {
    const r = records.find((x) => x.id === e.id && x.receivedAt.getTime() === e.at.getTime());
    if (r === undefined || r.organizationId !== organizationId) continue;
    const merged = mergedCopiesOf(r.objects);
    out.push({
      archiveId: r.id,
      archiveReceivedAt: r.receivedAt,
      direction: r.direction,
      receivedAt: r.receivedAt,
      keyCreatedAt: e.first,
      status: r.status,
      wrappedDek: r.wrappedDek !== null,
      hasGateway: r.sourceGateway,
      hasIntake: r.sourceJournalIntake,
      bodySha256s: [...new Set(e.bodies)],
      contentVariants: merged.filter((c) => c.eml !== null).length,
      mergedCopies: Math.max(r.mergedCount, merged.length),
    });
  }
  return out.sort(
    (a, b) =>
      a.keyCreatedAt.getTime() - b.keyCreatedAt.getTime() ||
      (a.archiveId < b.archiveId ? -1 : a.archiveId > b.archiveId ? 1 : 0),
  );
}

/** One `archive_dedupe_keys` row (a record's primary body or a stored content variant). */
export async function insertDedupeRow(
  db: Db,
  row: {
    organizationId: bigint;
    key: DedupeKey;
    bodySha256: string;
    archiveId: bigint;
    archiveReceivedAt: Date;
    source: IngestSource;
    now: Date;
  },
): Promise<void> {
  await db.archiveDedupeKey.create({
    data: {
      organizationId: row.organizationId,
      messageIdHash: row.key.messageIdHash,
      headerFingerprint: row.key.fingerprint,
      bodySha256: row.bodySha256.toLowerCase(),
      archiveId: row.archiveId,
      archiveReceivedAt: row.archiveReceivedAt,
      hasGateway: row.source === 'gateway',
      hasIntake: row.source === 'journal_intake',
      createdAt: row.now,
    },
    select: { id: true },
  });
}

/**
 * The parties of a record after the outcome refresh of one of its copies (step 8.6 D7): the copy's
 * fresh parties are matched by address into the stored (merged) parties. A gateway copy is
 * authoritative for the facts of its recipients (direction, status, final action); an intake copy
 * only fills unknown directions and missing fields. Recipients the copy adds are appended. The
 * stored order and every other copy's recipients are kept.
 */
export function refreshMergedParties(
  stored: ArchiveParties,
  fresh: ArchiveParties,
  freshSource: IngestSource,
  max = 65_535,
): ArchiveParties {
  const recipients = stored.recipients.map((r) => ({ ...r }));
  const index = new Map<string, number>();
  recipients.forEach((r, i) => {
    const k = r.address.trim().toLowerCase();
    if (!index.has(k)) index.set(k, i);
  });
  let nextSeq = recipients.reduce((m, r) => Math.max(m, r.seq + 1), 0);
  for (const r of fresh.recipients) {
    const k = r.address.trim().toLowerCase();
    const at = index.get(k);
    if (at === undefined) {
      if (recipients.length >= max || nextSeq > 65_535) continue;
      const added = { ...r, seq: nextSeq++, sources: [freshSource] };
      index.set(k, recipients.length);
      recipients.push(added);
      continue;
    }
    const current = recipients[at]!;
    const sources: IngestSource[] = [...new Set([...(current.sources ?? []), freshSource])].sort();
    recipients[at] =
      freshSource === 'gateway'
        ? {
            ...current,
            direction: r.direction ?? current.direction,
            status: r.status,
            finalAction: r.finalAction,
            ...(current.field === undefined && r.field !== undefined ? { field: r.field } : {}),
            ...(current.sources !== undefined ? { sources } : {}),
          }
        : {
            ...current,
            direction: current.direction ?? r.direction,
            ...(current.field === undefined && r.field !== undefined ? { field: r.field } : {}),
            ...(current.sources !== undefined ? { sources } : {}),
          };
  }
  return {
    v: 1,
    from: stored.from !== '' ? stored.from : fresh.from,
    headerFrom: stored.headerFrom ?? fresh.headerFrom,
    recipients,
  };
}

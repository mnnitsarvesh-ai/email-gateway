import {
  ARCHIVE_CATEGORIES,
  ARCHIVE_RECORD_STATUSES,
  type ArchiveParties,
  INGEST_SOURCES,
  archivePartiesSchema,
  archiveScanRoundsSchema,
  MESSAGE_ACTIONS,
  MESSAGE_DIRECTIONS,
  MESSAGE_VERDICTS,
  normalizeAddress,
  OBJECT_LOCK_MODES,
} from '@email-gateway/archive';
import { Prisma } from '@email-gateway/database';
import { maskAddress } from '../../messages/domain/sensitive-masking';
import type {
  ArchiveKeyView,
  ArchiveMessageView,
  RetentionPolicyView,
} from '../dto/archive.schemas';
import type { EngineResultRow } from '../../messages/repositories/message-scans-read.repository';
import type { KeyRow, PolicyRow } from '../repositories/archive-config.repository';
import type { RecordRow } from '../repositories/archive-records.repository';
import type { ArchiveSearchSource } from '../services/archive-search.client';

/**
 * Pure mappers of the archive views (step 8.1 A17, A19; ADR-0062 masking): every recipient
 * address is masked with `maskAddress` and every subject is `null` + `subjectMasked: true`,
 * whoever calls. Sender-side values and attachment names stay in clear (the open ADR-0062
 * question applies equally). Values that do not belong to the documented enums are dropped to
 * null rather than passed through.
 */

const frozenDecimal = (value: unknown): Prisma.Decimal | null => {
  if (value === null || value === undefined) return null;
  if (Prisma.Decimal.isDecimal(value)) return value;
  if (typeof value === 'string' || typeof value === 'number') {
    try {
      return new Prisma.Decimal(value);
    } catch {
      return null;
    }
  }
  return null;
};

/**
 * The frozen `scan_engine_results` rows of an `archive-scan/1` snapshot as the live scans mapper
 * reads them. The archive-worker freezes `score` / `required_score` (`DECIMAL(8,3)`) as their exact
 * decimal strings because the tagged codec does not carry `Decimal` (WP3 deviation D2); they are
 * restored to `Prisma.Decimal` here, since the mapper calls `.toNumber()`. A value that is not a
 * decimal is shown as `null`, never passed through raw.
 */
export function engineRowsOfSnapshot(rows: unknown): EngineResultRow[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((row: Record<string, unknown>) => ({
    ...row,
    score: frozenDecimal(row.score),
    requiredScore: frozenDecimal(row.requiredScore),
  })) as unknown as EngineResultRow[];
}

/** Recipients listed in a list item (the detail lists up to `DETAIL_RECIPIENTS`). */
export const LIST_RECIPIENTS = 20;
export const DETAIL_RECIPIENTS = 500;

const iso = (d: Date | null | undefined): string | null => (d ? d.toISOString() : null);

const oneOf = <T extends string>(values: readonly T[], value: unknown): T | null =>
  typeof value === 'string' && (values as readonly string[]).includes(value) ? (value as T) : null;

const list = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((v): v is string => typeof v === 'string')
    : typeof value === 'string'
      ? [value]
      : [];

/** The parties JSON of a record (`archive-parties/1`); unparsable → empty (never raw). */
export function partiesOf(
  record: Pick<RecordRow, 'parties' | 'envelopeFrom' | 'headerFrom'>,
): ArchiveParties {
  const parsed = archivePartiesSchema.safeParse(record.parties);
  if (parsed.success) return parsed.data;
  return { v: 1, from: record.envelopeFrom, headerFrom: record.headerFrom, recipients: [] };
}

/** The linked rounds of a record (`scan_rounds`). */
export function roundsOf(record: Pick<RecordRow, 'scanRounds'>) {
  const parsed = archiveScanRoundsSchema.safeParse(record.scanRounds);
  return parsed.success ? parsed.data : [];
}

/** `journal` / `policy` sources of a record. */
export function sourcesOf(record: Pick<RecordRow, 'capturedByJournal' | 'capturedByPolicy'>) {
  return [
    ...(record.capturedByJournal ? (['journal'] as const) : []),
    ...(record.capturedByPolicy ? (['policy'] as const) : []),
  ];
}

/** Step 8.6: the copy sources of a record (`gateway`, `journal_intake`). */
export function ingestSourcesOf(record: Pick<RecordRow, 'sourceGateway' | 'sourceJournalIntake'>) {
  return [
    ...(record.sourceGateway ? (['gateway'] as const) : []),
    ...(record.sourceJournalIntake ? (['journal_intake'] as const) : []),
  ];
}

/** The facts a legal hold matcher tests, from the record (writer or replica). */
export function holdFactsOf(record: RecordRow) {
  const parties = partiesOf(record);
  return {
    receivedAt: record.receivedAt,
    direction: record.direction,
    recipientDirections: [...new Set(parties.recipients.map((r) => r.direction))],
    senderAddresses: [record.envelopeFrom, record.headerFrom ?? '']
      .map((a) => normalizeAddress(a))
      .filter((a): a is string => a !== null),
    recipientAddresses: parties.recipients
      .map((r) => normalizeAddress(r.address))
      .filter((a): a is string => a !== null),
  };
}

/** The masked list item of a MySQL record (case search hits, detail base). */
export function messageViewOfRecord(record: RecordRow): ArchiveMessageView {
  const parties = partiesOf(record);
  const recipients = parties.recipients.map((r) => maskAddress(r.address));
  return {
    messageId: record.messagePublicId,
    receivedAt: record.receivedAt.toISOString(),
    capturedAt: iso(record.archivedAt),
    direction: record.direction,
    category: record.category,
    sources: sourcesOf(record),
    ingestSources: ingestSourcesOf(record),
    status: record.status,
    envelopeFrom: record.envelopeFrom,
    headerFrom: normalizeAddress(record.headerFrom),
    recipients: recipients.slice(0, LIST_RECIPIENTS),
    recipientsTruncated: recipients.length > LIST_RECIPIENTS,
    subject: null,
    subjectMasked: true,
    sizeBytes: record.sizeBytes,
    attachmentCount: record.attachmentCount,
    attachmentNames: [],
    verdict: record.finalVerdict,
    finalAction: record.finalAction,
    riskScore: record.riskScore,
    malicious: record.malicious,
    retainUntil: record.retainUntil.toISOString(),
    legalHold: record.legalHold,
    lockMode: record.lockMode,
  };
}

/** The masked list item of an index document (`GET /archive/messages`). */
export function messageViewOfSource(source: ArchiveSearchSource): ArchiveMessageView | null {
  const messageId = source.message_id;
  const receivedAt = source.received_at;
  const direction = oneOf(MESSAGE_DIRECTIONS, source.direction);
  const category = oneOf(ARCHIVE_CATEGORIES, source.category);
  const status = oneOf(ARCHIVE_RECORD_STATUSES, source.status);
  if (!messageId || !receivedAt || !direction || !category || !status) return null;
  const recipients = list(source.recipients).map(maskAddress);
  const sources = list(source.sources).filter(
    (s): s is 'journal' | 'policy' => s === 'journal' || s === 'policy',
  );
  // Step 8.6: documents indexed before mapping revision 2 have no `ingest_sources` (gateway).
  const ingest =
    source.ingest_sources === undefined
      ? (['gateway'] as const)
      : INGEST_SOURCES.filter((s) => list(source.ingest_sources).includes(s));
  return {
    messageId,
    receivedAt: new Date(receivedAt).toISOString(),
    capturedAt: source.captured_at ? new Date(source.captured_at).toISOString() : null,
    direction,
    category,
    sources,
    ingestSources: [...ingest],
    status,
    envelopeFrom: source.envelope_from ?? '',
    headerFrom: source.header_from ?? null,
    recipients: recipients.slice(0, LIST_RECIPIENTS),
    recipientsTruncated: recipients.length > LIST_RECIPIENTS,
    subject: null,
    subjectMasked: true,
    sizeBytes: typeof source.size_bytes === 'number' ? source.size_bytes : 0,
    attachmentCount: typeof source.attachment_count === 'number' ? source.attachment_count : 0,
    attachmentNames: list(source.attachment_names),
    verdict: oneOf(MESSAGE_VERDICTS, source.verdict),
    finalAction: oneOf(MESSAGE_ACTIONS, source.final_action),
    riskScore: typeof source.risk_score === 'number' ? source.risk_score : null,
    malicious: source.malicious === true,
    retainUntil: source.retain_until ? new Date(source.retain_until).toISOString() : null,
    legalHold: source.legal_hold === true,
    lockMode: oneOf(OBJECT_LOCK_MODES, source.lock_mode) ?? 'none',
  };
}

export function policyView(row: PolicyRow, defaultPolicyId: bigint | null): RetentionPolicyView {
  return {
    id: row.publicId,
    name: row.name,
    retentionDays: row.retentionDays,
    onExpiry: row.onExpiry,
    priority: row.priority,
    criteria:
      row.criteria !== null && typeof row.criteria === 'object' && !Array.isArray(row.criteria)
        ? row.criteria
        : {},
    isDefault: defaultPolicyId !== null && row.id === defaultPolicyId,
    rowVersion: row.rowVersion,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function keyView(row: KeyRow): ArchiveKeyView {
  return {
    id: row.publicId,
    version: row.version,
    status: row.status,
    rootKeyId: row.rootKeyId,
    algorithm: row.algorithm,
    rotationReason: row.rotationReason,
    createdBy: row.createdByPublicId,
    createdAt: row.createdAt.toISOString(),
    activatedAt: iso(row.activatedAt),
    retiredAt: iso(row.retiredAt),
    destroyedAt: iso(row.destroyedAt),
  };
}

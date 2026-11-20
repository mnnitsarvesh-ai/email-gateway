import { domainOf, normalizeAddress } from '../capture/eligibility';
import { archivePartiesSchema, ArchiveDocumentError } from '../documents';
import { type NumericId } from '../ids';
import type {
  ArchiveCategory,
  ArchiveRecordStatus,
  IngestSource,
  MessageDirection,
  ObjectLockMode,
} from '../vocabulary';
import { organizationTerm, yearlyIndexName } from './names';

/**
 * The index document of one archive record (§4.3, A16): metadata only, built from the current
 * MySQL row (and, optionally, facts the worker read from the record's own objects). Only the
 * fields of the template are emitted — never a body, a header value other than the subject and
 * addresses, an attachment's content or a URL.
 */

/** The `email_archives` columns the document reads. */
export interface ArchiveIndexRecord {
  organizationId: NumericId;
  messagePublicId: string;
  receivedAt: Date;
  /** `archived_at` (captured at). */
  archivedAt: Date;
  direction: MessageDirection;
  category: ArchiveCategory;
  capturedByJournal: boolean;
  capturedByPolicy: boolean;
  status: ArchiveRecordStatus;
  envelopeFrom: string;
  headerFrom: string | null;
  /** `archive-parties/1`. */
  parties: unknown;
  subject: string | null;
  internetMessageId: string | null;
  sizeBytes: number | bigint;
  attachmentCount: number;
  finalVerdict: string | null;
  finalAction: string | null;
  riskScore: number | null;
  malicious: boolean;
  retainUntil: Date | null;
  legalHold: boolean;
  lockMode: ObjectLockMode;
  /** Step 8.6 `email_archives.source_gateway` (undefined = true, the column default). */
  sourceGateway?: boolean;
  /** Step 8.6 `email_archives.source_journal_intake` (undefined = false). */
  sourceJournalIntake?: boolean;
}

/** Facts from the record's journal object and latest scan snapshot (optional). */
export interface ArchiveIndexExtraFacts {
  attachmentNames?: readonly (string | null)[];
  attachmentSha256s?: readonly (string | null)[];
  dlpMatched?: boolean | null;
  spf?: string | null;
  dkim?: string | null;
  dmarc?: string | null;
}

export interface ArchiveSearchDocument {
  org_id: string;
  message_id: string;
  received_at: string;
  captured_at: string;
  direction: MessageDirection;
  category: ArchiveCategory;
  sources: ('journal' | 'policy')[];
  status: ArchiveRecordStatus;
  envelope_from: string | null;
  header_from: string | null;
  sender_domain: string[];
  recipients: string[];
  recipient_domains: string[];
  subject: string | null;
  message_id_key: string | null;
  size_bytes: number;
  attachment_count: number;
  attachment_names: string[];
  attachment_sha256: string[];
  verdict: string | null;
  final_action: string | null;
  risk_score: number | null;
  malicious: boolean;
  dlp_matched: boolean;
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  retain_until: string | null;
  legal_hold: boolean;
  lock_mode: ObjectLockMode;
  indexed_at: string;
  /** Step 8.6: the copies merged into the record. */
  ingest_sources: IngestSource[];
}

/** The Message-ID search key: trimmed, angle brackets removed, lower-case; null when empty. */
export function messageIdKey(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const v = value
    .trim()
    .replace(/^<(.*)>$/, '$1')
    .trim()
    .toLowerCase();
  return v === '' ? null : v.slice(0, 998);
}

const uniq = (values: readonly (string | null | undefined)[]): string[] => [
  ...new Set(values.filter((v): v is string => typeof v === 'string' && v !== '')),
];

const resultKeyword = (value: string | null | undefined): string | null =>
  typeof value === 'string' && /^[a-z_]{1,32}$/.test(value) ? value : null;

export interface BuiltArchiveSearchDocument {
  /** The yearly index of `received_at`. */
  index: string;
  /** `_id` = message public id. */
  id: string;
  /** Custom routing = organization id. */
  routing: string;
  document: ArchiveSearchDocument;
}

export function buildArchiveSearchDocument(
  record: ArchiveIndexRecord,
  options: { prefix: string; now: Date; version?: number; extra?: ArchiveIndexExtraFacts },
): BuiltArchiveSearchDocument {
  const parties = archivePartiesSchema.safeParse(record.parties);
  if (!parties.success) throw new ArchiveDocumentError('archive-parties/1');
  const org = organizationTerm(record.organizationId);
  const envelopeFrom = normalizeAddress(record.envelopeFrom);
  const headerFrom = normalizeAddress(record.headerFrom);
  const recipients = uniq(parties.data.recipients.map((r) => normalizeAddress(r.address)));
  const extra = options.extra ?? {};
  const size = Number(record.sizeBytes);
  const document: ArchiveSearchDocument = {
    org_id: org,
    message_id: record.messagePublicId,
    received_at: record.receivedAt.toISOString(),
    captured_at: record.archivedAt.toISOString(),
    direction: record.direction,
    category: record.category,
    sources: [
      ...(record.capturedByJournal ? (['journal'] as const) : []),
      ...(record.capturedByPolicy ? (['policy'] as const) : []),
    ],
    status: record.status,
    envelope_from: envelopeFrom,
    header_from: headerFrom,
    sender_domain: uniq([domainOf(envelopeFrom), domainOf(headerFrom)]),
    recipients,
    recipient_domains: uniq(recipients.map((r) => domainOf(r))),
    subject: record.subject,
    message_id_key: messageIdKey(record.internetMessageId),
    size_bytes: Number.isFinite(size) ? size : 0,
    attachment_count: record.attachmentCount,
    attachment_names: uniq(extra.attachmentNames ?? []).map((n) => n.slice(0, 1024)),
    attachment_sha256: uniq(
      (extra.attachmentSha256s ?? []).map((h) =>
        typeof h === 'string' && /^[0-9a-fA-F]{64}$/.test(h) ? h.toLowerCase() : null,
      ),
    ),
    verdict: record.finalVerdict,
    final_action: record.finalAction,
    risk_score: record.riskScore,
    malicious: record.malicious,
    dlp_matched: extra.dlpMatched === true,
    spf: resultKeyword(extra.spf),
    dkim: resultKeyword(extra.dkim),
    dmarc: resultKeyword(extra.dmarc),
    retain_until: record.retainUntil?.toISOString() ?? null,
    legal_hold: record.legalHold,
    lock_mode: record.lockMode,
    indexed_at: options.now.toISOString(),
    ingest_sources: [
      ...(record.sourceGateway !== false ? (['gateway'] as const) : []),
      ...(record.sourceJournalIntake === true ? (['journal_intake'] as const) : []),
    ],
  };
  return {
    index: yearlyIndexName(options.prefix, record.receivedAt, options.version ?? 1),
    id: record.messagePublicId,
    routing: org,
    document,
  };
}

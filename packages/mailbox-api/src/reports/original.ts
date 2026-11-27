/**
 * The reported original and report triage helpers (step API-3, design note 37 C10.1, C10.2,
 * C11.2, C11.3): the `api-report-original/1` document (hashes, normalized keys, sender and date;
 * never bodies), the group key of reports of the same original, the automatic pre-triage
 * assessment and the reporter checks. Pure; the per-reporter rate limit stays in the worker.
 */
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { copyMessageIdHash } from '../identifiers';
import { canonicalJson } from '../remediation/policy';
import type { MessageVerdict, RiskLevel } from '../remediation/vocabulary';
import { subjectKeyOf } from '../clawback/search-keys';
import type { ReportExtraction, ReportedMessageHeaders } from './extract';
import type { ReportAssessment, ReportIdentification, ReportRejectReason } from './vocabulary';

export const REPORT_ORIGINAL_SCHEMA_VERSION = 1;

/** Limits of `api-report-original/1` (C10.2). */
export const REPORT_ORIGINAL_LIMITS = Object.freeze({
  attachmentSha256: 20,
  urlSha256: 50,
  maxExtraOriginals: 200,
  subjectKeyMaxCodePoints: 128,
});

const HEX64 = /^[0-9a-f]{64}$/;
const hex64 = z.string().regex(HEX64);
const codePoints = (value: string): number => Array.from(value).length;

/** `api-report-original/1` (C10.2), strict. */
export const reportOriginalSchema = z.strictObject({
  v: z.literal(REPORT_ORIGINAL_SCHEMA_VERSION),
  /** `copyMessageIdHash(organizationId, Message-ID)`; null without a usable Message-ID. */
  messageIdHash: hex64.nullable(),
  /** The original's From addr-spec, lower case (untrusted). */
  sender: z.string().min(3).max(320).nullable(),
  /** The original's `subject_key` (C4.4 parity), 1..128 code points (untrusted). */
  subjectKey: z
    .string()
    .refine(
      (v) => codePoints(v) >= 1 && codePoints(v) <= REPORT_ORIGINAL_LIMITS.subjectKeyMaxCodePoints,
    )
    .nullable(),
  /** The original's Date (ISO), null when absent or unparseable. */
  date: z.iso.datetime({ offset: true }).nullable(),
  attachmentSha256: z.array(hex64).max(REPORT_ORIGINAL_LIMITS.attachmentSha256),
  urlSha256: z.array(hex64).max(REPORT_ORIGINAL_LIMITS.urlSha256),
  extraOriginals: z.number().int().min(0).max(REPORT_ORIGINAL_LIMITS.maxExtraOriginals),
});
export type ReportOriginal = z.infer<typeof reportOriginalSchema>;

const uniqueHex = (values: readonly string[], max: number): string[] => {
  const out: string[] = [];
  for (const v of values) {
    const lower = v.toLowerCase();
    if (HEX64.test(lower) && !out.includes(lower)) out.push(lower);
    if (out.length >= max) break;
  }
  return out;
};

export interface BuildReportOriginalInput {
  organizationId: bigint | number | string;
  /** A successful extraction (`attachment` or `inline`); other identifications have no original. */
  extraction: ReportExtraction;
  /**
   * Attachment hashes to use when the original is not attached (an inline forward): the report
   * message's own `email_attachments` rows (C10.2).
   */
  fallbackAttachmentSha256?: readonly string[];
  /** URL identity hashes from the report message's `message_urls` (filled by the caller). */
  urlSha256?: readonly string[];
}

function senderOf(headers: ReportedMessageHeaders): string | null {
  const from = headers.from?.trim().toLowerCase() ?? '';
  return from.length >= 3 && from.length <= 320 && from.includes('@') ? from : null;
}

/**
 * C10.2: the `api-report-original/1` document of an `attachment` or `inline` identification, or
 * null for `none`, `unsupported` and failures (the report row then stores `original = NULL`).
 */
export function buildReportOriginal(input: BuildReportOriginalInput): ReportOriginal | null {
  const x = input.extraction;
  if (!x.ok || (x.identification !== 'attachment' && x.identification !== 'inline')) return null;
  const subjectKey = x.headers.subject === null ? '' : subjectKeyOf(x.headers.subject);
  const attachments =
    x.identification === 'attachment' ? x.attachmentSha256 : (input.fallbackAttachmentSha256 ?? []);
  return {
    v: REPORT_ORIGINAL_SCHEMA_VERSION,
    messageIdHash: copyMessageIdHash(input.organizationId, x.headers.messageId),
    sender: senderOf(x.headers),
    subjectKey: subjectKey.length > 0 ? subjectKey : null,
    date: x.headers.date === null ? null : x.headers.date.toISOString(),
    attachmentSha256: uniqueHex(attachments, REPORT_ORIGINAL_LIMITS.attachmentSha256),
    urlSha256: uniqueHex(input.urlSha256 ?? [], REPORT_ORIGINAL_LIMITS.urlSha256),
    extraOriginals: Math.min(x.extraOriginals, REPORT_ORIGINAL_LIMITS.maxExtraOriginals),
  };
}

/** The `api_user_reports.identification` of an extraction (null for a failure). */
export function reportIdentificationOf(extraction: ReportExtraction): ReportIdentification | null {
  return extraction.ok ? extraction.identification : null;
}

/** Domain prefix of the canonical group key (C11.3). */
export const REPORT_GROUP_KEY_DOMAIN = 'api-report-group/1';

/**
 * C11.3 `group_key`: the original's Message-ID hash; else hex SHA-256 of the canonical
 * `{ v, sender, subjectKey, dateHour }` when sender, subject key and date are all known (the hour
 * of the date in UTC); else null (the report stands alone).
 */
export function reportGroupKey(original: ReportOriginal | null): string | null {
  if (original === null) return null;
  if (original.messageIdHash !== null) return original.messageIdHash;
  if (original.sender === null || original.subjectKey === null || original.date === null) {
    return null;
  }
  const date = new Date(original.date);
  if (Number.isNaN(date.getTime())) return null;
  const dateHour = `${date.toISOString().slice(0, 13)}:00:00.000Z`;
  return createHash('sha256')
    .update(
      canonicalJson({
        v: REPORT_GROUP_KEY_DOMAIN,
        sender: original.sender,
        subjectKey: original.subjectKey,
        dateHour,
      }),
      'utf8',
    )
    .digest('hex');
}

/** The scan facts of a report (the original's scan, else the report copy's). */
export interface ReportScanFacts {
  verdict: MessageVerdict | null;
  level: RiskLevel | null;
  hardBlocks: readonly string[];
}

/**
 * C11.2 (a hint; never acts): `malware`/`phishing` with level `critical` or a hard block →
 * `malicious`; other non-clean verdicts (`malware`/`phishing` below critical, `bec`,
 * `suspicious`, and `spam`/`bulk`/`dlp_violation`, which a user report should not hide as clean)
 * → `suspicious`; `clean` → `clean`; no scan or `unknown` → `unknown`.
 */
export function assessReport(scan: ReportScanFacts | null): ReportAssessment {
  if (scan === null || scan.verdict === null || scan.verdict === 'unknown') return 'unknown';
  if (scan.verdict === 'clean') return 'clean';
  if (
    (scan.verdict === 'malware' || scan.verdict === 'phishing') &&
    (scan.level === 'critical' || scan.hardBlocks.length > 0)
  ) {
    return 'malicious';
  }
  return 'suspicious';
}

export interface ReporterCheckInput {
  /** Header From addr-spec of the report (else the envelope sender); null when none. */
  reporterAddress: string | null;
  /** The organization's verified domains. */
  orgDomains: Iterable<string>;
  /** Addresses (primary and aliases) of the organization's report mailboxes. */
  reportMailboxAddresses: Iterable<string>;
  headers: { autoSubmitted: string | null; precedence: string | null };
}

export type ReporterCheck =
  | { ok: true }
  | {
      ok: false;
      reason: Extract<ReportRejectReason, 'external_reporter' | 'loop' | 'auto_submitted'>;
    };

const normDomain = (d: string): string => d.trim().replace(/\.$/, '').toLowerCase();

/**
 * C10.1 in order: a reporter not on an organization domain → `external_reporter`; a report
 * mailbox address → `loop`; `Auto-Submitted` other than `no`, or `Precedence: bulk|auto_reply` →
 * `auto_submitted`. The rate limit (`rate_limited`) is checked by the worker afterwards.
 */
export function reporterCheck(input: ReporterCheckInput): ReporterCheck {
  const address = input.reporterAddress?.trim().toLowerCase() ?? '';
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return { ok: false, reason: 'external_reporter' };
  const domains = new Set<string>();
  for (const d of input.orgDomains) domains.add(normDomain(d));
  if (!domains.has(normDomain(address.slice(at + 1)))) {
    return { ok: false, reason: 'external_reporter' };
  }
  for (const mailbox of input.reportMailboxAddresses) {
    if (mailbox.trim().toLowerCase() === address) return { ok: false, reason: 'loop' };
  }
  const auto = input.headers.autoSubmitted?.split(';')[0]?.trim().toLowerCase() ?? '';
  const precedence = input.headers.precedence?.trim().toLowerCase() ?? '';
  if ((auto.length > 0 && auto !== 'no') || precedence === 'bulk' || precedence === 'auto_reply') {
    return { ok: false, reason: 'auto_submitted' };
  }
  return { ok: true };
}

import { BadRequestException } from '@nestjs/common';
import {
  attachmentArchiveResultSchema,
  attachmentYaraResultSchema,
  ENGINE_CATALOG,
  fileTypeFamilySchema,
  fileTypeIdSchema,
  isAttachmentReasonCode,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import type {
  AttachmentScanView,
  ScanAttempt,
  ScanAuthView,
  ScanEngineResultView,
  ScanRoundView,
  ScanSymbol,
} from '../dto/message-scans.schemas';
import type {
  AttachmentPartRow,
  AttachmentResultRow,
  AuthResultRow,
  EngineResultRow,
  SandboxSubmissionRow,
  ScanRoundRow,
} from '../repositories/message-scans-read.repository';

/**
 * Pure mapping of the scan rows to the read API (step 4.1 S16) and its round cursor. Stored
 * JSON is parsed defensively: a malformed value is shown as empty, never passed through raw.
 */

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());
const decimal = (value: { toNumber(): number } | null): number | null =>
  value === null ? null : value.toNumber();

const stringList = z.array(z.string());
/** A JSON array of strings, or `[]` for anything else. */
export function stringArray(value: unknown): string[] {
  const parsed = stringList.safeParse(value);
  return parsed.success ? parsed.data : [];
}

const MAX_SYMBOLS = 200;
const symbolSchema = z.object({
  name: z.string().min(1).max(128),
  score: z.number().finite(),
  options: z.array(z.string().max(200)).max(5).default([]),
});

/** `evidence.signals` (S9) as symbols; invalid entries are skipped, at most 200. */
export function symbolsOf(evidence: unknown): ScanSymbol[] {
  if (evidence === null || typeof evidence !== 'object' || Array.isArray(evidence)) return [];
  const signals = (evidence as { signals?: unknown }).signals;
  if (!Array.isArray(signals)) return [];
  const out: ScanSymbol[] = [];
  for (const signal of signals) {
    const parsed = symbolSchema.safeParse(signal);
    if (parsed.success) out.push(parsed.data);
    if (out.length >= MAX_SYMBOLS) break;
  }
  return out;
}

const signatureSchema = z.object({
  domain: z.string(),
  result: z.enum(['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror']),
  selector: z.string().nullable().default(null),
});

export function authOf(row: AuthResultRow): ScanAuthView {
  const signatures = Array.isArray(row.dkimSignatures)
    ? row.dkimSignatures.flatMap((entry) => {
        const parsed = signatureSchema.safeParse(entry);
        return parsed.success ? [parsed.data] : [];
      })
    : [];
  return {
    spf: row.spf,
    spfDomain: row.spfDomain,
    dkim: row.dkim,
    dkimSignatures: signatures,
    dmarc: row.dmarc,
    dmarcPolicy: row.dmarcPolicy,
    dmarcDomain: row.dmarcDomain,
    arc: row.arc,
  };
}

/** Whole seconds (the `attachment` engine's timestamps, see `engineOf`). */
const toSecond = (value: Date): string =>
  new Date(Math.floor(value.getTime() / 1000) * 1000).toISOString();

function attemptOf(row: EngineResultRow, coarse: boolean): ScanAttempt {
  return {
    attempt: row.attempt,
    outcome: row.outcome,
    errorCode: row.errorCode,
    durationMs: coarse ? null : row.durationMs,
    at: coarse ? toSecond(row.completedAt) : row.completedAt.toISOString(),
  };
}

/**
 * One engine of a round: the final row as the result (if any), every row as an attempt. For the
 * `attachment` engine the durations are withheld and the times rounded down to the second: its
 * content cache is shared across organizations (A10), and a fast result would tell a tenant
 * that another organization received the same file. Operators keep the exact values in
 * `scan_engine_results` and the metrics.
 */
export function engineOf(engine: string, rows: readonly EngineResultRow[]): ScanEngineResultView {
  const sorted = [...rows].sort((a, b) => a.attempt - b.attempt);
  const final = sorted.find((row) => row.isFinal) ?? null;
  const coarse = engine === ATTACHMENT_ENGINE;
  const completedAt = (value: Date): string => (coarse ? toSecond(value) : value.toISOString());
  return {
    engine,
    final: final !== null,
    engineVersion: final?.engineVersion ?? sorted.at(-1)?.engineVersion ?? null,
    outcome: final?.outcome ?? null,
    score: final ? decimal(final.score) : null,
    requiredScore: final ? decimal(final.requiredScore) : null,
    action: final?.action ?? null,
    reasonCodes: final ? stringArray(final.reasonCodes) : [],
    symbols: final ? symbolsOf(final.evidence) : [],
    attempts: sorted.map((row) => attemptOf(row, coarse)),
    durationMs: coarse ? null : (final?.durationMs ?? null),
    settingsVersion: final?.settingsVersion ?? null,
    completedAt: final ? completedAt(final.completedAt) : null,
  };
}

/** The attachment engine's name (step 4.2 A1). */
export const ATTACHMENT_ENGINE = 'attachment';

/** The per-attachment rows of a page with the display metadata they are joined with. */
export interface AttachmentInputs {
  results: readonly AttachmentResultRow[];
  parts: readonly AttachmentPartRow[];
  submissions: readonly SandboxSubmissionRow[];
}

export const NO_ATTACHMENTS: AttachmentInputs = Object.freeze({
  results: [],
  parts: [],
  submissions: [],
});

/**
 * One `attachment_scan_results` row as the A16 view. Stored JSON (reason codes, YARA matches,
 * archive) is validated against the security-contracts schemas; a malformed value is shown as
 * empty/null, never passed through raw. `knownHash.family` is not stored per result (A18
 * stores the severity only), so it is null.
 */
export function attachmentOf(
  row: AttachmentResultRow,
  part: AttachmentPartRow | undefined,
  submission: SandboxSubmissionRow | undefined,
): AttachmentScanView {
  const detected = fileTypeIdSchema.safeParse(row.detectedType);
  const family = fileTypeFamilySchema.safeParse(row.typeFamily);
  const yara =
    row.yaraBundleId === null
      ? null
      : attachmentYaraResultSchema.safeParse({
          bundleId: row.yaraBundleId,
          matches: Array.isArray(row.yaraMatches) ? row.yaraMatches : [],
        });
  const archive =
    row.archive === null ? null : attachmentArchiveResultSchema.safeParse(row.archive);
  return {
    partIndex: row.partIndex,
    filename: part?.filename ?? null,
    declaredContentType: part?.declaredContentType ?? null,
    sha256: row.sha256,
    sizeBytes: row.sizeBytes,
    detectedType: detected.success ? detected.data : 'unknown',
    typeFamily: family.success ? family.data : 'other',
    typeMismatch: row.typeMismatch,
    verdict: row.verdict,
    reasonCodes: Array.isArray(row.reasonCodes)
      ? row.reasonCodes
          .filter((c): c is string => typeof c === 'string')
          .filter(isAttachmentReasonCode)
      : [],
    clamav:
      row.clamavEngineVersion === null || row.clamavDbVersion === null
        ? null
        : {
            signature: row.clamavSignature,
            engineVersion: row.clamavEngineVersion,
            dbVersion: row.clamavDbVersion,
          },
    yara: yara?.success ? yara.data : null,
    archive: archive?.success ? archive.data : null,
    knownHash:
      row.knownHashSeverity === null ? null : { severity: row.knownHashSeverity, family: null },
    // No `cache` / `durationMs`: they reveal the cross-tenant cache (AttachmentScanViewSchema).
    sandbox: submission
      ? { submissionId: submission.id.toString(), status: submission.status }
      : null,
  };
}

/** The attachments of one round (by part index). */
export function attachmentsOf(scanId: bigint, inputs: AttachmentInputs): AttachmentScanView[] {
  const parts = new Map(inputs.parts.map((p) => [p.partIndex, p]));
  const submissions = new Map(
    inputs.submissions
      .filter((s) => s.scanId === scanId)
      .map((s) => [s.attachmentId.toString(), s]),
  );
  return inputs.results
    .filter((row) => row.scanId === scanId)
    .sort((a, b) => a.partIndex - b.partIndex)
    .map((row) =>
      attachmentOf(row, parts.get(row.partIndex), submissions.get(row.attachmentId.toString())),
    );
}

const catalogRank = (engine: string): number => {
  const index = ENGINE_CATALOG.findIndex((entry) => entry.name === engine);
  return index === -1 ? ENGINE_CATALOG.length : index;
};
const byCatalog = (a: string, b: string): number =>
  catalogRank(a) - catalogRank(b) || (a < b ? -1 : a > b ? 1 : 0);

/**
 * A round with its engines (catalog order), the first engine's authentication results and, on
 * the `attachment` engine entry, its per-attachment results (step 4.2 A16).
 */
export function roundOf(
  scan: ScanRoundRow,
  engineRows: readonly EngineResultRow[],
  authRows: readonly AuthResultRow[],
  attachments: AttachmentInputs = NO_ATTACHMENTS,
): ScanRoundView {
  const byEngine = new Map<string, EngineResultRow[]>();
  for (const row of engineRows) {
    if (row.scanId !== scan.id) continue;
    const list = byEngine.get(row.engine) ?? [];
    list.push(row);
    byEngine.set(row.engine, list);
  }
  const auth = authRows
    .filter((row) => row.scanId === scan.id)
    .sort((a, b) => byCatalog(a.engine, b.engine))[0];
  return {
    round: scan.lifecycleRound,
    scanKind: scan.scanKind,
    status: scan.status,
    verdict: scan.scanVerdict,
    reasonCodes: stringArray(scan.reasonCodes),
    requiredEngines: stringArray(scan.requiredEngines),
    startedAt: iso(scan.startedAt),
    completedAt: iso(scan.completedAt),
    deadlineAt: iso(scan.deadlineAt),
    auth: auth ? authOf(auth) : null,
    engines: [...byEngine.keys()].sort(byCatalog).map((engine) => {
      const view = engineOf(engine, byEngine.get(engine)!);
      return engine === ATTACHMENT_ENGINE
        ? { ...view, attachments: attachmentsOf(scan.id, attachments) }
        : view;
    }),
  };
}

const CURSOR_PREFIX = 'r';

/** Scan cursor: the round of the last entry of the previous page (rounds are unique). */
export function encodeScanCursor(round: number): string {
  return Buffer.from(`${CURSOR_PREFIX}${round}`, 'utf8').toString('base64url');
}

export function decodeScanCursor(cursor: string): number {
  const decoded = Buffer.from(cursor, 'base64url').toString('utf8');
  const match = /^r(0|[1-9][0-9]{0,4})$/.exec(decoded);
  const round = match ? Number(match[1]) : NaN;
  if (!Number.isSafeInteger(round) || round > 65_535 || encodeScanCursor(round) !== cursor) {
    throw new BadRequestException(['cursor: Invalid cursor']);
  }
  return round;
}

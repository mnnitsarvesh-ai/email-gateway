import type { DlpExtraction, ExtractLimits, WalkSummary } from '@email-gateway/dlp/extract';
import {
  DLP_EXTRACT_FORMATS,
  DLP_EXTRACT_STATUSES,
  DLP_INDEX_PATH_PATTERN,
  DLP_NOT_EXTRACTED_REASONS,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import type { InspectionResult, InspectLimits } from '../../attachment/content';

/**
 * The DLP extractor's job limits and reply (step 4.5 D4), shared by the worker (pool, engine) and
 * the extractor child. Pure: no process API, no `@email-gateway/bec`.
 */

/** Limits of one `extract` job: the 4.2 walker's platform limits plus the extraction bounds. */
export interface DlpExtractJobLimits {
  walk: InspectLimits;
  extract: ExtractLimits;
}

const positive = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

/** Validates job limits received over IPC (the child refuses anything else). */
export function isExtractJobLimits(value: unknown): value is DlpExtractJobLimits {
  if (typeof value !== 'object' || value === null) return false;
  const { walk, extract } = value as Record<string, unknown>;
  if (typeof walk !== 'object' || walk === null) return false;
  if (typeof extract !== 'object' || extract === null) return false;
  const w = walk as Record<string, unknown>;
  const e = extract as Record<string, unknown>;
  return (
    [
      'archiveMaxDepth',
      'archiveMaxEntries',
      'maxEntryBytes',
      'maxDecompressedBytes',
      'maxCompressionRatio',
      'maxEntryFindings',
      'yaraTimeoutMs',
      'cpuSeconds',
      'maxRssMb',
    ].every((k) => positive(w[k])) &&
    ['maxTextChars', 'maxSegments', 'pdfMaxPages', 'maxTableColumns', 'maxXmlBytes'].every((k) =>
      positive(e[k]),
    )
  );
}

/**
 * The 4.2 inspection result of the shared walk (no-op YARA) → the walk summary of the extraction
 * session: encrypted entries, any archive limit, malformed containers, unsupported formats.
 */
export function walkSummaryOf(inspection: InspectionResult): WalkSummary {
  const codes = new Set<string>([...inspection.codes, ...inspection.limits]);
  const archive = inspection.archive;
  return {
    encrypted: codes.has('archive.encrypted') || (archive?.encrypted ?? false),
    limitReached: inspection.limits.some(
      (code) => code.startsWith('limit.') && code !== 'limit.yara_timeout',
    ),
    malformed: codes.has('archive.malformed') || (archive?.malformed ?? false),
    unsupported: codes.has('archive.unsupported_format') || archive?.supported === false,
  };
}

/** Segments per attachment (D4: ≤ 200). */
export const DLP_MAX_SEGMENTS = 200;
/** Table header cells kept (D4: ≤ 64). */
export const DLP_MAX_TABLE_COLUMNS = 64;

const segmentSchema = z.strictObject({
  path: z.union([
    z.literal('attachment'),
    z.string().max(96).regex(DLP_INDEX_PATH_PATTERN, 'Expected an index path'),
  ]),
  format: z.enum(DLP_EXTRACT_FORMATS),
  kind: z.enum(['text', 'table', 'html']),
  text: z.string(),
  headers: z.array(z.string()).max(DLP_MAX_TABLE_COLUMNS).optional(),
  truncated: z.boolean(),
});

/** The extractor's reply as the worker accepts it (bounded; anything else is a crash). */
export function extractionSchema(maxTextChars: number) {
  return z
    .strictObject({
      extractorVersion: z.literal('dlp-extract/1'),
      status: z.enum(DLP_EXTRACT_STATUSES),
      format: z.enum(DLP_EXTRACT_FORMATS),
      reasons: z.array(z.enum(DLP_NOT_EXTRACTED_REASONS)).max(DLP_NOT_EXTRACTED_REASONS.length),
      segments: z.array(segmentSchema).max(DLP_MAX_SEGMENTS),
      entriesVisited: z.number().int().min(0).max(1_000_000),
    })
    .refine((e) => e.segments.reduce((sum, s) => sum + s.text.length, 0) <= maxTextChars, {
      message: 'More text than the per-attachment limit',
    });
}

/** Parses a reply; undefined when it is not a bounded extraction (the pool reports a crash). */
export function parseExtraction(value: unknown, maxTextChars: number): DlpExtraction | undefined {
  const parsed = extractionSchema(maxTextChars).safeParse(value);
  return parsed.success ? parsed.data : undefined;
}

/** A definite "not extracted" result decided without a child (D4: not stored, cap, oversize). */
export function notExtracted(
  reason: DlpExtraction['reasons'][number],
  format: DlpExtraction['format'] = 'unsupported',
): DlpExtraction {
  return {
    extractorVersion: 'dlp-extract/1',
    status: 'not_extracted',
    format,
    reasons: [reason],
    segments: [],
    entriesVisited: 0,
  };
}

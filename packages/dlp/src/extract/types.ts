import type {
  DlpExtractFormat,
  DlpExtractStatus,
  DlpNotExtractedReason,
} from '@email-gateway/security-contracts';

/**
 * The attachment extraction contract of step 4.5 D4 (`dlp-extract/1`): what the DLP extractor
 * child returns per attachment. Bounded, JSON-serializable. Entries inside archives are
 * addressed by index path (`"2/0/5"`), never by name.
 */

export interface ExtractLimits {
  /** Text per attachment (`DLP_TEXT_MAX_CHARS_PER_PART`, 1 000 000 UTF-16 code units). */
  maxTextChars: number;
  /** Segments per attachment (200). */
  maxSegments: number;
  /** PDF pages read (`DLP_PDF_MAX_PAGES`, 200). */
  pdfMaxPages: number;
  /** Table columns kept as headers (64). */
  maxTableColumns: number;
  /** XML part size accepted by the tokenizer (bytes; the walker's entry limit applies first). */
  maxXmlBytes: number;
}

export const DEFAULT_EXTRACT_LIMITS: Readonly<ExtractLimits> = Object.freeze({
  maxTextChars: 1_000_000,
  maxSegments: 200,
  pdfMaxPages: 200,
  maxTableColumns: 64,
  maxXmlBytes: 26_214_400,
});

/** What the worker knows about the attachment (names stay in memory, never in the result). */
export interface ExtractHint {
  declaredContentType: string | null;
  /** Lower-case filename extension without the dot (`csv`), or null. */
  filenameExt: string | null;
}

export type SegmentKind = 'text' | 'table' | 'html';

export interface DlpExtractedSegment {
  /** `attachment` for the attachment itself, else the walker's index path. */
  path: string;
  format: DlpExtractFormat;
  kind: SegmentKind;
  text: string;
  /** Table segments: the first row (≤ 64 cells). */
  headers?: string[];
  truncated: boolean;
}

export interface DlpExtraction {
  extractorVersion: 'dlp-extract/1';
  status: DlpExtractStatus;
  format: DlpExtractFormat;
  reasons: DlpNotExtractedReason[];
  segments: DlpExtractedSegment[];
  entriesVisited: number;
}

/** Summary of the shared walker's run over a container (from the 4.2 inspection result). */
export interface WalkSummary {
  /** Encrypted entries were met (they are never visited). */
  encrypted: boolean;
  /** An archive limit stopped or skipped part of the walk (entries, size, ratio, depth). */
  limitReached: boolean;
  /** A container or entry was malformed / truncated. */
  malformed: boolean;
  /** An unsupported container format (7z, rar, cab, bzip2, xz) was met. */
  unsupported: boolean;
}

export const EMPTY_WALK: Readonly<WalkSummary> = Object.freeze({
  encrypted: false,
  limitReached: false,
  malformed: false,
  unsupported: false,
});

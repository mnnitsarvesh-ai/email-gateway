/** Extraction types (docs/plan/steps/11-url-protection.md U4). */

export const EXTRACTOR_VERSION = 'url-extract/1';

/** Where an occurrence was found; also the `source` label of `scan_url_extracted_total`. */
export const URL_SOURCES = [
  'text',
  'html_href',
  'html_src',
  'form_action',
  'meta_refresh',
  'srcset',
  'attachment',
] as const;
export type UrlSource = (typeof URL_SOURCES)[number];

/** Per-occurrence extraction codes (U4 obfuscations); normalization adds its own (U5). */
export type ExtractionFlag =
  | 'url.entity_obfuscation'
  | 'url.control_chars'
  | 'url.text_mismatch'
  | 'url.in_attachment'
  | 'url.charset_guess';

/** Message-level codes (counted per message, no URL rows). */
export const MESSAGE_CODES = [
  'url.script_scheme',
  'url.data_uri',
  'url.unsafe_scheme',
  'url.invalid',
  'limit.url_count',
] as const;
export type MessageCode = (typeof MESSAGE_CODES)[number];

export interface Range {
  /** Offsets in the input string (UTF-16 code units), end exclusive. */
  start: number;
  end: number;
}

export interface UrlOccurrence {
  /** The URL candidate as found (entity-decoded attribute value or the text match). */
  raw: string;
  /** The absolute candidate after base resolution and `www.` → `http://` (input of U5). */
  candidate: string;
  source: Exclude<UrlSource, 'attachment'>;
  /** Element and attribute (HTML only). */
  element: string | null;
  attribute: string | null;
  /**
   * HTML: the whole attribute (`name=value` with quotes) in the source; text: the URL match.
   * The rewriter replaces exactly this range.
   */
  range: Range;
  flags: ExtractionFlag[];
  /** Visible text of an `a` element (kept in memory only, never stored). */
  anchorText: string | null;
  /** `a[href]`/`area[href]` (HTML) or a text URL: what U11 may rewrite. */
  rewritable: boolean;
}

export interface ExtractionLimits {
  /** Occurrences scanned before `limit.url_count` (URL_MAX_OCCURRENCES). */
  maxOccurrences: number;
}

export interface PartExtraction {
  occurrences: UrlOccurrence[];
  messageCodes: Partial<Record<MessageCode, number>>;
  /** More than `maxOccurrences` candidates in this part. */
  limitHit: boolean;
}

export const DEFAULT_EXTRACTION_LIMITS: ExtractionLimits = { maxOccurrences: 5000 };

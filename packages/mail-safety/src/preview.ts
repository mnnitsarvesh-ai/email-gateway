import { sanitizeDisplayText } from '@email-gateway/quarantine';
import {
  DLP_CATEGORIES,
  FILE_TYPE_FAMILIES,
  type DlpCategory,
} from '@email-gateway/security-contracts';
import { extractFromText } from '@email-gateway/url-security';
import { z } from 'zod';
import { defangUrl } from './defang';
import { maskDlp } from './dlp-mask';
import { htmlToPreviewText } from './html-to-text';

/**
 * The sanitized, DLP-masked quarantine preview (step 5.3 Q11, ADR-0048). Pure: the api passes
 * plain data read from the stored rows and the decoded parts (bounded Range GETs); the raw EML is
 * never parsed. The result is **JSON text only**: no HTML, no clickable or rewritten links (every
 * URL is defanged and numbered), no attribute, style or resource reference survives.
 */

export const PREVIEW_VERSION = 'preview/1';
export const BODY_UNAVAILABLE_REASONS = [
  'not_parsed',
  'too_large',
  'no_text_part',
  'purged',
] as const;
export type BodyUnavailableReason = (typeof BODY_UNAVAILABLE_REASONS)[number];

export interface PreviewLimits {
  /** `QUARANTINE_PREVIEW_MAX_TEXT_CHARS` (default 100 000). */
  maxTextChars: number;
  /** Links listed at most (default 200). */
  maxLinks: number;
  /** HTML input bound before parsing (default 1 MiB characters). */
  maxHtmlChars: number;
  /** Nodes visited at most in the HTML tree (default 200 000). */
  maxHtmlNodes: number;
  /** Header values and the subject are cut to this many characters (default 998). */
  maxHeaderValueChars: number;
  /** Headers listed at most (default 64). */
  maxHeaders: number;
}

export const DEFAULT_PREVIEW_LIMITS: Readonly<PreviewLimits> = Object.freeze({
  maxTextChars: 100_000,
  maxLinks: 200,
  maxHtmlChars: 1_048_576,
  maxHtmlNodes: 200_000,
  maxHeaderValueChars: 998,
  maxHeaders: 64,
});

export interface PreviewAttachmentInput {
  partIndex: number;
  filename: string | null;
  declaredType: string | null;
  detectedType: string | null;
  typeFamily: string | null;
  sizeBytes: number;
  sha256: string | null;
  verdict: string | null;
  reasonCodes: readonly string[];
  /** Computed by the caller with `checkDownloadable` (and the tenant/permission switches). */
  downloadable: boolean;
}

export interface PreviewInput {
  subject: string | null;
  /** Allow-listed header rows (`email_headers`). */
  headers: ReadonlyArray<{ name: string; value: string }>;
  /** Decoded `text/plain` body (`.text` object), possibly cut by the range read. */
  textPart: string | null;
  /** Decoded `text/html` body (`.html` object), possibly cut by the range read. */
  htmlPart: string | null;
  /** The caller's range read cut the part it passed. */
  partsTruncated?: boolean;
  /** Why no body can be shown (the caller knows: parse outcome, purge, missing keys). */
  unavailableReason?: BodyUnavailableReason | null;
  attachments: readonly PreviewAttachmentInput[];
  /** URL verdicts of the latest round by `message_urls.url_sha256`. */
  urlVerdicts: ReadonlyArray<{ urlSha256: string; verdict: string | null }>;
  /** DLP date plausibility uses it; nothing else reads a clock. */
  now: Date;
  limits?: Partial<PreviewLimits>;
}

const linkSchema = z.strictObject({
  n: z.number().int().min(1),
  displayUrl: z.string().max(256),
  host: z.string().max(1024).nullable(),
  verdict: z.string().max(32).nullable(),
});

export const quarantinePreviewSchema = z.strictObject({
  version: z.literal(PREVIEW_VERSION),
  subject: z.string().max(1024).nullable(),
  headers: z
    .array(z.strictObject({ name: z.string().max(64), value: z.string().max(1024) }))
    .max(256),
  body: z.strictObject({
    source: z.enum(['text', 'html']).nullable(),
    text: z.string(),
    truncated: z.boolean(),
    unavailableReason: z.enum(BODY_UNAVAILABLE_REASONS).nullable(),
  }),
  links: z.array(linkSchema).max(500),
  linksTruncated: z.boolean(),
  attachments: z
    .array(
      z.strictObject({
        partIndex: z.number().int().min(0),
        filename: z.string().max(128).nullable(),
        declaredType: z.string().max(255).nullable(),
        detectedType: z.string().max(255).nullable(),
        typeFamily: z.enum(FILE_TYPE_FAMILIES).nullable(),
        sizeBytes: z.number().int().min(0),
        sha256: z
          .string()
          .regex(/^[0-9a-f]{64}$/)
          .nullable(),
        verdict: z.string().max(32).nullable(),
        reasonCodes: z.array(z.string().max(64)).max(64),
        downloadable: z.boolean(),
      }),
    )
    .max(1000),
  dlp: z.strictObject({
    masked: z.number().int().min(0),
    categories: z.array(z.enum(DLP_CATEGORIES)),
  }),
});
export type QuarantinePreview = z.infer<typeof quarantinePreviewSchema>;

const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/;
const MIME_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;

/**
 * Drops the trailing partial token of text cut by a size bound, then any trailing run of digit
 * groups (a card or account number cut in the middle is never shown partially).
 */
function dropPartialTail(text: string): string {
  const cut = Math.max(text.lastIndexOf(' '), text.lastIndexOf('\n'), text.lastIndexOf('\t'));
  const head =
    cut > 0 && cut >= text.length - 128
      ? text.slice(0, cut)
      : text.slice(0, Math.max(0, text.length - 128));
  return head.replace(/[\s\d./-]+$/, '');
}

class LinkRegistry {
  readonly links: Array<{
    key: string;
    displayUrl: string;
    host: string | null;
    sha: string | null;
  }> = [];
  private readonly byKey = new Map<string, number>();
  register(url: string): { n: number; displayUrl: string } {
    const d = defangUrl(url);
    const key = d.identitySha256 ?? `raw:${d.displayUrl}`;
    const known = this.byKey.get(key);
    if (known !== undefined) return { n: known, displayUrl: d.displayUrl };
    this.links.push({ key, displayUrl: d.displayUrl, host: d.host, sha: d.identitySha256 });
    const n = this.links.length;
    this.byKey.set(key, n);
    return { n, displayUrl: d.displayUrl };
  }
}

/** Replaces every http(s)/www URL of `text` with its defanged form (and a link number). */
function defangInline(text: string, links: LinkRegistry | null): string {
  const { occurrences } = extractFromText(text, { maxOccurrences: 5000 });
  let out = text;
  for (const o of [...occurrences].sort((a, b) => b.range.start - a.range.start)) {
    if (o.range.start < 0 || o.range.end > out.length) continue;
    const display = links
      ? links.register(o.candidate)
      : { n: 0, displayUrl: defangUrl(o.candidate).displayUrl };
    const marker = links ? ` [link ${display.n}]` : '';
    out = out.slice(0, o.range.start) + display.displayUrl + marker + out.slice(o.range.end);
  }
  // Anything that still says http(s):// (outside the extractor's rules) is defanged as text.
  return out.replace(/\bhttp(s?):\/\//gi, 'hxxp$1://');
}

/** Q11: the preview of one entry. Never throws for well-typed input. */
export function renderPreview(input: PreviewInput): QuarantinePreview {
  const limits: PreviewLimits = { ...DEFAULT_PREVIEW_LIMITS, ...input.limits };
  const categories = new Set<DlpCategory>();
  let masked = 0;
  const mask = (text: string): string => {
    const r = maskDlp(text, { now: input.now });
    masked += r.masked;
    for (const c of r.categories) categories.add(c);
    return r.text;
  };
  // Sanitize first (hidden characters cannot split a URL or a value), then defang, mask, cut.
  const line = (text: string, max: number): string =>
    sanitizeDisplayText(
      mask(
        defangInline(sanitizeDisplayText(text, { maxChars: Number.MAX_SAFE_INTEGER }).text, null),
      ),
      { maxChars: max },
    ).text;

  const subject = input.subject === null ? null : line(input.subject, limits.maxHeaderValueChars);
  const headers = input.headers
    .filter((h) => HEADER_NAME.test(h.name))
    .slice(0, limits.maxHeaders)
    .map((h) => ({ name: h.name, value: line(h.value, limits.maxHeaderValueChars) }));

  const links = new LinkRegistry();
  let source: 'text' | 'html' | null = null;
  let raw = '';
  let truncated = input.partsTruncated === true;
  if (input.textPart !== null && input.textPart.trim().length > 0) {
    source = 'text';
    raw = input.textPart;
    if (raw.length > limits.maxHtmlChars) {
      raw = raw.slice(0, limits.maxHtmlChars);
      truncated = true;
    }
  } else if (input.htmlPart !== null && input.htmlPart.trim().length > 0) {
    source = 'html';
    let html = input.htmlPart;
    if (html.length > limits.maxHtmlChars) {
      html = html.slice(0, limits.maxHtmlChars);
      truncated = true;
    }
    const converted = htmlToPreviewText(
      html,
      { maxChars: limits.maxTextChars + 1024, maxNodes: limits.maxHtmlNodes },
      (href) => links.register(href).n,
    );
    raw = converted.text;
    if (converted.truncated) truncated = true;
  }
  if (truncated && raw.length > 0) raw = dropPartialTail(raw);
  let text = '';
  if (source !== null) {
    const sanitized = sanitizeDisplayText(raw, {
      maxChars: Number.MAX_SAFE_INTEGER,
      multiline: true,
    }).text;
    const cut = sanitizeDisplayText(mask(defangInline(sanitized, links)), {
      maxChars: limits.maxTextChars,
      multiline: true,
    });
    text = cut.text;
    if (cut.truncated) truncated = true;
  }
  const verdicts = new Map(input.urlVerdicts.map((u) => [u.urlSha256, u.verdict]));
  const attachments = input.attachments.map((a) => ({
    partIndex: a.partIndex,
    filename:
      a.filename === null
        ? null
        : mask(sanitizeDisplayText(a.filename, { maxChars: 128 }).text) || null,
    declaredType:
      a.declaredType !== null && MIME_TYPE.test(a.declaredType.toLowerCase())
        ? a.declaredType.toLowerCase()
        : null,
    detectedType:
      a.detectedType !== null && MIME_TYPE.test(a.detectedType.toLowerCase())
        ? a.detectedType.toLowerCase()
        : null,
    typeFamily: (FILE_TYPE_FAMILIES as readonly string[]).includes(a.typeFamily ?? '')
      ? (a.typeFamily as QuarantinePreview['attachments'][number]['typeFamily'])
      : null,
    sizeBytes: Math.max(0, Math.floor(a.sizeBytes)),
    sha256: a.sha256 !== null && /^[0-9a-f]{64}$/.test(a.sha256) ? a.sha256 : null,
    verdict: a.verdict,
    reasonCodes: a.reasonCodes.slice(0, 64),
    downloadable: a.downloadable,
  }));
  return {
    version: PREVIEW_VERSION,
    subject,
    headers,
    body: {
      source,
      text,
      truncated,
      unavailableReason: source === null ? (input.unavailableReason ?? 'no_text_part') : null,
    },
    links: links.links.slice(0, limits.maxLinks).map((l, i) => ({
      n: i + 1,
      displayUrl: l.displayUrl,
      host: l.host,
      verdict: l.sha === null ? null : (verdicts.get(l.sha) ?? null),
    })),
    linksTruncated: links.links.length > limits.maxLinks,
    attachments,
    dlp: { masked, categories: [...categories].sort() },
  };
}

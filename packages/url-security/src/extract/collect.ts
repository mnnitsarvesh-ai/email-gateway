import { parse as parseDomain } from 'tldts';
import { normalizeUrl, type NormalizedUrl } from '../normalize/url';
import { extractFromHtml } from './html';
import { extractFromText } from './text';
import {
  DEFAULT_EXTRACTION_LIMITS,
  type ExtractionFlag,
  type ExtractionLimits,
  type MessageCode,
  type PartExtraction,
  type UrlOccurrence,
  type UrlSource,
} from './types';

/** One input part of a message (U4 sources: stored bodies and small text/html attachments). */
export interface ExtractionPart {
  kind: 'text' | 'html';
  /** `body` (stored text/html body) or `attachment` (never rewritten, `url.in_attachment`). */
  origin: 'body' | 'attachment';
  content: string;
  /** The part's charset had to be guessed (`url.charset_guess`). */
  charsetGuess?: boolean;
}

/** A unique URL of the message (keyed by the identity hash). */
export interface ExtractedUrl {
  url: NormalizedUrl;
  sources: Partial<Record<UrlSource, number>>;
  /** Extraction + normalization codes, sorted, unique. */
  flags: string[];
  occurrences: number;
  /** Found only in attachments (informational `url.in_attachment`; never rewritten). */
  attachmentOnly: boolean;
}

export interface MessageExtraction {
  /** Unique URLs in extraction order, at most `maxUrls`. */
  urls: ExtractedUrl[];
  /** Message codes with counts (`url.script_scheme`, …, `limit.url_count`). */
  messageCodes: Partial<Record<MessageCode, number>>;
  /** Occurrences or unique URLs above the limits (`limit.url_count`). */
  limitHit: boolean;
  /** Occurrences per source (the `scan_url_extracted_total` increments). */
  sourceCounts: Partial<Record<UrlSource, number>>;
}

export interface CollectLimits extends ExtractionLimits {
  /** Unique URLs kept (URL_MAX_PER_MESSAGE). */
  maxUrls: number;
  /** URL_MAX_LENGTH (normalized form). */
  maxLength: number;
}

export const DEFAULT_COLLECT_LIMITS: CollectLimits = {
  ...DEFAULT_EXTRACTION_LIMITS,
  maxUrls: 200,
  maxLength: 2048,
};

const URL_LIKE =
  /^(?:(?:https?:\/\/|www\.)\S+|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+(?:[/?#]\S*)?)$/i;

/**
 * Text mismatch (U10 S7): the visible text of a link is URL-like and its registrable domain
 * differs from the href's.
 */
export function anchorTextMismatch(anchorText: string | null, href: NormalizedUrl): boolean {
  if (!anchorText) return false;
  const text = anchorText.trim();
  if (!URL_LIKE.test(text) || text.length > 512) return false;
  const explicit = /^(?:https?:\/\/|www\.)/i.test(text);
  const candidate = /^https?:\/\//i.test(text) ? text : `http://${text}`;
  const result = normalizeUrl(candidate);
  if (!result.ok) return false;
  const shown = result.url;
  // A bare `name.ext` counts only with a real (ICANN) suffix: `report.pdf` is not a domain.
  if (!explicit && shown.hostKind === 'domain' && parseDomain(shown.host).isIcann !== true) {
    return false;
  }
  const shownKey = shown.registrableDomain ?? shown.host;
  const hrefKey = href.registrableDomain ?? href.host;
  return shownKey !== hrefKey;
}

function extractPart(part: ExtractionPart, limits: ExtractionLimits): PartExtraction {
  return part.kind === 'html'
    ? extractFromHtml(part.content, limits)
    : extractFromText(part.content, limits);
}

/**
 * Extracts and normalizes the URLs of a message's parts: unique by identity hash, first-seen
 * order, sources counted, codes merged. Occurrences beyond `maxOccurrences` (over all parts) and
 * unique URLs beyond `maxUrls` set `limit.url_count`; the extra URLs are not returned.
 */
export function extractMessageUrls(
  parts: readonly ExtractionPart[],
  limits: CollectLimits = DEFAULT_COLLECT_LIMITS,
): MessageExtraction {
  const byHash = new Map<string, ExtractedUrl & { inBody: boolean }>();
  const messageCodes: Partial<Record<MessageCode, number>> = {};
  const sourceCounts: Partial<Record<UrlSource, number>> = {};
  let limitHit = false;
  let remaining = limits.maxOccurrences;
  const addCode = (code: MessageCode, n: number): void => {
    messageCodes[code] = (messageCodes[code] ?? 0) + n;
  };

  for (const part of parts) {
    if (remaining <= 0) {
      limitHit = true;
      break;
    }
    const extraction = extractPart(part, { ...limits, maxOccurrences: remaining });
    remaining -= extraction.occurrences.length;
    if (extraction.limitHit) limitHit = true;
    for (const [code, n] of Object.entries(extraction.messageCodes) as [MessageCode, number][]) {
      if (code !== 'limit.url_count') addCode(code, n);
    }
    for (const occurrence of extraction.occurrences) {
      const source: UrlSource = part.origin === 'attachment' ? 'attachment' : occurrence.source;
      sourceCounts[source] = (sourceCounts[source] ?? 0) + 1;
      const result = normalizeUrl(occurrence.candidate, { maxLength: limits.maxLength });
      if (!result.ok) {
        if (result.code === 'url.invalid') addCode('url.invalid', 1);
        continue;
      }
      const flags = new Set<string>([...occurrence.flags, ...result.url.flags]);
      if (part.charsetGuess) flags.add('url.charset_guess' satisfies ExtractionFlag);
      if (anchorTextMismatch(occurrence.anchorText, result.url)) flags.add('url.text_mismatch');
      let entry = byHash.get(result.url.sha256);
      if (!entry) {
        if (byHash.size >= limits.maxUrls) {
          limitHit = true;
          continue;
        }
        entry = {
          url: result.url,
          sources: {},
          flags: [],
          occurrences: 0,
          attachmentOnly: true,
          inBody: false,
        };
        byHash.set(result.url.sha256, entry);
      }
      entry.sources[source] = (entry.sources[source] ?? 0) + 1;
      entry.occurrences += 1;
      if (part.origin === 'body') entry.inBody = true;
      entry.flags = [...new Set([...entry.flags, ...flags])].sort();
    }
  }
  if (limitHit) messageCodes['limit.url_count'] = 1;

  const urls: ExtractedUrl[] = [...byHash.values()].map(({ inBody, ...entry }) => {
    const attachmentOnly = !inBody;
    const flags = attachmentOnly
      ? [...new Set([...entry.flags, 'url.in_attachment'])].sort()
      : entry.flags;
    return { ...entry, attachmentOnly, flags };
  });
  return { urls, messageCodes, limitHit, sourceCounts };
}

/** Occurrences of one rewritable body part (the rewriter's view; no normalization). */
export function rewritableOccurrences(kind: 'text' | 'html', content: string): UrlOccurrence[] {
  const extraction =
    kind === 'html'
      ? extractFromHtml(content, { maxOccurrences: Number.MAX_SAFE_INTEGER })
      : extractFromText(content, { maxOccurrences: Number.MAX_SAFE_INTEGER });
  return extraction.occurrences.filter((occurrence) => occurrence.rewritable);
}

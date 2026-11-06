import { URL_MAX_LENGTH } from '@email-gateway/security-contracts';
import {
  type FetchResult,
  type LookalikeResult,
  normalizeUrl,
  type ReputationItem,
  type ReputationLookup,
} from '@email-gateway/url-security';
import type { StoredUrlRow, UrlAttachmentRow } from './url-store';

// Shared with the click-service recheck (moved to url-security; re-exported for the engine).
export { chainItems, mergeLookalike } from '@email-gateway/url-security';

/**
 * Pure helpers of the url engine (step 4.3 U3, U4, U16): content completeness (E1), extra part
 * selection, seq assignment, static risk for fetch selection, and the bounded JSON of the
 * `url_scan_results` columns. No I/O, no URL in any return value except the stored columns.
 */

/** Final parse statuses whose bodies and attachment rows are complete (unless a limit hit). */
export const COMPLETE_PARSE_STATUSES: ReadonlySet<string> = new Set([
  'parsed',
  'parsed_with_defects',
  'parse_limit_exceeded',
]);

/**
 * Parse limits that make the URL extraction incomplete (U4 E1): a body not stored
 * (`body_size`) and every structural stop (`message_size`, `nesting_depth`, `part_count`,
 * `header_*`, `parse_timeout`, `decoded_ratio`, `total_decoded_size`). `attachment_count` /
 * `attachment_size` do not hide a body.
 */
export const INCOMPLETE_PARSE_LIMITS: ReadonlySet<string> = new Set([
  'body_size',
  'message_size',
  'nesting_depth',
  'part_count',
  'header_count',
  'header_line_length',
  'header_block_size',
  'parse_timeout',
  'decoded_ratio',
  'total_decoded_size',
]);

export function parseComplete(status: string, limits: readonly string[]): boolean {
  return (
    COMPLETE_PARSE_STATUSES.has(status) &&
    !limits.some((l) => INCOMPLETE_PARSE_LIMITS.has(l) || l.startsWith('header_'))
  );
}

const HTML_TYPES = new Set(['text/html', 'application/xhtml+xml']);
const HTML_EXTENSION = /\.(?:s?html?|xhtml)$/i;
const TEXT_EXTENSION = /\.txt$/i;

/** The extraction kind of an attachment row (U4 sources), or null when it is not text. */
export function extraPartKind(
  row: Pick<UrlAttachmentRow, 'declaredContentType' | 'detectedContentType' | 'filename'>,
): 'html' | 'text' | null {
  const types = [row.detectedContentType, row.declaredContentType]
    .filter((t): t is string => typeof t === 'string')
    .map((t) => t.toLowerCase().split(';')[0]?.trim() ?? '');
  if (types.some((t) => HTML_TYPES.has(t)) || (row.filename && HTML_EXTENSION.test(row.filename)))
    return 'html';
  if (types.includes('text/plain') || (row.filename && TEXT_EXTENSION.test(row.filename)))
    return 'text';
  return null;
}

/**
 * The extra parts of U4: stored text/html attachment rows within the size bound, at most `max`,
 * in part order.
 */
export function selectExtraParts(
  rows: readonly UrlAttachmentRow[],
  max: number,
  maxBytes: number,
): Array<{ row: UrlAttachmentRow; kind: 'html' | 'text' }> {
  const out: Array<{ row: UrlAttachmentRow; kind: 'html' | 'text' }> = [];
  for (const row of rows) {
    if (out.length >= max) break;
    if (row.objectKey === null || row.sizeBytes > maxBytes) continue;
    const kind = extraPartKind(row);
    if (kind) out.push({ row, kind });
  }
  return out;
}

export const MAX_URL_SEQ = 65_535;

/**
 * `url_seq` per URL (U3 step 3): a URL already in `message_urls` keeps its seq (matched by the
 * identity hash); new URLs get `max + 1…` in extraction order. A seq above 65 535 cannot be
 * stored: such URLs are reported in `overflow` (the engine drops them with `limit.url_count`).
 */
export function assignSeqs(
  hashes: readonly string[],
  existing: readonly StoredUrlRow[],
): { seqs: Array<number | null>; isNew: boolean[]; overflow: number } {
  const known = new Map(existing.map((r) => [r.urlSha256, r.urlSeq]));
  let next = existing.reduce((max, r) => Math.max(max, r.urlSeq), -1) + 1;
  const seqs: Array<number | null> = [];
  const isNew: boolean[] = [];
  let overflow = 0;
  for (const hash of hashes) {
    const seq = known.get(hash);
    if (seq !== undefined) {
      seqs.push(seq);
      isNew.push(false);
    } else if (next > MAX_URL_SEQ) {
      seqs.push(null);
      isNew.push(false);
      overflow += 1;
    } else {
      known.set(hash, next);
      seqs.push(next);
      isNew.push(true);
      next += 1;
    }
  }
  return { seqs, isNew, overflow };
}

/** Static S-rule signals of U10 that make a URL "suspicious" for fetch selection (U9). */
const STATIC_FLAGS = new Set([
  'url.userinfo',
  'url.obfuscated_host',
  'url.ip_obfuscated',
  'url.entity_obfuscation',
  'url.control_chars',
  'url.text_mismatch',
  'url.too_long',
]);

/** Static risk (U9 `suspicious` mode): static S-rule signals + non-clear reputation answers. */
export function staticRisk(input: {
  flags: readonly string[];
  hostKind: 'domain' | 'ipv4' | 'ipv6';
  lookalike: LookalikeResult;
  reputation: readonly Pick<ReputationLookup, 'status'>[];
}): number {
  let risk = input.flags.filter((f) => STATIC_FLAGS.has(f)).length;
  if (input.hostKind !== 'domain') risk += 1;
  if (input.lookalike.mixedScript) risk += 1;
  risk += input.lookalike.findings.filter(
    (f) => f.rule !== 'L5' || f.targetKind !== 'brand',
  ).length;
  risk += input.reputation.filter((a) => a.status !== 'clear').length;
  return risk;
}

/** `url_scan_results.lookalike` (≤ 5): the findings, then L4 / L6 markers without a target. */
export function storedLookalike(result: LookalikeResult): Array<Record<string, unknown>> | null {
  const entries: Array<Record<string, unknown>> = result.findings.map((f) => ({
    rule: f.rule,
    targetKind: f.targetKind,
    targetDomain: f.targetDomain,
    score: f.score,
    distance: f.distance,
  }));
  if (result.mixedScript) {
    entries.push({ rule: 'L4', targetKind: null, targetDomain: null, score: 1, distance: null });
  }
  if (result.idn) {
    entries.push({ rule: 'L6', targetKind: null, targetDomain: null, score: 0, distance: null });
  }
  return entries.length > 0 ? entries.slice(0, 5) : null;
}

const STATUS_ORDER: Readonly<Record<string, number>> = { listed: 0, error: 1, clear: 2 };

/** `url_scan_results.reputation` (≤ 12): listed answers first, then errors, then clear. */
export function storedReputation(
  answers: readonly ReputationLookup[],
  max = 12,
): Array<Record<string, unknown>> {
  return [...answers]
    .map((a, index) => ({ a, index }))
    .sort(
      (x, y) =>
        (STATUS_ORDER[x.a.status] ?? 3) - (STATUS_ORDER[y.a.status] ?? 3) || x.index - y.index,
    )
    .slice(0, max)
    .map(({ a }) => ({
      provider: a.provider,
      version: a.version,
      kind: a.kind,
      status: a.status,
      category: a.category,
      severity: a.severity,
      cache: a.cache,
    }));
}

const itemKey = (item: ReputationItem): string => `${item.kind}\u0000${item.value}`;

/** Indexes reputation answers by item. */
export function answersByItem(
  answers: readonly ReputationLookup[],
): Map<string, ReputationLookup[]> {
  const map = new Map<string, ReputationLookup[]>();
  for (const answer of answers) {
    const key = itemKey(answer);
    const list = map.get(key) ?? [];
    list.push(answer);
    map.set(key, list);
  }
  return map;
}

export function answersFor(
  index: ReadonlyMap<string, ReputationLookup[]>,
  items: readonly ReputationItem[],
): ReputationLookup[] {
  return items.flatMap((item) => index.get(itemKey(item)) ?? []);
}

/** The fetch columns of `url_scan_results` (chain hosts only, U8; final URL in its own column). */
export function storedFetch(result: FetchResult | null): {
  fetchStatus: 'not_attempted' | 'completed' | 'error' | 'blocked';
  fetchError: string | null;
  hopCount: number;
  redirectChain: Array<Record<string, unknown>> | null;
  finalUrl: string | null;
  finalUrlSha256: string | null;
  finalHost: string | null;
  finalStatus: number | null;
  landing: Record<string, unknown> | null;
} {
  if (!result) {
    return {
      fetchStatus: 'not_attempted',
      fetchError: null,
      hopCount: 0,
      redirectChain: null,
      finalUrl: null,
      finalUrlSha256: null,
      finalHost: null,
      finalStatus: null,
      landing: null,
    };
  }
  const final = result.finalUrl ? normalizeUrl(result.finalUrl) : null;
  const finalStatus =
    result.finalStatus !== null && result.finalStatus >= 100 && result.finalStatus <= 599
      ? result.finalStatus
      : null;
  return {
    fetchStatus: result.status,
    fetchError: result.error,
    hopCount: Math.min(255, Math.max(0, result.hops.length - 1)),
    redirectChain: result.hops.slice(0, 10).map((hop) => ({
      host: hop.host.slice(0, 253),
      port: hop.port,
      status: hop.status,
      kind: hop.kind,
      blocked: hop.blocked,
    })),
    finalUrl: final?.ok ? final.url.stored.slice(0, URL_MAX_LENGTH) : null,
    finalUrlSha256: final?.ok ? final.url.sha256 : null,
    finalHost: final?.ok ? final.url.host.slice(0, 253) : null,
    finalStatus,
    landing: result.landing
      ? {
          passwordFields: result.landing.passwordFields,
          forms: result.landing.forms,
          crossOriginFormAction: result.landing.crossOriginFormAction,
          formActionHosts: result.landing.formActionHosts.slice(0, 5),
          titleBrandMatches: result.landing.titleBrandMatches.slice(0, 5),
        }
      : null,
  };
}

/** `org/<org>/rewrite/<yyyy>/<mm>/<dd>/<messageId>/r<round>-<suffix>.eml` (U11, UTC date of received_at). */
export function rewriteObjectKey(
  organizationId: bigint,
  messageId: bigint,
  receivedAt: Date,
  round: number,
  suffix: string,
): string {
  const yyyy = String(receivedAt.getUTCFullYear());
  const mm = String(receivedAt.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(receivedAt.getUTCDate()).padStart(2, '0');
  return `org/${organizationId.toString()}/rewrite/${yyyy}/${mm}/${dd}/${messageId.toString()}/r${String(round)}-${suffix}.eml`;
}

/** First 12 hex characters of a URL hash: the only URL-derived value that is ever logged. */
export const hashPrefix = (sha256: string): string => sha256.slice(0, 12);

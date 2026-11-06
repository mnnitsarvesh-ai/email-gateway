import { createHash } from 'node:crypto';
import { Transform, type Readable, type TransformCallback, type Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { Joiner, Splitter, type MimeNode, type SplitterChunk } from '@zone-eu/mailsplit';
import * as libbase64 from 'libbase64';
import * as libqp from 'libqp';
import { decodeLossless, encodeText, isRewritableCharset } from '../extract/charset';
import { rewritableOccurrences } from '../extract/collect';
import { hostMatchesAny, hostMatchesDomain, normalizeUrl } from '../normalize/url';

/**
 * Streaming URL rewriter (docs/plan/steps/11-url-protection.md U11). The stored EML flows through
 * mailsplit `Splitter → (this rewriter) → Joiner`: headers and bytes of every untouched node pass
 * through byte-identical. A rewritable leaf (text/html or text/plain, inline, no filename, outside
 * message/rfc822, ≤ maxPartBytes) is buffered, transfer-decoded (base64/QP/7bit/8bit), decoded
 * with its charset (lossless round trip required, ASCII-compatible charsets only), and only the
 * `href` attribute ranges of eligible `a`/`area` start tags (HTML, parse5 source offsets) or the
 * URL ranges of the plain-text extractor are replaced. The part is re-encoded with its charset and
 * ORIGINAL Content-Transfer-Encoding; a 7bit/8bit/binary part that would get a line longer than
 * 998 octets becomes quoted-printable (header updated). A part without a replaced link is passed
 * through untouched.
 *
 * mailsplit's own `Rewriter` is not used: it re-encodes every selected 7bit/8bit node as
 * quoted-printable, which would violate "original CTE preserved" (deviation recorded in §12);
 * the node decode/encode uses libqp/libbase64 instead.
 *
 * A message-level skip (signed/encrypted, DKIM policy, size, structure mismatch) aborts the
 * stream: the sink is destroyed and the result is `skipped`; the caller discards the partial
 * object (aborts the upload). A complete run without any rewritten link is `skipped`/`no_urls`.
 */

export const REWRITE_SKIP_REASONS = [
  'disabled',
  'direction',
  'no_urls',
  'parse_incomplete',
  'too_large',
  'signed_smime',
  'signed_pgp',
  'encrypted',
  'dkim_policy',
  'structure_mismatch',
  'error',
] as const;
export type RewriteSkipReason = (typeof REWRITE_SKIP_REASONS)[number];

/** Why a single part was left untouched (counted in `parts_skipped`). */
export const PART_SKIP_REASONS = [
  'too_large',
  'charset_roundtrip',
  'unsupported_charset',
  'decode_error',
] as const;
export type PartSkipReason = (typeof PART_SKIP_REASONS)[number];

export interface RewriteUrlEntry {
  seq: number;
  /** URL longer than URL_MAX_LENGTH: never rewritten. */
  truncated: boolean;
}

export interface RewritePolicy {
  /** Rewrite text/plain parts (`rewrite.plainText`, default true). */
  plainText: boolean;
  /** `rewrite.excludedDomains` (suffix match on labels). */
  excludedDomains: readonly string[];
  /** Tenant `allowedDomains` (never rewritten). */
  allowedDomains: readonly string[];
  dkimSignedPolicy: 'rewrite' | 'skip';
}

export interface RewriteLimits {
  /** URL_REWRITE_MAX_MESSAGE_BYTES. */
  maxMessageBytes: number;
  /** URL_REWRITE_MAX_PART_BYTES (encoded bytes of one part). */
  maxPartBytes: number;
}

export interface RewriteOptions {
  source: Readable;
  sink: Writable;
  /** URL identity SHA-256 → the scan's URL row. Occurrences not in the map stay untouched. */
  urlMap: ReadonlyMap<string, RewriteUrlEntry>;
  policy: RewritePolicy;
  /** URL_CLICK_BASE_URL (no trailing slash needed). */
  clickBaseUrl: string;
  /** Returns the signed token (U12) for a URL seq. */
  sign: (seq: number) => string;
  limits: RewriteLimits;
  /** `email_message_parses.structure` (content types in document order) for the structure echo. */
  structure?: ReadonlyArray<{ contentType: string }> | null;
  /** Splitter header-block limit (MIME_MAX_HEADER_BLOCK_BYTES). */
  maxHeadSize?: number;
}

export interface RewriteResult {
  status: 'rewritten' | 'skipped';
  skipReason: RewriteSkipReason | null;
  linksRewritten: number;
  linksUnmapped: number;
  partsRewritten: number;
  partsSkipped: number;
  partSkipReasons: Partial<Record<PartSkipReason, number>>;
  /** Links rewritten per part kind (`scan_url_rewritten_links_total{part}`). */
  linksByPart: { text: number; html: number };
  /** A DKIM-Signature header is present on the message. */
  dkimSigned: boolean;
  /** Seqs that got at least one rewritten link. */
  rewrittenSeqs: number[];
  /** SHA-256 and size of the output (null when skipped). */
  sha256: string | null;
  sizeBytes: number | null;
  /** The unexpected error behind `skipReason = error` (never contains message content). */
  error?: Error;
}

class RewriteSkip extends Error {
  constructor(readonly reason: RewriteSkipReason) {
    super(`rewrite skipped: ${reason}`);
    this.name = 'RewriteSkip';
  }
}

const SIGNED_OR_ENCRYPTED: Readonly<Record<string, RewriteSkipReason>> = {
  'multipart/signed': 'signed_smime',
  'application/pkcs7-signature': 'signed_smime',
  'application/x-pkcs7-signature': 'signed_smime',
  'application/pkcs7-mime': 'encrypted',
  'application/x-pkcs7-mime': 'encrypted',
  'multipart/encrypted': 'encrypted',
  'application/pgp-encrypted': 'encrypted',
  'application/pgp-signature': 'signed_pgp',
};

/** Message-level reason from a content type list (`structure`), or null. */
export function signedOrEncrypted(contentTypes: readonly string[]): RewriteSkipReason | null {
  const types = contentTypes.map((t) => t.toLowerCase().trim());
  if (types.includes('multipart/signed')) {
    return types.includes('application/pgp-signature') ? 'signed_pgp' : 'signed_smime';
  }
  for (const type of types) {
    const reason = SIGNED_OR_ENCRYPTED[type];
    if (reason) return reason;
  }
  return null;
}

/** Inline PGP in a body part (signed → signed_pgp, encrypted → encrypted). */
export function inlinePgp(text: string): RewriteSkipReason | null {
  if (text.includes('-----BEGIN PGP SIGNED MESSAGE-----')) return 'signed_pgp';
  if (text.includes('-----BEGIN PGP MESSAGE-----')) return 'encrypted';
  return null;
}

export interface EligibilityInput {
  enabled: boolean;
  direction: string;
  directions: readonly string[];
  /** E1 false: the parse row is not final or a body/structural limit was hit. */
  contentComplete: boolean;
  messageSizeBytes: number;
  maxMessageBytes: number;
  /** Content types of `structure`. */
  contentTypes: readonly string[];
  /** Stored text/html bodies (inline PGP check). */
  bodies?: ReadonlyArray<string | null>;
  /** Number of URLs eligible for rewriting (mapped, not truncated, from bodies). */
  eligibleUrls: number;
}

/** Message-level eligibility before streaming (U11); null = rewrite. */
export function checkRewriteEligibility(input: EligibilityInput): RewriteSkipReason | null {
  if (!input.enabled) return 'disabled';
  if (!input.directions.includes(input.direction)) return 'direction';
  if (!input.contentComplete) return 'parse_incomplete';
  if (input.messageSizeBytes > input.maxMessageBytes) return 'too_large';
  const structural = signedOrEncrypted(input.contentTypes);
  if (structural) return structural;
  for (const body of input.bodies ?? []) {
    const reason = body ? inlinePgp(body) : null;
    if (reason) return reason;
  }
  if (input.eligibleUrls === 0) return 'no_urls';
  return null;
}

/** Escapes an attribute value written inside double quotes. */
export const escapeAttribute = (value: string): string =>
  value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const nodeContentType = (node: MimeNode): string =>
  (node.contentType || 'text/plain').toLowerCase();

function insideRfc822(node: MimeNode): boolean {
  for (let parent = node.parentNode; parent; parent = parent.parentNode) {
    if (parent.rfc822) return true;
  }
  return false;
}

function hasLongLine(bytes: Buffer, max = 998): boolean {
  let start = 0;
  for (;;) {
    const lf = bytes.indexOf(0x0a, start);
    const end = lf < 0 ? bytes.length : lf;
    const length = end - start - (end > start && bytes[end - 1] === 0x0d ? 1 : 0);
    if (length > max) return true;
    if (lf < 0) return false;
    start = lf + 1;
  }
}

interface PendingPart {
  node: MimeNode;
  kind: 'text' | 'html';
  chunks: Buffer[];
  bytes: number;
}

interface Counters {
  linksRewritten: number;
  linksUnmapped: number;
  partsRewritten: number;
  partsSkipped: number;
  partSkipReasons: Partial<Record<PartSkipReason, number>>;
  linksByPart: { text: number; html: number };
  dkimSigned: boolean;
  seqs: Set<number>;
}

class NodeRewriter extends Transform {
  private pending: PendingPart | null = null;
  private nodeIndex = -1;
  private readonly clickBase: string;
  private readonly clickHost: string;

  constructor(
    private readonly options: RewriteOptions,
    private readonly counters: Counters,
  ) {
    super({ readableObjectMode: true, writableObjectMode: true });
    this.clickBase = options.clickBaseUrl.replace(/\/+$/, '');
    this.clickHost = new URL(this.clickBase).hostname.toLowerCase();
  }

  override _transform(
    chunk: SplitterChunk,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    try {
      if (chunk.type === 'body' && this.pending) {
        this.pending.chunks.push(chunk.value);
        this.pending.bytes += chunk.value.length;
        if (this.pending.bytes > this.options.limits.maxPartBytes) {
          // Too large to rewrite: pass the part through untouched from here on.
          this.skipPart('too_large');
        }
        callback();
        return;
      }
      if (chunk.type !== 'body') this.flushPending();
      if (chunk.type === 'node') this.onNode(chunk);
      else this.push(chunk);
      callback();
    } catch (error) {
      callback(error as Error);
    }
  }

  override _flush(callback: TransformCallback): void {
    try {
      this.flushPending();
      const structure = this.options.structure;
      if (structure && structure.length !== this.nodeIndex + 1)
        throw new RewriteSkip('structure_mismatch');
      callback();
    } catch (error) {
      callback(error as Error);
    }
  }

  private onNode(node: MimeNode): void {
    this.nodeIndex += 1;
    const contentType = nodeContentType(node);
    const structure = this.options.structure;
    if (structure) {
      const expected = structure[this.nodeIndex];
      if (!expected || expected.contentType.toLowerCase() !== contentType)
        throw new RewriteSkip('structure_mismatch');
    }
    if (node.root && node.headers && node.headers.hasHeader('dkim-signature')) {
      this.counters.dkimSigned = true;
      if (this.options.policy.dkimSignedPolicy === 'skip') throw new RewriteSkip('dkim_policy');
    }
    if (contentType === 'multipart/signed') {
      const header = node.headers ? node.headers.getFirst('Content-Type') : '';
      throw new RewriteSkip(
        /protocol\s*=\s*"?application\/pgp-signature/i.test(header) ? 'signed_pgp' : 'signed_smime',
      );
    }
    const structural = signedOrEncrypted([contentType]);
    if (structural) throw new RewriteSkip(structural);

    const kind =
      contentType === 'text/html' ? 'html' : contentType === 'text/plain' ? 'text' : null;
    const rewritable =
      kind !== null &&
      !node.multipart &&
      (kind === 'html' || this.options.policy.plainText) &&
      node.disposition !== 'attachment' &&
      !node.filename &&
      !insideRfc822(node);
    if (!rewritable) {
      this.push(node);
      return;
    }
    this.pending = { node, kind, chunks: [], bytes: 0 };
  }

  private skipPart(reason: PartSkipReason): void {
    const part = this.pending;
    if (!part) return;
    this.pending = null;
    this.counters.partsSkipped += 1;
    this.counters.partSkipReasons[reason] = (this.counters.partSkipReasons[reason] ?? 0) + 1;
    this.passThrough(part);
  }

  private passThrough(part: PendingPart): void {
    this.push(part.node);
    for (const value of part.chunks) this.push({ node: part.node, type: 'body', value });
  }

  private flushPending(): void {
    const part = this.pending;
    if (!part) return;
    this.pending = null;
    const raw = Buffer.concat(part.chunks, part.bytes);
    const node = part.node;
    const encoding = (node.encoding || '7bit').toLowerCase();
    const charset = (node.charset || 'us-ascii').toLowerCase();

    if (!isRewritableCharset(charset)) {
      this.pending = part;
      this.skipPart('unsupported_charset');
      return;
    }
    let decoded: Buffer;
    try {
      if (encoding === 'base64') decoded = libbase64.decode(raw.toString('latin1'));
      else if (encoding === 'quoted-printable') decoded = libqp.decode(raw);
      else if (encoding === '7bit' || encoding === '8bit' || encoding === 'binary') decoded = raw;
      else throw new Error('unknown transfer encoding');
    } catch {
      this.pending = part;
      this.skipPart('decode_error');
      return;
    }
    const text = decodeLossless(decoded, charset);
    if (text === null) {
      this.pending = part;
      this.skipPart('charset_roundtrip');
      return;
    }
    const pgp = inlinePgp(text);
    if (pgp) throw new RewriteSkip(pgp);

    const replacements = this.replacements(part.kind, text);
    if (replacements.length === 0) {
      this.passThrough(part);
      return;
    }
    let next = text;
    for (const r of [...replacements].sort((a, b) => b.start - a.start)) {
      next = next.slice(0, r.start) + r.value + next.slice(r.end);
    }
    const bytes = encodeText(next, charset);
    const eol = raw.includes('\r\n') ? '\r\n' : raw.includes('\n') ? '\n' : '\r\n';
    const trailing = /\r?\n$/.exec(raw.toString('latin1'))?.[0] ?? '';
    let body: Buffer;
    let targetEncoding = encoding;
    if (
      (encoding === '7bit' || encoding === '8bit' || encoding === 'binary') &&
      hasLongLine(bytes)
    ) {
      targetEncoding = 'quoted-printable';
      if (node.headers) node.headers.update('Content-Transfer-Encoding', 'quoted-printable');
    }
    if (targetEncoding === 'base64') {
      body = Buffer.from(
        libbase64.wrap(libbase64.encode(bytes), 76).replace(/\r?\n/g, eol) + trailing,
        'latin1',
      );
    } else if (targetEncoding === 'quoted-printable') {
      let encoded = libqp.wrap(libqp.encode(bytes), 76).replace(/\r?\n/g, eol);
      if (encoding !== 'quoted-printable') encoded = encoded.replace(new RegExp(`${eol}$`), '');
      body = Buffer.from(encoded + (encoded.endsWith(eol) ? '' : trailing), 'latin1');
    } else {
      body = bytes;
    }
    this.counters.partsRewritten += 1;
    this.counters.linksRewritten += replacements.length;
    this.counters.linksByPart[part.kind] += replacements.length;
    for (const r of replacements) this.counters.seqs.add(r.seq);
    this.push(node);
    this.push({ node, type: 'body', value: body });
  }

  private replacements(
    kind: 'text' | 'html',
    text: string,
  ): Array<{ start: number; end: number; value: string; seq: number }> {
    const out: Array<{ start: number; end: number; value: string; seq: number }> = [];
    for (const occurrence of rewritableOccurrences(kind, text)) {
      if (occurrence.range.start < 0) continue;
      const normalized = normalizeUrl(occurrence.candidate);
      if (!normalized.ok) continue;
      const url = normalized.url;
      // The click host itself (already rewritten), excluded and allow-listed domains.
      if (hostMatchesDomain(url.host, this.clickHost)) continue;
      if (hostMatchesAny(url.host, this.options.policy.excludedDomains)) continue;
      if (hostMatchesAny(url.host, this.options.policy.allowedDomains)) continue;
      const entry = this.options.urlMap.get(url.sha256);
      if (!entry) {
        this.counters.linksUnmapped += 1;
        continue;
      }
      if (entry.truncated || url.truncated) continue;
      const target = `${this.clickBase}/c/${this.options.sign(entry.seq)}`;
      if (kind === 'html') {
        const source = text.slice(occurrence.range.start, occurrence.range.end);
        const name = /^[^\s=]+/.exec(source)?.[0] ?? 'href';
        out.push({
          ...occurrence.range,
          value: `${name}="${escapeAttribute(target)}"`,
          seq: entry.seq,
        });
      } else {
        out.push({ ...occurrence.range, value: target, seq: entry.seq });
      }
    }
    return out;
  }
}

class Measure extends Transform {
  readonly hash = createHash('sha256');
  size = 0;
  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    this.hash.update(chunk);
    this.size += chunk.length;
    callback(null, chunk);
  }
}

class InputCap extends Transform {
  private size = 0;
  constructor(private readonly max: number) {
    super();
  }
  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    this.size += chunk.length;
    if (this.size > this.max) {
      callback(new RewriteSkip('too_large'));
      return;
    }
    callback(null, chunk);
  }
}

export async function rewriteEml(options: RewriteOptions): Promise<RewriteResult> {
  const counters: Counters = {
    linksRewritten: 0,
    linksUnmapped: 0,
    partsRewritten: 0,
    partsSkipped: 0,
    partSkipReasons: {},
    linksByPart: { text: 0, html: 0 },
    dkimSigned: false,
    seqs: new Set(),
  };
  const result = (
    status: RewriteResult['status'],
    skipReason: RewriteSkipReason | null,
    measure: Measure | null,
  ): RewriteResult => ({
    status,
    skipReason,
    linksRewritten: counters.linksRewritten,
    linksUnmapped: counters.linksUnmapped,
    partsRewritten: counters.partsRewritten,
    partsSkipped: counters.partsSkipped,
    partSkipReasons: counters.partSkipReasons,
    linksByPart: counters.linksByPart,
    dkimSigned: counters.dkimSigned,
    rewrittenSeqs: [...counters.seqs].sort((a, b) => a - b),
    sha256: measure ? measure.hash.digest('hex') : null,
    sizeBytes: measure ? measure.size : null,
  });
  const measure = new Measure();
  try {
    await pipeline(
      options.source,
      new InputCap(options.limits.maxMessageBytes),
      new Splitter({
        ignoreEmbedded: false,
        ...(options.maxHeadSize ? { maxHeadSize: options.maxHeadSize } : {}),
      }),
      new NodeRewriter(options, counters),
      new Joiner(),
      measure,
      options.sink,
    );
  } catch (error) {
    if (error instanceof RewriteSkip) return result('skipped', error.reason, null);
    return {
      ...result('skipped', 'error', null),
      error: error instanceof Error ? error : new Error(String(error)),
    };
  }
  if (counters.linksRewritten === 0) return result('skipped', 'no_urls', null);
  return result('rewritten', null, measure);
}

import { createHash } from 'node:crypto';
import {
  PassThrough,
  Readable,
  Transform,
  type TransformCallback,
  type Writable,
} from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { Joiner, Splitter, type MimeNode, type SplitterChunk } from '@zone-eu/mailsplit';
import {
  decodeLossless,
  encodeText,
  inlinePgp,
  isRewritableCharset,
} from '@email-gateway/url-security';
import * as libbase64 from 'libbase64';
import * as libqp from 'libqp';
import { parse } from 'parse5';
import { detectSignedOrEncrypted, type SignedOrEncrypted } from './signed';

/**
 * WARN body banners (step 5.3 Q22, ADR-0049): a streaming MIME edit that mirrors the 4.3 URL
 * rewriter (`rewriteEml`). The object flows through mailsplit `Splitter → editor → Joiner`: every
 * untouched node passes through byte-identical. The **first** inline, filename-less `text/plain`
 * leaf and the **first** `text/html` leaf of the primary body (outside `message/rfc822`; inside a
 * `multipart/related` only its root part) are buffered (≤ `maxPartBytes` encoded), decoded
 * (transfer encoding; ASCII-compatible charsets only, lossless round trip required), edited, and
 * re-encoded with the **original** Content-Transfer-Encoding (a 7bit/8bit part that would get a
 * line over 998 octets becomes quoted-printable, header updated).
 *
 * Text parts get `"[<LEVEL>] <text>" CRLF "-"×40 CRLF CRLF` (the part's own line ending)
 * prepended; HTML parts get a `<div role="alert">` with inline styles (no `url()`) right after
 * the `<body …>` start tag (parse5 source offsets), or at the start without a body tag. The text is
 * the rule's `text` (HTML-escaped) or the fixed template of the level; never message data.
 *
 * Message-level skips — signed (S/MIME, PGP), encrypted, too large, no candidate part, every
 * candidate part not editable — **destroy the sink** (like `rewriteEml`) and return the
 * `skipped_*` status: the caller keeps delivering its input object unchanged. Unexpected errors
 * (source failures) are thrown (retryable).
 */

export const BANNER_LEVELS = ['caution', 'warning', 'danger'] as const;
export type BannerLevel = (typeof BANNER_LEVELS)[number];

export const BANNER_TEMPLATES: Readonly<Record<BannerLevel, string>> = Object.freeze({
  caution: 'Be careful with this message. Check the sender before you open links or attachments.',
  warning:
    'This message may be unsafe. Do not open links or attachments unless you trust the sender.',
  danger:
    'This message is likely dangerous. Do not click links, open attachments or reply with information.',
});

const STYLES: Readonly<Record<BannerLevel, string>> = Object.freeze({
  caution: 'border:1px solid #b54708;background:#fffaeb;color:#7a2e0e;',
  warning: 'border:2px solid #dc6803;background:#fef6ee;color:#7e2410;',
  danger: 'border:2px solid #b42318;background:#fef3f2;color:#7a271a;',
});
const COMMON_STYLE =
  'padding:12px;margin:0 0 12px 0;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.4;';

export const BANNER_STATUSES = [
  'applied',
  'skipped_signed',
  'skipped_encrypted',
  'skipped_too_large',
  'skipped_no_text_part',
  'skipped_part',
] as const;
export type BannerStatus = (typeof BANNER_STATUSES)[number];
type BannerSkipStatus = Exclude<BannerStatus, 'applied'>;

/** Why one candidate part was left untouched. */
export const BANNER_PART_SKIP_REASONS = [
  'too_large',
  'unsupported_charset',
  'charset_roundtrip',
  'decode_error',
] as const;
export type BannerPartSkipReason = (typeof BANNER_PART_SKIP_REASONS)[number];

export interface BannerLimits {
  /** `POLICY_BANNER_MAX_PART_BYTES` (encoded bytes of one candidate part). */
  maxPartBytes: number;
  /** `POLICY_COPY_MAX_MESSAGE_BYTES`. */
  maxMessageBytes: number;
}

export interface BannerOptions {
  source: Readable;
  sink: Writable;
  level: BannerLevel;
  /** The WARN rule text (printable ASCII, validated by the policy schema); null → template. */
  text: string | null;
  limits: BannerLimits;
  /** `email_message_parses.structure` content types (signed/encrypted pre-check). */
  structure?: ReadonlyArray<string | { contentType: string }> | null;
  /** Splitter header-block limit (`MIME_MAX_HEADER_BLOCK_BYTES`). */
  maxHeadSize?: number;
}

export interface BannerResult {
  status: BannerStatus;
  partsEdited: number;
  /** Edited part kinds. */
  edited: { text: boolean; html: boolean };
  partsSkipped: number;
  partSkipReasons: Partial<Record<BannerPartSkipReason, number>>;
  /** SHA-256 and size of the output (null when skipped). */
  sha256: string | null;
  sizeBytes: number | null;
}

class BannerSkip extends Error {
  constructor(readonly status: BannerSkipStatus) {
    super(`banner skipped: ${status}`);
    this.name = 'BannerSkip';
  }
}

const escapeHtml = (s: string): string =>
  s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

/** The banner line text (rule text or template), printable ASCII only. */
export function bannerText(level: BannerLevel, text: string | null): string {
  const chosen = text !== null && text.trim().length > 0 ? text : BANNER_TEMPLATES[level];
  // Defence in depth: the policy schema already restricts WARN text to printable ASCII.
  return `[${level.toUpperCase()}] ${chosen.replace(/[^\x20-\x7e]/g, '').slice(0, 256)}`;
}

/** The plain-text banner block with the part's line ending. */
export function textBanner(level: BannerLevel, text: string | null, eol: string): string {
  return `${bannerText(level, text)}${eol}${'-'.repeat(40)}${eol}${eol}`;
}

/** The HTML banner element (inline styles only, escaped text, no resource reference). */
export function htmlBanner(level: BannerLevel, text: string | null): string {
  return `<div role="alert" style="${STYLES[level]}${COMMON_STYLE}">${escapeHtml(bannerText(level, text))}</div>`;
}

/** Offset right after the `<body …>` start tag in the source, or 0 when there is none. */
export function bodyInsertOffset(html: string): number {
  const document = parse(html, { sourceCodeLocationInfo: true });
  const htmlEl = document.childNodes.find((n) => n.nodeName === 'html') as
    | {
        childNodes: Array<{
          nodeName: string;
          sourceCodeLocation?: { startTag?: { endOffset: number } } | null;
        }>;
      }
    | undefined;
  const body = htmlEl?.childNodes.find((n) => n.nodeName === 'body');
  const end = body?.sourceCodeLocation?.startTag?.endOffset;
  return typeof end === 'number' ? end : 0;
}

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

/** S/MIME `application/pkcs7-mime`: signed-data is signed, everything else encrypted. */
function pkcs7Status(node: MimeNode): SignedOrEncrypted {
  const header = node.headers ? node.headers.getFirst('Content-Type') : '';
  return /smime-type\s*=\s*"?signed-data/i.test(header) ? 'skipped_signed' : 'skipped_encrypted';
}

interface PendingPart {
  node: MimeNode;
  kind: 'text' | 'html';
  chunks: Buffer[];
  bytes: number;
}

interface Counters {
  partsEdited: number;
  candidates: number;
  partsSkipped: number;
  partSkipReasons: Partial<Record<BannerPartSkipReason, number>>;
  edited: { text: boolean; html: boolean };
}

class BannerEditor extends Transform {
  private pending: PendingPart | null = null;
  private seenText = false;
  private seenHtml = false;
  private readonly childIndex = new WeakMap<object, number>();

  constructor(
    private readonly options: BannerOptions,
    private readonly counters: Counters,
  ) {
    super({ readableObjectMode: true, writableObjectMode: true });
  }

  override _transform(chunk: SplitterChunk, _e: BufferEncoding, callback: TransformCallback): void {
    try {
      if (chunk.type === 'body' && this.pending) {
        this.pending.chunks.push(chunk.value);
        this.pending.bytes += chunk.value.length;
        if (this.pending.bytes > this.options.limits.maxPartBytes) this.skipPart('too_large');
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
      callback();
    } catch (error) {
      callback(error as Error);
    }
  }

  /** Position of the node among its parent's children (0-based). */
  private indexInParent(node: MimeNode): number {
    const parent = node.parentNode;
    if (!parent) return 0;
    const n = this.childIndex.get(parent) ?? 0;
    this.childIndex.set(parent, n + 1);
    return n;
  }

  private onNode(node: MimeNode): void {
    const index = this.indexInParent(node);
    const contentType = nodeContentType(node);
    if (contentType === 'multipart/signed') throw new BannerSkip('skipped_signed');
    if (contentType === 'application/pkcs7-mime' || contentType === 'application/x-pkcs7-mime') {
      throw new BannerSkip(pkcs7Status(node));
    }
    const structural = detectSignedOrEncrypted([contentType]);
    if (structural) throw new BannerSkip(structural);

    const kind =
      contentType === 'text/html' ? 'html' : contentType === 'text/plain' ? 'text' : null;
    const parent = node.parentNode;
    const relatedNonRoot = parent && parent.multipart === 'related' && index > 0;
    const candidate =
      kind !== null &&
      !node.multipart &&
      node.disposition !== 'attachment' &&
      !node.filename &&
      !insideRfc822(node) &&
      !relatedNonRoot &&
      (kind === 'text' ? !this.seenText : !this.seenHtml);
    if (!candidate) {
      this.push(node);
      return;
    }
    if (kind === 'text') this.seenText = true;
    else this.seenHtml = true;
    this.counters.candidates += 1;
    this.pending = { node, kind, chunks: [], bytes: 0 };
  }

  private skipPart(reason: BannerPartSkipReason): void {
    const part = this.pending;
    if (!part) return;
    this.pending = null;
    this.counters.partsSkipped += 1;
    this.counters.partSkipReasons[reason] = (this.counters.partSkipReasons[reason] ?? 0) + 1;
    this.push(part.node);
    for (const value of part.chunks) this.push({ node: part.node, type: 'body', value });
  }

  private flushPending(): void {
    const part = this.pending;
    if (!part) return;
    const raw = Buffer.concat(part.chunks, part.bytes);
    const node = part.node;
    const encoding = (node.encoding || '7bit').toLowerCase();
    const charset = (node.charset || 'us-ascii').toLowerCase();
    if (!isRewritableCharset(charset)) return this.skipPart('unsupported_charset');
    let decoded: Buffer;
    try {
      if (encoding === 'base64') decoded = libbase64.decode(raw.toString('latin1'));
      else if (encoding === 'quoted-printable') decoded = libqp.decode(raw);
      else if (encoding === '7bit' || encoding === '8bit' || encoding === 'binary') decoded = raw;
      else throw new Error('unknown transfer encoding');
    } catch {
      return this.skipPart('decode_error');
    }
    const text = decodeLossless(decoded, charset);
    if (text === null) return this.skipPart('charset_roundtrip');
    const pgp = inlinePgp(text);
    if (pgp) throw new BannerSkip(pgp === 'encrypted' ? 'skipped_encrypted' : 'skipped_signed');
    this.pending = null;

    const decodedText = decoded.toString('latin1');
    const eol = decodedText.includes('\r\n') ? '\r\n' : decodedText.includes('\n') ? '\n' : '\r\n';
    let next: string;
    if (part.kind === 'text') {
      next = textBanner(this.options.level, this.options.text, eol) + text;
    } else {
      const at = bodyInsertOffset(text);
      next = text.slice(0, at) + htmlBanner(this.options.level, this.options.text) + text.slice(at);
    }
    const bytes = encodeText(next, charset);
    const rawText = raw.toString('latin1');
    const rawEol = rawText.includes('\r\n') ? '\r\n' : rawText.includes('\n') ? '\n' : '\r\n';
    const trailing = /\r?\n$/.exec(rawText)?.[0] ?? '';
    let targetEncoding = encoding;
    if (
      (encoding === '7bit' || encoding === '8bit' || encoding === 'binary') &&
      hasLongLine(bytes)
    ) {
      targetEncoding = 'quoted-printable';
      if (node.headers) node.headers.update('Content-Transfer-Encoding', 'quoted-printable');
    }
    let body: Buffer;
    if (targetEncoding === 'base64') {
      body = Buffer.from(
        libbase64.wrap(libbase64.encode(bytes), 76).replace(/\r?\n/g, rawEol) + trailing,
        'latin1',
      );
    } else if (targetEncoding === 'quoted-printable') {
      let encoded = libqp.wrap(libqp.encode(bytes), 76).replace(/\r?\n/g, rawEol);
      if (encoding !== 'quoted-printable') encoded = encoded.replace(new RegExp(`${rawEol}$`), '');
      body = Buffer.from(encoded + (encoded.endsWith(rawEol) ? '' : trailing), 'latin1');
    } else {
      body = bytes;
    }
    this.counters.partsEdited += 1;
    this.counters.edited[part.kind] = true;
    this.push(node);
    this.push({ node, type: 'body', value: body });
  }
}

class Measure extends Transform {
  readonly hash = createHash('sha256');
  size = 0;
  override _transform(chunk: Buffer, _e: BufferEncoding, callback: TransformCallback): void {
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
  override _transform(chunk: Buffer, _e: BufferEncoding, callback: TransformCallback): void {
    this.size += chunk.length;
    if (this.size > this.max) {
      callback(new BannerSkip('skipped_too_large'));
      return;
    }
    callback(null, chunk);
  }
}

/** The end-of-stream decision: applied, or the reason nothing was edited. */
class Outcome extends Transform {
  constructor(private readonly counters: Counters) {
    super({ readableObjectMode: true, writableObjectMode: true });
  }
  override _transform(chunk: unknown, _e: BufferEncoding, callback: TransformCallback): void {
    callback(null, chunk);
  }
  override _flush(callback: TransformCallback): void {
    if (this.counters.partsEdited > 0) callback();
    else
      callback(
        new BannerSkip(this.counters.candidates > 0 ? 'skipped_part' : 'skipped_no_text_part'),
      );
  }
}

/** Q22: inserts the WARN banner while streaming `source` into `sink`. */
export async function insertWarningBanner(options: BannerOptions): Promise<BannerResult> {
  const counters: Counters = {
    partsEdited: 0,
    candidates: 0,
    partsSkipped: 0,
    partSkipReasons: {},
    edited: { text: false, html: false },
  };
  const result = (status: BannerStatus, measure: Measure | null): BannerResult => ({
    status,
    partsEdited: counters.partsEdited,
    edited: counters.edited,
    partsSkipped: counters.partsSkipped,
    partSkipReasons: counters.partSkipReasons,
    sha256: measure ? measure.hash.digest('hex') : null,
    sizeBytes: measure ? measure.size : null,
  });
  const pre = options.structure ? detectSignedOrEncrypted(options.structure) : null;
  if (pre !== null) {
    const error = new BannerSkip(pre);
    options.source.destroy();
    options.sink.destroy(error);
    return result(pre, null);
  }
  const measure = new Measure();
  try {
    await pipeline(
      options.source,
      new InputCap(options.limits.maxMessageBytes),
      new Splitter({
        ignoreEmbedded: false,
        ...(options.maxHeadSize ? { maxHeadSize: options.maxHeadSize } : {}),
      }),
      new BannerEditor(options, counters),
      new Outcome(counters),
      new Joiner(),
      measure,
      options.sink,
    );
  } catch (error) {
    if (error instanceof BannerSkip) return result(error.status, null);
    throw error;
  }
  return result('applied', measure);
}

/**
 * Buffer convenience for callers that hold the object in memory (≤ the copy size bound): the
 * output is the edited message when applied, else the **input unchanged**.
 */
export async function insertWarningBannerBuffer(
  input: Buffer,
  options: Omit<BannerOptions, 'source' | 'sink'>,
): Promise<{ result: BannerResult; output: Buffer }> {
  const chunks: Buffer[] = [];
  const sink = new PassThrough();
  sink.on('data', (c: Buffer) => chunks.push(c));
  sink.on('error', () => undefined);
  const result = await insertWarningBanner({ ...options, source: Readable.from([input]), sink });
  return { result, output: result.status === 'applied' ? Buffer.concat(chunks) : input };
}

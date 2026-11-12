import { PassThrough, Readable } from 'node:stream';
import { DeleteObjectCommand, GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { type BannerStatus, insertWarningBannerBuffer } from '@email-gateway/mail-safety';
import {
  canonicalJson,
  POLICY_TAG_HEADER,
  POLICY_WARNING_HEADER,
  sha256Hex,
  type WarnLevel,
} from '@email-gateway/policy-dsl';
import {
  rewriteEml,
  type RewriteLimits,
  type RewritePolicy,
  type RewriteSkipReason,
  type RewriteUrlEntry,
} from '@email-gateway/url-security';

/** The header edits of a policy copy (P21): headers built from policy data only, a prefix. */
export interface PolicyCopyEdits {
  headers: ReadonlyArray<{ name: string; value: string }>;
  subjectPrefix: string | null;
}

/** True when the edits change anything (otherwise no copy is made). */
export const hasEdits = (edits: PolicyCopyEdits | null): edits is PolicyCopyEdits =>
  edits !== null && (edits.headers.length > 0 || edits.subjectPrefix !== null);

/** The object tag the MinIO/S3 lifecycle rule `eg-policy-copy-expiry` expires (P21). */
export const POLICY_COPY_OBJECT_TAG = { Key: 'eg-object', Value: 'policy-copy' } as const;
/** `x-amz-tagging` form, set atomically on PutObject / CreateMultipartUpload (never afterwards). */
export const POLICY_COPY_OBJECT_TAGGING = `${POLICY_COPY_OBJECT_TAG.Key}=${POLICY_COPY_OBJECT_TAG.Value}`;

/** The release header of a release copy (step 5.3 Q13.6): the release public id. */
export const QUARANTINE_RELEASE_HEADER = 'X-EG-Quarantine-Release';

/** RFC 5322 line limit (octets, excluding CRLF). */
export const MAX_LINE_OCTETS = 998;

const two = (n: number) => String(n).padStart(2, '0');

/**
 * The deterministic key of a policy copy (P21):
 * `org/<org>/policy/<yyyy>/<mm>/<dd>/<messageId>/r<round>-<first 32 hex of sha256(baseKey | canonical edits)>.eml`
 * (UTC date of `received_at`). A retry of the same round and edits overwrites the same object
 * with the same bytes.
 */
export function policyCopyKey(input: {
  organizationId: bigint;
  messageId: bigint;
  receivedAt: Date;
  round: number;
  baseKey: string;
  edits: PolicyCopyEdits;
  /**
   * Step 5.3 body edits (Q22, Q23): part of the canonical edits only when present, so a 5.2
   * header-only copy keeps its key.
   */
  body?: { banner: { level: WarnLevel; text: string | null } | null; urlRewrite: boolean };
  /** Step 5.3 Q13.6: the release public id of a release copy (`… | releaseId`). */
  releaseId?: string;
}): string {
  const d = input.receivedAt;
  const canonical: Record<string, unknown> = {
    headers: input.edits.headers.map((h) => ({ name: h.name, value: h.value })),
    subjectPrefix: input.edits.subjectPrefix,
  };
  if (input.body !== undefined && (input.body.banner !== null || input.body.urlRewrite)) {
    canonical.banner = input.body.banner;
    canonical.urlRewrite = input.body.urlRewrite;
  }
  const digest = sha256Hex(
    `${input.baseKey}|${canonicalJson(canonical)}${input.releaseId === undefined ? '' : `|${input.releaseId}`}`,
  ).slice(0, 32);
  return [
    'org',
    input.organizationId.toString(),
    'policy',
    String(d.getUTCFullYear()),
    two(d.getUTCMonth() + 1),
    two(d.getUTCDate()),
    input.messageId.toString(),
    `r${input.round}-${digest}.eml`,
  ].join('/');
}

/** True when `key` is a policy copy of `organizationId` (`org/<org>/policy/…`, clean segments). */
export function isPolicyCopyKeyOf(key: string, organizationId: bigint): boolean {
  return (
    key.startsWith(`org/${organizationId.toString()}/policy/`) &&
    !key.split('/').some((segment) => segment === '..' || segment === '.' || segment === '')
  );
}

/** One header field: its lines (each with its own terminator, the last possibly without). */
interface Field {
  name: string | null;
  lines: string[];
}

const REMOVED_HEADERS = new Set([
  POLICY_TAG_HEADER.toLowerCase(),
  POLICY_WARNING_HEADER.toLowerCase(),
  // Step 5.3 Q13.6: a sender can never pre-set the release header either.
  QUARANTINE_RELEASE_HEADER.toLowerCase(),
]);

/** The line terminator style of a header block: the first line's, CRLF when there is none. */
export function lineEnding(header: string): '\r\n' | '\n' {
  const lf = header.indexOf('\n');
  if (lf < 0) return '\r\n';
  return lf > 0 && header[lf - 1] === '\r' ? '\r\n' : '\n';
}

function splitFields(header: string): Field[] {
  const lines = header.match(/[^\n]*\n|[^\n]+$/g) ?? [];
  const fields: Field[] = [];
  for (const line of lines) {
    const continuation = line[0] === ' ' || line[0] === '\t';
    if (continuation && fields.length > 0) {
      fields[fields.length - 1]!.lines.push(line);
      continue;
    }
    const colon = line.indexOf(':');
    const name = colon > 0 ? line.slice(0, colon).replace(/[ \t]+$/, '') : null;
    fields.push({ name, lines: [line] });
  }
  return fields;
}

const stripEol = (line: string): [string, string] => {
  if (line.endsWith('\r\n')) return [line.slice(0, -2), '\r\n'];
  if (line.endsWith('\n')) return [line.slice(0, -1), '\n'];
  return [line, ''];
};

/** The unfolded value of a field without leading whitespace (`Subject:` value). */
function unfoldedValue(field: Field): string {
  const joined = field.lines.map((l) => stripEol(l)[0]).join('');
  const colon = joined.indexOf(':');
  return joined.slice(colon + 1).replace(/^[ \t]+/, '');
}

function prefixSubject(field: Field, prefix: string, eol: string): Field {
  if (unfoldedValue(field).startsWith(prefix)) return field;
  const [first, firstEol] = stripEol(field.lines[0]!);
  const colon = first.indexOf(':');
  const ws = /^[ \t]*/.exec(first.slice(colon + 1))![0];
  const head = first.slice(0, colon + 1) + ws;
  const rest = first.slice(colon + 1 + ws.length);
  // editHeaderBlock terminated every line before this runs.
  const end = firstEol || eol;
  let lines: string[];
  if (rest === '') {
    // The value starts on a continuation line (or is empty): the prefix stands alone here.
    lines = [`${head}${ws === '' ? ' ' : ''}${prefix}${end}`];
  } else {
    const inserted = `${head}${prefix} ${rest}`;
    lines =
      Buffer.byteLength(inserted, 'latin1') > MAX_LINE_OCTETS
        ? [`${head}${prefix}${eol}`, ` ${rest}${end}`]
        : [`${inserted}${end}`];
  }
  return { name: field.name, lines: [...lines, ...field.lines.slice(1)] };
}

/**
 * Applies the P21 header edits to a header block (bytes up to, not including, the empty line).
 * Byte-preserving: the block is handled as latin1 (one char per octet), every untouched line is
 * kept verbatim, and the original line ending (CRLF or LF) is used for inserted lines.
 *
 * 1. Every existing `X-EG-Policy-Tag` / `X-EG-Policy-Warning` / `X-EG-Quarantine-Release` field
 *    (with its continuation lines) is removed (a sender cannot pre-set them in the copy).
 * 2. The new headers are prepended in the order given (`X-EG-Policy-Tag`, then
 *    `X-EG-Policy-Warning`).
 * 3. With a subject prefix: `<prefix> ` is inserted after `Subject:` and its whitespace unless the
 *    unfolded value already starts with the prefix; a line that would exceed 998 octets is folded
 *    at the inserted point; without a Subject, `Subject: <prefix>` is added after the new headers.
 */
export function editHeaderBlock(header: Buffer, edits: PolicyCopyEdits): Buffer {
  const text = header.toString('latin1');
  const eol = lineEnding(text);
  let fields = splitFields(text).filter(
    (f) => f.name === null || !REMOVED_HEADERS.has(f.name.toLowerCase()),
  );
  // A header block whose last line has no terminator gets one before anything follows it.
  const last = fields[fields.length - 1];
  if (last !== undefined) {
    const lastLine = last.lines[last.lines.length - 1]!;
    if (!lastLine.endsWith('\n')) last.lines[last.lines.length - 1] = lastLine + eol;
  }
  const added: string[] = edits.headers.map((h) => `${h.name}: ${h.value}${eol}`);
  if (edits.subjectPrefix !== null) {
    const index = fields.findIndex((f) => f.name?.toLowerCase() === 'subject');
    if (index >= 0) {
      fields = fields.map((f, i) =>
        i === index ? prefixSubject(f, edits.subjectPrefix!, eol) : f,
      );
    } else {
      added.push(`Subject: ${edits.subjectPrefix}${eol}`);
    }
  }
  return Buffer.from(added.join('') + fields.map((f) => f.lines.join('')).join(''), 'latin1');
}

/** Where the header block ends in `data`: index of the empty line and its length, or null. */
export function findHeaderEnd(data: Buffer): { headerEnd: number; separatorLength: number } | null {
  // The message starts with an empty line: no header fields at all.
  if (data[0] === 0x0a) return { headerEnd: 0, separatorLength: 1 };
  if (data[0] === 0x0d && data[1] === 0x0a) return { headerEnd: 0, separatorLength: 2 };
  let from = 0;
  for (;;) {
    const lf = data.indexOf(0x0a, from);
    if (lf < 0) return null;
    const next = lf + 1;
    if (data[next] === 0x0a) return { headerEnd: next, separatorLength: 1 };
    if (data[next] === 0x0d && data[next + 1] === 0x0a) {
      return { headerEnd: next, separatorLength: 2 };
    }
    from = next;
  }
}

/** The result of writing a policy copy. */
export type PolicyCopyResult =
  { result: 'written'; key: string } | { result: 'too_large' } | { result: 'header_too_large' };

class TooLargeError extends Error {
  override readonly name = 'PolicyCopyTooLargeError';
}

/**
 * The body edits of a step 5.3 policy copy (Q22, Q23), applied in this order after the base is
 * read: the policy URL rewrite, then the WARN banner, then the header edits (P21).
 */
export interface BodyEditPlan {
  /** URL_REWRITE after the scan (Q23); null when not eligible or not required. */
  urlRewrite: {
    urlMap: ReadonlyMap<string, RewriteUrlEntry>;
    policy: RewritePolicy;
    clickBaseUrl: string;
    sign: (seq: number) => string;
    limits: RewriteLimits;
  } | null;
  /** WARN body banner (Q22). */
  banner: { level: WarnLevel; text: string | null; maxPartBytes: number } | null;
  /** `email_message_parses.structure` (content types in document order); null when unknown. */
  structure: ReadonlyArray<{ contentType: string }> | null;
  /**
   * URL_REWRITE `ifNotRewritten = quarantine`: a deterministic rewrite skip (other than
   * `no_urls`) stops before anything is written (`unchanged`), so the engine can re-evaluate.
   */
  requireUrlRewrite?: boolean;
}

/** The outcome of a policy copy with body edits. */
export interface EditedCopyResult {
  /** `unchanged`: no edit applied and no header edit: the base object is delivered. */
  result: 'written' | 'too_large' | 'header_too_large' | 'unchanged';
  key?: string;
  /** The banner outcome (null when not requested). */
  banner: Exclude<BannerStatus, never> | null;
  /** The policy URL rewrite outcome (null when not requested). */
  urlRewrite: { status: 'rewritten' | 'skipped'; skipReason: RewriteSkipReason | null } | null;
}

/** Something that writes policy copies (the S3 implementation below; fakes in unit tests). */
export interface PolicyCopyWriter {
  /** Header edits only (step 5.2 P21): streamed. */
  write(request: {
    baseKey: string;
    key: string;
    edits: PolicyCopyEdits;
    signal: AbortSignal;
  }): Promise<PolicyCopyResult>;
  /** Header edits plus body edits (step 5.3 Q22, Q23): bounded in memory. */
  writeEdited(request: {
    baseKey: string;
    key: string;
    edits: PolicyCopyEdits;
    plan: BodyEditPlan;
    signal: AbortSignal;
  }): Promise<EditedCopyResult>;
}

/** A URL rewrite that failed unexpectedly (`skipReason = error`): retryable, never a skip. */
export class PolicyUrlRewriteError extends Error {
  override readonly name = 'PolicyUrlRewriteError';
}

/**
 * Applies the body edits of `plan` and then the header edits to `input` (the whole base object,
 * ≤ the copy size bound), in the Q23 → Q22 → P21 order. Each body step that skips passes its
 * input through unchanged (a skip never corrupts the object). Pure apart from the token signer.
 */
export async function applyCopyEdits(
  input: Buffer,
  edits: PolicyCopyEdits,
  plan: BodyEditPlan,
  limits: { maxMessageBytes: number; maxHeaderBytes: number },
): Promise<{ output: Buffer | null } & Omit<EditedCopyResult, 'key'>> {
  const refused = (result: 'too_large' | 'header_too_large') => ({
    output: null,
    result,
    banner: plan.banner === null ? null : ('skipped_too_large' as const),
    urlRewrite:
      plan.urlRewrite === null
        ? null
        : { status: 'skipped' as const, skipReason: 'too_large' as const },
  });
  if (input.length > limits.maxMessageBytes) return refused('too_large');
  const baseEnd = findHeaderEnd(input);
  if ((baseEnd === null ? input.length : baseEnd.headerEnd) > limits.maxHeaderBytes) {
    return refused('header_too_large');
  }
  let current = input;
  let urlRewrite: EditedCopyResult['urlRewrite'] = null;
  if (plan.urlRewrite !== null) {
    const r = plan.urlRewrite;
    const chunks: Buffer[] = [];
    const sink = new PassThrough();
    sink.on('data', (c: Buffer) => chunks.push(c));
    sink.on('error', () => undefined);
    const rewritten = await rewriteEml({
      source: Readable.from([current]),
      sink,
      urlMap: r.urlMap,
      policy: r.policy,
      clickBaseUrl: r.clickBaseUrl,
      sign: r.sign,
      limits: r.limits,
      structure: plan.structure,
    });
    if (rewritten.status === 'rewritten') {
      current = Buffer.concat(chunks);
      urlRewrite = { status: 'rewritten', skipReason: null };
    } else if (rewritten.skipReason === 'error' || rewritten.skipReason === null) {
      throw new PolicyUrlRewriteError('policy url rewrite failed unexpectedly');
    } else {
      urlRewrite = { status: 'skipped', skipReason: rewritten.skipReason };
      if (plan.requireUrlRewrite === true && rewritten.skipReason !== 'no_urls') {
        return { output: null, result: 'unchanged', banner: null, urlRewrite };
      }
    }
  }
  let banner: BannerStatus | null = null;
  if (plan.banner !== null) {
    const out = await insertWarningBannerBuffer(current, {
      level: plan.banner.level,
      text: plan.banner.text,
      limits: { maxPartBytes: plan.banner.maxPartBytes, maxMessageBytes: limits.maxMessageBytes },
      structure: plan.structure,
    });
    banner = out.result.status;
    current = out.output;
  }
  const bodyChanged = urlRewrite?.status === 'rewritten' || banner === 'applied';
  if (!bodyChanged && !hasEdits(edits)) {
    return { output: null, result: 'unchanged', banner, urlRewrite };
  }
  if (current.length > limits.maxMessageBytes) return refused('too_large');
  const end = findHeaderEnd(current);
  const headerEnd = end?.headerEnd ?? current.length;
  if (headerEnd > limits.maxHeaderBytes) return refused('header_too_large');
  const header = hasEdits(edits)
    ? editHeaderBlock(current.subarray(0, headerEnd), edits)
    : current.subarray(0, headerEnd);
  return {
    output: Buffer.concat([header, current.subarray(headerEnd)]),
    result: 'written',
    banner,
    urlRewrite,
  };
}

/**
 * Streams the base object from the mail bucket, edits its header block and uploads the copy
 * (`@aws-sdk/lib-storage` `Upload`: `ContentType: message/rfc822`, `ContentDisposition:
 * attachment`, `Tagging: eg-object=policy-copy` on the creating request so the object never
 * exists untagged). The body is streamed byte-identical after the edited header. Deterministic
 * refusals (P21, recorded by the engine as TAG/WARN `recorded`): the object is larger than
 * `maxMessageBytes` (`too_large`, from `ContentLength` or counted while streaming) or no empty
 * line is found within `maxHeaderBytes` (`header_too_large`). Every other failure (missing base
 * object, S3 outage, abort) is thrown: retryable, never a silent skip. An upload that fails after
 * starting deletes the key (best effort; it is tagged, so the lifecycle rule expires it anyway).
 */
export class S3PolicyCopyWriter implements PolicyCopyWriter {
  constructor(
    private readonly client: S3Client,
    private readonly bucket: string,
    private readonly limits: { maxMessageBytes: number; maxHeaderBytes: number },
  ) {}

  async write(request: {
    baseKey: string;
    key: string;
    edits: PolicyCopyEdits;
    signal: AbortSignal;
  }): Promise<PolicyCopyResult> {
    const object = await this.client.send(
      new GetObjectCommand({ Bucket: this.bucket, Key: request.baseKey }),
      { abortSignal: request.signal },
    );
    const body = object.Body as Readable | undefined;
    if (body === undefined) throw new Error('policy copy base object has no body');
    if (object.ContentLength !== undefined && object.ContentLength > this.limits.maxMessageBytes) {
      body.destroy();
      return { result: 'too_large' };
    }
    const iterator = body[Symbol.asyncIterator]() as AsyncIterator<Buffer>;
    let buffered = Buffer.alloc(0);
    let end: ReturnType<typeof findHeaderEnd> = null;
    let done = false;
    while (end === null) {
      const next = await iterator.next();
      if (next.done === true) {
        done = true;
        break;
      }
      buffered = Buffer.concat([buffered, Buffer.from(next.value)]);
      end = findHeaderEnd(buffered);
      if (end === null && buffered.length > this.limits.maxHeaderBytes) {
        body.destroy();
        return { result: 'header_too_large' };
      }
      if (buffered.length > this.limits.maxMessageBytes) {
        body.destroy();
        return { result: 'too_large' };
      }
    }
    if (end !== null && end.headerEnd > this.limits.maxHeaderBytes) {
      body.destroy();
      return { result: 'header_too_large' };
    }
    if (end === null && buffered.length > this.limits.maxHeaderBytes) {
      return { result: 'header_too_large' };
    }
    const headerEnd = end?.headerEnd ?? buffered.length;
    const header = editHeaderBlock(buffered.subarray(0, headerEnd), request.edits);
    const rest = buffered.subarray(headerEnd);
    const limit = this.limits.maxMessageBytes;
    let total = buffered.length;
    async function* copy(): AsyncGenerator<Buffer> {
      yield header;
      if (rest.length > 0) yield rest;
      if (done) return;
      for (;;) {
        const next = await iterator.next();
        if (next.done === true) return;
        const chunk = Buffer.from(next.value);
        total += chunk.length;
        if (total > limit) throw new TooLargeError('base object larger than the copy limit');
        yield chunk;
      }
    }
    const upload = new Upload({
      client: this.client,
      params: {
        Bucket: this.bucket,
        Key: request.key,
        Body: Readable.from(copy()),
        ContentType: 'message/rfc822',
        ContentDisposition: 'attachment',
        Tagging: POLICY_COPY_OBJECT_TAGGING,
      },
      leavePartsOnError: false,
    });
    const onAbort = (): void => void upload.abort().catch(() => undefined);
    request.signal.addEventListener('abort', onAbort, { once: true });
    try {
      await upload.done();
      return { result: 'written', key: request.key };
    } catch (error) {
      body.destroy();
      await this.client
        .send(new DeleteObjectCommand({ Bucket: this.bucket, Key: request.key }))
        .catch(() => undefined);
      if (
        error instanceof TooLargeError ||
        (error as { cause?: unknown }).cause instanceof TooLargeError
      ) {
        return { result: 'too_large' };
      }
      throw error;
    } finally {
      request.signal.removeEventListener('abort', onAbort);
    }
  }

  async writeEdited(request: {
    baseKey: string;
    key: string;
    edits: PolicyCopyEdits;
    plan: BodyEditPlan;
    signal: AbortSignal;
  }): Promise<EditedCopyResult> {
    const object = await this.client.send(
      new GetObjectCommand({ Bucket: this.bucket, Key: request.baseKey }),
      { abortSignal: request.signal },
    );
    const body = object.Body as Readable | undefined;
    if (body === undefined) throw new Error('policy copy base object has no body');
    const limit = this.limits.maxMessageBytes;
    const tooLarge = (): EditedCopyResult => ({
      result: 'too_large',
      banner: request.plan.banner === null ? null : 'skipped_too_large',
      urlRewrite:
        request.plan.urlRewrite === null ? null : { status: 'skipped', skipReason: 'too_large' },
    });
    if (object.ContentLength !== undefined && object.ContentLength > limit) {
      body.destroy();
      return tooLarge();
    }
    const chunks: Buffer[] = [];
    let total = 0;
    for await (const chunk of body as AsyncIterable<Buffer>) {
      total += chunk.length;
      if (total > limit) {
        body.destroy();
        return tooLarge();
      }
      chunks.push(Buffer.from(chunk));
    }
    const applied = await applyCopyEdits(
      Buffer.concat(chunks),
      request.edits,
      request.plan,
      this.limits,
    );
    if (applied.output === null) {
      return { result: applied.result, banner: applied.banner, urlRewrite: applied.urlRewrite };
    }
    const upload = new Upload({
      client: this.client,
      params: {
        Bucket: this.bucket,
        Key: request.key,
        Body: applied.output,
        ContentType: 'message/rfc822',
        ContentDisposition: 'attachment',
        Tagging: POLICY_COPY_OBJECT_TAGGING,
      },
      leavePartsOnError: false,
    });
    const onAbort = (): void => void upload.abort().catch(() => undefined);
    request.signal.addEventListener('abort', onAbort, { once: true });
    try {
      await upload.done();
    } catch (error) {
      await this.client
        .send(new DeleteObjectCommand({ Bucket: this.bucket, Key: request.key }))
        .catch(() => undefined);
      throw error;
    } finally {
      request.signal.removeEventListener('abort', onAbort);
    }
    return {
      result: 'written',
      key: request.key,
      banner: applied.banner,
      urlRewrite: applied.urlRewrite,
    };
  }
}

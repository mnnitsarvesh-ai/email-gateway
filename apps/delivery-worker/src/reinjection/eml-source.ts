import { GetObjectCommand, type S3Client } from '@aws-sdk/client-s3';
import type { Readable } from 'node:stream';

/** The approval's object does not exist (R8 step 2: `failed`, reason `content_missing`). */
export class ContentMissingError extends Error {
  override readonly name = 'ContentMissingError';
}

/** The object key is not under the reinjection's organization prefix (never read). */
export class ForeignObjectKeyError extends Error {
  override readonly name = 'ForeignObjectKeyError';
}

export interface HeaderSummary {
  /** Number of `Received:` header fields. */
  receivedCount: number;
  /** Every `X-Gateway-Trace` value, unfolded. */
  traces: string[];
  /** False when the header block is longer than the read cap (counts cover the cap only). */
  complete: boolean;
  /** Bytes of the header block (or of the cap) already read from the stream. */
  bytesRead: number;
}

export interface EmlStream {
  /** Object size from S3 (`ContentLength`), null when unknown. */
  size: number | null;
  header: HeaderSummary;
  /** The whole object: the already-read prefix, then the rest of the S3 stream. */
  body: AsyncIterable<Uint8Array>;
  /** Releases the S3 connection when the body is not (fully) consumed. */
  destroy(): void;
}

const HEADER_END = [Buffer.from('\r\n\r\n'), Buffer.from('\n\n')] as const;

function headerEnd(buffer: Buffer, limit: number): number {
  let best = -1;
  for (const marker of HEADER_END) {
    const at = buffer.indexOf(marker);
    if (at !== -1 && at < limit && (best === -1 || at < best)) best = at;
  }
  return best;
}

/** Unfolded header fields (RFC 5322 §2.2.3) of a header block: lower-cased names, raw values. */
export function headerFields(text: string): { name: string; value: string }[] {
  const fields: { name: string; value: string }[] = [];
  let current: { name: string; value: string } | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.length === 0) break;
    if (line[0] === ' ' || line[0] === '\t') {
      if (current) current.value += line;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0 || /\s/.test(line.slice(0, colon))) {
      current = null;
      continue;
    }
    current = { name: line.slice(0, colon).toLowerCase(), value: line.slice(colon + 1) };
    fields.push(current);
  }
  return fields.map(({ name, value }) => ({ name, value: value.trim() }));
}

/** Counts `Received:` and collects `X-Gateway-Trace` values of a header block. */
export function summarizeHeaders(block: Buffer, complete: boolean): HeaderSummary {
  let receivedCount = 0;
  const traces: string[] = [];
  for (const field of headerFields(block.toString('utf8'))) {
    if (field.name === 'received') receivedCount += 1;
    else if (field.name === 'x-gateway-trace') traces.push(field.value);
  }
  return { receivedCount, traces, complete, bytesRead: block.length };
}

function isNoSuchKey(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const e = error as { name?: unknown; Code?: unknown; $metadata?: { httpStatusCode?: number } };
  return e.name === 'NoSuchKey' || e.Code === 'NoSuchKey' || e.$metadata?.httpStatusCode === 404;
}

/**
 * Opens the EML stream (R8 step 2): checks the key is under `org/<organizationId>/`, issues
 * `GetObject`, and reads only the header block (≤ `maxHeaderBytes`) before anything is sent,
 * so the hop check runs before connecting. The message is never buffered whole: the body
 * replays the header prefix and then continues the S3 stream.
 */
export async function openEml(
  s3: Pick<S3Client, 'send'>,
  bucket: string,
  key: string,
  organizationId: bigint,
  maxHeaderBytes: number,
): Promise<EmlStream> {
  if (!key.startsWith(`org/${organizationId.toString()}/`)) {
    throw new ForeignObjectKeyError('object key is outside the organization prefix');
  }
  let result;
  try {
    result = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  } catch (err) {
    if (isNoSuchKey(err)) throw new ContentMissingError('EML object not found');
    throw err;
  }
  const stream = result.Body as Readable | undefined;
  if (!stream || typeof (stream as Partial<Readable>)[Symbol.asyncIterator] !== 'function') {
    throw new Error('S3 GetObject returned no stream');
  }
  const iterator = (stream as AsyncIterable<Uint8Array>)[Symbol.asyncIterator]();
  let prefix = Buffer.alloc(0);
  let end = -1;
  let done = false;
  try {
    while (end === -1 && prefix.length < maxHeaderBytes) {
      const next = await iterator.next();
      if (next.done) {
        done = true;
        break;
      }
      prefix = Buffer.concat([prefix, Buffer.from(next.value)]);
      end = headerEnd(prefix, maxHeaderBytes);
    }
  } catch (err) {
    stream.destroy();
    throw err;
  }
  const complete = end !== -1 || done;
  const blockLength = end !== -1 ? end : Math.min(prefix.length, maxHeaderBytes);
  const header = summarizeHeaders(prefix.subarray(0, blockLength), complete);
  const already = prefix;
  async function* body(): AsyncGenerator<Uint8Array> {
    if (already.length > 0) yield already;
    if (done) return;
    for (;;) {
      const next = await iterator.next();
      if (next.done) return;
      yield next.value;
    }
  }
  return {
    size: typeof result.ContentLength === 'number' ? result.ContentLength : null,
    header,
    body: body(),
    destroy: () => stream.destroy(),
  };
}

import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { DEFAULT_MIME_LIMITS, type MimeLimits } from '../src/limits';
import { parseMessage } from '../src/parse-message';
import type { MimeParseResult, PartInfo, PartSink, PartWriter, StoredPart } from '../src/types';

export interface MemoryObject {
  info: PartInfo;
  data: Buffer;
}

/**
 * In-memory PartSink for tests: objects become visible only on finish, abort removes the
 * pending part, and hooks let a test inject failures or observe backpressure.
 */
export class MemorySink implements PartSink {
  readonly objects = new Map<string, MemoryObject>();
  readonly opened: PartInfo[] = [];
  readonly aborted: PartInfo[] = [];
  readonly ranges: { key: string; start: number; end: number }[] = [];
  failOpen: Error | null = null;
  failWriteAfterBytes: { bytes: number; error: Error } | null = null;
  failReadRange: Error | null = null;
  writeDelayMs = 0;
  inFlight = 0;

  open(info: PartInfo): Promise<PartWriter> {
    if (this.failOpen) return Promise.reject(this.failOpen);
    this.opened.push(info);
    const key = `part/${info.partIndex}.${info.kind === 'attachment' ? 'att' : info.kind}`;
    const chunks: Buffer[] = [];
    let written = 0;
    let state: 'open' | 'finished' | 'aborted' = 'open';
    const writer: PartWriter = {
      write: async (chunk: Buffer): Promise<void> => {
        if (state !== 'open') throw new Error(`write on a ${state} writer`);
        this.inFlight++;
        try {
          if (this.writeDelayMs)
            await new Promise((resolve) => setTimeout(resolve, this.writeDelayMs));
          written += chunk.length;
          if (this.failWriteAfterBytes && written > this.failWriteAfterBytes.bytes) {
            throw this.failWriteAfterBytes.error;
          }
          chunks.push(Buffer.from(chunk));
        } finally {
          this.inFlight--;
        }
      },
      finish: (): Promise<StoredPart> => {
        if (state !== 'open') return Promise.reject(new Error(`finish on a ${state} writer`));
        state = 'finished';
        const data = Buffer.concat(chunks);
        this.objects.set(key, { info, data });
        return Promise.resolve(this.stored(key));
      },
      abort: (): Promise<void> => {
        state = 'aborted';
        this.aborted.push(info);
        return Promise.resolve();
      },
    };
    return Promise.resolve(writer);
  }

  stored(key: string): StoredPart {
    return {
      key,
      readRange: (start: number, end: number): Promise<Buffer> => {
        this.ranges.push({ key, start, end });
        if (this.failReadRange) return Promise.reject(this.failReadRange);
        const object = this.objects.get(key);
        if (!object) return Promise.reject(new Error('no such object'));
        return Promise.resolve(object.data.subarray(start, end + 1));
      },
    };
  }

  text(key: string | null | undefined): string {
    if (!key) throw new Error('no key');
    const object = this.objects.get(key);
    if (!object) throw new Error(`no object ${key}`);
    return object.data.toString('utf8');
  }
}

export function limits(overrides: Partial<MimeLimits> = {}): MimeLimits {
  return { ...DEFAULT_MIME_LIMITS, ...overrides };
}

export function sha256(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Feeds a buffer in fixed-size chunks (mailsplit sees realistic write boundaries). */
export function chunked(data: Buffer, size = 64 * 1024): Readable {
  return Readable.from(
    (function* () {
      for (let offset = 0; offset < data.length; offset += size)
        yield data.subarray(offset, offset + size);
    })(),
  );
}

export async function parse(
  message: Buffer | string,
  options: {
    limits?: Partial<MimeLimits>;
    sink?: MemorySink;
    signal?: AbortSignal;
    chunkSize?: number;
  } = {},
): Promise<{ result: MimeParseResult; sink: MemorySink }> {
  const sink = options.sink ?? new MemorySink();
  const data = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
  const result = await parseMessage(chunked(data, options.chunkSize), {
    limits: limits(options.limits),
    sink,
    signal: options.signal ?? new AbortController().signal,
  });
  return { result, sink };
}

/** Joins lines with CRLF. */
export function crlf(...lines: string[]): string {
  return lines.join('\r\n');
}

export function simpleMessage(headers: string[], body: string): string {
  return crlf(...headers, '', body);
}

export interface PartSpec {
  headers: string[];
  body: string | Buffer;
}

/** A multipart message (or part) from parts; the closing delimiter can be left out. */
export function multipart(
  subtype: string,
  boundary: string,
  parts: PartSpec[],
  options: { headers?: string[]; close?: boolean } = {},
): Buffer {
  const pieces: Buffer[] = [
    Buffer.from(
      crlf(
        ...(options.headers ?? []),
        `Content-Type: multipart/${subtype}; boundary="${boundary}"`,
        '',
        'preamble',
        '',
      ),
    ),
  ];
  for (const part of parts) {
    pieces.push(Buffer.from(crlf(`--${boundary}`, ...part.headers, '', '')));
    pieces.push(typeof part.body === 'string' ? Buffer.from(part.body) : part.body);
    pieces.push(Buffer.from('\r\n'));
  }
  if (options.close ?? true) pieces.push(Buffer.from(`--${boundary}--\r\n`));
  return Buffer.concat(pieces);
}

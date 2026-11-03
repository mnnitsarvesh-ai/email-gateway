import { createHash, type Hash } from 'node:crypto';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { DEFAULT_MIME_LIMITS } from '../src/limits';
import { parseMessage } from '../src/parse-message';
import type { PartInfo, PartSink, PartWriter, StoredPart } from '../src/types';

const MiB = 1024 * 1024;

/** Hashes and counts what it is given and keeps nothing (large tests measure the parser). */
class HashingSink implements PartSink {
  readonly parts = new Map<string, { info: PartInfo; sha256: string; size: number }>();
  aborted = 0;
  onWrite: () => void = () => undefined;

  open(info: PartInfo): Promise<PartWriter> {
    const hash = createHash('sha256');
    let size = 0;
    const key = `part/${info.partIndex}`;
    return Promise.resolve({
      write: (chunk: Buffer) => {
        hash.update(chunk);
        size += chunk.length;
        this.onWrite();
        return Promise.resolve();
      },
      finish: (): Promise<StoredPart> => {
        this.parts.set(key, { info, sha256: hash.digest('hex'), size });
        return Promise.resolve({ key, readRange: () => Promise.reject(new Error('not stored')) });
      },
      abort: () => {
        this.aborted++;
        return Promise.resolve();
      },
    });
  }
}

/** A deterministic block whose length is a multiple of 57, so its base64 is whole 76-char lines. */
function block(seed: number, length = 57 * 1024): Buffer {
  const data = Buffer.alloc(length);
  let state = seed >>> 0;
  for (let index = 0; index < length; index++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    data[index] = state >>> 24;
  }
  return data;
}

interface Expected {
  input: Hash;
  bytes: number;
}

/** Streams pieces from a generator while hashing them, so no test builds the message in memory. */
function stream(pieces: () => Generator<Buffer>, expected: Expected): Readable {
  return Readable.from(
    (function* () {
      for (const piece of pieces()) {
        expected.input.update(piece);
        expected.bytes += piece.length;
        yield piece;
      }
    })(),
  );
}

function* base64Lines(data: Buffer, repeat: number, hash: Hash): Generator<Buffer> {
  const encoded = Buffer.from(data.toString('base64').replace(/.{76}/g, '$&\r\n'));
  for (let index = 0; index < repeat; index++) {
    hash.update(data);
    yield encoded;
  }
}

describe('large messages', () => {
  it('parses a 20 MiB single-line base64 body with bounded heap', async () => {
    const data = block(7, 48 * 1024);
    const chunk = Buffer.from(data.toString('base64')); // 64 KiB, no line break anywhere
    const chunks = 320; // 20 MiB of base64 on one line
    const decoded = createHash('sha256');
    const expected: Expected = { input: createHash('sha256'), bytes: 0 };
    const input = stream(function* () {
      yield Buffer.from(
        'Subject: one line\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n',
      );
      for (let index = 0; index < chunks; index++) {
        decoded.update(data);
        yield chunk;
      }
    }, expected);
    const sink = new HashingSink();
    const baseline = process.memoryUsage().heapUsed;
    let peak = baseline;
    sink.onWrite = () => {
      peak = Math.max(peak, process.memoryUsage().heapUsed);
    };
    const result = await parseMessage(input, {
      limits: { ...DEFAULT_MIME_LIMITS },
      sink,
      signal: new AbortController().signal,
    });
    expect(result.status).toBe('parsed');
    expect(result.stats.bytesRead).toBe(expected.bytes);
    expect(result.stats.sha256).toBe(expected.input.digest('hex'));
    const [attachment] = result.attachments;
    expect(attachment?.sizeBytes).toBe(chunks * data.length);
    expect(attachment?.sha256).toBe(decoded.digest('hex'));
    expect(peak - baseline).toBeLessThan(64 * MiB);
  });

  it('parses a message near MIME_MAX_MESSAGE_BYTES streamed from a generator, with a 20 MiB attachment', async () => {
    const expected: Expected = { input: createHash('sha256'), bytes: 0 };
    const text = createHash('sha256');
    const big = createHash('sha256');
    const second = createHash('sha256');
    const line = Buffer.from(`${'The quick brown fox jumps over the lazy dog. '.repeat(2)}\r\n`);
    const textLines = Math.floor((9 * MiB) / line.length);
    const input = stream(function* () {
      yield Buffer.from(
        'From: big@example.com\r\nSubject: near the limit\r\nContent-Type: multipart/mixed; boundary="big"\r\n\r\n' +
          '--big\r\nContent-Type: text/plain\r\n\r\n',
      );
      for (let index = 0; index < textLines; index++) {
        // The line ending before the delimiter belongs to the delimiter.
        text.update(index === textLines - 1 ? line.subarray(0, line.length - 2) : line);
        yield line;
      }
      yield Buffer.from(
        '--big\r\nContent-Type: application/octet-stream; name="big.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\n',
      );
      yield* base64Lines(block(1), Math.round((20 * MiB) / (57 * 1024)), big);
      yield Buffer.from(
        '--big\r\nContent-Type: application/pdf; name="second.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\n',
      );
      yield* base64Lines(block(2), Math.round((9.5 * MiB) / (57 * 1024)), second);
      yield Buffer.from('--big--\r\n');
    }, expected);
    const sink = new HashingSink();
    const result = await parseMessage(input, {
      limits: { ...DEFAULT_MIME_LIMITS },
      sink,
      signal: new AbortController().signal,
    });
    expect(expected.bytes).toBeGreaterThan(49 * MiB);
    expect(expected.bytes).toBeLessThanOrEqual(DEFAULT_MIME_LIMITS.maxMessageBytes);
    expect(result).toMatchObject({ status: 'parsed', limitsExceeded: [], defects: [] });
    expect(result.stats).toMatchObject({
      bytesRead: expected.bytes,
      sha256: expected.input.digest('hex'),
      inputComplete: true,
    });
    expect(result.textBody?.sha256).toBe(text.digest('hex'));
    expect(result.attachments.map((attachment) => attachment.sha256)).toEqual([
      big.digest('hex'),
      second.digest('hex'),
    ]);
    expect(result.attachments[0]?.sizeBytes).toBeGreaterThanOrEqual(20 * MiB - 57 * 1024);
    expect(sink.parts.size).toBe(3);
  });

  it('does not store a body over MIME_MAX_BODY_BYTES or an attachment over MIME_MAX_ATTACHMENT_BYTES', async () => {
    const expected: Expected = { input: createHash('sha256'), bytes: 0 };
    const attachmentHash = createHash('sha256');
    const line = Buffer.from(`${'x'.repeat(1022)}\r\n`);
    const input = stream(function* () {
      yield Buffer.from(
        'Subject: over\r\nContent-Type: multipart/mixed; boundary="o"\r\n\r\n--o\r\nContent-Type: text/plain\r\n\r\n',
      );
      for (let index = 0; index < 10 * 1024; index++) yield line; // 10 MiB + the delimiter's CRLF trimmed
      yield Buffer.from(
        'x\r\n--o\r\nContent-Type: application/octet-stream; name="over.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\n',
      );
      yield* base64Lines(block(3), Math.ceil((25 * MiB + 1) / (57 * 1024)), attachmentHash);
      yield Buffer.from('--o--\r\n');
    }, expected);
    const sink = new HashingSink();
    const result = await parseMessage(input, {
      limits: { ...DEFAULT_MIME_LIMITS },
      sink,
      signal: new AbortController().signal,
    });
    expect(result.status).toBe('parse_limit_exceeded');
    expect(result.limitsExceeded).toEqual(['body_size', 'attachment_size']);
    expect(result.textBody).toMatchObject({ key: null, flags: ['not_stored_size_limit'] });
    expect(result.textBody?.sizeBytes).toBeGreaterThan(DEFAULT_MIME_LIMITS.maxBodyBytes);
    expect(result.attachments[0]).toMatchObject({
      key: null,
      sha256: attachmentHash.digest('hex'),
    });
    expect(result.attachments[0]?.sizeBytes).toBeGreaterThan(
      DEFAULT_MIME_LIMITS.maxAttachmentBytes,
    );
    expect(sink.aborted).toBe(2);
    expect(sink.parts.size).toBe(0);
    expect(result.stats.inputComplete).toBe(true);
  });

  it('stops reading a message over MIME_MAX_MESSAGE_BYTES', async () => {
    const expected: Expected = { input: createHash('sha256'), bytes: 0 };
    const chunk = Buffer.from(`${'y'.repeat(1022)}\r\n`.repeat(1024));
    let produced = 0;
    const input = stream(function* () {
      yield Buffer.from('Subject: too big\r\nContent-Type: application/octet-stream\r\n\r\n');
      for (let index = 0; index < 60; index++) {
        produced += chunk.length;
        yield chunk;
      }
    }, expected);
    const limits = {
      ...DEFAULT_MIME_LIMITS,
      maxAttachmentBytes: DEFAULT_MIME_LIMITS.maxMessageBytes,
    };
    const sink = new HashingSink();
    const result = await parseMessage(input, {
      limits,
      sink,
      signal: new AbortController().signal,
    });
    expect(result.limitsExceeded).toEqual(['message_size']);
    expect(result.structure[0]?.truncated).toBe(true);
    expect(sink.aborted).toBe(1);
    expect(result.stats.inputComplete).toBe(false);
    expect(result.stats.bytesRead).toBeLessThanOrEqual(
      DEFAULT_MIME_LIMITS.maxMessageBytes + chunk.length,
    );
    expect(produced).toBeLessThan(60 * chunk.length);
  });
});

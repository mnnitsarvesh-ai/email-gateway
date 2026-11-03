import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { MAX_PART_PATH_CHARS } from '../src/constants';
import { parseMessage } from '../src/parse-message';
import {
  crlf,
  limits,
  MemorySink,
  multipart,
  parse,
  type PartSpec,
  sha256,
  simpleMessage,
} from './helpers';

const fixture = (name: string): Buffer => readFileSync(join(__dirname, 'fixtures', name));
const textPart = (body: string) => ({ headers: ['Content-Type: text/plain'], body });
const attachmentPart = (name: string, body: string | Buffer) => ({
  headers: [
    `Content-Type: application/octet-stream; name="${name}"`,
    'Content-Disposition: attachment',
  ],
  body,
});

describe('message_size', () => {
  const message = Buffer.from(simpleMessage(['Subject: size'], 'x'.repeat(1000)));

  it('passes at the limit', async () => {
    const { result } = await parse(message, { limits: { maxMessageBytes: message.length } });
    expect(result.status).toBe('parsed');
    expect(result.stats.inputComplete).toBe(true);
  });

  it('stops reading at limit + 1 and aborts the in-flight part', async () => {
    // A paced input, so mailsplit has emitted the root before the limit is reached.
    const paced = Readable.from(
      (async function* () {
        for (let offset = 0; offset < message.length; offset += 256) {
          yield message.subarray(offset, offset + 256);
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
      })(),
    );
    const sink = new MemorySink();
    const result = await parseMessage(paced, {
      limits: limits({ maxMessageBytes: message.length - 1 }),
      sink,
      signal: new AbortController().signal,
    });
    expect(result.status).toBe('parse_limit_exceeded');
    expect(result.limitsExceeded).toEqual(['message_size']);
    expect(result.stats.inputComplete).toBe(false);
    expect(result.textBody).toBeNull();
    expect(result.structure[0]?.truncated).toBe(true);
    expect(sink.aborted).toHaveLength(1);
    expect(sink.objects.size).toBe(0);
  });
});

describe('nesting_depth', () => {
  it('passes at the limit (depth 10)', async () => {
    const { result } = await parse(fixture('depth-at-limit.eml'));
    expect(result.status).toBe('parsed');
    expect(result.stats.maxDepth).toBe(10);
    expect(result.textBody?.partIndex).toBe(10);
  });

  it('stops at limit + 1 and marks the node truncated', async () => {
    const { result, sink } = await parse(fixture('depth-over-limit.eml'));
    expect(result.limitsExceeded).toEqual(['nesting_depth']);
    expect(result.structure.at(-1)).toMatchObject({ depth: 11, truncated: true });
    expect(result.textBody).toBeNull();
    expect(sink.opened).toHaveLength(0);
  });

  it('counts the root of an embedded message one level below its container', async () => {
    const inner = crlf('Content-Type: text/plain', '', 'inner');
    const message = multipart('mixed', 'b', [
      { headers: ['Content-Type: message/rfc822'], body: inner },
    ]);
    const { result } = await parse(message, { limits: { maxDepth: 2 } });
    expect(result.structure.map((node) => [node.kind, node.depth])).toEqual([
      ['container', 0],
      ['message', 1],
      ['attachment', 2],
    ]);
    const over = await parse(message, { limits: { maxDepth: 1 } });
    expect(over.result.limitsExceeded).toEqual(['nesting_depth']);
  });
});

describe('part_path length (MAX_PART_PATH_CHARS)', () => {
  /**
   * `levels` nested multiparts; in each, 9 small attachments come before the nested one, so its
   * child number is 10 and every level adds 3 characters ('.10') to the path.
   */
  const wide = (levels: number): Buffer => {
    const node = (level: number): PartSpec => {
      if (level === levels) return textPart('deep');
      const children = [
        ...Array.from({ length: 9 }, (_, i) => attachmentPart(`f${level}-${i}.bin`, 'x')),
        node(level + 1),
      ];
      const body = [
        ...children.map((child) =>
          crlf(`--b${level}`, ...child.headers, '', child.body.toString()),
        ),
        `--b${level}--`,
        '',
      ].join('\r\n');
      return { headers: [`Content-Type: multipart/mixed; boundary="b${level}"`], body };
    };
    const root = node(0);
    return Buffer.from(crlf(...root.headers, '', root.body.toString()));
  };
  const deep = { maxDepth: 50, maxParts: 1000, maxAttachments: 1000 };

  it('records a leaf whose path is exactly at the cap', async () => {
    const { result } = await parse(wide(42), { limits: deep });
    expect(result.limitsExceeded).toEqual([]);
    expect(result.structure.at(-1)).toMatchObject({ depth: 42 });
    expect(result.structure.at(-1)!.path).toHaveLength(127);
  });

  it('stops as nesting_depth before a path longer than the column, within maxDepth', async () => {
    const { result } = await parse(wide(45), { limits: deep });
    expect(result.limitsExceeded).toEqual(['nesting_depth']);
    const last = result.structure.at(-1)!;
    expect(last).toMatchObject({ depth: 43, truncated: true });
    expect(last.path.length).toBeGreaterThan(MAX_PART_PATH_CHARS);
    expect(result.attachments.length).toBeGreaterThan(300);
    for (const attachment of result.attachments) {
      expect(attachment.partPath.length).toBeLessThanOrEqual(MAX_PART_PATH_CHARS);
    }
  });
});

describe('part_count', () => {
  const message = (leaves: number) =>
    multipart(
      'mixed',
      'b',
      Array.from({ length: leaves }, (_, index) => textPart(`p${index}`)),
    );

  it('passes with root + leaves = limit', async () => {
    const { result } = await parse(message(4), { limits: { maxParts: 5 } });
    expect(result.status).toBe('parsed');
    expect(result.stats.partCount).toBe(5);
  });

  it('stops at limit + 1 keeping the parts completed before', async () => {
    const { result, sink } = await parse(message(5), { limits: { maxParts: 5 } });
    expect(result.limitsExceeded).toEqual(['part_count']);
    expect(result.structure).toHaveLength(5);
    expect(result.attachments).toHaveLength(3);
    expect(sink.objects.size).toBe(4);
  });

  it('maps mailsplit maxChildNodes (nodes that never finish their headers) to part_count', async () => {
    const flood = crlf(
      'Content-Type: multipart/mixed; boundary="b"',
      '',
      ...Array.from({ length: 20 }, () => '--b'),
      '',
    );
    const { result } = await parse(flood, { limits: { maxParts: 5 } });
    expect(result.limitsExceeded).toEqual(['part_count']);
    expect(result.status).toBe('parse_limit_exceeded');
  });
});

describe('header_count', () => {
  const headers = (count: number) =>
    Array.from({ length: count }, (_, index) => `X-H${index}: ${index}`);

  it('passes at the limit and stops at limit + 1, in any node', async () => {
    expect(
      (await parse(simpleMessage(headers(10), 'b'), { limits: { maxHeaders: 10 } })).result.status,
    ).toBe('parsed');
    const root = await parse(simpleMessage(headers(11), 'b'), { limits: { maxHeaders: 10 } });
    expect(root.result.limitsExceeded).toEqual(['header_count']);
    expect(root.result.structure[0]?.truncated).toBe(true);
    const child = multipart('mixed', 'b', [{ headers: headers(11), body: 'x' }]);
    expect((await parse(child, { limits: { maxHeaders: 10 } })).result.limitsExceeded).toEqual([
      'header_count',
    ]);
  });
});

describe('header_line_length', () => {
  it('passes at the limit and stops at limit + 1 (unfolded bytes)', async () => {
    const field = (bytes: number) => `X-Long: ${'a'.repeat(bytes - 8)}`;
    expect(
      (await parse(simpleMessage([field(100)], 'b'), { limits: { maxHeaderLineBytes: 100 } }))
        .result.status,
    ).toBe('parsed');
    const folded = `X-Long: ${'a'.repeat(40)}\r\n ${'b'.repeat(52)}`;
    expect(
      (await parse(simpleMessage([folded], 'b'), { limits: { maxHeaderLineBytes: 100 } })).result
        .limitsExceeded,
    ).toEqual(['header_line_length']);
    expect(
      (await parse(simpleMessage([field(101)], 'b'), { limits: { maxHeaderLineBytes: 100 } }))
        .result.limitsExceeded,
    ).toEqual(['header_line_length']);
  });
});

describe('header_block_size', () => {
  // mailsplit counts every header line as at least 64 bytes, plus the blank line ending the block.
  const lines = Array.from(
    { length: 10 },
    (_, index) => `X-H${index}: ${'v'.repeat(62 - `X-H${index}: `.length)}`,
  );
  const message = simpleMessage(lines, 'body');
  const cost = 10 * 64 + 2;

  it('passes at the limit', async () => {
    const { result } = await parse(message, {
      limits: { maxHeaderBlockBytes: cost, maxHeaderLineBytes: 100 },
    });
    expect(result.status).toBe('parsed');
  });

  it('stops at limit + 1 (mailsplit maxHeadSize)', async () => {
    const { result } = await parse(message, {
      limits: { maxHeaderBlockBytes: cost - 1, maxHeaderLineBytes: 100 },
    });
    expect(result.limitsExceeded).toEqual(['header_block_size']);
    expect(result.status).toBe('parse_limit_exceeded');
    expect(result.stats.inputComplete).toBe(true);
  });

  it('bounds a header block that never ends', async () => {
    const endless = Buffer.alloc(2 * 1024 * 1024, 'a');
    const { result } = await parse(endless, {
      limits: { maxHeaderBlockBytes: 4096, maxHeaderLineBytes: 1024 },
    });
    expect(result.limitsExceeded).toEqual(['header_block_size']);
    expect(result.stats.bytesRead).toBe(endless.length);
  });
});

describe('attachment_count', () => {
  const message = (count: number) =>
    multipart('mixed', 'b', [
      textPart('body'),
      ...Array.from({ length: count }, (_, index) => attachmentPart(`a${index}.bin`, `${index}`)),
    ]);

  it('passes at the limit and stops at limit + 1', async () => {
    expect(
      (await parse(message(3), { limits: { maxAttachments: 3 } })).result.attachments,
    ).toHaveLength(3);
    const { result, sink } = await parse(message(4), { limits: { maxAttachments: 3 } });
    expect(result.limitsExceeded).toEqual(['attachment_count']);
    expect(result.attachments).toHaveLength(3);
    expect(result.structure.at(-1)?.truncated).toBe(true);
    expect(sink.opened).toHaveLength(4);
  });
});

describe('attachment_size', () => {
  const message = (size: number) =>
    multipart('mixed', 'b', [
      attachmentPart('big.bin', 'z'.repeat(size)),
      attachmentPart('after.bin', 'after'),
    ]);

  it('stores an attachment at the limit', async () => {
    const { result } = await parse(message(1000), { limits: { maxAttachmentBytes: 1000 } });
    expect(result.status).toBe('parsed');
    expect(result.attachments[0]?.key).not.toBeNull();
  });

  it('does not store one at limit + 1, keeps hashing and continues the parse', async () => {
    const { result, sink } = await parse(message(1001), {
      limits: { maxAttachmentBytes: 1000 },
      chunkSize: 300,
    });
    expect(result.status).toBe('parse_limit_exceeded');
    expect(result.limitsExceeded).toEqual(['attachment_size']);
    const [big, after] = result.attachments;
    expect(big).toMatchObject({ key: null, sizeBytes: 1001, sha256: sha256('z'.repeat(1001)) });
    expect(big?.flags).toContain('not_stored_size_limit');
    expect(after?.key).not.toBeNull();
    expect(sink.aborted.map((info) => info.partIndex)).toEqual([1]);
    expect([...sink.objects.keys()]).toEqual(['part/2.att']);
  });
});

describe('body_size', () => {
  it('counts decoded and UTF-8 converted bytes', async () => {
    // 600 latin1 bytes "é" become 1 200 UTF-8 bytes.
    const body = Buffer.concat([
      Buffer.from(
        crlf(
          'Content-Type: text/plain; charset=iso-8859-1',
          'Content-Transfer-Encoding: 8bit',
          '',
          '',
        ),
      ),
      Buffer.alloc(600, 0xe9),
    ]);
    const atLimit = await parse(body, { limits: { maxBodyBytes: 1200 } });
    expect(atLimit.result.textBody).toMatchObject({ sizeBytes: 1200 });
    expect(atLimit.result.textBody?.key).not.toBeNull();
    const over = await parse(body, { limits: { maxBodyBytes: 1199 } });
    expect(over.result.limitsExceeded).toEqual(['body_size']);
    expect(over.result.textBody).toMatchObject({
      key: null,
      sizeBytes: 1200,
      flags: ['not_stored_size_limit'],
    });
    expect(over.result.textBody?.sha256).toBe(sha256(Buffer.from('é'.repeat(600))));
    expect(over.sink.aborted).toHaveLength(1);
  });
});

describe('decoded_ratio', () => {
  const identity = simpleMessage(['Content-Type: application/octet-stream'], 'r'.repeat(70_000));
  const base64 = simpleMessage(
    ['Content-Type: application/octet-stream', 'Content-Transfer-Encoding: base64'],
    Buffer.alloc(100_000, 1).toString('base64').replace(/.{76}/g, '$&\r\n'),
  );

  it('passes at the limit (identity encoding is exactly 1)', async () => {
    expect((await parse(identity, { limits: { maxDecodedRatio: 1 } })).result.status).toBe(
      'parsed',
    );
    expect((await parse(base64, { limits: { maxDecodedRatio: 0.75 } })).result.status).toBe(
      'parsed',
    );
  });

  it('stops above the limit once 64 KiB are decoded', async () => {
    const { result, sink } = await parse(identity, { limits: { maxDecodedRatio: 0.999 } });
    expect(result.limitsExceeded).toEqual(['decoded_ratio']);
    expect(result.structure[0]?.truncated).toBe(true);
    expect(result.attachments).toHaveLength(0);
    expect(sink.aborted).toHaveLength(1);
    expect(
      (await parse(base64, { limits: { maxDecodedRatio: 0.7 } })).result.limitsExceeded,
    ).toEqual(['decoded_ratio']);
  });

  it('does not judge small parts', async () => {
    const small = simpleMessage(['Content-Type: application/octet-stream'], 'r'.repeat(1000));
    expect((await parse(small, { limits: { maxDecodedRatio: 0.5 } })).result.status).toBe('parsed');
  });
});

describe('total_decoded_size', () => {
  const message = multipart('mixed', 'b', [
    attachmentPart('a.bin', 'a'.repeat(600)),
    attachmentPart('b.bin', 'b'.repeat(400)),
  ]);

  it('passes at the limit and stops at limit + 1', async () => {
    expect((await parse(message, { limits: { maxTotalDecodedBytes: 1000 } })).result.status).toBe(
      'parsed',
    );
    const { result } = await parse(message, { limits: { maxTotalDecodedBytes: 999 } });
    expect(result.limitsExceeded).toEqual(['total_decoded_size']);
    expect(result.attachments).toHaveLength(1);
    expect(result.structure.at(-1)?.truncated).toBe(true);
  });
});

describe('parse_timeout', () => {
  const message = multipart('mixed', 'b', [
    textPart('body'),
    attachmentPart('slow.bin', `${'x'.repeat(98)}\r\n`.repeat(500)),
  ]);

  it('records a timeout for an already aborted signal without reading', async () => {
    const controller = new AbortController();
    controller.abort();
    const { result, sink } = await parse(message, { signal: controller.signal });
    expect(result).toMatchObject({
      status: 'parse_limit_exceeded',
      limitsExceeded: ['parse_timeout'],
    });
    expect(result.stats).toMatchObject({ bytesRead: 0, inputComplete: false });
    expect(sink.opened).toHaveLength(0);
  });

  it('stops when the signal fires during a slow write, aborting the in-flight part', async () => {
    const sink = new MemorySink();
    sink.writeDelayMs = 20;
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 60);
    const { result } = await parse(message, { sink, signal: controller.signal, chunkSize: 1024 });
    expect(result.limitsExceeded).toEqual(['parse_timeout']);
    expect(result.attachments).toHaveLength(0);
    expect(result.structure.some((node) => node.truncated)).toBe(true);
    expect(sink.aborted.length).toBeGreaterThan(0);
  });

  it('applies parseTimeoutMs itself, also while the input stalls', async () => {
    const stalled = new Readable({ read() {} });
    stalled.push(Buffer.from(simpleMessage(['Subject: stall'], 'first bytes')));
    const result = await parseMessage(stalled, {
      limits: limits({ parseTimeoutMs: 50 }),
      sink: new MemorySink(),
      signal: new AbortController().signal,
    });
    expect(result.limitsExceeded).toEqual(['parse_timeout']);
    expect(result.subject).toBe('stall');
  });

  it('passes within the limit', async () => {
    expect((await parse(message, { limits: { parseTimeoutMs: 10_000 } })).result.status).toBe(
      'parsed',
    );
  });
});

describe('status', () => {
  it('records every limit hit, in order, and keeps the defects', async () => {
    const message = multipart(
      'mixed',
      'b',
      [
        {
          headers: ['Content-Type: text/plain', 'Content-Transfer-Encoding: x-weird'],
          body: 't'.repeat(200),
        },
        attachmentPart('a.bin', 'a'.repeat(200)),
        attachmentPart('b.bin', 'b'),
        attachmentPart('c.bin', 'c'),
      ],
      { close: false },
    );
    const { result } = await parse(message, {
      limits: { maxBodyBytes: 100, maxAttachmentBytes: 100, maxAttachments: 2 },
    });
    expect(result.status).toBe('parse_limit_exceeded');
    expect(result.limitsExceeded).toEqual(['body_size', 'attachment_size', 'attachment_count']);
    expect(result.defects).toEqual(['unknown_transfer_encoding']);
  });
});

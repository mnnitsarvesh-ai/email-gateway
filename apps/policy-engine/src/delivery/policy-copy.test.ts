import { Readable } from 'node:stream';
import { S3Client } from '@aws-sdk/client-s3';
import { describe, expect, it } from 'vitest';
import {
  editHeaderBlock,
  findHeaderEnd,
  isPolicyCopyKeyOf,
  lineEnding,
  MAX_LINE_OCTETS,
  POLICY_COPY_OBJECT_TAGGING,
  policyCopyKey,
  S3PolicyCopyWriter,
} from './policy-copy';

const TAG = { name: 'X-EG-Policy-Tag', value: 'external,sample-policy' };
const WARN = { name: 'X-EG-Policy-Warning', value: 'warning; Check the sender' };
const edit = (
  header: string,
  edits: { headers?: { name: string; value: string }[]; subjectPrefix?: string | null },
) =>
  editHeaderBlock(Buffer.from(header, 'latin1'), {
    headers: edits.headers ?? [],
    subjectPrefix: edits.subjectPrefix ?? null,
  }).toString('latin1');

describe('policyCopyKey (P21)', () => {
  const input = {
    organizationId: 7n,
    messageId: 123n,
    receivedAt: new Date('2026-01-02T23:59:59.000Z'),
    round: 1,
    baseKey: 'org/7/eml/2026/01/02/a.eml',
    edits: { headers: [TAG], subjectPrefix: '[EXT]' },
  };

  it('is org/<org>/policy/<yyyy>/<mm>/<dd>/<messageId>/r<round>-<32 hex>.eml (UTC date)', () => {
    expect(policyCopyKey(input)).toMatch(
      /^org\/7\/policy\/2026\/01\/02\/123\/r1-[0-9a-f]{32}\.eml$/,
    );
    expect(isPolicyCopyKeyOf(policyCopyKey(input), 7n)).toBe(true);
    expect(isPolicyCopyKeyOf(policyCopyKey(input), 70n)).toBe(false);
  });

  it('is deterministic and changes with the base object and the edits', () => {
    expect(policyCopyKey(input)).toBe(policyCopyKey({ ...input }));
    expect(policyCopyKey({ ...input, baseKey: 'org/7/rewrite/x.eml' })).not.toBe(
      policyCopyKey(input),
    );
    expect(policyCopyKey({ ...input, edits: { headers: [TAG], subjectPrefix: null } })).not.toBe(
      policyCopyKey(input),
    );
    expect(policyCopyKey({ ...input, round: 2 })).not.toBe(policyCopyKey(input));
  });
});

describe('editHeaderBlock (P21 header edits)', () => {
  it('prepends the tag and warning headers with CRLF line endings kept', () => {
    const out = edit('From: a@example.org\r\nSubject: hi\r\n', { headers: [TAG, WARN] });
    expect(out).toBe(
      'X-EG-Policy-Tag: external,sample-policy\r\nX-EG-Policy-Warning: warning; Check the sender\r\n' +
        'From: a@example.org\r\nSubject: hi\r\n',
    );
  });

  it('keeps LF line endings of an LF message', () => {
    const out = edit('From: a@example.org\nSubject: hi\n', {
      headers: [TAG],
      subjectPrefix: '[EXT]',
    });
    expect(out).toBe(
      'X-EG-Policy-Tag: external,sample-policy\nFrom: a@example.org\nSubject: [EXT] hi\n',
    );
    expect(out).not.toContain('\r');
    expect(lineEnding('a: b\nc: d\n')).toBe('\n');
    expect(lineEnding('a: b\r\n')).toBe('\r\n');
  });

  it('removes spoofed X-EG-Policy-* headers (any case, with continuation lines) from the copy', () => {
    const out = edit(
      'x-eg-policy-tag: forged\r\n  continued\r\nFrom: a@example.org\r\nX-EG-POLICY-WARNING: danger; fake\r\nX-EG-Policy-Tagged: kept\r\n',
      { headers: [TAG] },
    );
    expect(out).toBe(
      'X-EG-Policy-Tag: external,sample-policy\r\nFrom: a@example.org\r\nX-EG-Policy-Tagged: kept\r\n',
    );
  });

  it('inserts the subject prefix after Subject: and its whitespace', () => {
    expect(edit('Subject:\thello\r\n', { subjectPrefix: '[EXT]' })).toBe(
      'Subject:\t[EXT] hello\r\n',
    );
    expect(edit('subject:hello\r\n', { subjectPrefix: '[EXT]' })).toBe('subject:[EXT] hello\r\n');
  });

  it('does not prefix twice (unfolded value already starts with the prefix)', () => {
    expect(edit('Subject: [EXT] hello\r\n', { subjectPrefix: '[EXT]' })).toBe(
      'Subject: [EXT] hello\r\n',
    );
    // Folded right after the colon: the unfolded value starts with the prefix.
    expect(edit('Subject:\r\n [EXT] hello\r\n', { subjectPrefix: '[EXT]' })).toBe(
      'Subject:\r\n [EXT] hello\r\n',
    );
  });

  it('prefixes a folded subject and keeps its continuation lines', () => {
    expect(
      edit('Subject: part one\r\n part two\r\nTo: b@example.org\r\n', { subjectPrefix: '[EXT]' }),
    ).toBe('Subject: [EXT] part one\r\n part two\r\nTo: b@example.org\r\n');
    // Value only on the continuation line.
    expect(edit('Subject:\r\n hello\r\n', { subjectPrefix: '[EXT]' })).toBe(
      'Subject: [EXT]\r\n hello\r\n',
    );
  });

  it('prefixes an encoded-word subject without touching the encoded word', () => {
    expect(edit('Subject: =?UTF-8?B?aMOpbGxv?=\r\n', { subjectPrefix: '[EXT]' })).toBe(
      'Subject: [EXT] =?UTF-8?B?aMOpbGxv?=\r\n',
    );
  });

  it('adds Subject: <prefix> when the message has none', () => {
    expect(edit('From: a@example.org\r\n', { headers: [TAG], subjectPrefix: '[EXT]' })).toBe(
      'X-EG-Policy-Tag: external,sample-policy\r\nSubject: [EXT]\r\nFrom: a@example.org\r\n',
    );
  });

  it('folds at the inserted point when the line would exceed 998 octets', () => {
    const long = 'x'.repeat(MAX_LINE_OCTETS - 'Subject: '.length);
    const out = edit(`Subject: ${long}\r\n`, { subjectPrefix: '[EXT]' });
    expect(out).toBe(`Subject: [EXT]\r\n ${long}\r\n`);
    for (const line of out.split('\r\n')) expect(line.length).toBeLessThanOrEqual(MAX_LINE_OCTETS);
  });

  it('preserves non-ASCII octets byte for byte', () => {
    const header = Buffer.concat([
      Buffer.from('Subject: caf', 'latin1'),
      Buffer.from([0xc3, 0xa9]),
      Buffer.from('\r\nX-Raw: ', 'latin1'),
      Buffer.from([0xff, 0x00, 0x80]),
      Buffer.from('\r\n', 'latin1'),
    ]);
    const out = editHeaderBlock(header, { headers: [], subjectPrefix: '[EXT]' });
    expect(out.subarray(out.indexOf('X-Raw'))).toEqual(header.subarray(header.indexOf('X-Raw')));
    expect(out.includes(Buffer.from([0xc3, 0xa9]))).toBe(true);
  });

  it('terminates an unterminated last header line before anything is appended', () => {
    expect(edit('From: a@example.org', { subjectPrefix: '[EXT]' })).toBe(
      'Subject: [EXT]\r\nFrom: a@example.org\r\n',
    );
  });
});

describe('findHeaderEnd', () => {
  it('finds the empty line (CRLF, LF, at the start) or nothing', () => {
    expect(findHeaderEnd(Buffer.from('A: b\r\n\r\nbody'))).toEqual({
      headerEnd: 6,
      separatorLength: 2,
    });
    expect(findHeaderEnd(Buffer.from('A: b\n\nbody'))).toEqual({
      headerEnd: 5,
      separatorLength: 1,
    });
    expect(findHeaderEnd(Buffer.from('\r\nbody'))).toEqual({ headerEnd: 0, separatorLength: 2 });
    expect(findHeaderEnd(Buffer.from('A: b\r\nC: d\r\n'))).toBeNull();
  });
});

/** An S3 client double: GetObject returns `object`, PutObject records the request. */
function fakeS3(object: Buffer, contentLength: number | undefined = object.length) {
  const puts: { input: Record<string, unknown>; body: Buffer }[] = [];
  const deletes: string[] = [];
  // A real client (lib-storage resolves endpoints from its config) whose transport is replaced.
  const client = new S3Client({
    region: 'us-east-1',
    endpoint: 'http://127.0.0.1:9',
    forcePathStyle: true,
    credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
  });
  const send = async (command: {
    constructor: { name: string };
    input: Record<string, unknown>;
  }) => {
    const name = command.constructor.name;
    if (name === 'GetObjectCommand') {
      return {
        Body: Readable.from([object.subarray(0, 7), object.subarray(7)]),
        ContentLength: contentLength,
      };
    }
    if (name === 'PutObjectCommand') {
      const body = command.input.Body;
      let bytes: Buffer;
      if (Buffer.isBuffer(body) || body instanceof Uint8Array) bytes = Buffer.from(body);
      else if (typeof body === 'string') bytes = Buffer.from(body);
      else {
        const chunks: Buffer[] = [];
        for await (const c of body as AsyncIterable<Buffer>) chunks.push(Buffer.from(c));
        bytes = Buffer.concat(chunks);
      }
      puts.push({ input: command.input, body: bytes });
      return { ETag: '"x"' };
    }
    if (name === 'DeleteObjectCommand') {
      deletes.push(String(command.input.Key));
      return {};
    }
    throw new Error(`unexpected ${name}`);
  };
  (client as unknown as { send: typeof send }).send = send;
  return { client, puts, deletes };
}

describe('S3PolicyCopyWriter', () => {
  const limits = { maxMessageBytes: 1_048_576, maxHeaderBytes: 16_384 };
  const edits = { headers: [TAG], subjectPrefix: '[EXT]' };
  const request = (signal = new AbortController().signal) => ({
    baseKey: 'org/7/eml/a.eml',
    key: 'org/7/policy/2026/11/11/1/r0-ab.eml',
    edits,
    signal,
  });

  it('writes the edited header and a byte-identical body, tagged, message/rfc822', async () => {
    const body = Buffer.concat([
      Buffer.from('line 1\r\n\r\n.\r\n', 'latin1'),
      Buffer.from([0, 255, 13, 10]),
    ]);
    const eml = Buffer.concat([
      Buffer.from('From: a@example.org\r\nSubject: hi\r\n\r\n', 'latin1'),
      body,
    ]);
    const s3 = fakeS3(eml);
    const writer = new S3PolicyCopyWriter(s3.client, 'mail', limits);
    expect(await writer.write(request())).toEqual({ result: 'written', key: request().key });
    expect(s3.puts).toHaveLength(1);
    const put = s3.puts[0]!;
    expect(put.input).toMatchObject({
      Bucket: 'mail',
      Key: request().key,
      ContentType: 'message/rfc822',
      ContentDisposition: 'attachment',
      Tagging: POLICY_COPY_OBJECT_TAGGING,
    });
    expect(POLICY_COPY_OBJECT_TAGGING).toBe('eg-object=policy-copy');
    const expectedHeader =
      'X-EG-Policy-Tag: external,sample-policy\r\nFrom: a@example.org\r\nSubject: [EXT] hi\r\n';
    expect(put.body.subarray(0, expectedHeader.length).toString('latin1')).toBe(expectedHeader);
    // Separator + body unchanged.
    expect(put.body.subarray(expectedHeader.length)).toEqual(
      Buffer.concat([Buffer.from('\r\n'), body]),
    );
  });

  it('refuses an object larger than POLICY_COPY_MAX_MESSAGE_BYTES (too_large, nothing written)', async () => {
    const s3 = fakeS3(Buffer.from('A: b\r\n\r\nbody'), 2_000_000);
    const writer = new S3PolicyCopyWriter(s3.client, 'mail', limits);
    expect(await writer.write(request())).toEqual({ result: 'too_large' });
    expect(s3.puts).toHaveLength(0);
  });

  it('refuses a header block larger than POLICY_COPY_MAX_HEADER_BYTES (header_too_large)', async () => {
    const header = `X-Big: ${'a'.repeat(20_000)}\r\n\r\nbody`;
    const s3 = fakeS3(Buffer.from(header));
    const writer = new S3PolicyCopyWriter(s3.client, 'mail', limits);
    expect(await writer.write(request())).toEqual({ result: 'header_too_large' });
    expect(s3.puts).toHaveLength(0);
  });
});

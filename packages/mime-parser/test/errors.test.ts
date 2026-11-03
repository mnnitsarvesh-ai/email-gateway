import { Readable } from 'node:stream';
import { Splitter } from '@zone-eu/mailsplit';
import iconv from 'iconv-lite';
import libmime from 'libmime';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseMessage } from '../src/parse-message';
import { limits, MemorySink, multipart, parse, sha256, simpleMessage } from './helpers';
import { buildZip } from './zip-builders';

afterEach(() => {
  vi.restoreAllMocks();
});

const message = multipart('mixed', 'b', [
  { headers: ['Content-Type: text/plain'], body: 'body text' },
  { headers: ['Content-Type: application/octet-stream; name="a.bin"'], body: 'attachment bytes' },
]);

describe('error mapping (design M4)', () => {
  it('rethrows an error of sink.open unchanged', async () => {
    const sink = new MemorySink();
    const failure = new Error('S3 down');
    sink.failOpen = failure;
    await expect(parse(message, { sink })).rejects.toBe(failure);
  });

  it('rethrows an error of writer.write unchanged and aborts the in-flight writer', async () => {
    const sink = new MemorySink();
    const failure = Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' });
    sink.failWriteAfterBytes = { bytes: 0, error: failure };
    await expect(parse(message, { sink })).rejects.toBe(failure);
    expect(sink.aborted).toHaveLength(1);
    expect(sink.objects.size).toBe(0);
  });

  it('rethrows an error of readRange unchanged', async () => {
    const zip = await buildZip([{ name: 'a.txt', data: Buffer.from('a') }]);
    const withZip = multipart('mixed', 'b', [
      {
        headers: [
          'Content-Type: application/zip; name="a.zip"',
          'Content-Transfer-Encoding: base64',
        ],
        body: zip.toString('base64'),
      },
    ]);
    const sink = new MemorySink();
    const failure = new Error('range read failed');
    sink.failReadRange = failure;
    await expect(parse(withZip, { sink })).rejects.toBe(failure);
  });

  it('rethrows an error of the input stream unchanged', async () => {
    const failure = new Error('GetObject stream reset');
    const input = Readable.from(
      (function* () {
        yield Buffer.from(simpleMessage(['Content-Type: text/plain'], 'start of the body '));
        throw failure;
      })(),
    );
    const sink = new MemorySink();
    await expect(
      parseMessage(input, { limits: limits(), sink, signal: new AbortController().signal }),
    ).rejects.toBe(failure);
    expect(sink.objects.size).toBe(0);
  });

  it('maps an unexpected mailsplit error to parse_failed / parser_error and keeps what was parsed', async () => {
    const original = Splitter.prototype._transform;
    let calls = 0;
    vi.spyOn(Splitter.prototype, '_transform').mockImplementation(function (
      this: Splitter,
      chunk,
      encoding,
      callback,
    ) {
      calls++;
      if (calls === 1) return original.call(this, chunk, encoding, callback);
      callback(new TypeError('library bug'));
    });
    const first = Buffer.from(simpleMessage(['Subject: partial', 'Content-Type: text/plain'], 'x'));
    const input = Buffer.concat([first, Buffer.from('more body')]);
    // Paced, so the first chunk's node is consumed before the failing write.
    const paced = Readable.from(
      (async function* () {
        yield first;
        await new Promise((resolve) => setTimeout(resolve, 20));
        yield Buffer.from('more body');
      })(),
    );
    const result = await parseMessage(paced, {
      limits: limits(),
      sink: new MemorySink(),
      signal: new AbortController().signal,
    });
    expect(result).toMatchObject({
      status: 'parse_failed',
      failureReason: 'parser_error',
      subject: 'partial',
    });
    // The input is still read to its end, so the integrity check sees every byte.
    expect(result.stats).toMatchObject({
      bytesRead: input.length,
      sha256: sha256(input),
      inputComplete: true,
    });
  });

  it('maps an exception of a decoder library to parser_error', async () => {
    vi.spyOn(iconv, 'getDecoder').mockImplementation(() => {
      throw new Error('codec failure');
    });
    const { result } = await parse(
      simpleMessage(['Content-Type: text/plain; charset=koi8-r'], 'x'),
    );
    expect(result).toMatchObject({ status: 'parse_failed', failureReason: 'parser_error' });
  });

  it('turns a throwing RFC 2047 decoder into invalid_encoded_word, not a failure', async () => {
    vi.spyOn(libmime, 'decodeWords').mockImplementation(() => {
      throw new Error('decode failure');
    });
    const { result } = await parse(simpleMessage(['Subject: =?utf-8?Q?abc?='], 'b'));
    expect(result.status).toBe('parsed_with_defects');
    expect(result.defects).toEqual(['invalid_encoded_word']);
    expect(result.subject).toBe('=?utf-8?Q?abc?=');
  });

  it('never puts error text into the result', async () => {
    vi.spyOn(iconv, 'getDecoder').mockImplementation(() => {
      throw new Error('SECRET-MARKER');
    });
    const { result } = await parse(
      simpleMessage(['Content-Type: text/plain; charset=koi8-r'], 'x'),
    );
    expect(JSON.stringify(result)).not.toContain('SECRET-MARKER');
  });
});

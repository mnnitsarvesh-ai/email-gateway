import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import {
  ContentMissingError,
  ForeignObjectKeyError,
  headerFields,
  openEml,
  summarizeHeaders,
} from './eml-source';

const s3 = (body: Buffer | Error, chunkSize = 7) => ({
  sent: [] as unknown[],
  send(command: unknown) {
    this.sent.push(command);
    if (body instanceof Error) return Promise.reject(body);
    const parts: Buffer[] = [];
    for (let i = 0; i < body.length; i += chunkSize) parts.push(body.subarray(i, i + chunkSize));
    return Promise.resolve({ Body: Readable.from(parts), ContentLength: body.length });
  },
});

async function collect(iterable: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const parts: Buffer[] = [];
  for await (const part of iterable) parts.push(Buffer.from(part));
  return Buffer.concat(parts);
}

const EML = Buffer.from(
  [
    'Received: from a by b; Mon, 2 Nov 2026 10:00:00 +0000',
    'X-Gateway-Trace: v=1; g=gw-local; d=in;',
    '\tt=1762077600; s=abc',
    'received: from c by d',
    'Subject: hello',
    '',
    'Received: not a header (body)',
    'X-Gateway-Trace: v=1; body',
    '',
  ].join('\r\n'),
);

describe('openEml', () => {
  it('reads only the header block before connecting, then replays the whole object', async () => {
    const client = s3(EML);
    const eml = await openEml(client, 'bucket', 'org/7/eml/x.eml', 7n, 65_536);
    expect(eml.size).toBe(EML.length);
    expect(eml.header).toMatchObject({ receivedCount: 2, complete: true });
    expect(eml.header.traces).toEqual(['v=1; g=gw-local; d=in;\tt=1762077600; s=abc']);
    expect(await collect(eml.body)).toEqual(EML);
  });

  it('counts within the cap when the header block is longer (complete = false)', async () => {
    const long = Buffer.from(`${'Received: x\r\n'.repeat(200)}\r\nbody`);
    const eml = await openEml(s3(long, 100), 'bucket', 'org/7/k', 7n, 1024);
    expect(eml.header.complete).toBe(false);
    expect(eml.header.receivedCount).toBeGreaterThan(70);
    expect(eml.header.receivedCount).toBeLessThan(200);
    expect(await collect(eml.body)).toEqual(long);
  });

  it('handles LF-only messages and a message without a body', async () => {
    const lf = Buffer.from('Received: a\nSubject: x\n\nbody\n');
    expect((await openEml(s3(lf), 'b', 'org/1/k', 1n, 65_536)).header).toMatchObject({
      receivedCount: 1,
      complete: true,
    });
    const headersOnly = Buffer.from('Received: a\r\nSubject: x\r\n');
    const eml = await openEml(s3(headersOnly), 'b', 'org/1/k', 1n, 65_536);
    expect(eml.header).toMatchObject({ receivedCount: 1, complete: true });
    expect(await collect(eml.body)).toEqual(headersOnly);
  });

  it('refuses keys outside the organization prefix without reading them', async () => {
    const client = s3(EML);
    await expect(openEml(client, 'b', 'org/8/eml/x.eml', 7n, 65_536)).rejects.toBeInstanceOf(
      ForeignObjectKeyError,
    );
    await expect(openEml(client, 'b', 'org/77/eml/x.eml', 7n, 65_536)).rejects.toBeInstanceOf(
      ForeignObjectKeyError,
    );
    expect(client.sent).toHaveLength(0);
  });

  it('maps NoSuchKey to ContentMissingError and passes other errors through', async () => {
    const missing = Object.assign(new Error('The specified key does not exist.'), {
      name: 'NoSuchKey',
    });
    await expect(openEml(s3(missing), 'b', 'org/1/k', 1n, 65_536)).rejects.toBeInstanceOf(
      ContentMissingError,
    );
    await expect(
      openEml(s3(new Error('socket hang up')), 'b', 'org/1/k', 1n, 65_536),
    ).rejects.toThrow('socket hang up');
  });
});

describe('header helpers', () => {
  it('unfolds fields and skips non-field lines', () => {
    expect(headerFields('A: 1\r\n 2\r\nFrom x\r\nB:3\r\n\r\nC: body')).toEqual([
      { name: 'a', value: '1 2' },
      { name: 'b', value: '3' },
    ]);
    expect(summarizeHeaders(Buffer.from('Received: a\nX-Gateway-Trace: t\n'), true)).toEqual({
      receivedCount: 1,
      traces: ['t'],
      complete: true,
      bytesRead: 31,
    });
  });
});

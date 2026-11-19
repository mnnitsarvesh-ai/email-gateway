import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { HeaderScanner, MAX_RELAY_EVIDENCE_VALUES } from '../ingestion/header-scanner';
import { readMessage } from '../ingestion/message-reader';
import { headerFromDomain } from './provider-relay-ingestion.service';

const scan = (text: string, max = 65_536) => {
  const scanner = new HeaderScanner(max);
  scanner.push(Buffer.from(text));
  scanner.finish();
  return scanner.result();
};

describe('HeaderScanner provider relay evidence (D8)', () => {
  it('collects every tenant id (case-insensitive name, trimmed, lower-cased) and DKIM signature', () => {
    const meta = scan(
      [
        'DKIM-Signature: v=1; a=rsa-sha256; d=acme.test; s=s1;',
        '\th=from:to; bh=abc; b=def',
        'x-ms-exchange-crosstenant-id:  11111111-2222-3333-4444-555555555555 ',
        'X-MS-Exchange-CrossTenant-Id: ABCDEF00-2222-3333-4444-555555555555',
        'From: a@acme.test',
        '',
        'body',
      ].join('\r\n'),
    );
    expect(meta.crossTenantIds).toEqual([
      '11111111-2222-3333-4444-555555555555',
      'abcdef00-2222-3333-4444-555555555555',
    ]);
    expect(meta.dkimSignatures).toEqual([
      'v=1; a=rsa-sha256; d=acme.test; s=s1;\th=from:to; bh=abc; b=def',
    ]);
  });

  it('leaves both lists absent without such headers (step 2.2 metadata unchanged)', () => {
    const meta = scan('From: a@acme.test\r\n\r\nbody');
    expect('crossTenantIds' in meta).toBe(false);
    expect('dkimSignatures' in meta).toBe(false);
  });

  it('is bounded: at most 32 values, and nothing beyond INGEST_HEADER_MAX_BYTES', () => {
    const many = Array.from({ length: 40 }, (_, i) => `X-MS-Exchange-CrossTenant-Id: id-${i}`);
    expect(scan(`${many.join('\r\n')}\r\n\r\n`).crossTenantIds).toHaveLength(
      MAX_RELAY_EVIDENCE_VALUES,
    );
    const padded = `X-Pad: ${'x'.repeat(1100)}\r\nX-MS-Exchange-CrossTenant-Id: hidden\r\n\r\n`;
    const meta = scan(padded, 1024);
    expect(meta.truncated).toBe(true);
    expect(meta.crossTenantIds).toBeUndefined();
  });

  it('derives the single header-From domain', () => {
    expect(headerFromDomain(scan('From: "A" <a@Mail.ACME.test>\r\n\r\n'))).toBe('mail.acme.test');
    expect(headerFromDomain(scan('From: a@acme.test, b@acme.test\r\n\r\n'))).toBeNull();
    expect(headerFromDomain(scan('From: a@acme.test\r\nFrom: b@acme.test\r\n\r\n'))).toBeNull();
    expect(headerFromDomain(null)).toBeNull();
  });
});

describe('readMessage tee (D8 streaming DKIM)', () => {
  it('receives every byte of a complete read, in order', async () => {
    const seen: Buffer[] = [];
    const stream = Object.assign(new PassThrough(), { sizeExceeded: false });
    const text = `Subject: x\r\n\r\n${'y'.repeat(10_000)}`;
    stream.write(Buffer.from(text.slice(0, 7)));
    stream.end(Buffer.from(text.slice(7)));
    const result = await readMessage(stream, {
      headerMaxBytes: 1024,
      onHeaders: () => null,
      tee: {
        write: (chunk) => {
          seen.push(chunk);
          return Promise.resolve();
        },
      },
    });
    expect(result.outcome).toBe('complete');
    expect(Buffer.concat(seen).toString()).toBe(text);
  });
});

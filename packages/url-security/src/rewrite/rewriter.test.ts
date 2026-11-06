import { createHash } from 'node:crypto';
import { PassThrough, Readable } from 'node:stream';
import { Splitter, type SplitterChunk } from '@zone-eu/mailsplit';
import iconv from 'iconv-lite';
import * as libbase64 from 'libbase64';
import * as libqp from 'libqp';
import { describe, expect, it } from 'vitest';
import { normalizeUrl } from '../normalize/url';
import {
  checkRewriteEligibility,
  escapeAttribute,
  inlinePgp,
  rewriteEml,
  signedOrEncrypted,
  type RewriteOptions,
  type RewriteResult,
  type RewriteUrlEntry,
} from './rewriter';

const CLICK = 'https://protect.example.com';
const token = (seq: number): string => `T${String(seq).padStart(61, '0')}`;

function urlMap(urls: string[]): Map<string, RewriteUrlEntry> {
  return new Map(
    urls.map((u, i) => {
      const r = normalizeUrl(u);
      if (!r.ok) throw new Error(u);
      return [r.url.sha256, { seq: i + 1, truncated: false }];
    }),
  );
}

async function run(
  eml: string | Buffer,
  urls: string[],
  extra: Partial<RewriteOptions> = {},
): Promise<{ result: RewriteResult; output: Buffer }> {
  const chunks: Buffer[] = [];
  const sink = new PassThrough();
  sink.on('data', (c: Buffer) => chunks.push(c));
  const result = await rewriteEml({
    source: Readable.from([Buffer.isBuffer(eml) ? eml : Buffer.from(eml, 'latin1')]),
    sink,
    urlMap: urlMap(urls),
    policy: {
      plainText: true,
      excludedDomains: [],
      allowedDomains: [],
      dkimSignedPolicy: 'rewrite',
    },
    clickBaseUrl: CLICK,
    sign: token,
    limits: { maxMessageBytes: 26_214_400, maxPartBytes: 5_242_880 },
    ...extra,
  });
  return { result, output: Buffer.concat(chunks) };
}

/** Nodes of a message: [headers, body] buffers per node (data chunks attached to the preceding node). */
async function nodes(
  eml: Buffer,
): Promise<Array<{ contentType: string; headers: Buffer; body: Buffer }>> {
  const out: Array<{ contentType: string; headers: Buffer; body: Buffer[] }> = [];
  const splitter = new Splitter();
  const done = new Promise<void>((resolve, reject) => {
    splitter.on('data', (chunk: SplitterChunk) => {
      if (chunk.type === 'node')
        out.push({
          contentType: chunk.contentType || 'text/plain',
          headers: chunk.getHeaders(),
          body: [],
        });
      else out.at(-1)?.body.push(chunk.value);
    });
    const emitter: NodeJS.EventEmitter = splitter;
    emitter.on('end', resolve);
    emitter.on('error', reject);
  });
  splitter.end(eml);
  await done;
  return out.map((n) => ({ ...n, body: Buffer.concat(n.body) }));
}

const CRLF = (s: string): string => s.replace(/\r?\n/g, '\r\n');

const MIXED = CRLF(`From: sender@example.org
To: rcpt@example.net
Subject: test
DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=s; b=abc
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

preamble
--outer
Content-Type: multipart/alternative; boundary="alt"

--alt
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

Visit http://clean-site.test/a and www.short-link.test/s/clean.
Mail me: mailto:a@b.test  Unmapped: http://unmapped.test/x
--alt
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

<p><a HREF=3D"http://clean-site.test/a" class=3Dx>clean</a>
<a href=3D'http://clean-site.test/q?a=3D1&amp;b=3D2'>q</a>
<a href=3Dhttp://evil-site.test/>e</a>
<img src=3D"http://clean-site.test/img.png">
<a href=3D"mailto:a@b.test">m</a>
<a href=3D"${CLICK}/c/abc">already</a></p>
--alt--

--outer
Content-Type: text/html; charset=utf-8
Content-Disposition: attachment; filename="page.html"

<a href="http://clean-site.test/a">attached</a>
--outer
Content-Type: message/rfc822

Subject: inner
Content-Type: text/html

<a href="http://clean-site.test/a">inner</a>
--outer
Content-Type: image/png
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk
--outer--
epilogue
`);

const MIXED_URLS = [
  'http://clean-site.test/a',
  'http://www.short-link.test/s/clean',
  'http://clean-site.test/q?a=1&b=2',
  'http://evil-site.test/',
  'http://clean-site.test/img.png',
];

describe('rewriteEml', () => {
  it('rewrites eligible links only and keeps every untouched node byte-identical', async () => {
    const { result, output } = await run(MIXED, MIXED_URLS);
    expect(result).toMatchObject({
      status: 'rewritten',
      skipReason: null,
      linksRewritten: 5,
      linksUnmapped: 1,
      partsRewritten: 2,
      partsSkipped: 0,
      dkimSigned: true,
      rewrittenSeqs: [1, 2, 3, 4],
    });
    expect(result.linksByPart).toEqual({ text: 2, html: 3 });
    expect(result.sha256).toBe(createHash('sha256').update(output).digest('hex'));
    expect(result.sizeBytes).toBe(output.length);

    const before = await nodes(Buffer.from(MIXED, 'latin1'));
    const after = await nodes(output);
    expect(after.map((n) => n.contentType)).toEqual(before.map((n) => n.contentType));
    const changed = after.map(
      (n, i) =>
        !n.body.equals((before[i] as { body: Buffer }).body) ||
        !n.headers.equals((before[i] as { headers: Buffer }).headers),
    );
    // Only the inline text/plain (index 2) and text/html (index 3) changed.
    expect(changed).toEqual([false, false, true, true, false, false, false]);
    for (const i of [2, 3])
      expect(after[i]?.headers.equals(before[i]?.headers as Buffer)).toBe(true);

    const text = after[2]?.body.toString() ?? '';
    // (The test splitter attaches the following delimiter line to the body.)
    expect(
      text.startsWith(
        CRLF(
          `Visit ${CLICK}/c/${token(1)} and ${CLICK}/c/${token(2)}.\nMail me: mailto:a@b.test  Unmapped: http://unmapped.test/x\r\n--alt`,
        ),
      ),
    ).toBe(true);
    const html = libqp.decode(after[3]?.body ?? Buffer.alloc(0)).toString();
    expect(html).toContain(`<a HREF="${CLICK}/c/${token(1)}" class=x>clean</a>`);
    expect(html).toContain(`<a href="${CLICK}/c/${token(3)}">q</a>`);
    expect(html).toContain(`<a href="${CLICK}/c/${token(4)}">e</a>`);
    expect(html).toContain('<img src="http://clean-site.test/img.png">');
    expect(html).toContain('<a href="mailto:a@b.test">m</a>');
    expect(html).toContain(`<a href="${CLICK}/c/abc">already</a>`);
    // The bytes outside the nodes (preamble, delimiters, epilogue) are unchanged.
    expect(output.toString('latin1')).toContain('preamble\r\n--outer\r\n');
    expect(output.toString('latin1').endsWith('--outer--\r\nepilogue\r\n')).toBe(true);
  });

  it('passes a message without mapped links through byte-identical (no_urls)', async () => {
    const { result, output } = await run(MIXED, []);
    expect(result).toMatchObject({
      status: 'skipped',
      skipReason: 'no_urls',
      linksRewritten: 0,
      linksUnmapped: 6,
      sha256: null,
    });
    expect(output.equals(Buffer.from(MIXED, 'latin1'))).toBe(true);
  });

  it('honours exclusions: excluded and allowed domains, plain text off', async () => {
    const excluded = await run(MIXED, MIXED_URLS, {
      policy: {
        plainText: false,
        excludedDomains: ['clean-site.test'],
        allowedDomains: ['evil-site.test'],
        dkimSignedPolicy: 'rewrite',
      },
    });
    expect(excluded.result).toMatchObject({
      status: 'skipped',
      skipReason: 'no_urls',
      linksRewritten: 0,
    });
    const noText = await run(MIXED, MIXED_URLS, {
      policy: {
        plainText: false,
        excludedDomains: [],
        allowedDomains: [],
        dkimSignedPolicy: 'rewrite',
      },
    });
    expect(noText.result).toMatchObject({
      linksRewritten: 3,
      partsRewritten: 1,
      linksByPart: { text: 0, html: 3 },
    });
  });

  it('never rewrites truncated URLs', async () => {
    const map = urlMap(['http://clean-site.test/a']);
    for (const entry of map.values()) entry.truncated = true;
    const eml = CRLF('Content-Type: text/plain\n\nhttp://clean-site.test/a\n');
    const result = await rewriteEml({
      source: Readable.from([Buffer.from(eml)]),
      sink: new PassThrough().resume(),
      urlMap: map,
      policy: {
        plainText: true,
        excludedDomains: [],
        allowedDomains: [],
        dkimSignedPolicy: 'rewrite',
      },
      clickBaseUrl: CLICK,
      sign: token,
      limits: { maxMessageBytes: 1e6, maxPartBytes: 1e6 },
    });
    expect(result.skipReason).toBe('no_urls');
  });

  it('keeps base64 parts base64 (line length 76, CRLF)', async () => {
    const html = '<a href="http://clean-site.test/a">x</a>'.repeat(5);
    const eml = CRLF(
      `Content-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: base64\n\n${libbase64.wrap(libbase64.encode(Buffer.from(html)), 76)}\n`,
    );
    const { result, output } = await run(eml, ['http://clean-site.test/a']);
    expect(result).toMatchObject({ status: 'rewritten', linksRewritten: 5 });
    const [node] = await nodes(output);
    expect(node?.headers.toString()).toContain('Content-Transfer-Encoding: base64');
    const body = node?.body.toString('latin1') ?? '';
    expect(body.split('\r\n').every((line) => line.length <= 76)).toBe(true);
    expect(body.endsWith('\r\n')).toBe(true);
    expect(libbase64.decode(body).toString()).toBe(
      `<a href="${CLICK}/c/${token(1)}">x</a>`.repeat(5),
    );
  });

  it('keeps 7bit/8bit, switching to quoted-printable only for lines over 998 octets', async () => {
    const eight = Buffer.concat([
      Buffer.from(
        CRLF(
          'Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\nhé http://clean-site.test/a\n',
        ),
      ),
      Buffer.alloc(0),
    ]);
    const kept = await run(eight, ['http://clean-site.test/a']);
    const [node] = await nodes(kept.output);
    expect(node?.headers.toString()).toContain('Content-Transfer-Encoding: 8bit');
    expect(node?.body.toString('utf8')).toBe(`hé ${CLICK}/c/${token(1)}\r\n`);

    const long = `${'x'.repeat(940)} http://clean-site.test/a`;
    const seven = CRLF(
      `Content-Type: text/plain\nContent-Transfer-Encoding: 7bit\n\n${long}\nsecond line\n`,
    );
    const switched = await run(seven, ['http://clean-site.test/a']);
    const [qp] = await nodes(switched.output);
    expect(qp?.headers.toString()).toContain('Content-Transfer-Encoding: quoted-printable');
    expect(qp?.headers.toString()).not.toContain('7bit');
    const decoded = libqp.decode(qp?.body ?? Buffer.alloc(0)).toString();
    expect(decoded).toBe(`${'x'.repeat(940)} ${CLICK}/c/${token(1)}\r\nsecond line\r\n`);
    expect(
      (qp?.body.toString('latin1') ?? '').split('\r\n').every((line) => line.length <= 76),
    ).toBe(true);
  });

  it.each(['iso-8859-1', 'windows-1252', 'shift_jis'])(
    'round-trips the %s charset losslessly',
    async (charset) => {
      const text =
        charset === 'shift_jis'
          ? '日本語 http://clean-site.test/a です'
          : 'café € http://clean-site.test/a ü';
      const content = charset === 'iso-8859-1' ? text.replace('€', 'E') : text;
      const body = iconv.encode(content, charset);
      const eml = Buffer.concat([
        Buffer.from(
          CRLF(`Content-Type: text/plain; charset=${charset}\nContent-Transfer-Encoding: 8bit\n\n`),
        ),
        body,
        Buffer.from('\r\n'),
      ]);
      const { result, output } = await run(eml, ['http://clean-site.test/a']);
      expect(result.status).toBe('rewritten');
      const [node] = await nodes(output);
      expect(iconv.decode(node?.body ?? Buffer.alloc(0), charset)).toBe(
        `${content.replace('http://clean-site.test/a', `${CLICK}/c/${token(1)}`)}\r\n`,
      );
    },
  );

  it('skips UTF-16 and charset round-trip failures (part untouched, counted)', async () => {
    const utf16 = Buffer.concat([
      Buffer.from(
        CRLF('Content-Type: text/plain; charset=utf-16\nContent-Transfer-Encoding: base64\n\n'),
      ),
      Buffer.from(libbase64.encode(iconv.encode('http://clean-site.test/a', 'utf-16'))),
    ]);
    const a = await run(utf16, ['http://clean-site.test/a']);
    expect(a.result).toMatchObject({
      status: 'skipped',
      skipReason: 'no_urls',
      partsSkipped: 1,
      partSkipReasons: { unsupported_charset: 1 },
    });
    expect(a.output.equals(utf16)).toBe(true);
    const broken = Buffer.concat([
      Buffer.from(
        CRLF(
          'Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\nhttp://clean-site.test/a ',
        ),
      ),
      Buffer.from([0xff, 0xfe]),
      Buffer.from('\r\n'),
    ]);
    const b = await run(broken, ['http://clean-site.test/a']);
    expect(b.result).toMatchObject({ partsSkipped: 1, partSkipReasons: { charset_roundtrip: 1 } });
    expect(b.output.equals(broken)).toBe(true);
  });

  it('passes parts larger than the part limit through untouched', async () => {
    const eml = CRLF(`Content-Type: text/plain\n\nhttp://clean-site.test/a ${'y'.repeat(5000)}\n`);
    const { result, output } = await run(eml, ['http://clean-site.test/a'], {
      limits: { maxMessageBytes: 1e6, maxPartBytes: 1000 },
    });
    expect(result).toMatchObject({
      skipReason: 'no_urls',
      partsSkipped: 1,
      partSkipReasons: { too_large: 1 },
    });
    expect(output.equals(Buffer.from(eml))).toBe(true);
  });

  it.each([
    [
      'multipart/signed; protocol="application/pkcs7-signature"; boundary=b',
      'application/pkcs7-signature',
      'signed_smime',
    ],
    [
      'multipart/signed; protocol="application/pgp-signature"; boundary=b',
      'application/pgp-signature',
      'signed_pgp',
    ],
    [
      'multipart/encrypted; protocol="application/pgp-encrypted"; boundary=b',
      'application/pgp-encrypted',
      'encrypted',
    ],
  ])('skips the whole message for %s', async (type, child, reason) => {
    const eml = CRLF(
      `Content-Type: ${type}\n\n--b\nContent-Type: text/plain\n\nhttp://clean-site.test/a\n--b\nContent-Type: ${child}\n\nsig\n--b--\n`,
    );
    expect((await run(eml, ['http://clean-site.test/a'])).result).toMatchObject({
      status: 'skipped',
      skipReason: reason,
    });
  });

  it('skips application/pkcs7-mime and inline PGP', async () => {
    const pkcs7 = CRLF(
      'Content-Type: application/pkcs7-mime; smime-type=enveloped-data\nContent-Transfer-Encoding: base64\n\nAAAA\n',
    );
    expect((await run(pkcs7, ['http://clean-site.test/a'])).result.skipReason).toBe('encrypted');
    const pgp = CRLF(
      'Content-Type: text/plain\n\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nhttp://clean-site.test/a\n',
    );
    expect((await run(pgp, ['http://clean-site.test/a'])).result.skipReason).toBe('signed_pgp');
    const encrypted = CRLF('Content-Type: text/plain\n\n-----BEGIN PGP MESSAGE-----\nabc\n');
    expect((await run(encrypted, ['http://clean-site.test/a'])).result.skipReason).toBe(
      'encrypted',
    );
  });

  it('applies the DKIM policy', async () => {
    const skip = await run(MIXED, MIXED_URLS, {
      policy: {
        plainText: true,
        excludedDomains: [],
        allowedDomains: [],
        dkimSignedPolicy: 'skip',
      },
    });
    expect(skip.result).toMatchObject({
      status: 'skipped',
      skipReason: 'dkim_policy',
      dkimSigned: true,
    });
    const unsigned = await run(
      CRLF('Content-Type: text/plain\n\nhttp://clean-site.test/a\n'),
      ['http://clean-site.test/a'],
      {
        policy: {
          plainText: true,
          excludedDomains: [],
          allowedDomains: [],
          dkimSignedPolicy: 'skip',
        },
      },
    );
    expect(unsigned.result).toMatchObject({ status: 'rewritten', dkimSigned: false });
  });

  it('checks the structure echo and the message size', async () => {
    const eml = CRLF('Content-Type: text/plain\n\nhttp://clean-site.test/a\n');
    expect(
      (await run(eml, ['http://clean-site.test/a'], { structure: [{ contentType: 'text/plain' }] }))
        .result.status,
    ).toBe('rewritten');
    expect(
      (await run(eml, ['http://clean-site.test/a'], { structure: [{ contentType: 'text/html' }] }))
        .result.skipReason,
    ).toBe('structure_mismatch');
    expect(
      (
        await run(eml, ['http://clean-site.test/a'], {
          structure: [{ contentType: 'text/plain' }, { contentType: 'text/plain' }],
        })
      ).result.skipReason,
    ).toBe('structure_mismatch');
    expect(
      (
        await run(eml, ['http://clean-site.test/a'], {
          limits: { maxMessageBytes: 10, maxPartBytes: 1e6 },
        })
      ).result.skipReason,
    ).toBe('too_large');
  });

  it('keeps LF-only parts LF-only', async () => {
    const eml =
      'Content-Type: text/html\nContent-Transfer-Encoding: quoted-printable\n\n<a href=3D"http://clean-site.test/a">x</a>\nline2\n';
    const { output } = await run(eml, ['http://clean-site.test/a']);
    expect(output.toString('latin1')).not.toContain('\r');
  });
});

describe('rewrite helpers', () => {
  it('escapes attribute values', () => {
    expect(escapeAttribute('a"b&c<d>e')).toBe('a&quot;b&amp;c&lt;d&gt;e');
  });

  it('detects signed/encrypted structures and inline PGP', () => {
    expect(signedOrEncrypted(['multipart/mixed', 'text/plain'])).toBeNull();
    expect(
      signedOrEncrypted(['multipart/signed', 'text/plain', 'application/pkcs7-signature']),
    ).toBe('signed_smime');
    expect(signedOrEncrypted(['multipart/signed', 'text/plain', 'application/pgp-signature'])).toBe(
      'signed_pgp',
    );
    expect(signedOrEncrypted(['application/x-pkcs7-mime'])).toBe('encrypted');
    expect(signedOrEncrypted(['multipart/encrypted', 'application/pgp-encrypted'])).toBe(
      'encrypted',
    );
    expect(inlinePgp('x -----BEGIN PGP SIGNED MESSAGE----- y')).toBe('signed_pgp');
    expect(inlinePgp('plain')).toBeNull();
  });

  it('decides message eligibility before streaming', () => {
    const base = {
      enabled: true,
      direction: 'inbound',
      directions: ['inbound'],
      contentComplete: true,
      messageSizeBytes: 100,
      maxMessageBytes: 1000,
      contentTypes: ['text/plain'],
      eligibleUrls: 1,
    };
    expect(checkRewriteEligibility(base)).toBeNull();
    expect(checkRewriteEligibility({ ...base, enabled: false })).toBe('disabled');
    expect(checkRewriteEligibility({ ...base, direction: 'outbound' })).toBe('direction');
    expect(checkRewriteEligibility({ ...base, contentComplete: false })).toBe('parse_incomplete');
    expect(checkRewriteEligibility({ ...base, messageSizeBytes: 1001 })).toBe('too_large');
    expect(
      checkRewriteEligibility({
        ...base,
        contentTypes: ['multipart/signed', 'application/pkcs7-signature'],
      }),
    ).toBe('signed_smime');
    expect(checkRewriteEligibility({ ...base, bodies: ['-----BEGIN PGP MESSAGE-----'] })).toBe(
      'encrypted',
    );
    expect(checkRewriteEligibility({ ...base, eligibleUrls: 0 })).toBe('no_urls');
  });
});

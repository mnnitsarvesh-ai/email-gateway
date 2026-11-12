import { createHash } from 'node:crypto';
import { PassThrough, Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import {
  bannerText,
  bodyInsertOffset,
  htmlBanner,
  insertWarningBanner,
  insertWarningBannerBuffer,
  textBanner,
  type BannerOptions,
} from './banner';
import { detectSignedOrEncrypted } from './signed';
import { b64, CRLF, message, multipart, part, qp, readParts } from './mime.test-support';

const LIMITS = { maxPartBytes: 1_048_576, maxMessageBytes: 26_214_400 };
const opts = (extra: Partial<Omit<BannerOptions, 'source' | 'sink'>> = {}) => ({
  level: 'warning' as const,
  text: null,
  limits: LIMITS,
  ...extra,
});
const run = (eml: Buffer, extra: Partial<Omit<BannerOptions, 'source' | 'sink'>> = {}) =>
  insertWarningBannerBuffer(eml, opts(extra));
const BANNER = bannerText('warning', null);

describe('banner templates', () => {
  it('fixed templates per level; rule text escaped; ASCII only', () => {
    expect(bannerText('caution', null)).toMatch(/^\[CAUTION\] Be careful/);
    expect(bannerText('danger', 'Possible executive impersonation')).toBe(
      '[DANGER] Possible executive impersonation',
    );
    expect(bannerText('danger', 'café \u202e')).toBe('[DANGER] caf ');
    expect(textBanner('caution', 'X', '\n')).toBe(`[CAUTION] X\n${'-'.repeat(40)}\n\n`);
    const html = htmlBanner('danger', '<script>alert(1)</script> & "q"');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;q&quot;');
    expect(html).toMatch(/^<div role="alert" style="[^"]*">/);
    expect(html).not.toMatch(/url\(|<script|src=|href=/i);
  });
  it('inserts after the body start tag, or at the start', () => {
    const doc = '<html><head><title>t</title></head><body class="x" onload="y">Hi</body></html>';
    expect(doc.slice(0, bodyInsertOffset(doc))).toBe(
      '<html><head><title>t</title></head><body class="x" onload="y">',
    );
    expect(bodyInsertOffset('<p>no body</p>')).toBe(0);
    expect(bodyInsertOffset('<!doctype html><BODY>x')).toBe('<!doctype html><BODY>'.length);
  });
});

describe('insertWarningBanner (Q22)', () => {
  it('text/plain 7bit CRLF: banner prepended, everything else byte-identical', async () => {
    const body = `Hello,${CRLF}please pay.${CRLF}`;
    const eml = message(
      ['Content-Type: text/plain; charset=us-ascii', 'Content-Transfer-Encoding: 7bit'],
      body,
    );
    const { result, output } = await run(eml);
    expect(result).toMatchObject({
      status: 'applied',
      partsEdited: 1,
      edited: { text: true, html: false },
    });
    const expected = eml
      .toString('latin1')
      .replace(body, `${BANNER}${CRLF}${'-'.repeat(40)}${CRLF}${CRLF}${body}`);
    expect(output.toString('latin1')).toBe(expected);
    expect(result.sha256).toBe(createHash('sha256').update(output).digest('hex'));
    expect(result.sizeBytes).toBe(output.length);
  });

  it('text/plain with LF line endings keeps LF', async () => {
    const body = 'Hello\nworld\n';
    const eml = message(['Content-Type: text/plain'], body, '\n');
    const { result, output } = await run(eml, { level: 'caution', text: 'Check the sender' });
    expect(result.status).toBe('applied');
    expect(output.toString('latin1')).toBe(
      eml
        .toString('latin1')
        .replace(body, `[CAUTION] Check the sender\n${'-'.repeat(40)}\n\n${body}`),
    );
  });

  it('HTML with a body tag: the banner follows <body …>; without one it comes first', async () => {
    const withBody =
      '<html><head><style>p{}</style></head><body bgcolor="#fff">\r\n<p>Pay now</p></body></html>\r\n';
    const a = await run(message(['Content-Type: text/html; charset=utf-8'], withBody));
    expect(a.result.edited).toEqual({ text: false, html: true });
    const [p] = await readParts(a.output);
    expect(p!.text).toBe(
      withBody.replace(
        '<body bgcolor="#fff">',
        `<body bgcolor="#fff">${htmlBanner('warning', null)}`,
      ),
    );
    const noBody = '<p>Pay now</p>\r\n';
    const b = await run(message(['Content-Type: text/html'], noBody));
    expect((await readParts(b.output))[0]!.text).toBe(htmlBanner('warning', null) + noBody);
  });

  it('multipart/alternative QP text + base64 HTML: both edited, original CTE kept', async () => {
    const text = 'Grüße — invoice attached\r\n';
    const html = '<html><body><p>Grüße</p></body></html>';
    const mp = multipart('alternative', 'b1', [
      part(
        ['Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: quoted-printable'],
        qp(text),
      ),
      part(
        ['Content-Type: text/html; charset=utf-8', 'Content-Transfer-Encoding: base64'],
        b64(html),
      ),
    ]);
    const eml = message(mp.headers, mp.body);
    const { result, output } = await run(eml, { level: 'danger', text: 'Lookalike domain' });
    expect(result).toMatchObject({
      status: 'applied',
      partsEdited: 2,
      edited: { text: true, html: true },
    });
    const parts = await readParts(output);
    expect(parts.map((p) => p.encoding)).toEqual(['quoted-printable', 'base64']);
    expect(parts[0]!.text).toBe(`[DANGER] Lookalike domain\r\n${'-'.repeat(40)}\r\n\r\n${text}`);
    expect(parts[1]!.text).toBe(
      html.replace('<body>', `<body>${htmlBanner('danger', 'Lookalike domain')}`),
    );
    for (const p of parts)
      expect(
        p.raw
          .toString('latin1')
          .split(/\r\n/)
          .every((l) => l.length <= 76),
      ).toBe(true);
  });

  it('multipart/mixed with attachments: attachments and the second text part are byte-identical', async () => {
    const pdf = b64('%PDF-1.4 fake '.repeat(50), 'latin1');
    const mp = multipart('mixed', 'm1', [
      part(['Content-Type: text/plain; charset=us-ascii'], 'Body\r\n'),
      part(
        [
          'Content-Type: application/pdf; name="a.pdf"',
          'Content-Disposition: attachment; filename="a.pdf"',
          'Content-Transfer-Encoding: base64',
        ],
        pdf,
      ),
      part(
        ['Content-Type: text/plain', 'Content-Disposition: attachment; filename="notes.txt"'],
        'Attached notes\r\n',
      ),
      part(['Content-Type: text/plain'], 'Second inline text\r\n'),
    ]);
    const eml = message(mp.headers, mp.body);
    const { result, output } = await run(eml);
    expect(result.partsEdited).toBe(1);
    const before = await readParts(eml);
    const after = await readParts(output);
    expect(after[0]!.text.startsWith(BANNER)).toBe(true);
    for (const i of [1, 2, 3]) {
      expect(after[i]!.raw.equals(before[i]!.raw)).toBe(true);
      expect(after[i]!.header).toBe(before[i]!.header);
    }
    expect(output.toString('latin1').replace(/\[WARNING\][^\r]*\r\n-{40}\r\n\r\n/, '')).toBe(
      eml.toString('latin1'),
    );
  });

  it('7bit/8bit: a line over 998 octets after the edit becomes quoted-printable (header updated)', async () => {
    const html = `<body>${'x'.repeat(900)}</body>`;
    const eml = message(
      ['Content-Type: text/html; charset=us-ascii', 'Content-Transfer-Encoding: 7bit'],
      html,
    );
    const { result, output } = await run(eml);
    expect(result.status).toBe('applied');
    const [p] = await readParts(output);
    expect(p!.encoding).toBe('quoted-printable');
    expect(p!.header).toMatch(/Content-Transfer-Encoding: quoted-printable/);
    expect(p!.text).toBe(html.replace('<body>', `<body>${htmlBanner('warning', null)}`));
    // A short 8bit UTF-8 text part stays 8bit.
    const t = message(
      ['Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 8bit'],
      Buffer.from('Grüße\r\n', 'utf8').toString('latin1'),
    );
    const r = await run(t);
    const [q] = await readParts(r.output);
    expect(q!.encoding).toBe('8bit');
    expect(q!.text).toBe(`${BANNER}\r\n${'-'.repeat(40)}\r\n\r\nGrüße\r\n`);
  });

  it('a non-ASCII-compatible charset is skipped (skipped_part); the output is the input', async () => {
    const eml = message(
      ['Content-Type: text/plain; charset=utf-16', 'Content-Transfer-Encoding: base64'],
      b64('Hello', 'utf-16le'),
    );
    const { result, output } = await run(eml);
    expect(result).toMatchObject({
      status: 'skipped_part',
      partsEdited: 0,
      partSkipReasons: { unsupported_charset: 1 },
    });
    expect(output).toBe(eml);
  });

  it('a candidate part over maxPartBytes is skipped_part; an undecodable charset round trip too', async () => {
    const big = message(['Content-Type: text/plain'], 'x'.repeat(5000));
    expect(
      (await run(big, { limits: { maxPartBytes: 1000, maxMessageBytes: LIMITS.maxMessageBytes } }))
        .result,
    ).toMatchObject({
      status: 'skipped_part',
      partSkipReasons: { too_large: 1 },
    });
    const bad = message(
      ['Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 8bit'],
      '\xff\xfe broken\r\n',
    );
    expect((await run(bad)).result).toMatchObject({
      status: 'skipped_part',
      partSkipReasons: { charset_roundtrip: 1 },
    });
  });

  it('a message over maxMessageBytes is skipped_too_large', async () => {
    const eml = message(['Content-Type: text/plain'], 'x'.repeat(2000));
    const { result, output } = await run(eml, {
      limits: { maxPartBytes: 1_048_576, maxMessageBytes: 1000 },
    });
    expect(result.status).toBe('skipped_too_large');
    expect(output).toBe(eml);
  });

  it('no text part → skipped_no_text_part', async () => {
    const eml = message(
      ['Content-Type: application/pdf', 'Content-Transfer-Encoding: base64'],
      b64('%PDF'),
    );
    expect((await run(eml)).result.status).toBe('skipped_no_text_part');
    const attachedOnly = message(
      ['Content-Type: text/plain', 'Content-Disposition: attachment; filename="x.txt"'],
      'x',
    );
    expect((await run(attachedOnly)).result.status).toBe('skipped_no_text_part');
  });

  describe('signed and encrypted messages are never edited', () => {
    it('S/MIME multipart/signed → skipped_signed', async () => {
      const mp = multipart(
        'signed',
        's1',
        [
          part(['Content-Type: text/plain'], 'Signed body\r\n'),
          part(
            [
              'Content-Type: application/pkcs7-signature; name="smime.p7s"',
              'Content-Transfer-Encoding: base64',
            ],
            b64('sig'),
          ),
        ],
        CRLF,
      );
      mp.headers[0] =
        'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="s1"';
      const eml = message(mp.headers, mp.body);
      const { result, output } = await run(eml);
      expect(result.status).toBe('skipped_signed');
      expect(output).toBe(eml);
    });
    it('S/MIME application/pkcs7-mime: enveloped → encrypted, signed-data → signed', async () => {
      const env = message(
        [
          'Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"',
          'Content-Transfer-Encoding: base64',
        ],
        b64('enc'),
      );
      expect((await run(env)).result.status).toBe('skipped_encrypted');
      const sig = message(
        [
          'Content-Type: application/pkcs7-mime; smime-type=signed-data; name="smime.p7m"',
          'Content-Transfer-Encoding: base64',
        ],
        b64('sig'),
      );
      expect((await run(sig)).result.status).toBe('skipped_signed');
    });
    it('PGP/MIME encrypted and inline PGP', async () => {
      const mp = multipart('encrypted', 'e1', [
        part(['Content-Type: application/pgp-encrypted'], 'Version: 1\r\n'),
        part(
          ['Content-Type: application/octet-stream'],
          '-----BEGIN PGP MESSAGE-----\r\nx\r\n-----END PGP MESSAGE-----\r\n',
        ),
      ]);
      expect((await run(message(mp.headers, mp.body))).result.status).toBe('skipped_encrypted');
      const inlineSigned = message(
        ['Content-Type: text/plain'],
        '-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\nhi\r\n',
      );
      expect((await run(inlineSigned)).result.status).toBe('skipped_signed');
      const inlineEnc = message(
        ['Content-Type: text/plain'],
        '-----BEGIN PGP MESSAGE-----\r\nabc\r\n',
      );
      expect((await run(inlineEnc)).result.status).toBe('skipped_encrypted');
    });
    it('the structure pre-check skips without reading the source', async () => {
      const eml = message(['Content-Type: text/plain'], 'hi\r\n');
      const { result, output } = await run(eml, {
        structure: [
          { contentType: 'multipart/signed' },
          { contentType: 'text/plain' },
          { contentType: 'application/pgp-signature' },
        ],
      });
      expect(result.status).toBe('skipped_signed');
      expect(output).toBe(eml);
    });
    it('detectSignedOrEncrypted on structure and head bytes', () => {
      expect(detectSignedOrEncrypted(['multipart/mixed', 'text/plain'])).toBeNull();
      expect(
        detectSignedOrEncrypted(['multipart/signed', 'text/plain', 'application/pkcs7-signature']),
      ).toBe('skipped_signed');
      expect(detectSignedOrEncrypted(['application/pkcs7-mime'])).toBe('skipped_encrypted');
      expect(detectSignedOrEncrypted([{ contentType: 'multipart/encrypted' }])).toBe(
        'skipped_encrypted',
      );
      expect(
        detectSignedOrEncrypted(
          ['text/plain'],
          [Buffer.from('-----BEGIN PGP SIGNED MESSAGE-----')],
        ),
      ).toBe('skipped_signed');
      expect(detectSignedOrEncrypted(null, '-----BEGIN PGP MESSAGE-----')).toBe(
        'skipped_encrypted',
      );
      expect(detectSignedOrEncrypted(null, 'plain text')).toBeNull();
    });
  });

  it('a nested message/rfc822 is untouched; the outer text part is edited', async () => {
    const inner = message(['Content-Type: text/plain'], 'Inner body\r\n').toString('latin1');
    const mp = multipart('mixed', 'n1', [
      part(['Content-Type: text/plain'], 'Outer body\r\n'),
      part(['Content-Type: message/rfc822'], inner),
    ]);
    const eml = message(mp.headers, mp.body);
    const { result, output } = await run(eml);
    expect(result.partsEdited).toBe(1);
    const parts = await readParts(output);
    expect(parts[0]!.text.startsWith(BANNER)).toBe(true);
    const inner_ = parts.filter((p) => p.text.includes('Inner body'));
    expect(inner_.length).toBeGreaterThan(0);
    for (const p of inner_) expect(p.text).not.toContain('[WARNING]');
    expect(output.toString('latin1')).toContain(inner);
  });

  it('a text part inside an earlier message/rfc822 is never the candidate', async () => {
    const inner = message(['Content-Type: text/plain'], 'Inner first\r\n').toString('latin1');
    const mp = multipart('mixed', 'n2', [
      part(['Content-Type: message/rfc822'], inner),
      part(['Content-Type: text/plain'], 'Outer after\r\n'),
    ]);
    const eml = message(mp.headers, mp.body);
    const { result, output } = await run(eml);
    expect(result.partsEdited).toBe(1);
    expect(output.toString('latin1')).toContain(inner);
    expect(output.toString('latin1')).toContain(`${'-'.repeat(40)}\r\n\r\nOuter after`);
  });

  it('multipart/related: only the HTML root is a candidate; the inline image is untouched', async () => {
    const img = b64('\x89PNG fake', 'latin1');
    const mp = multipart('related', 'r1', [
      part(['Content-Type: text/html'], '<body><img src="cid:i1"></body>'),
      part(
        ['Content-Type: image/png', 'Content-ID: <i1>', 'Content-Transfer-Encoding: base64'],
        img,
      ),
      part(['Content-Type: text/html'], '<body>second html resource</body>'),
    ]);
    const { result, output } = await run(message(mp.headers, mp.body));
    expect(result.partsEdited).toBe(1);
    const parts = await readParts(output);
    expect(parts[0]!.text).toContain('role="alert"');
    expect(parts[1]!.raw.toString('latin1')).toBe(img);
    expect(parts[2]!.text).toBe('<body>second html resource</body>');
  });

  it('streams: the sink gets the edited message; on a skip the sink is destroyed', async () => {
    const eml = message(['Content-Type: text/plain'], 'hi\r\n');
    const sink = new PassThrough();
    const chunks: Buffer[] = [];
    sink.on('data', (c: Buffer) => chunks.push(c));
    const result = await insertWarningBanner({ ...opts(), source: Readable.from([eml]), sink });
    expect(result.status).toBe('applied');
    expect(Buffer.concat(chunks).toString('latin1')).toContain(BANNER);

    const skipSink = new PassThrough();
    skipSink.on('error', () => undefined);
    skipSink.resume();
    const skipped = await insertWarningBanner({
      ...opts(),
      source: Readable.from([message(['Content-Type: application/pdf'], 'x')]),
      sink: skipSink,
    });
    expect(skipped.status).toBe('skipped_no_text_part');
    expect(skipSink.destroyed).toBe(true);
  });

  it('a failing source is thrown (retryable), not reported as a skip', async () => {
    const source = new Readable({
      read() {
        this.destroy(new Error('s3 reset'));
      },
    });
    const sink = new PassThrough();
    sink.on('error', () => undefined);
    await expect(insertWarningBanner({ ...opts(), source, sink })).rejects.toThrow('s3 reset');
  });
});

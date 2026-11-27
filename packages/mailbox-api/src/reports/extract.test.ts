import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  decodeEncodedWords,
  extractReportedMessage,
  htmlToText,
  originalAttachmentHashes,
  parseForwardDate,
  parseInlineForward,
  reportEnvelopeHeaders,
  type ReportExtraction,
} from './extract';

// Synthetic MIME only (example.com / example.net / example.org, invented ids); no real mail.
const LIMITS = { maxBytes: 25 * 1024 * 1024, maxOriginalBytes: 10 * 1024 * 1024 };
const crlf = (lines: string[]): string => lines.join('\r\n');
const bytes = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, 'utf8'));
const sha = (data: Buffer | string): string => createHash('sha256').update(data).digest('hex');
const b64 = (text: string | Buffer): string =>
  (Buffer.isBuffer(text) ? text : Buffer.from(text, 'utf8'))
    .toString('base64')
    .replace(/.{1,76}/g, '$&\r\n')
    .trimEnd();

const PDF = Buffer.from('%PDF-1.4 synthetic test document, not a real file\n%%EOF\n', 'latin1');
const IMAGE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4, 5]);

/** The reported original: multipart/alternative body + a PDF attachment. */
const ORIGINAL = crlf([
  'Received: from mx.example.net by mx.example.com; Tue, 24 Nov 2026 09:00:00 +0000',
  'From: "Billing Team" <billing@Example.NET>',
  'To: alice@example.com',
  'Subject: =?UTF-8?B?UmU6IFJlY2hudW5nIGbDvHIgTcO8bGxlcg==?=',
  'Date: Tue, 24 Nov 2026 09:00:00 +0000',
  'Message-ID: <orig-123@mx.example.net>',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="orig-outer"',
  '',
  '--orig-outer',
  'Content-Type: multipart/alternative; boundary="orig-alt"',
  '',
  '--orig-alt',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Please pay the attached invoice.',
  '--orig-alt',
  'Content-Type: text/html; charset=utf-8',
  '',
  '<p>Please pay the attached invoice.</p>',
  '--orig-alt--',
  '--orig-outer',
  'Content-Type: application/pdf; name="invoice.pdf"',
  'Content-Disposition: attachment; filename="invoice.pdf"',
  'Content-Transfer-Encoding: base64',
  '',
  b64(PDF),
  '--orig-outer',
  'Content-Type: image/png',
  'Content-Disposition: inline',
  'Content-Transfer-Encoding: base64',
  '',
  b64(IMAGE),
  '--orig-outer--',
  '',
]);

function report(parts: string[], boundary = 'rpt-b', extraHeaders: string[] = []): string {
  return crlf([
    'From: Alice Example <alice@example.com>',
    'To: phish-report@example.com',
    'Subject: Fwd: suspicious invoice',
    'Date: Wed, 25 Nov 2026 08:00:00 +0000',
    'Message-ID: <rpt-1@example.com>',
    ...extraHeaders,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    'This is a multi-part message in MIME format.',
    ...parts.flatMap((p) => [`--${boundary}`, p]),
    `--${boundary}--`,
    '',
  ]);
}

const NOTE = crlf(['Content-Type: text/plain; charset=utf-8', '', 'Looks like phishing to me.']);

function expectAttachment(result: ReportExtraction) {
  expect(result.ok).toBe(true);
  if (!result.ok || result.identification !== 'attachment') {
    throw new Error(`expected attachment, got ${JSON.stringify(result)}`);
  }
  return result;
}

describe('extractReportedMessage: forward as attachment (C10.2)', () => {
  it('Gmail style: message/rfc822 attachment with 7bit body', () => {
    const eml = report([
      NOTE,
      crlf([
        'Content-Type: message/rfc822; name="Rechnung.eml"',
        'Content-Disposition: attachment; filename="Rechnung.eml"',
        '',
        ORIGINAL,
      ]),
    ]);
    const result = expectAttachment(extractReportedMessage(bytes(eml), LIMITS));
    expect(result.headers).toEqual({
      messageId: '<orig-123@mx.example.net>',
      from: 'billing@example.net',
      date: new Date('2026-11-24T09:00:00.000Z'),
      subject: 'Re: Rechnung für Müller',
    });
    expect(result.extraOriginals).toBe(0);
    expect(Buffer.from(result.original).toString('utf8')).toBe(ORIGINAL);
    // The PDF and the inline image (every leaf except the first text/plain and text/html bodies).
    expect(result.attachmentSha256).toEqual([sha(PDF), sha(IMAGE)]);
    expect(result.attachmentsComplete).toBe(true);
  });

  it('Outlook style: alternative note, base64-encoded rfc822 parts, extra originals counted', () => {
    const second = ORIGINAL.replace('orig-123@', 'orig-456@');
    const eml = report([
      crlf([
        'Content-Type: multipart/alternative; boundary="alt-1"',
        '',
        '--alt-1',
        'Content-Type: text/plain; charset="us-ascii"',
        '',
        'FYI',
        '--alt-1',
        'Content-Type: text/html; charset="us-ascii"',
        '',
        '<p>FYI</p>',
        '--alt-1--',
      ]),
      crlf([
        'Content-Type: message/rfc822',
        'Content-Transfer-Encoding: base64',
        'Content-Disposition: attachment',
        '',
        b64(ORIGINAL),
      ]),
      crlf(['Content-Type: message/rfc822', 'Content-Disposition: attachment', '', second]),
    ]);
    const result = expectAttachment(extractReportedMessage(bytes(eml), LIMITS));
    expect(result.headers.messageId).toBe('<orig-123@mx.example.net>');
    expect(result.extraOriginals).toBe(1);
    expect(Buffer.from(result.original).toString('utf8')).toBe(ORIGINAL);
  });

  it('.eml as application/octet-stream with an RFC 2231 file name', () => {
    const eml = report([
      NOTE,
      crlf([
        'Content-Type: application/octet-stream',
        "Content-Disposition: attachment; filename*=utf-8''Rechnung%20M%C3%A4rz.EML",
        'Content-Transfer-Encoding: base64',
        '',
        b64(ORIGINAL),
      ]),
    ]);
    const result = expectAttachment(extractReportedMessage(bytes(eml), LIMITS));
    expect(result.headers.from).toBe('billing@example.net');
  });

  it('application/eml in quoted-printable', () => {
    const simple = crlf([
      'From: sender@example.org',
      'Subject: =?iso-8859-1?Q?Gr=FC=DFe_aus_K=F6ln?=',
      'Message-ID: <qp-1@example.org>',
      '',
      'Body with a long line that is soft-broken by quoted printable encoding here.',
    ]);
    const qp = simple.replace(/=/g, '=3D').replace('soft-broken by', 'soft-=\r\nbroken by');
    const eml = report([
      crlf([
        'Content-Type: application/eml; name="forwarded.eml"',
        'Content-Transfer-Encoding: quoted-printable',
        '',
        qp,
      ]),
    ]);
    const result = expectAttachment(extractReportedMessage(bytes(eml), LIMITS));
    expect(Buffer.from(result.original).toString('utf8')).toBe(simple);
    expect(result.headers.subject).toBe('Grüße aus Köln');
    expect(result.headers.messageId).toBe('<qp-1@example.org>');
  });

  it('an octet-stream without .eml name is not an original', () => {
    const eml = report([
      NOTE,
      crlf(['Content-Type: application/octet-stream; name="data.bin"', '', 'xyz']),
    ]);
    expect(extractReportedMessage(bytes(eml), LIMITS)).toEqual({
      ok: true,
      identification: 'none',
      extraOriginals: 0,
    });
  });

  it('nested multipart (depth 3) and a missing close delimiter', () => {
    const eml = crlf([
      'From: alice@example.com',
      'Content-Type: multipart/mixed; boundary=L0',
      '',
      '--L0',
      'Content-Type: multipart/related; boundary=L1',
      '',
      '--L1',
      'Content-Type: multipart/alternative; boundary=L2',
      '',
      '--L2',
      'Content-Type: text/plain',
      '',
      'see attached',
      '--L2--',
      '--L1',
      'Content-Type: message/rfc822',
      '',
      ORIGINAL,
      '--L1--',
      // L0 is never closed: tolerated, the last part runs to the end.
    ]);
    const result = expectAttachment(extractReportedMessage(bytes(eml), LIMITS));
    expect(result.headers.messageId).toBe('<orig-123@mx.example.net>');
  });

  it('a top-level message/rfc822 body is the original', () => {
    const eml = crlf(['From: alice@example.com', 'Content-Type: message/rfc822', '', ORIGINAL]);
    expect(expectAttachment(extractReportedMessage(bytes(eml), LIMITS)).headers.messageId).toBe(
      '<orig-123@mx.example.net>',
    );
  });

  it('the attachment wins over an inline forward in the note', () => {
    const note = crlf([
      'Content-Type: text/plain',
      '',
      '-----Original Message-----',
      'From: other@example.org',
      'Subject: other',
    ]);
    const eml = report([note, crlf(['Content-Type: message/rfc822', '', ORIGINAL])]);
    expect(extractReportedMessage(bytes(eml), LIMITS)).toMatchObject({
      identification: 'attachment',
    });
  });
});

describe('extractReportedMessage: inline forwards (C10.2)', () => {
  const plain = (body: string, charset = 'utf-8', encoding?: string) =>
    crlf([
      'From: alice@example.com',
      'Subject: Fwd: hello',
      `Content-Type: text/plain; charset=${charset}`,
      ...(encoding ? [`Content-Transfer-Encoding: ${encoding}`] : []),
      '',
      body,
    ]);
  const inline = (eml: string) => {
    const result = extractReportedMessage(bytes(eml), LIMITS);
    if (!result.ok || result.identification !== 'inline') {
      throw new Error(`expected inline, got ${JSON.stringify(result)}`);
    }
    return result;
  };

  it('Gmail (English)', () => {
    const result = inline(
      plain(
        crlf([
          'Is this real?',
          '',
          '---------- Forwarded message ---------',
          'From: Billing Team <billing@example.net>',
          'Date: Mon, Nov 23, 2026 at 10:15 AM',
          'Subject: Re: Invoice 4711',
          'To: <alice@example.com>',
          '',
          'Please pay.',
        ]),
      ),
    );
    expect(result.separator).toBe('forwarded_message');
    expect(result.headers).toEqual({
      messageId: null,
      from: 'billing@example.net',
      date: new Date('2026-11-23T10:15:00.000Z'),
      subject: 'Re: Invoice 4711',
    });
  });

  it('Outlook (English) with Sent:, [mailto:] and a Message-ID line', () => {
    const result = inline(
      plain(
        crlf([
          '-----Original Message-----',
          'From: Billing Team [mailto:billing@example.net]',
          'Sent: Monday, November 23, 2026 4:05 PM',
          'To: Alice Example',
          'Subject: Payment overdue',
          'Message-ID: <inline-9@example.net>',
          '',
          'Body',
        ]),
      ),
    );
    expect(result.separator).toBe('original_message');
    expect(result.headers).toEqual({
      messageId: '<inline-9@example.net>',
      from: 'billing@example.net',
      date: new Date('2026-11-23T16:05:00.000Z'),
      subject: 'Payment overdue',
    });
  });

  it('Outlook (German), quoted-printable', () => {
    const body = crlf([
      'Bitte prüfen.',
      '-----Ursprüngliche Nachricht-----',
      'Von: Buchhaltung <buchhaltung@example.net>',
      'Gesendet: Montag, 23. November 2026 10:15',
      'An: Alice <alice@example.com>',
      'Betreff: Offene Rechnung',
      '',
      'Text',
    ]);
    const qp = Buffer.from(body, 'utf8')
      .toString('latin1')
      .replace(
        /[\u0080-ÿ=]/g,
        (c) => `=${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`,
      );
    const result = inline(plain(qp, 'utf-8', 'quoted-printable'));
    expect(result.headers).toEqual({
      messageId: null,
      from: 'buchhaltung@example.net',
      date: new Date('2026-11-23T10:15:00.000Z'),
      subject: 'Offene Rechnung',
    });
  });

  it('Gmail (German) and Apple Mail (German)', () => {
    expect(
      inline(
        plain(
          crlf([
            '---------- Weitergeleitete Nachricht ---------',
            'Von: x <x@example.net>',
            'Date: Mo., 23. Nov. 2026 um 10:15 Uhr',
            'Subject: Paket',
          ]),
        ),
      ).headers,
    ).toMatchObject({
      from: 'x@example.net',
      subject: 'Paket',
      date: new Date('2026-11-23T10:15:00.000Z'),
    });
    expect(
      inline(
        plain(
          crlf([
            'Anfang der weitergeleiteten Nachricht:',
            '',
            'Von: x <x@example.net>',
            'Betreff: Paket 2',
            'Datum: 23. November 2026 um 10:15:00 MEZ',
          ]),
        ),
      ).headers.subject,
    ).toBe('Paket 2');
  });

  it('Outlook (French) in latin-1 and Apple Mail (French)', () => {
    const body = crlf([
      "-----Message d'origine-----",
      'De : Service <service@example.net>',
      'Envoyé : lundi 23 novembre 2026 10:15',
      'À : alice@example.com',
      'Objet : Votre colis',
    ]);
    const latin1 = Buffer.from(body, 'latin1').toString('base64');
    const result = inline(plain(latin1, 'iso-8859-1', 'base64'));
    expect(result.headers).toEqual({
      messageId: null,
      from: 'service@example.net',
      date: new Date('2026-11-23T10:15:00.000Z'),
      subject: 'Votre colis',
    });
    expect(
      inline(
        plain(
          crlf([
            'Début du message réexpédié :',
            '',
            'De: Service <service@example.net>',
            'Objet: Colis 2',
            'Date: 23 novembre 2026 à 10:15:00 UTC+1',
          ]),
        ),
      ).headers.subject,
    ).toBe('Colis 2');
  });

  it('Apple Mail (English), Thunderbird and quoted lines', () => {
    expect(
      inline(
        plain(
          crlf([
            'Begin forwarded message:',
            '',
            'From: a@example.net',
            'Subject: Apple',
            'Date: November 23, 2026 at 10:15:00 AM GMT+1',
          ]),
        ),
      ).headers,
    ).toMatchObject({
      from: 'a@example.net',
      subject: 'Apple',
      date: new Date('2026-11-23T09:15:00.000Z'),
    });
    expect(
      inline(
        plain(
          crlf([
            '-------- Forwarded Message --------',
            'Subject: \tThunderbird',
            'Date: \tMon, 23 Nov 2026 10:15:00 +0100',
            'From: \tT <t@example.net>',
          ]),
        ),
      ).headers,
    ).toMatchObject({ from: 't@example.net', date: new Date('2026-11-23T09:15:00.000Z') });
    expect(
      inline(
        plain(crlf(['> -----Original Message-----', '> From: q@example.net', '> Subject: quoted'])),
      ).headers.from,
    ).toBe('q@example.net');
  });

  it('HTML only (Gmail markup reduced to text)', () => {
    const html = crlf([
      'From: alice@example.com',
      'Content-Type: text/html; charset=utf-8',
      '',
      '<html><head><style>p{color:red}</style></head><body><div dir="ltr">FYI<br>',
      '<div class="gmail_quote"><div dir="ltr" class="gmail_attr">---------- Forwarded message ---------<br>',
      'From: <strong class="gmail_sendername" dir="auto">Billing</strong> <span dir="auto">&lt;<a href="mailto:billing@example.net">billing@example.net</a>&gt;</span><br>',
      'Date: Mon, Nov 23, 2026 at 10:15&nbsp;AM<br>Subject: Invoice &amp; reminder<br>To: &lt;alice@example.com&gt;<br></div>',
      '<script>document.write("x")</script></div></div></body></html>',
    ]);
    const result = inline(html);
    expect(result.headers).toEqual({
      messageId: null,
      from: 'billing@example.net',
      date: new Date('2026-11-23T10:15:00.000Z'),
      subject: 'Invoice & reminder',
    });
  });

  it('a separator without From/Subject within 20 lines is not a forward', () => {
    const lines = [
      '-----Original Message-----',
      ...Array(20).fill('filler'),
      'From: late@example.net',
      'Subject: late',
    ];
    expect(extractReportedMessage(bytes(plain(crlf(lines))), LIMITS)).toMatchObject({
      identification: 'none',
    });
    expect(
      extractReportedMessage(
        bytes(plain(crlf(['-----Original Message-----', 'From: a@example.net', 'no subject']))),
        LIMITS,
      ),
    ).toMatchObject({ identification: 'none' });
  });

  it('a From without an address keeps the subject (sender null)', () => {
    expect(
      inline(
        plain(
          crlf([
            '________________________________',
            'From: Billing Team',
            'Sent: Monday, November 23, 2026 10:15 AM',
            'Subject: x',
          ]),
        ),
      ).headers,
    ).toMatchObject({ from: null, subject: 'x' });
  });
});

describe('extractReportedMessage: unsupported, none, limits, malformed', () => {
  it('Outlook .msg attachment → unsupported', () => {
    const eml = report([
      NOTE,
      crlf([
        'Content-Type: application/vnd.ms-outlook; name="Invoice.msg"',
        'Content-Transfer-Encoding: base64',
        '',
        b64(Buffer.from([0xd0, 0xcf, 0x11, 0xe0])),
      ]),
    ]);
    expect(extractReportedMessage(bytes(eml), LIMITS)).toEqual({
      ok: true,
      identification: 'unsupported',
      extraOriginals: 0,
    });
    const byName = report([
      crlf(['Content-Type: application/octet-stream; name="x.MSG"', '', 'x']),
    ]);
    expect(extractReportedMessage(bytes(byName), LIMITS)).toMatchObject({
      identification: 'unsupported',
    });
  });

  it('nothing found → none', () => {
    expect(extractReportedMessage(bytes(report([NOTE])), LIMITS)).toEqual({
      ok: true,
      identification: 'none',
      extraOriginals: 0,
    });
    expect(extractReportedMessage(bytes('From: a@example.com\r\n\r\nhello'), LIMITS)).toMatchObject(
      {
        identification: 'none',
      },
    );
    expect(extractReportedMessage(bytes(''), LIMITS)).toMatchObject({ identification: 'none' });
  });

  it('too large report, too large original', () => {
    const eml = bytes(report([NOTE, crlf(['Content-Type: message/rfc822', '', ORIGINAL])]));
    expect(extractReportedMessage(eml, { ...LIMITS, maxBytes: eml.length - 1 })).toEqual({
      ok: false,
      code: 'too_large',
      limit: 'bytes',
    });
    expect(extractReportedMessage(eml, { ...LIMITS, maxOriginalBytes: 100 })).toEqual({
      ok: false,
      code: 'too_large',
      limit: 'original_bytes',
    });
  });

  it('more than 200 parts, deeper than 4 levels', () => {
    const many = report(Array.from({ length: 200 }, () => NOTE));
    expect(extractReportedMessage(bytes(many), LIMITS)).toEqual({
      ok: false,
      code: 'too_large',
      limit: 'parts',
    });
    expect(
      extractReportedMessage(bytes(report(Array.from({ length: 199 }, () => NOTE))), LIMITS),
    ).toMatchObject({
      ok: true,
    });
    let nested = NOTE;
    for (let i = 4; i >= 1; i -= 1) {
      nested = crlf([
        `Content-Type: multipart/mixed; boundary="d${i}"`,
        '',
        `--d${i}`,
        nested,
        `--d${i}--`,
      ]);
    }
    // top (0) → d1 (1) → d2 (2) → d3 (3) → d4 (4) → note (5)
    expect(extractReportedMessage(bytes(report([nested])), LIMITS)).toEqual({
      ok: false,
      code: 'too_large',
      limit: 'depth',
    });
    expect(
      extractReportedMessage(bytes(report([nested])), { ...LIMITS, maxDepth: 5 }),
    ).toMatchObject({ ok: true });
  });

  it('malformed boundaries → parse_failed', () => {
    const noParam = crlf([
      'From: a@example.com',
      'Content-Type: multipart/mixed',
      '',
      '--x',
      NOTE,
      '--x--',
    ]);
    expect(extractReportedMessage(bytes(noParam), LIMITS)).toEqual({
      ok: false,
      code: 'parse_failed',
    });
    const neverFound = crlf([
      'From: a@example.com',
      'Content-Type: multipart/mixed; boundary="expected"',
      '',
      '--other',
      NOTE,
      '--other--',
    ]);
    expect(extractReportedMessage(bytes(neverFound), LIMITS)).toEqual({
      ok: false,
      code: 'parse_failed',
    });
    const tooLong = crlf([
      `From: a@example.com`,
      `Content-Type: multipart/mixed; boundary="${'b'.repeat(201)}"`,
      '',
      'x',
    ]);
    expect(extractReportedMessage(bytes(tooLong), LIMITS)).toEqual({
      ok: false,
      code: 'parse_failed',
    });
    const unknownEncoding = report([
      crlf([
        'Content-Type: message/rfc822',
        'Content-Transfer-Encoding: x-uuencode',
        '',
        'begin 644 x',
      ]),
    ]);
    expect(extractReportedMessage(bytes(unknownEncoding), LIMITS)).toEqual({
      ok: false,
      code: 'parse_failed',
    });
  });

  it('ignores a boundary string that is not at a line start or has trailing text', () => {
    const eml = crlf([
      'From: a@example.com',
      'Content-Type: multipart/mixed; boundary="bb"',
      '',
      'preamble mentions --bb inline',
      '--bbX not a delimiter',
      '--bb',
      NOTE,
      '--bb',
      'Content-Type: message/rfc822',
      '',
      ORIGINAL,
      '--bb--',
    ]);
    expect(extractReportedMessage(bytes(eml), LIMITS)).toMatchObject({
      identification: 'attachment',
    });
  });

  it('carries no address, subject or content in failures (redaction)', () => {
    const results = [
      extractReportedMessage(bytes(report([NOTE])), { ...LIMITS, maxBytes: 10 }),
      extractReportedMessage(
        bytes(
          crlf([
            'From: secret.person@example.com',
            'Subject: Top secret merger',
            'Content-Type: multipart/mixed',
            '',
            'x',
          ]),
        ),
        LIMITS,
      ),
    ];
    for (const r of results) {
      expect(r.ok).toBe(false);
      const text = JSON.stringify(r);
      expect(text).not.toMatch(/@|secret|merger|alice|phishing/i);
    }
  });

  it('stays linear on hostile input', () => {
    const started = Date.now();
    extractReportedMessage(
      bytes(crlf(['Content-Type: text/html', '', '<script'.repeat(100_000)])),
      LIMITS,
    );
    extractReportedMessage(
      bytes(crlf(['Content-Type: text/html', '', '<'.repeat(500_000)])),
      LIMITS,
    );
    extractReportedMessage(
      bytes(crlf(['Content-Type: multipart/mixed; boundary=z', '', '--z\r\n'.repeat(150)])),
      LIMITS,
    );
    extractReportedMessage(
      bytes(crlf(['Content-Type: text/plain', '', '-----Original Message-----\n'.repeat(50_000)])),
      LIMITS,
    );
    expect(Date.now() - started).toBeLessThan(3000);
  });
});

describe('helpers', () => {
  it('decodes encoded-words', () => {
    expect(decodeEncodedWords('=?UTF-8?B?w4RyZ2Vy?= =?UTF-8?Q?_mit_=C3=9Cmlaut?=')).toBe(
      'Ärger mit Ümlaut',
    );
    expect(decodeEncodedWords('plain =?unknown-cs?Q?x?=')).toBe('plain x');
    expect(decodeEncodedWords('no words')).toBe('no words');
  });

  it.each([
    ['Tue, 24 Nov 2026 09:00:00 +0100', '2026-11-24T08:00:00.000Z'],
    ['Mon, Nov 23, 2026 at 10:15 AM', '2026-11-23T10:15:00.000Z'],
    ['Monday, November 23, 2026 12:05 AM', '2026-11-23T00:05:00.000Z'],
    ['Monday, November 23, 2026 12:05 PM', '2026-11-23T12:05:00.000Z'],
    ['Montag, 23. November 2026 10:15', '2026-11-23T10:15:00.000Z'],
    ['lundi 23 novembre 2026 10:15', '2026-11-23T10:15:00.000Z'],
    ['1 février 2026 08:00', '2026-02-01T08:00:00.000Z'],
    ['2026-11-23 10:15', '2026-11-23T10:15:00.000Z'],
    ['23.11.2026 10:15', '2026-11-23T10:15:00.000Z'],
    ['23/11/2026 10:15', '2026-11-23T10:15:00.000Z'],
    ['11/23/2026 10:15 PM', '2026-11-23T22:15:00.000Z'],
    ['November 23, 2026 at 10:15:00 AM GMT+01:00', '2026-11-23T09:15:00.000Z'],
    ['05/06/2026 10:15', null],
    ['31.02.2026 10:00', null],
    ['13:15 PM 23.11.2026', null],
    ['yesterday', null],
  ])('parses forward date %j', (value, expected) => {
    expect(parseForwardDate(value)?.toISOString() ?? null).toBe(expected);
  });

  it('reduces HTML to text', () => {
    expect(htmlToText('<p>a<br/>b</p><style>x{}</style>c &lt;d&gt; &#228;&#xE4; &bogus;')).toBe(
      '\na\nb\nc <d> ää &bogus;',
    );
    expect(htmlToText('a < b and c')).toBe('a < b and c');
    expect(htmlToText('x<script>never')).toBe('x');
  });

  it('parseInlineForward returns null without a separator', () => {
    expect(parseInlineForward('From: a@example.net\nSubject: x')).toBeNull();
  });

  it('hashes attachments of an original (mime-parser rule, nested message leaves included)', () => {
    const inner = crlf(['From: i@example.org', 'Content-Type: text/plain', '', 'inner body']);
    const original = crlf([
      'From: o@example.org',
      'Content-Type: multipart/mixed; boundary=o',
      '',
      '--o',
      'Content-Type: text/plain',
      '',
      'outer body',
      '--o',
      'Content-Type: text/plain',
      '',
      'second plain is an attachment',
      '--o',
      'Content-Type: message/rfc822',
      '',
      inner,
      '--o--',
    ]);
    expect(originalAttachmentHashes(bytes(original))).toEqual({
      sha256: [sha('second plain is an attachment'), sha('inner body')],
      complete: true,
    });
    expect(originalAttachmentHashes(bytes(original), { max: 1 }).sha256).toHaveLength(1);
    expect(originalAttachmentHashes(bytes(original), { maxParts: 3 })).toEqual({
      sha256: [sha('second plain is an attachment')],
      complete: false,
    });
  });

  it('reads the report envelope headers', () => {
    expect(
      reportEnvelopeHeaders(
        bytes(
          crlf([
            'From: "Alice" <Alice@Example.com>',
            'Auto-Submitted: Auto-Replied; owner-email="x@example.com"',
            'Precedence: Bulk',
            '',
            'body',
          ]),
        ),
      ),
    ).toEqual({ from: 'Alice@example.com', autoSubmitted: 'auto-replied', precedence: 'bulk' });
    expect(reportEnvelopeHeaders(bytes('From: a@example.com\r\n\r\n'))).toEqual({
      from: 'a@example.com',
      autoSubmitted: null,
      precedence: null,
    });
  });
});

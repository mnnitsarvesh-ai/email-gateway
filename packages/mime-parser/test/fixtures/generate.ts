/**
 * Generates the committed MIME fixture corpus (design §9). Deterministic: no clock, no
 * randomness. `pnpm --filter @email-gateway/mime-parser fixtures:generate` rewrites the .eml files;
 * test/corpus.test.ts regenerates them in memory and asserts byte equality, so drift between the
 * generator and the committed files fails the build. Large and over-limit inputs, bombs and
 * archives are generated at test time instead and never committed.
 *
 * Self-contained (node builtins only) so it also runs directly under Node's type stripping.
 */
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const CRLF = '\r\n';
const lines = (...items: string[]): string => items.join(CRLF);
const b64 = (data: string | Buffer): string =>
  (typeof data === 'string' ? Buffer.from(data, 'utf8') : data)
    .toString('base64')
    .replace(/.{1,76}/g, (line) => `${line}${CRLF}`)
    .trimEnd();

const BASE = [
  'From: Alice <alice@example.com>',
  'To: bob@example.net',
  'Date: Mon, 2 Nov 2026 10:00:00 +0000',
];
const msgId = (name: string): string => `Message-ID: <${name}@fixtures.example>`;

interface Part {
  headers: string[];
  body: string;
}

function multipart(boundary: string, parts: Part[], close = true): string {
  const out: string[] = ['This is a multi-part message in MIME format.'];
  for (const part of parts) out.push(`--${boundary}`, ...part.headers, '', part.body);
  if (close) out.push(`--${boundary}--`, '');
  return lines(...out);
}

function message(name: string, headers: string[], body: string): string {
  return lines(...BASE, msgId(name), 'MIME-Version: 1.0', ...headers, '', body);
}

function attachment(
  type: string,
  filenameParam: string,
  content: string | Buffer,
  disposition = 'attachment',
): Part {
  return {
    headers: [
      `Content-Type: ${type}`,
      `Content-Disposition: ${disposition}; ${filenameParam}`,
      'Content-Transfer-Encoding: base64',
    ],
    body: b64(content),
  };
}

const text = (body: string, charset = 'utf-8'): Part => ({
  headers: [`Content-Type: text/plain; charset=${charset}`, 'Content-Transfer-Encoding: 7bit'],
  body,
});

const PNG_1X1 = Buffer.from(
  '89504e470d0a1a0a0000000d4948445200000001000000010806000000' +
    '1f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a4ab0000000049454e44ae426082',
  'hex',
);
const PDF = '%PDF-1.4\n% fixture\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n';

function nested(depth: number): string {
  // Root multipart at depth 0, one multipart per level, a text leaf at `depth`.
  let body = lines('Content-Type: text/plain', '', `leaf at depth ${depth}`);
  for (let level = depth - 1; level >= 1; level--) {
    const boundary = `level-${level}`;
    body = lines(
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      multipart(boundary, [splitPart(body)]),
    );
  }
  return message(
    `depth-${depth}`,
    [`Subject: depth ${depth}`, 'Content-Type: multipart/mixed; boundary="level-0"'],
    multipart('level-0', [splitPart(body)]),
  );
}

function splitPart(raw: string): Part {
  const end = raw.indexOf(CRLF + CRLF);
  return { headers: raw.slice(0, end).split(CRLF), body: raw.slice(end + 4) };
}

/** Builders of every committed fixture, keyed by file name. */
export const FIXTURES: Record<string, () => Buffer> = {
  'missing-boundary-parameter.eml': () =>
    Buffer.from(
      message(
        'no-boundary',
        ['Subject: no boundary', 'Content-Type: multipart/mixed'],
        lines('--x', 'Content-Type: text/plain', '', 'hello', '--x--', ''),
      ),
    ),
  'boundary-not-found.eml': () =>
    Buffer.from(
      message(
        'boundary-missing',
        ['Subject: boundary never used', 'Content-Type: multipart/mixed; boundary="never-used"'],
        lines('--other', '', 'text without our delimiter', ''),
      ),
    ),
  'unterminated-multipart.eml': () =>
    Buffer.from(
      message(
        'unterminated',
        ['Subject: unterminated', 'Content-Type: multipart/mixed; boundary="open"'],
        multipart(
          'open',
          [text('first part'), text('second part, no closing delimiter follows')],
          false,
        ),
      ),
    ),
  'base64-truncated.eml': () =>
    Buffer.from(
      message(
        'b64-truncated',
        [
          'Subject: truncated base64',
          'Content-Type: application/octet-stream; name="t.bin"',
          'Content-Transfer-Encoding: base64',
        ],
        'SGVsbG8gd29ybGQ',
      ),
    ),
  'base64-invalid-chars.eml': () =>
    Buffer.from(
      lines(
        ...BASE,
        msgId('b64-invalid'),
        'Subject: invalid base64',
        'Content-Type: text/plain; charset=utf-8',
        'Content-Transfer-Encoding: base64',
        '',
        'SGVs*bG8g!d29y#bGQh',
        '',
      ),
    ),
  'qp-invalid.eml': () =>
    Buffer.from(
      lines(
        ...BASE,
        msgId('qp-invalid'),
        'Subject: invalid qp',
        'Content-Type: text/plain; charset=utf-8',
        'Content-Transfer-Encoding: quoted-printable',
        '',
        'price =3D 10 =ZZ and =4 end',
        '',
      ),
    ),
  'unknown-cte.eml': () =>
    Buffer.from(
      lines(
        ...BASE,
        msgId('unknown-cte'),
        'Subject: unknown cte',
        'Content-Type: text/plain',
        'Content-Transfer-Encoding: x-uuencode',
        '',
        'begin 644 file',
        '',
      ),
    ),
  'unknown-charset.eml': () =>
    Buffer.from(
      lines(
        ...BASE,
        msgId('unknown-charset'),
        'Subject: unknown charset',
        'Content-Type: text/plain; charset=x-unknown',
        '',
        'plain text in an unknown charset',
        '',
      ),
    ),
  'mislabelled-charset.eml': () =>
    Buffer.concat([
      Buffer.from(
        lines(
          ...BASE,
          msgId('mislabelled'),
          'Subject: mislabelled charset',
          'Content-Type: text/plain; charset=us-ascii',
          'Content-Transfer-Encoding: 8bit',
          '',
          '',
        ),
      ),
      Buffer.from('caf\xe9 cr\xe8me\r\n', 'latin1'),
    ]),
  'garbage-binary.eml': () => {
    const bytes = Buffer.alloc(2048);
    let state = 0x2545f491;
    for (let index = 0; index < bytes.length; index++) {
      state = (Math.imul(state, 1103515245) + 12345) >>> 0;
      bytes[index] = state >>> 24;
    }
    return bytes;
  },
  'empty.eml': () => Buffer.alloc(0),
  'headers-only.eml': () =>
    Buffer.from(lines(...BASE, msgId('headers-only'), 'Subject: headers only', '')),
  'no-headers.eml': () => Buffer.from(lines('', 'This message starts with a blank line.', '')),
  'nul-in-headers.eml': () =>
    Buffer.from(
      lines(...BASE, msgId('nul'), 'Subject: nul\u0000inside', 'X-Test: a\u0000b', '', 'body', ''),
    ),
  'duplicate-from-subject.eml': () =>
    Buffer.from(
      lines(
        'From: first@example.com',
        'From: second@example.com',
        'Subject: one',
        'Subject: two',
        'To: bob@example.net',
        '',
        'body',
        '',
      ),
    ),
  'nested-rfc822.eml': () => {
    const innermost = lines(
      'From: inner2@example.org',
      'Subject: innermost',
      'Content-Type: multipart/mixed; boundary="inner2"',
      '',
      multipart('inner2', [
        text('innermost text'),
        attachment('application/pdf', 'filename="deep.pdf"', PDF),
      ]),
    );
    const inner = lines(
      'From: inner1@example.org',
      'Subject: inner',
      'Content-Type: multipart/mixed; boundary="inner1"',
      '',
      multipart('inner1', [
        text('inner text'),
        attachment('text/csv', 'filename="data.csv"', 'a,b\n1,2\n'),
        { headers: ['Content-Type: message/rfc822'], body: innermost },
      ]),
    );
    return Buffer.from(
      message(
        'nested',
        ['Subject: forwarded twice', 'Content-Type: multipart/mixed; boundary="outer"'],
        multipart('outer', [
          text('outer text'),
          { headers: ['Content-Type: message/rfc822'], body: inner },
        ]),
      ),
    );
  },
  'depth-at-limit.eml': () => Buffer.from(nested(10)),
  'depth-over-limit.eml': () => Buffer.from(nested(11)),
  'multiple-attachments.eml': () =>
    Buffer.from(
      message(
        'multi',
        ['Subject: five attachments', 'Content-Type: multipart/mixed; boundary="multi"'],
        multipart('multi', [
          text('see attachments'),
          attachment('application/pdf', 'filename="one.pdf"', PDF),
          attachment('image/png', 'filename="two.png"', PNG_1X1, 'inline'),
          attachment('text/plain', 'filename="three.txt"', 'third'),
          attachment('application/octet-stream', 'filename="four.bin"', Buffer.from([0, 1, 2, 3])),
          attachment(
            'text/calendar',
            'filename="five.ics"',
            'BEGIN:VCALENDAR\nEND:VCALENDAR\n',
            'inline',
          ),
          { headers: ['Content-Type: text/plain; charset=utf-8'], body: 'second inline text part' },
        ]),
      ),
    ),
  'inline-image.eml': () =>
    Buffer.from(
      message(
        'inline-image',
        ['Subject: inline image', 'Content-Type: multipart/related; boundary="rel"'],
        multipart('rel', [
          {
            headers: ['Content-Type: text/html; charset=utf-8'],
            body: '<html><body><img src="cid:img1"></body></html>',
          },
          {
            headers: [
              'Content-Type: image/png',
              'Content-ID: <img1>',
              'Content-Disposition: inline',
              'Content-Transfer-Encoding: base64',
            ],
            body: b64(PNG_1X1),
          },
        ]),
      ),
    ),
  'alternative.eml': () =>
    Buffer.from(
      message(
        'alternative',
        ['Subject: alternative', 'Content-Type: multipart/alternative; boundary="alt"'],
        multipart('alt', [
          text('plain version'),
          {
            headers: [
              'Content-Type: text/html; charset=utf-8',
              'Content-Transfer-Encoding: quoted-printable',
            ],
            body: '<p>html =E2=9C=93 version</p>',
          },
        ]),
      ),
    ),
  'html-only.eml': () =>
    Buffer.from(
      message(
        'html-only',
        [
          'Subject: html only',
          'Content-Type: text/html; charset=iso-8859-1',
          'Content-Transfer-Encoding: quoted-printable',
        ],
        '<p>caf=E9</p>',
      ),
    ),
  'pdf-root.eml': () =>
    Buffer.from(
      message(
        'pdf-root',
        [
          'Subject: bare pdf',
          'Content-Type: application/pdf; name="bare.pdf"',
          'Content-Transfer-Encoding: base64',
        ],
        b64(PDF),
      ),
    ),
  'encoded-words.eml': () =>
    Buffer.from(
      lines(
        ...BASE,
        msgId('encoded-words'),
        'Subject: =?UTF-8?B?w5xiZXJ3ZWlzdW5nIOKckw==?=',
        'Reply-To: =?ISO-8859-1?Q?Andr=E9?= <andre@example.com>',
        'Sender: =?Shift_JIS?B?k/qWe4zq?= <jp@example.jp>',
        'Cc: =?KOI8-R?Q?=F0=D2=C9=D7=C5=D4?= <ru@example.ru>',
        'In-Reply-To: =?utf-8?Q?broken=ZZ?= =?utf-8?B?not-base64!?= =?utf-8?Q?unterminated',
        'References: =?x-unknown?Q?abc?=',
        '',
        'body',
        '',
      ),
    ),
  'rfc2231.eml': () =>
    Buffer.from(
      message(
        'rfc2231',
        ['Subject: rfc2231', 'Content-Type: multipart/mixed; boundary="r"'],
        multipart('r', [
          text('see attachment'),
          {
            headers: [
              'Content-Type: application/pdf',
              "Content-Disposition: attachment; filename*0*=UTF-8''%C3%9Cber%20den; filename*1*=%20Wolken%20%E2%98%81.pdf",
              'Content-Transfer-Encoding: base64',
            ],
            body: b64(PDF),
          },
          attachment('text/plain', 'filename="=?ISO-8859-1?Q?R=E9sum=E9=2Etxt?="', 'cv'),
        ]),
      ),
    ),
  'raw-utf8-headers.eml': () =>
    Buffer.from(
      lines(
        'From: Jürgen <jurgen@example.de>',
        'To: 山田 <yamada@example.jp>',
        'Subject: Grüße aus Köln 👋',
        msgId('raw-utf8'),
        '',
        'body',
        '',
      ),
    ),
  'filename-traversal.eml': () =>
    Buffer.from(
      message(
        'traversal',
        ['Subject: traversal', 'Content-Type: multipart/mixed; boundary="t"'],
        multipart('t', [
          attachment('text/plain', 'filename="../../etc/passwd"', 'root:x:0:0'),
          attachment('text/plain', 'filename="..\\\\..\\\\win.ini"', '[fonts]'),
          attachment(
            'application/octet-stream',
            'filename="C:\\\\x.exe"',
            Buffer.from('MZ\x90\x00', 'latin1'),
          ),
        ]),
      ),
    ),
  'filename-bidi.eml': () =>
    Buffer.from(
      message(
        'bidi',
        ['Subject: bidi', 'Content-Type: multipart/mixed; boundary="b"'],
        multipart('b', [
          attachment(
            'application/pdf',
            "filename*=UTF-8''invoice%E2%80%AEfdp.exe",
            Buffer.from('MZ\x90\x00', 'latin1'),
          ),
        ]),
      ),
    ),
  'filename-zero-width.eml': () =>
    Buffer.from(
      message(
        'zero-width',
        ['Subject: zero width', 'Content-Type: multipart/mixed; boundary="z"'],
        multipart('z', [
          attachment('application/pdf', "filename*=UTF-8''re%E2%80%8Bport%EF%BB%BF.pdf", PDF),
        ]),
      ),
    ),
  'filename-double-extension.eml': () =>
    Buffer.from(
      message(
        'double-ext',
        ['Subject: double extension', 'Content-Type: multipart/mixed; boundary="d"'],
        multipart('d', [
          attachment(
            'application/pdf',
            'filename="report.pdf.exe"',
            Buffer.from('MZ\x90\x00', 'latin1'),
          ),
          attachment(
            'application/pdf',
            'filename="invoice.pdf          .exe"',
            Buffer.from('MZ\x90\x00', 'latin1'),
          ),
        ]),
      ),
    ),
  'filename-reserved.eml': () =>
    Buffer.from(
      message(
        'reserved',
        ['Subject: reserved', 'Content-Type: multipart/mixed; boundary="r"'],
        multipart('r', [attachment('text/plain', 'filename="CON.txt"', 'con')]),
      ),
    ),
  'filename-long.eml': () =>
    Buffer.from(
      message(
        'long-name',
        ['Subject: long name', 'Content-Type: multipart/mixed; boundary="l"'],
        multipart('l', [attachment('application/pdf', `filename="${'a'.repeat(300)}.pdf"`, PDF)]),
      ),
    ),
  'header-flood.eml': () => {
    const flood = Array.from({ length: 1001 }, (_, index) => `X-Flood-${index}: ${index}`);
    return Buffer.from(lines(...BASE, msgId('flood'), 'Subject: flood', ...flood, '', 'body', ''));
  },
  'header-long-line.eml': () =>
    Buffer.from(
      lines(
        ...BASE,
        msgId('long-line'),
        'Subject: long line',
        `X-Long: ${'x'.repeat(32_768)}`,
        '',
        'body',
        '',
      ),
    ),
  'part-flood.eml': () => {
    const parts = Array.from({ length: 250 }, (_, index) => text(`part ${index}`));
    return Buffer.from(
      message(
        'part-flood',
        ['Subject: part flood', 'Content-Type: multipart/mixed; boundary="p"'],
        multipart('p', parts),
      ),
    );
  },
};

export function buildCorpus(): Map<string, Buffer> {
  return new Map(Object.entries(FIXTURES).map(([name, build]) => [name, build()]));
}

const script = process.argv[1];
if (script?.endsWith('generate.ts')) {
  for (const [name, data] of buildCorpus()) writeFileSync(join(dirname(script), name), data);
}

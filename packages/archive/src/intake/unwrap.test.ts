import { createHash } from 'node:crypto';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { parseJournalEnvelope } from './envelope';
import { stripHeaderFields, stripHeaderFieldsFromBuffer } from './header-strip';
import { decodeTransfer } from './transfer-decoding';
import {
  JournalReportSplitter,
  JournalReportUnwrapper,
  type JournalUnwrapDecision,
  type JournalUnwrapOptions,
  parseContentType,
  prefixLimitOf,
  unwrapJournalReport,
} from './unwrap';

/** A synthetic original message: CRLF lines, 8-bit and binary bytes, no trailing whitespace. */
const EMBEDDED = Buffer.concat([
  Buffer.from(
    [
      'Message-ID: <q1@example.com>',
      'Date: Mon, 16 Nov 2026 10:15:00 +0000',
      'From: Alice <alice@example.com>',
      'To: bob@example.org',
      'Subject: Quarterly report',
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      'Hello Bob, the numbers are in. Gr=C3=BC=C3=9Fe =',
      '--not-the-boundary',
      '',
    ].join('\r\n'),
    'utf8',
  ),
  Buffer.from([0xc3, 0xa9, 0x00, 0xff, 0x0d, 0x0a]),
  Buffer.from('Last line\r\n', 'utf8'),
]);

/** Quoted-printable encoding with soft line breaks (test encoder, RFC 2045 §6.7). */
function qp(data: Buffer): string {
  const lines: string[] = [];
  let start = 0;
  const raw: Buffer[] = [];
  for (let i = 0; i < data.length; i++) {
    if (data[i] === 0x0d && data[i + 1] === 0x0a) {
      raw.push(data.subarray(start, i));
      start = i + 2;
      i++;
    }
  }
  raw.push(data.subarray(start));
  for (const line of raw) {
    let out = '';
    let width = 0;
    for (let i = 0; i < line.length; i++) {
      const b = line[i]!;
      const last = i === line.length - 1;
      const enc =
        (b >= 33 && b <= 126 && b !== 61) || (b === 32 && !last)
          ? String.fromCharCode(b)
          : `=${b.toString(16).toUpperCase().padStart(2, '0')}`;
      if (width + enc.length > 75) {
        out += '=\r\n';
        width = 0;
      }
      out += enc;
      width += enc.length;
    }
    lines.push(out);
  }
  return lines.join('\r\n');
}

interface ReportOptions {
  eol?: '\r\n' | '\n';
  encoding?: '7bit' | '8bit' | 'binary' | 'base64' | 'quoted-printable';
  boundary?: string;
  envelope?: string[];
  envelopeEncoding?: 'base64' | null;
  embedded?: Buffer;
  journalHeader?: boolean;
  closing?: boolean;
  extraPart?: boolean;
}

const DEFAULT_ENVELOPE = [
  'Sender: alice@example.com',
  'Subject: Quarterly report',
  'Message-Id: <q1@example.com>',
  'To: bob@example.org',
  'Bcc: dave@example.com',
  'To: erin@example.com, Expanded: team@example.com',
];

function report(o: ReportOptions = {}): Buffer {
  const eol = o.eol ?? '\r\n';
  const boundary = o.boundary ?? 'b1_journal_report_example';
  const embedded = o.embedded ?? EMBEDDED;
  const encoding = o.encoding ?? '7bit';
  const encodedEmbedded =
    encoding === 'base64'
      ? Buffer.from((embedded.toString('base64').match(/.{1,76}/g) ?? []).join(eol), 'latin1')
      : encoding === 'quoted-printable'
        ? Buffer.from(qp(embedded).replace(/\r\n/g, eol), 'latin1')
        : embedded;
  const envelopeText = (o.envelope ?? DEFAULT_ENVELOPE).join(eol) + eol;
  const envelopeBody =
    o.envelopeEncoding === 'base64'
      ? Buffer.from(Buffer.from(envelopeText).toString('base64'))
      : Buffer.from(envelopeText);
  const head = [
    ...(o.journalHeader === false ? [] : ['X-MS-Journal-Report:']),
    'X-MS-Exchange-CrossTenant-Id: 11111111-2222-3333-4444-555555555555',
    'From: Microsoft Outlook <journal@example.com>',
    'To: journal-o24pprcjhsfn6ligyvusv5yz7r@journal.gateway.test',
    'Subject: Quarterly report',
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed;${eol}\tboundary="${boundary}"`,
    '',
    'This is a multi-part message in MIME format.',
    `--${boundary}`,
    'Content-Type: text/plain; charset="us-ascii"',
    ...(o.envelopeEncoding === 'base64' ? ['Content-Transfer-Encoding: base64'] : []),
    '',
    '',
  ].join(eol);
  const mid = [
    '',
    `--${boundary}`,
    'Content-Type: message/rfc822',
    ...(encoding === '7bit' ? [] : [`Content-Transfer-Encoding: ${encoding}`]),
    '',
    '',
  ].join(eol);
  // The line break before a delimiter belongs to the delimiter (RFC 2046), so each part body is
  // exactly the bytes written here.
  const tail =
    o.closing === false
      ? ''
      : [
          '',
          ...(o.extraPart ? [`--${boundary}`, 'Content-Type: text/plain', '', 'extra'] : []),
          `--${boundary}--`,
          'epilogue text',
          '',
        ].join(eol);
  return Buffer.concat([
    Buffer.from(head, 'latin1'),
    envelopeBody,
    Buffer.from(mid, 'latin1'),
    encodedEmbedded,
    Buffer.from(tail, 'latin1'),
  ]);
}

function splitAt(message: Buffer, positions: number[], options?: JournalUnwrapOptions) {
  const s = new JournalReportSplitter(options);
  const out: Buffer[] = [];
  let prev = 0;
  for (const p of [...positions, message.length]) {
    out.push(...s.push(message.subarray(prev, p)));
    prev = p;
  }
  out.push(...s.end());
  return { output: Buffer.concat(out), result: s.result() };
}

/** The embedded message as stored. */
const STORED = EMBEDDED;

describe('JournalReportSplitter: recognized reports', () => {
  it('Microsoft 365 report (7bit embedded, CRLF): envelope captured, original byte-exact', () => {
    const { output, result } = unwrapJournalReport(report());
    expect(result.format).toBe('journal_report');
    expect(result.reason).toBeNull();
    expect(result.embeddedEncoding).toBe('identity');
    expect(result.anomalies).toEqual([]);
    expect(output.equals(STORED)).toBe(true);
    expect(result.outputBytes).toBe(STORED.length);
    expect(result.outerHeaderBlock!.toString()).toContain('X-MS-Journal-Report:');
    const env = parseJournalEnvelope(result.envelopeText!, {
      embeddedMessageId: '<q1@example.com>',
    });
    expect(env.recipients.map((r) => [r.address, r.field])).toEqual([
      ['bob@example.org', 'to'],
      ['dave@example.com', 'bcc'],
      ['erin@example.com', 'to'],
    ]);
    expect(env.envelopeMismatch).toBe(false);
  });

  it.each(['8bit', 'binary'] as const)('%s embedded part passes through byte-exact', (encoding) => {
    const { output, result } = unwrapJournalReport(report({ encoding }));
    expect(result.format).toBe('journal_report');
    expect(output.equals(STORED)).toBe(true);
  });

  it.each(['\r\n', '\n'] as const)('base64 embedded part is decoded (eol %j)', (eol) => {
    const { output, result } = unwrapJournalReport(report({ encoding: 'base64', eol }));
    expect(result.format).toBe('journal_report');
    expect(result.embeddedEncoding).toBe('base64');
    expect(output.equals(EMBEDDED)).toBe(true);
  });

  it('quoted-printable embedded part is decoded', () => {
    const { output, result } = unwrapJournalReport(report({ encoding: 'quoted-printable' }));
    expect(result.format).toBe('journal_report');
    expect(output.equals(EMBEDDED)).toBe(true);
  });

  it('on-premises style report: LF, quoted boundary with specials, legacy Recipient lines, base64 envelope', () => {
    const message = report({
      eol: '\n',
      boundary: '----=_NextPart_000_0001_01DA.EXAMPLE',
      envelopeEncoding: 'base64',
      envelope: [
        'Sender: alice@example.com',
        'Message-Id: <q1@example.com>',
        'Recipient: bob@example.org',
        'Recipient: carol@example.com, Expanded: team@example.com',
      ],
    });
    const { output, result } = unwrapJournalReport(message);
    expect(result.format).toBe('journal_report');
    expect(output.equals(STORED)).toBe(true);
    const env = parseJournalEnvelope(result.envelopeText!);
    expect(env.recipients).toEqual([
      { address: 'bob@example.org', field: 'recipient' },
      { address: 'carol@example.com', field: 'recipient', expandedFrom: 'team@example.com' },
    ]);
  });

  it('records a missing closing delimiter and extra parts without changing the output', () => {
    const open = unwrapJournalReport(report({ closing: false }));
    expect(open.result.format).toBe('journal_report');
    expect(open.result.anomalies).toEqual(['closing_delimiter_missing']);
    expect(open.output.equals(STORED)).toBe(true);
    const extra = unwrapJournalReport(report({ extraPart: true }));
    expect(extra.result.anomalies).toEqual(['extra_parts']);
    expect(extra.output.equals(STORED)).toBe(true);
  });

  it('an empty embedded message is recognized', () => {
    const { output, result } = unwrapJournalReport(report({ embedded: Buffer.alloc(0) }));
    expect(result.format).toBe('journal_report');
    expect(output.length).toBe(0);
  });
});

describe('JournalReportSplitter: unparsed reports are stored as received', () => {
  const cases: [string, Buffer, string][] = [
    ['no X-MS-Journal-Report', report({ journalHeader: false }), 'not_journal_report'],
    [
      'not multipart/mixed',
      Buffer.from('X-MS-Journal-Report:\r\nContent-Type: text/plain\r\n\r\nhello\r\n'),
      'not_multipart_mixed',
    ],
    [
      'no boundary',
      Buffer.from('X-MS-Journal-Report:\r\nContent-Type: multipart/mixed\r\n\r\nhello\r\n'),
      'boundary_missing',
    ],
    [
      'first part not text/plain',
      Buffer.from(
        report()
          .toString('latin1')
          .replace(
            'Content-Type: text/plain; charset="us-ascii"',
            'Content-Type: application/ms-tnef',
          ),
        'latin1',
      ),
      'envelope_part_missing',
    ],
    [
      'second part not message/rfc822',
      Buffer.from(
        report()
          .toString('latin1')
          .replace('Content-Type: message/rfc822', 'Content-Type: application/octet-stream'),
        'latin1',
      ),
      'embedded_part_missing',
    ],
    [
      'unknown transfer encoding',
      Buffer.from(
        report()
          .toString('latin1')
          .replace(
            'Content-Type: message/rfc822',
            'Content-Type: message/rfc822\r\nContent-Transfer-Encoding: x-uuencode',
          ),
        'latin1',
      ),
      'unsupported_encoding',
    ],
    [
      'closing delimiter after the envelope',
      Buffer.from(
        'X-MS-Journal-Report:\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nSender: a@example.com\r\n--b--\r\n',
      ),
      'embedded_part_missing',
    ],
    [
      'truncated header block',
      Buffer.from('X-MS-Journal-Report:\r\nContent-Type: multi'),
      'truncated',
    ],
    ['empty message', Buffer.alloc(0), 'truncated'],
  ];

  it.each(cases)('%s', (_name, message, reason) => {
    const { output, result } = unwrapJournalReport(message);
    expect(result.format).toBe('journal_report_unparsed');
    expect(result.reason).toBe(reason);
    expect(output.equals(message)).toBe(true);
    expect(result.outputBytes).toBe(message.length);
  });

  it('an oversized envelope is unparsed (bounded memory)', () => {
    const envelope = ['Sender: alice@example.com'];
    for (let i = 0; i < 200; i++) envelope.push(`Bcc: user${i}@example.com`);
    const message = report({ envelope });
    const { output, result } = unwrapJournalReport(message, { envelopeMaxBytes: 1024 });
    expect(result.reason).toBe('envelope_too_large');
    expect(output.equals(message)).toBe(true);
  });

  it('a prefix that reaches the limit without a decision is unparsed, streamed in small chunks', () => {
    const options = { envelopeMaxBytes: 1024, headerMaxBytes: 1024, preambleMaxBytes: 1024 };
    const big = Buffer.concat([
      Buffer.from('X-MS-Journal-Report:\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n'),
      Buffer.alloc(prefixLimitOf(options) * 2, 0x61),
    ]);
    const positions = Array.from({ length: Math.floor(big.length / 100) }, (_, i) => (i + 1) * 100);
    const { output, result } = splitAt(big, positions, options);
    expect(result.format).toBe('journal_report_unparsed');
    expect(['preamble_too_large', 'prefix_too_large']).toContain(result.reason);
    expect(output.equals(big)).toBe(true);
    expect(prefixLimitOf()).toBe(3 * 262_144 + 65_536 + 1_048_576 + 4096);
  });

  it('a header block over the bound is unparsed', () => {
    const message = Buffer.concat([
      Buffer.from('X-MS-Journal-Report:\r\nX-Long: '),
      Buffer.alloc(5000, 0x62),
      Buffer.from('\r\n\r\nbody\r\n'),
    ]);
    const { output, result } = unwrapJournalReport(message, { headerMaxBytes: 1024 });
    expect(result.reason).toBe('header_too_large');
    expect(output.equals(message)).toBe(true);
  });
});

describe('JournalReportSplitter: chunk boundaries', () => {
  const variants = [
    report(),
    report({ encoding: 'base64' }),
    report({ encoding: 'quoted-printable', eol: '\r\n' }),
    report({ eol: '\n', closing: false }),
    report({ journalHeader: false }),
  ];

  it('gives identical output and result for a split at every byte', () => {
    for (const message of variants) {
      const whole = unwrapJournalReport(message);
      for (let i = 0; i <= message.length; i++) {
        const split = splitAt(message, [i]);
        expect(split.output.equals(whole.output), `split at ${i}`).toBe(true);
        expect(split.result).toEqual(whole.result);
      }
    }
  });

  it('property: any chunking gives the same output (fast-check)', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...variants.keys()),
        fc.array(fc.nat(), { maxLength: 40 }),
        (v, cuts) => {
          const message = variants[v]!;
          const positions = [...new Set(cuts.map((c) => c % (message.length + 1)))].sort(
            (a, b) => a - b,
          );
          const whole = unwrapJournalReport(message);
          const split = splitAt(message, positions);
          return split.output.equals(whole.output) && split.result.format === whole.result.format;
        },
      ),
      { numRuns: 300 },
    );
  });

  it('property: one-byte chunks over a random embedded body round-trip through base64 and QP', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 600 }), (bytes) => {
        const body = Buffer.concat([Buffer.from('Subject: x\r\n\r\n'), Buffer.from(bytes)]);
        for (const encoding of ['base64', 'quoted-printable'] as const) {
          const message = report({ encoding, embedded: body });
          const positions = Array.from({ length: message.length }, (_, i) => i);
          const { output, result } = splitAt(message, positions);
          if (result.format !== 'journal_report' || !output.equals(body)) return false;
        }
        return true;
      }),
      { numRuns: 100 },
    );
  });
});

describe('JournalReportUnwrapper (Transform)', () => {
  async function run(message: Buffer, chunk: number) {
    const unwrapper = new JournalReportUnwrapper();
    const events: string[] = [];
    let decision: JournalUnwrapDecision | null = null;
    unwrapper.on('decision', (d: JournalUnwrapDecision) => {
      decision = d;
      events.push('decision');
    });
    const out: Buffer[] = [];
    const chunks = Array.from({ length: Math.ceil(message.length / chunk) }, (_, i) =>
      message.subarray(i * chunk, (i + 1) * chunk),
    );
    await pipeline(
      Readable.from(chunks),
      unwrapper,
      new Writable({
        write(c: Buffer, _e, cb) {
          events.push('data');
          out.push(c);
          cb();
        },
      }),
    );
    return { output: Buffer.concat(out), events, decision: decision!, result: unwrapper.result! };
  }

  it('announces the decision before the first output byte and streams the original', async () => {
    const r = await run(report({ encoding: 'base64' }), 7);
    expect(r.events[0]).toBe('decision');
    expect(r.decision.format).toBe('journal_report');
    expect(r.output.equals(EMBEDDED)).toBe(true);
    expect(createHash('sha256').update(r.output).digest('hex')).toBe(
      createHash('sha256').update(EMBEDDED).digest('hex'),
    );
    expect(r.result.inputBytes).toBe(report({ encoding: 'base64' }).length);
  });

  it('streams an unrecognized message unchanged', async () => {
    const message = report({ journalHeader: false });
    const r = await run(message, 64);
    expect(r.events[0]).toBe('decision');
    expect(r.decision.format).toBe('journal_report_unparsed');
    expect(r.output.equals(message)).toBe(true);
  });
});

describe('transfer decoding and Content-Type', () => {
  it('decodes base64 tolerantly and QP with soft breaks, padding and literal =', () => {
    expect(decodeTransfer('base64', Buffer.from('aGVs\r\nbG8=\r\n')).toString()).toBe('hello');
    expect(decodeTransfer('base64', Buffer.from('aGVsbG8=aGk=')).toString()).toBe('hellohi');
    expect(decodeTransfer('base64', Buffer.from('aGk')).toString()).toBe('hi');
    expect(
      decodeTransfer(
        'quoted-printable',
        Buffer.from('a=3Db =\r\nc  \r\nd=ZZ e=\n=c3=A9='),
      ).toString('latin1'),
    ).toBe('a=b c\r\nd=ZZ eÃ©=');
    expect(decodeTransfer('identity', Buffer.from('x')).toString()).toBe('x');
  });

  it('parses Content-Type parameters', () => {
    expect(parseContentType('Multipart/Mixed; boundary="a;b=\\"c"; charset=x')).toEqual({
      mediaType: 'multipart/mixed',
      params: { boundary: 'a;b="c', charset: 'x' },
    });
    expect(parseContentType('nonsense')).toBeNull();
    expect(parseContentType(undefined)).toBeNull();
  });
});

describe('stripHeaderFields (X-EG-Journal-Token)', () => {
  const message = Buffer.from(
    [
      'Received: from mail.example.com',
      'X-EG-Journal-Token: y4tzc2c2n43uhmrtmf6mvu7tsh',
      'From: alice@example.com',
      'x-eg-journal-token:',
      '\ty4tzc2c2n43uhmrtmf6mvu7tsh',
      'Subject: X-EG-Journal-Token: in the subject stays',
      'X-EG-Journal-Token-Extra: kept',
      'X-EG-JOURNAL-TOKEN : spaced',
      '',
      'X-EG-Journal-Token: in the body stays',
      '',
    ].join('\r\n'),
  );
  const expected = Buffer.from(
    [
      'Received: from mail.example.com',
      'From: alice@example.com',
      'Subject: X-EG-Journal-Token: in the subject stays',
      'X-EG-Journal-Token-Extra: kept',
      '',
      'X-EG-Journal-Token: in the body stays',
      '',
    ].join('\r\n'),
  );

  it('removes every occurrence (case-insensitive, folded) from the header block only', () => {
    const { output, removed } = stripHeaderFieldsFromBuffer(message, ['X-EG-Journal-Token']);
    expect(output.toString()).toBe(expected.toString());
    expect(removed).toBe(3);
  });

  it('gives the same bytes and SHA-256 for a split at every byte', () => {
    const sha = createHash('sha256').update(expected).digest('hex');
    for (let i = 0; i <= message.length; i++) {
      const stream = stripHeaderFields(['X-EG-Journal-Token']);
      const out: Buffer[] = [];
      stream.on('data', (c: Buffer) => out.push(c));
      stream.write(message.subarray(0, i));
      stream.write(message.subarray(i));
      stream.end();
      const got = Buffer.concat(out);
      expect(createHash('sha256').update(got).digest('hex'), `split at ${i}`).toBe(sha);
      expect(stream.removed).toBe(3);
    }
  });

  it('passes LF messages, bodies and headerless input untouched', () => {
    const lf = Buffer.from('A: 1\nX-EG-Journal-Token: t\n continued\nB: 2\n\nbody\n');
    expect(stripHeaderFieldsFromBuffer(lf, ['X-EG-Journal-Token']).output.toString()).toBe(
      'A: 1\nB: 2\n\nbody\n',
    );
    const body = Buffer.from('\r\nX-EG-Journal-Token: t\r\n');
    expect(stripHeaderFieldsFromBuffer(body, ['X-EG-Journal-Token']).output.equals(body)).toBe(
      true,
    );
    const noEol = Buffer.from('X-EG-Journal-Token: t');
    expect(stripHeaderFieldsFromBuffer(noEol, ['X-EG-Journal-Token']).output.length).toBe(0);
    expect(() => stripHeaderFields([])).toThrow(RangeError);
    expect(() => stripHeaderFields(['bad name'])).toThrow(RangeError);
  });

  it('passes an overlong line through (bounded memory) and still drops a long token field', () => {
    const long = Buffer.concat([
      Buffer.from('X-Long: '),
      Buffer.alloc(300, 0x61),
      Buffer.from('\r\nX-EG-Journal-Token: '),
      Buffer.alloc(300, 0x62),
      Buffer.from('\r\nA: 1\r\n\r\nbody'),
    ]);
    const s = stripHeaderFields(['X-EG-Journal-Token'], { maxLineBytes: 100 });
    const out: Buffer[] = [];
    s.on('data', (c: Buffer) => out.push(c));
    for (let i = 0; i < long.length; i += 16) s.write(long.subarray(i, i + 16));
    s.end();
    const text = Buffer.concat(out).toString();
    expect(text).toBe(`X-Long: ${'a'.repeat(300)}\r\nA: 1\r\n\r\nbody`);
    expect(s.overlongLines).toBe(2);
    expect(s.removed).toBe(1);
  });
});

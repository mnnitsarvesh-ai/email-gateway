import { describe, expect, it } from 'vitest';
import {
  INTAKE_NETWORKS_EXAMPLE,
  intakeNetworksSchema,
  JOURNAL_ENVELOPE_EXAMPLE,
  JOURNAL_INTAKE_PROOF_EXAMPLE,
  journalEnvelopeSchema,
  journalIntakeProofSchema,
} from './documents';
import { bareMessageId, buildCopyEnvelope, parseJournalEnvelope } from './envelope';
import { classifyIntakeParties } from './parties';
import { parseAddressList, parseRfc5322Date } from './rfc5322';

const crlf = (lines: string[]) => lines.join('\r\n') + '\r\n';

describe('parseJournalEnvelope (journal-envelope/1)', () => {
  it('parses an Exchange Online report envelope with To, Cc, Bcc, Expanded and Forwarded', () => {
    const text = crlf([
      'Sender: Alice@Example.COM',
      'Subject: Quarterly report',
      'Message-Id: <q1@example.com>',
      'To: bob@example.org',
      'Cc: carol@example.com',
      'Bcc: dave@example.com',
      'To: erin@example.com, Expanded: team@example.com',
      'To: frank@example.com, Forwarded: grace@example.com',
    ]);
    const e = parseJournalEnvelope(text, { embeddedMessageId: ' <q1@example.com> ' });
    expect(e).toEqual({
      v: 1,
      sender: 'Alice@example.com',
      onBehalfOf: null,
      messageId: '<q1@example.com>',
      recipients: [
        { address: 'bob@example.org', field: 'to' },
        { address: 'carol@example.com', field: 'cc' },
        { address: 'dave@example.com', field: 'bcc' },
        { address: 'erin@example.com', field: 'to', expandedFrom: 'team@example.com' },
        { address: 'frank@example.com', field: 'to', forwardedFrom: 'grace@example.com' },
      ],
      truncated: false,
      envelopeMismatch: false,
    });
    expect(journalEnvelopeSchema.parse(e)).toEqual(e);
  });

  it('accepts LF, folded lines, On-Behalf-Of, the older Recipient format and both suffixes', () => {
    const text = [
      'Sender: assistant@example.com',
      'On-Behalf-Of: ceo@example.com',
      'Message-Id:',
      ' <folded@example.com>',
      'Recipient: heidi@example.com,',
      '  Expanded: all@example.com',
      'Recipient: ivan@example.org, Forwarded: judy@example.org, Expanded: list@example.org',
      'Recipient: Heidi@EXAMPLE.com',
      'X-Unknown: whatever',
      '',
    ].join('\n');
    const e = parseJournalEnvelope(text, { embeddedMessageId: '<other@example.com>' });
    expect(e.sender).toBe('assistant@example.com');
    expect(e.onBehalfOf).toBe('ceo@example.com');
    expect(e.messageId).toBe('<folded@example.com>');
    expect(e.recipients).toEqual([
      { address: 'heidi@example.com', field: 'recipient', expandedFrom: 'all@example.com' },
      {
        address: 'ivan@example.org',
        field: 'recipient',
        forwardedFrom: 'judy@example.org',
        expandedFrom: 'list@example.org',
      },
    ]);
    expect(e.envelopeMismatch).toBe(true);
  });

  it('skips invalid addresses, takes angle forms and display names, caps recipients', () => {
    const lines = ['Sender: <>', 'To: not an address', 'To: "Bob B" <bob@example.org>'];
    for (let i = 0; i < 20; i++) lines.push(`Bcc: user${i}@example.com`);
    const e = parseJournalEnvelope(lines.join('\n'), { maxRecipients: 5 });
    expect(e.sender).toBeNull();
    expect(e.recipients).toHaveLength(5);
    expect(e.recipients[0]).toEqual({ address: 'bob@example.org', field: 'to' });
    expect(e.truncated).toBe(true);
    expect(e.envelopeMismatch).toBe(false);
    expect(() => parseJournalEnvelope('', { maxRecipients: 0 })).toThrow(RangeError);
    expect(parseJournalEnvelope('').recipients).toEqual([]);
  });

  it('bounds the cap at the schema maximum (10 000)', () => {
    const lines: string[] = [];
    for (let i = 0; i < 10_050; i++) lines.push(`To: u${i}@example.com`);
    const e = parseJournalEnvelope(lines.join('\n'), { maxRecipients: 50_000 });
    expect(e.recipients).toHaveLength(10_000);
    expect(e.truncated).toBe(true);
    expect(journalEnvelopeSchema.safeParse(e).success).toBe(true);
  });

  it('bareMessageId strips angle brackets and whitespace', () => {
    expect(bareMessageId('  <a@b>  ')).toBe('a@b');
    expect(bareMessageId('<>')).toBeNull();
    expect(bareMessageId(null)).toBeNull();
  });
});

describe('buildCopyEnvelope (copy kinds)', () => {
  const headers = crlf([
    'From: Alice <alice@example.com>',
    'To: Bob <bob@example.org>, carol@example.com',
    'Cc: team: dave@example.com, erin@example.com;',
    'X-Gm-Original-To: frank@example.com',
    'Subject: hi',
    '',
  ]);

  it('Google Workspace: X-Gm-Original-To when present (field envelope)', () => {
    const e = buildCopyEnvelope({
      kind: 'google_workspace_copy',
      headerBlock: headers,
      mailFrom: 'alice@example.com',
    });
    expect(e.recipients).toEqual([{ address: 'frank@example.com', field: 'envelope' }]);
    expect(e.sender).toBe('alice@example.com');
    expect(e.messageId).toBeNull();
  });

  it('Google without X-Gm-Original-To and SMTP BCC: To/Cc header addresses (field header)', () => {
    for (const kind of ['google_workspace_copy', 'smtp_bcc'] as const) {
      const block = kind === 'smtp_bcc' ? headers : headers.replace(/X-Gm-Original-To[^\n]*\n/, '');
      const e = buildCopyEnvelope({ kind, headerBlock: Buffer.from(block), mailFrom: '' });
      expect(e.recipients.map((r) => [r.address, r.field])).toEqual([
        ['bob@example.org', 'header'],
        ['carol@example.com', 'header'],
        ['dave@example.com', 'header'],
        ['erin@example.com', 'header'],
      ]);
      expect(e.sender).toBeNull();
    }
  });
});

describe('RFC 5322 helpers', () => {
  it.each([
    ['a@Example.COM', ['a@example.com']],
    ['"Doe, John" <John.Doe@Example.com>, b@x.example', ['John.Doe@example.com', 'b@x.example']],
    ['undisclosed-recipients:;', []],
    [
      'Team: a@x.example, (comment) b@y.example;, c@z.example',
      ['a@x.example', 'b@y.example', 'c@z.example'],
    ],
    ['<@route.example:a@x.example>', ['a@x.example']],
    ['broken, @x.example, a@', []],
    ['a@x.example (Alice)', ['a@x.example']],
  ])('parseAddressList(%j)', (value, expected) => {
    expect(parseAddressList(value)).toEqual(expected);
  });

  it.each([
    ['Mon, 16 Nov 2026 10:15:00 +0000', 1_794_824_100],
    ['16 Nov 2026 10:15:00 +0000', 1_794_824_100],
    ['Mon, 16 Nov 2026 11:15:00 +0100', 1_794_824_100],
    ['Mon, 16 Nov 2026 05:15:00 EST', 1_794_824_100],
    ['Mon, 16 Nov 2026 10:15 GMT', 1_794_824_100],
    ['Mon, 16 Nov 26 10:15:00 UT', 1_794_824_100],
    ['Mon,16 november 2026 10:15:00 +0000 (UTC)', 1_794_824_100],
    ['Mon, 16 Nov 2026 10:15:00', 1_794_824_100],
    ['Mon, 16 Nov 2026 10:15:00 Z', 1_794_824_100],
    ['Mon, 16 Nov 2026 10:15:00 -0000', 1_794_824_100],
    ['Thu, 1 Jan 1970 00:00:00 +0000', 0],
    ['Tue, 1 Jan 99 00:00:00 +0000', 915_148_800],
  ])('parseRfc5322Date(%j)', (value, expected) => {
    expect(parseRfc5322Date(value)).toBe(expected);
  });

  it.each([
    '',
    'yesterday',
    '31 Feb 2026 10:00:00 +0000',
    '16 Foo 2026 10:00:00 +0000',
    '16 Nov 2026 25:00:00 +0000',
    '16 Nov 2026 10:00:00 +0099',
    '16 Nov 2026 10:00:00 XYZZY',
    '2026-11-16T10:15:00Z',
  ])('parseRfc5322Date(%j) is null', (value) => {
    expect(parseRfc5322Date(value)).toBeNull();
  });
});

describe('classifyIntakeParties (D3)', () => {
  const orgDomains = ['example.com', 'Example.NET.'];
  const run = (sender: string | null, recipients: string[], headerFrom: string | null = null) =>
    classifyIntakeParties({
      sender,
      headerFrom,
      recipients: recipients.map((address) => ({ address })),
      orgDomains,
    });

  it.each([
    // sender, recipients, message direction, recipient directions, org-side domain
    ['ext@example.org', ['a@example.com'], 'inbound', ['inbound'], 'example.com'],
    [
      'ext@example.org',
      ['x@example.org', 'a@example.net'],
      'inbound',
      [null, 'inbound'],
      'example.net',
    ],
    ['ext@example.org', ['x@example.org'], 'inbound', [null], null],
    [
      'a@example.com',
      ['b@example.net', 'c@example.com'],
      'internal',
      ['internal', 'internal'],
      'example.com',
    ],
    [
      'a@example.com',
      ['b@example.com', 'x@example.org'],
      'outbound',
      ['internal', 'outbound'],
      'example.com',
    ],
    ['a@EXAMPLE.net', ['x@example.org'], 'outbound', ['outbound'], 'example.net'],
    ['a@example.com', [], 'outbound', [], 'example.com'],
    [null, ['a@example.com'], 'inbound', ['inbound'], 'example.com'],
    ['a@sub.example.com', ['b@example.com'], 'inbound', ['inbound'], 'example.com'],
  ] as const)('%s → %j', (sender, recipients, direction, recipientDirections, domain) => {
    const r = run(sender, [...recipients]);
    expect(r.direction).toBe(direction);
    expect(r.recipients.map((x) => x.direction)).toEqual(recipientDirections);
    expect(r.orgSideDomain).toBe(domain);
  });

  it('falls back to the header From when the envelope sender is unusable', () => {
    const r = run('<>', ['x@example.org'], 'Alice <alice@example.com>');
    expect(r.senderAddress).toBe('alice@example.com');
    expect(r.direction).toBe('outbound');
    expect(run(null, ['a@example.com'], null).senderAddress).toBeNull();
  });
});

describe('intake documents', () => {
  it('accept their examples and refuse unknown keys and bad values', () => {
    expect(journalEnvelopeSchema.parse(JOURNAL_ENVELOPE_EXAMPLE)).toEqual(JOURNAL_ENVELOPE_EXAMPLE);
    expect(journalIntakeProofSchema.parse(JOURNAL_INTAKE_PROOF_EXAMPLE)).toEqual(
      JOURNAL_INTAKE_PROOF_EXAMPLE,
    );
    expect(intakeNetworksSchema.parse(INTAKE_NETWORKS_EXAMPLE)).toEqual(INTAKE_NETWORKS_EXAMPLE);
    expect(journalEnvelopeSchema.safeParse({ ...JOURNAL_ENVELOPE_EXAMPLE, extra: 1 }).success).toBe(
      false,
    );
    expect(
      journalEnvelopeSchema.safeParse({
        ...JOURNAL_ENVELOPE_EXAMPLE,
        recipients: [{ address: 'a@example.com', field: 'from' }],
      }).success,
    ).toBe(false);
    expect(
      journalIntakeProofSchema.safeParse({ ...JOURNAL_INTAKE_PROOF_EXAMPLE, result: 'fail' })
        .success,
    ).toBe(false);
    expect(
      journalIntakeProofSchema.safeParse({
        ...JOURNAL_INTAKE_PROOF_EXAMPLE,
        dkim: { result: 'aligned_pass', domains: ['a', 'b', 'c', 'd', 'e', 'f'] },
      }).success,
    ).toBe(false);
    for (const cidrs of [
      [],
      ['198.51.100.1/24'],
      ['198.51.100.0/24', '198.51.100.0/24'],
      ['2001:DB8::/48'],
      Array(33).fill('198.51.100.0/24'),
    ]) {
      expect(intakeNetworksSchema.safeParse({ v: 1, cidrs }).success).toBe(false);
    }
  });
});

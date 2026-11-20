import { describe, expect, it } from 'vitest';
import {
  ATTESTATIONS,
  INTAKE_ATTESTATIONS,
  intakeAttestationByCode,
  intakeAttestationsFor,
  intakeConfigureAttestations,
  JOURNAL_INTAKE_KINDS,
  type JournalIntakeKind,
} from './attestations';
import {
  exampleJournalIntakeGuideInput,
  generateJournalIntakeGuide,
  JOURNAL_INTAKE_GUIDE_SCHEMA,
  type JournalIntakeGuideInput,
  maskJournalIntakeAddress,
  maskJournalIntakeToken,
} from './journal-intake-guide';
import { journalIntakeGuideFileName, renderJournalIntakeGuideMarkdown } from './markdown';
import { SetupGuideInputError } from './setup-guide';

// Synthetic, clearly fake tokens (lower-case base32 shape only).
const TOKEN = 'abcdefghijklmnopqrstuvwxyz';
const HEADER = 'zyxwvutsrqponmlkjihgfedcba';
const ADDRESS = `journal-${TOKEN}@journal.gateway.test`;
// Built from parts so the test file carries none of the patterns it forbids.
const FORBIDDEN = [
  'wh' + 'sec_',
  'AK' + 'IA',
  'gh' + 'p_',
  's' + 'k-',
  'eg' + 'k_',
  '-----' + 'BEGIN',
];

function input(kind: JournalIntakeKind, reveal: boolean): JournalIntakeGuideInput {
  return {
    ...exampleJournalIntakeGuideInput(kind),
    address: ADDRESS,
    headerToken: kind === 'google_workspace_copy' ? HEADER : null,
    reveal,
    attestations: [{ code: intakeAttestationsFor(kind)[0]!.code, at: '2026-11-20T10:00:00.000Z' }],
  };
}

describe('generateJournalIntakeGuide (journal-intake-guide/1)', () => {
  it.each(JOURNAL_INTAKE_KINDS)('%s: example guide and Markdown (snapshot)', (kind) => {
    const guide = generateJournalIntakeGuide(exampleJournalIntakeGuideInput(kind));
    expect(guide.schema).toBe(JOURNAL_INTAKE_GUIDE_SCHEMA);
    expect(guide.kind).toBe(kind);
    expect(guide.source).toEqual({
      id: '11111111-2222-3333-4444-555555555555',
      displayName: guide.source.displayName,
      kind,
    });
    const markdown = renderJournalIntakeGuideMarkdown(guide);
    for (const forbidden of FORBIDDEN) expect(markdown).not.toContain(forbidden);
    expect(markdown).toMatchSnapshot();
  });

  it.each(JOURNAL_INTAKE_KINDS)('%s: no revealed address or token when reveal = false', (kind) => {
    const guide = generateJournalIntakeGuide(input(kind, false));
    const json = JSON.stringify(guide);
    const markdown = renderJournalIntakeGuideMarkdown(guide);
    for (const out of [json, markdown]) {
      expect(out).not.toContain(TOKEN);
      expect(out).not.toContain(HEADER);
      expect(out).not.toContain(TOKEN.slice(0, 22));
    }
    expect(guide.revealed).toBe(false);
    expect(guide.address).toBe('journal-••••wxyz@journal.gateway.test');
    if (kind === 'google_workspace_copy') expect(guide.headerToken).toBe('••••dcba');
    else expect(guide).not.toHaveProperty('headerToken');
    expect(markdown).toContain('journal-••••wxyz@journal.gateway.test');
  });

  it.each(JOURNAL_INTAKE_KINDS)(
    '%s: reveal = true shows the address in values and commands',
    (kind) => {
      const guide = generateJournalIntakeGuide(input(kind, true));
      const markdown = renderJournalIntakeGuideMarkdown(guide);
      expect(guide.address).toBe(ADDRESS);
      expect(markdown).toContain(ADDRESS);
      if (kind === 'google_workspace_copy') {
        expect(guide.headerToken).toBe(HEADER);
        expect(markdown).toContain(HEADER);
      }
    },
  );

  it('Microsoft 365: Purview journal rule, NDR mailbox and the PowerShell commands', () => {
    const guide = generateJournalIntakeGuide(input('microsoft_365_journal', true));
    const steps = guide.sections.flatMap((s) => s.steps);
    const code = steps.flatMap((s) => s.commands ?? []).map((c) => c.code);
    expect(code).toContain(
      `New-JournalRule -Name 'Email security gateway journal' -JournalEmailAddress '${ADDRESS}' -Scope Global -Enabled $true`,
    );
    expect(code).toContain("Set-TransportConfig -JournalingReportNdrTo 'journal-ndr@example.com'");
    expect(steps.find((s) => s.id === 'm365-journal-rule')!.warning).toMatch(
      /Exchange Online does not journal to an Exchange Online mailbox/,
    );
    expect(guide.sections.map((s) => s.id)).toEqual([
      'overview',
      'intake-address',
      'm365-journaling',
      'verify',
    ]);
    expect(guide.sections.map((s) => s.number)).toEqual([1, 2, 3, 4]);
  });

  it('Google Workspace: Also deliver to, X-Gm-Original-To and the custom header', () => {
    const guide = generateJournalIntakeGuide(input('google_workspace_copy', true));
    const steps = guide.sections.flatMap((s) => s.steps);
    expect(steps.find((s) => s.id === 'google-route')!.values).toEqual([
      { label: 'Also deliver to', value: ADDRESS },
    ]);
    const headers = steps.find((s) => s.id === 'google-headers')!;
    expect(headers.values).toEqual([
      { label: 'Custom header name', value: 'X-EG-Journal-Token' },
      { label: 'Custom header value', value: HEADER },
    ]);
    expect(headers.paragraphs.join(' ')).toContain('Add X-Gm-Original-To header');
  });

  it('on-premises Exchange: journal recipient, rule and a TLS Send connector to the gateway hosts', () => {
    const guide = generateJournalIntakeGuide(input('exchange_onprem_journal', true));
    const code = guide.sections
      .flatMap((s) => s.steps)
      .flatMap((s) => s.commands ?? [])
      .map((c) => c.code);
    expect(code).toContain(
      `New-MailContact -Name 'Email security gateway journal' -ExternalEmailAddress '${ADDRESS}'`,
    );
    expect(code.find((c) => c.startsWith('New-SendConnector'))).toBe(
      "New-SendConnector -Name 'Email security gateway journal' -Usage Custom -AddressSpaces 'SMTP:journal.gateway.test;1' -DNSRoutingEnabled $false -SmartHosts 'mx1.gateway.example.net','mx2.gateway.example.net' -RequireTLS $true -TlsAuthLevel DomainValidation -TlsDomain 'journal.gateway.test'",
    );
    const networks = guide.sections
      .flatMap((s) => s.steps)
      .find((s) => s.id === 'source-networks')!;
    expect(networks.values).toEqual([
      { label: 'Network 1', value: '198.51.100.0/24' },
      { label: 'Network 2', value: '2001:db8:10::/48' },
    ]);
  });

  it('generic SMTP: always_bcc with a TLS policy for the intake domain', () => {
    const guide = generateJournalIntakeGuide(input('smtp_bcc', true));
    const code = guide.sections.flatMap((s) => s.steps).flatMap((s) => s.commands ?? []);
    expect(code[0]).toEqual({
      language: 'text',
      code: [
        '# /etc/postfix/main.cf',
        `always_bcc = ${ADDRESS}`,
        'smtp_tls_policy_maps = hash:/etc/postfix/tls_policy',
        '',
        '# /etc/postfix/tls_policy (then: postmap /etc/postfix/tls_policy)',
        'journal.gateway.test encrypt',
      ].join('\n'),
    });
  });

  it('records attestation state, labelled as statements', () => {
    const guide = generateJournalIntakeGuide(input('microsoft_365_journal', false));
    expect(guide.attestations).toEqual([
      {
        code: 'journal.m365.rule_created',
        statement: intakeAttestationByCode('microsoft_365_journal', 'journal.m365.rule_created')!
          .statement,
        attested: true,
        attestedAt: '2026-11-20T10:00:00.000Z',
      },
      {
        code: 'journal.m365.ndr_mailbox_set',
        statement: expect.any(String) as string,
        attested: false,
        attestedAt: null,
      },
    ]);
    const markdown = renderJournalIntakeGuideMarkdown(guide);
    expect(markdown).toContain('(your statement, not a gateway check)');
    expect(guide.notice).toMatch(/statements \(attestations\), not proofs/);
  });

  it('refuses values that would be unsafe in commands', () => {
    const base = input('exchange_onprem_journal', true);
    for (const bad of [
      { address: 'someone@example.com' },
      { address: `journal-${TOKEN}@bad domain` },
      { source: { publicId: 'x', displayName: 'X' } },
      { domains: ["example.com'; Remove-Item"] },
      { networks: ['198.51.100.0/24; rm'] },
      { gateway: { mxHosts: ['mx1 -Force'] } },
    ]) {
      expect(() => generateJournalIntakeGuide({ ...base, ...bad }), JSON.stringify(bad)).toThrow(
        SetupGuideInputError,
      );
    }
    expect(() =>
      generateJournalIntakeGuide({ ...input('google_workspace_copy', true), headerToken: null }),
    ).toThrow(SetupGuideInputError);
  });

  it('masks and names files', () => {
    expect(maskJournalIntakeAddress(ADDRESS)).toBe('journal-••••wxyz@journal.gateway.test');
    expect(maskJournalIntakeAddress('nope')).toBe('••••');
    expect(maskJournalIntakeToken(HEADER)).toBe('••••dcba');
    expect(maskJournalIntakeToken('short')).toBe('••••');
    expect(
      journalIntakeGuideFileName({
        kind: 'exchange_onprem_journal',
        source: { id: '', displayName: 'HQ Exchange (Mumbai)', kind: 'exchange_onprem_journal' },
      }),
    ).toBe('journal-intake-exchange-onprem-journal-hq-exchange-mumbai.md');
  });
});

describe('journal intake attestation codes', () => {
  it('are unique, journal-prefixed, disjoint from 8.2 codes and required for configure', () => {
    const codes = INTAKE_ATTESTATIONS.map((a) => a.code);
    expect(new Set(codes).size).toBe(codes.length);
    for (const c of codes) expect(c).toMatch(/^journal\.(m365|google|onprem|smtp)\.[a-z_]+$/);
    expect(codes.filter((c) => ATTESTATIONS.some((a) => a.code === c))).toEqual([]);
    expect(intakeConfigureAttestations('microsoft_365_journal')).toEqual([
      'journal.m365.rule_created',
      'journal.m365.ndr_mailbox_set',
    ]);
    expect(intakeConfigureAttestations('google_workspace_copy')).toEqual([
      'journal.google.route_created',
      'journal.google.headers_added',
    ]);
    expect(intakeConfigureAttestations('exchange_onprem_journal')).toEqual([
      'journal.onprem.journal_recipient_created',
      'journal.onprem.send_connector_tls',
    ]);
    expect(intakeConfigureAttestations('smtp_bcc')).toEqual(['journal.smtp.bcc_configured']);
    expect(intakeAttestationByCode('smtp_bcc', 'journal.m365.rule_created')).toBeUndefined();
  });

  it('every guide step attestation is a known code of the kind', () => {
    for (const kind of JOURNAL_INTAKE_KINDS) {
      const guide = generateJournalIntakeGuide(exampleJournalIntakeGuideInput(kind));
      const stepCodes = guide.sections
        .flatMap((s) => s.steps)
        .map((s) => s.attestation?.code)
        .filter((c): c is string => c !== undefined);
      expect(stepCodes.sort()).toEqual(intakeConfigureAttestations(kind).sort());
    }
  });
});

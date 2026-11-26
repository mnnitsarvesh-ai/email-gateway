import { describe, expect, it } from 'vitest';
import {
  API_MODE_GUIDE_SCHEMA,
  apiModeGuideFileName,
  exampleApiModeGuideInput,
  generateApiModeGuide,
  renderApiModeGuideMarkdown,
  type ApiModeGuideInput,
} from './api-mode-guide';
import {
  API_MODE_ATTESTATIONS,
  apiModeAttestationByCode,
  apiModeAttestationsFor,
  ATTESTATIONS,
  INTAKE_ATTESTATIONS,
} from './attestations';
import { SetupGuideInputError } from './setup-guide';

// Built from parts so the test file carries none of the patterns it forbids.
const FORBIDDEN = [
  'wh' + 'sec_',
  'AK' + 'IA',
  'gh' + 'p_',
  's' + 'k-',
  'eg' + 'k_',
  '-----' + 'BEGIN',
];
const PROVIDERS = ['microsoft_365', 'google_workspace'] as const;

describe('generateApiModeGuide (api-mode-guide/1)', () => {
  it.each(PROVIDERS)('%s: example guide and Markdown (snapshot)', (provider) => {
    const guide = generateApiModeGuide(exampleApiModeGuideInput(provider));
    expect(guide.schema).toBe(API_MODE_GUIDE_SCHEMA);
    expect(guide.provider).toBe(provider);
    expect(guide.connection.id).toBe('11111111-2222-3333-4444-555555555555');
    const markdown = renderApiModeGuideMarkdown(guide);
    for (const forbidden of FORBIDDEN) {
      expect(JSON.stringify(guide)).not.toContain(forbidden);
      expect(markdown).not.toContain(forbidden);
    }
    expect(guide).toMatchSnapshot();
    expect(markdown).toMatchSnapshot();
  });

  it('Microsoft: sections, exact permissions, scoping note, revoke and troubleshooting', () => {
    const guide = generateApiModeGuide(exampleApiModeGuideInput('microsoft_365'));
    expect(guide.sections.map((s) => [s.number, s.id])).toEqual([
      [1, 'overview'],
      [2, 'journal'],
      [3, 'mailbox-access'],
      [4, 'mailbox-scope'],
      [5, 'feeds'],
      [6, 'verify'],
      [7, 'revoke'],
      [8, 'troubleshooting'],
    ]);
    expect(guide.permissions).toEqual(['Mail.ReadWrite', 'User.Read.All']);
    expect(guide.platformClientId).toBe('11111111-2222-3333-4444-555555555555');
    expect(guide.journalSource).toEqual({
      id: '11111111-2222-3333-4444-555555555555',
      kind: 'microsoft_365_journal',
      addressMasked: 'journal-••••xamp@journal.gateway.example.net',
    });
    const markdown = renderApiModeGuideMarkdown(guide);
    expect(markdown).toContain('never changes your MX records');
    expect(markdown).toContain('never delivers');
    expect(markdown).toContain('docs/integrations/journal-intake-microsoft-365.md');
    expect(markdown).toContain('New-ManagementRoleAssignment');
    expect(markdown).toContain('coverage gaps');
    expect(markdown).toContain('Enterprise applications');
    expect(guide.attestations).toEqual([
      {
        code: 'api_mode.m365.app_access_scoped',
        statement: apiModeAttestationsFor('microsoft_365')[0]!.statement,
        attested: false,
        attestedAt: null,
      },
    ]);
  });

  it('Google: delegation with the client id, both scopes and the delegated admin; revoke', () => {
    const guide = generateApiModeGuide(exampleApiModeGuideInput('google_workspace'));
    expect(guide.sections.map((s) => s.id)).toEqual([
      'overview',
      'journal',
      'mailbox-access',
      'feeds',
      'verify',
      'revoke',
      'troubleshooting',
    ]);
    const delegation = guide.sections
      .find((s) => s.id === 'mailbox-access')!
      .steps.find((s) => s.id === 'delegation-add')!;
    expect(delegation.values).toEqual([
      { label: 'Client ID', value: '111122223333444455556' },
      {
        label: 'OAuth scopes',
        value:
          'https://www.googleapis.com/auth/gmail.modify,https://www.googleapis.com/auth/admin.directory.user.readonly',
      },
    ]);
    expect(delegation.attestation?.code).toBe('api_mode.google.delegation_added');
    const markdown = renderApiModeGuideMarkdown(guide);
    expect(markdown).toContain('Also deliver to');
    expect(markdown).toContain('admin@example.com');
    expect(markdown).toContain('Manage Domain Wide Delegation');
    expect(markdown).toContain('Gmail history');
  });

  it('reflects attestations, the grant method, feeds and a missing journal source', () => {
    const input: ApiModeGuideInput = {
      ...exampleApiModeGuideInput('microsoft_365'),
      journalSource: null,
      platformClientId: null,
      grantClientId: '99999999-8888-7777-6666-555555555555',
      authMethod: 'customer_app_secret',
      feeds: { enabled: true, mode: 'notify' },
      attestations: [
        { code: 'api_mode.m365.app_access_scoped', at: new Date('2026-11-25T10:00:00Z') },
      ],
    };
    const guide = generateApiModeGuide(input);
    expect(guide.attestations[0]).toMatchObject({
      attested: true,
      attestedAt: '2026-11-25T10:00:00.000Z',
    });
    expect(guide.journalSource).toBeUndefined();
    expect(guide.platformClientId).toBeUndefined();
    const markdown = renderApiModeGuideMarkdown(guide);
    expect(markdown).toContain('none bound yet');
    expect(markdown).toContain('your own application (option B below)');
    expect(markdown).toContain("-AppId '99999999-8888-7777-6666-555555555555'");
    expect(markdown).toContain('on (change notifications)');
    expect(markdown).toContain('not offered by this gateway operator');
  });

  it('refuses unusable inputs and a revealed intake address', () => {
    const base = exampleApiModeGuideInput('microsoft_365');
    const bad: Partial<ApiModeGuideInput>[] = [
      { connection: { ...base.connection, publicId: 'nope' } },
      { domains: ['exa mple.com'] },
      { platformClientId: 'not-a-guid' },
      { delegatedAdmin: 'no address' },
      {
        journalSource: {
          ...base.journalSource!,
          addressMasked: 'journal-abcdefghijklmnopqrstuvwxyz@journal.gateway.example.net',
        },
      },
    ];
    for (const patch of bad) {
      expect(() => generateApiModeGuide({ ...base, ...patch }), JSON.stringify(patch)).toThrow(
        SetupGuideInputError,
      );
    }
    expect(() =>
      generateApiModeGuide({
        ...exampleApiModeGuideInput('google_workspace'),
        platformClientId: '11111111-2222-3333-4444-555555555555',
      }),
    ).toThrow(SetupGuideInputError);
  });

  it('names the download file', () => {
    expect(
      apiModeGuideFileName(generateApiModeGuide(exampleApiModeGuideInput('microsoft_365'))),
    ).toBe('api-mode-microsoft-365-example-microsoft-365.md');
  });
});

describe('API-mode attestation codes', () => {
  it('adds exactly the two codes, unique across every guide family', () => {
    expect(API_MODE_ATTESTATIONS.map((a) => a.code)).toEqual([
      'api_mode.m365.app_access_scoped',
      'api_mode.google.delegation_added',
    ]);
    const all = [...ATTESTATIONS, ...INTAKE_ATTESTATIONS, ...API_MODE_ATTESTATIONS].map(
      (a) => a.code,
    );
    expect(new Set(all).size).toBe(all.length);
    expect(
      apiModeAttestationByCode('google_workspace', 'api_mode.google.delegation_added'),
    ).toBeDefined();
    expect(
      apiModeAttestationByCode('microsoft_365', 'api_mode.google.delegation_added'),
    ).toBeUndefined();
    // The 8.2 lists are unchanged by API mode.
    expect(ATTESTATIONS.some((a) => a.code.startsWith('api_mode.'))).toBe(false);
  });
});

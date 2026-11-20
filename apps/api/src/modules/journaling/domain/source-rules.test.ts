import { describe, expect, it } from 'vitest';
import {
  connectionIssue,
  type ConnectionFacts,
  maxMessageBytesIssue,
  resumedStatus,
  sourceFieldIssues,
} from './source-rules';

const BOUND: ConnectionFacts = {
  provider: 'microsoft_365',
  status: 'active',
  activeTenantKey: 'microsoft_365:tenant',
  externalTenantId: '11111111-2222-3333-4444-555555555555',
};

describe('intake source rules (step 8.6 D1)', () => {
  it.each([
    [
      'microsoft_365_journal',
      {},
      'create',
      ['providerConnectionId: Required for microsoft_365_journal'],
    ],
    ['microsoft_365_journal', { providerConnectionId: 'x' }, 'create', []],
    [
      'google_workspace_copy',
      { providerConnectionId: 'x', networks: ['198.51.100.0/28'] },
      'create',
      ["networks: Not allowed for google_workspace_copy (the provider's egress ranges apply)"],
    ],
    ['google_workspace_copy', {}, 'update', []],
    ['smtp_bcc', {}, 'create', ['networks: Required for smtp_bcc']],
    ['smtp_bcc', { networks: ['198.51.100.0/28'] }, 'create', []],
    [
      'exchange_onprem_journal',
      { networks: ['198.51.100.0/28'], providerConnectionId: 'x' },
      'create',
      ['providerConnectionId: Not allowed for exchange_onprem_journal'],
    ],
    ['exchange_onprem_journal', {}, 'update', []],
  ] as const)('%s %j (%s) → %j', (kind, fields, mode, issues) => {
    expect(sourceFieldIssues(kind, fields, mode)).toEqual(issues);
  });

  it.each<
    [
      string,
      ConnectionFacts | null,
      'microsoft_365_journal' | 'google_workspace_copy',
      string | null,
    ]
  >([
    ['bound Microsoft 365', BOUND, 'microsoft_365_journal', null],
    ['unknown or foreign', null, 'microsoft_365_journal', 'not_found'],
    ['other provider', BOUND, 'google_workspace_copy', 'provider_mismatch'],
    ['disabled', { ...BOUND, status: 'disabled' }, 'microsoft_365_journal', 'disabled'],
    [
      'tenant not bound',
      { ...BOUND, status: 'configuring', activeTenantKey: null },
      'microsoft_365_journal',
      'tenant_not_bound',
    ],
    [
      'no external tenant',
      { ...BOUND, externalTenantId: null },
      'microsoft_365_journal',
      'tenant_not_bound',
    ],
    [
      'bound Google (no mail flow needed)',
      { ...BOUND, provider: 'google_workspace', status: 'configuring' },
      'google_workspace_copy',
      null,
    ],
  ])('connection %s', (_name, facts, kind, issue) => {
    expect(connectionIssue(kind, facts)).toBe(issue);
  });

  it('caps the per-source size at the platform maximum', () => {
    expect(maxMessageBytesIssue(undefined, 1000)).toBeNull();
    expect(maxMessageBytesIssue(null, 1000)).toBeNull();
    expect(maxMessageBytesIssue(1000, 1000)).toBeNull();
    expect(maxMessageBytesIssue(1001, 1000)).toMatch(/maxMessageBytes/);
  });

  it('resumes to active only once verified', () => {
    expect(resumedStatus(null)).toBe('pending_verification');
    expect(resumedStatus(new Date())).toBe('active');
  });
});

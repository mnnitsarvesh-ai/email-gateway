import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  evaluateIntakeProof,
  intakeDkimDomainAcceptable,
  intakeDkimEvidence,
  type IntakeProofEvidence,
  type IntakeProofPolicy,
  intakeKindProvider,
  isJournalIntakeKind,
  isJournalReportKind,
  JOURNAL_INTAKE_KINDS,
  journalTokenSha256,
  sha256HexEquals,
} from './journal-intake-proof';
import type { DkimSignatureEvidence } from './provider-relay';

const TENANT = '7d1c0e6a-1b2c-4d3e-8f90-a1b2c3d4e5f6';
const TOKEN = 'abcdefghijklmnopqrstuvwxyz';
const OLD_TOKEN = 'zyxwvutsrqponmlkjihgfedcba';
const NOW = new Date('2026-11-20T10:00:00.000Z');
const sha = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

const signature = (overrides: Partial<DkimSignatureEvidence> = {}): DkimSignatureEvidence => ({
  status: 'pass',
  domain: 'example.com',
  algorithm: 'rsa-sha256',
  bodyLengthLimited: false,
  signedHeaders: ['from', 'to', 'subject'],
  keyBits: 2048,
  signedAt: NOW,
  signatureId: 'a'.repeat(64),
  ...overrides,
});

const evidence = (overrides: Partial<IntakeProofEvidence> = {}): IntakeProofEvidence => ({
  kind: 'microsoft_365_journal',
  network: 'provider_egress',
  tls: true,
  clientCertMatched: false,
  headerBlockComplete: true,
  tenantHeaderValues: [TENANT],
  headerTokens: [],
  dkim: { signatures: [], verifierError: false },
  ...overrides,
});

const policy = (overrides: Partial<IntakeProofPolicy> = {}): IntakeProofPolicy => ({
  expectedTenantId: TENANT,
  linkedDomains: ['example.com'],
  headerTokenSha256: sha(TOKEN),
  previousHeaderTokenSha256: sha(OLD_TOKEN),
  previousValidUntil: new Date(NOW.getTime() + 86_400_000),
  now: NOW,
  ...overrides,
});

describe('journal intake kinds', () => {
  it('maps provider kinds to their relay provider and report kinds', () => {
    expect(JOURNAL_INTAKE_KINDS.map(intakeKindProvider)).toEqual([
      'microsoft_365',
      'google_workspace',
      null,
      null,
    ]);
    expect(JOURNAL_INTAKE_KINDS.filter(isJournalReportKind)).toEqual([
      'microsoft_365_journal',
      'exchange_onprem_journal',
    ]);
    expect(isJournalIntakeKind('smtp_bcc')).toBe(true);
    expect(isJournalIntakeKind('gateway')).toBe(false);
  });
});

describe('evaluateIntakeProof: microsoft_365_journal (tenant header)', () => {
  const cases: [
    string,
    Partial<IntakeProofEvidence>,
    Partial<IntakeProofPolicy>,
    string,
    string | null,
    string,
  ][] = [
    ['one matching value', {}, {}, 'pass', null, 'match'],
    [
      'several matching values, any case',
      { tenantHeaderValues: [TENANT, ` ${TENANT.toUpperCase()} `] },
      {},
      'pass',
      null,
      'match',
    ],
    ['no header', { tenantHeaderValues: [] }, {}, 'fail', 'tenant_header_absent', 'absent'],
    [
      'another tenant',
      { tenantHeaderValues: ['00000000-0000-0000-0000-000000000000'] },
      {},
      'fail',
      'tenant_header_mismatch',
      'mismatch',
    ],
    [
      'a forged second value',
      { tenantHeaderValues: [TENANT, '00000000-0000-0000-0000-000000000000'] },
      {},
      'fail',
      'tenant_header_mismatch',
      'mismatch',
    ],
    [
      'truncated header block',
      { headerBlockComplete: false },
      {},
      'fail',
      'header_block_truncated',
      'mismatch',
    ],
    [
      'connection no longer bound',
      {},
      { expectedTenantId: null },
      'temperror',
      'tenant_unbound',
      'mismatch',
    ],
  ];
  it.each(cases)('%s', (_name, e, p, result, code, tenantHeader) => {
    const outcome = evaluateIntakeProof(evidence(e), policy(p));
    expect(outcome.result).toBe(result);
    expect(outcome.failureCode).toBe(code);
    expect(outcome.tenantHeader).toBe(tenantHeader);
    expect(outcome.headerToken).toBe('n/a');
    expect(outcome.document === null).toBe(result !== 'pass');
  });

  it('records DKIM as evidence without ever failing on it', () => {
    const bad = evaluateIntakeProof(
      evidence({ dkim: { signatures: [signature({ status: 'fail' })], verifierError: false } }),
      policy(),
    );
    expect(bad.result).toBe('pass');
    expect(bad.document?.dkim).toEqual({ result: 'fail', domains: ['example.com'] });
    const broken = evaluateIntakeProof(
      evidence({ dkim: { signatures: [], verifierError: true } }),
      policy(),
    );
    expect(broken.result).toBe('pass');
    expect(broken.document?.dkim.result).toBe('temperror');
    const notRun = evaluateIntakeProof(evidence({ dkim: null }), policy());
    expect(notRun.document?.dkim.result).toBe('temperror');
  });

  it('stores the document of a pass with the RCPT facts', () => {
    const outcome = evaluateIntakeProof(
      evidence({
        clientCertMatched: true,
        tls: false,
        dkim: {
          signatures: [signature({ domain: 'contoso.onmicrosoft.com' })],
          verifierError: false,
        },
      }),
      policy(),
    );
    expect(outcome.document).toEqual({
      v: 1,
      network: 'provider_egress',
      tls: false,
      clientCert: 'match',
      tenantHeader: 'match',
      headerToken: 'n/a',
      dkim: { result: 'aligned_pass', domains: ['contoso.onmicrosoft.com'] },
      result: 'pass',
    });
  });
});

describe('evaluateIntakeProof: google_workspace_copy (header token)', () => {
  const google = (e: Partial<IntakeProofEvidence>) =>
    evidence({ kind: 'google_workspace_copy', tenantHeaderValues: [], dkim: null, ...e });
  const expired = { previousValidUntil: new Date(NOW.getTime() - 1) };
  const cases: [
    string,
    Partial<IntakeProofEvidence>,
    Partial<IntakeProofPolicy>,
    string,
    string | null,
    string,
  ][] = [
    ['current token', { headerTokens: [TOKEN] }, {}, 'pass', null, 'match'],
    [
      'current token, upper case and padded',
      { headerTokens: [` ${TOKEN.toUpperCase()} `] },
      {},
      'pass',
      null,
      'match',
    ],
    [
      'previous token within the overlap',
      { headerTokens: [OLD_TOKEN] },
      {},
      'pass',
      null,
      'previous',
    ],
    [
      'previous token after the overlap',
      { headerTokens: [OLD_TOKEN] },
      expired,
      'fail',
      'header_token_mismatch',
      'mismatch',
    ],
    [
      'previous token without an end of overlap',
      { headerTokens: [OLD_TOKEN] },
      { previousValidUntil: null },
      'fail',
      'header_token_mismatch',
      'mismatch',
    ],
    ['no token', { headerTokens: [] }, {}, 'fail', 'header_token_absent', 'absent'],
    [
      'two tokens (even both valid)',
      { headerTokens: [TOKEN, TOKEN] },
      {},
      'fail',
      'header_token_multiple',
      'mismatch',
    ],
    [
      'wrong token',
      { headerTokens: ['a'.repeat(26)] },
      {},
      'fail',
      'header_token_mismatch',
      'mismatch',
    ],
    [
      'truncated header block',
      { headerTokens: [TOKEN], headerBlockComplete: false },
      {},
      'fail',
      'header_block_truncated',
      'mismatch',
    ],
    [
      'no token configured',
      { headerTokens: [TOKEN] },
      { headerTokenSha256: null },
      'temperror',
      'header_token_unconfigured',
      'mismatch',
    ],
  ];
  it.each(cases)('%s', (_name, e, p, result, code, headerToken) => {
    const outcome = evaluateIntakeProof(google(e), policy(p));
    expect(outcome.result).toBe(result);
    expect(outcome.failureCode).toBe(code);
    expect(outcome.headerToken).toBe(headerToken);
    expect(outcome.tenantHeader).toBe('n/a');
    expect(outcome.dkim).toEqual({ result: 'n/a', domains: [] });
  });

  it('ignores a Microsoft tenant header on a Google copy', () => {
    const outcome = evaluateIntakeProof(
      google({ headerTokens: [TOKEN], tenantHeaderValues: ['anything'] }),
      policy(),
    );
    expect(outcome.result).toBe('pass');
    expect(outcome.document?.tenantHeader).toBe('n/a');
  });
});

describe('evaluateIntakeProof: on-premises kinds', () => {
  it.each(['exchange_onprem_journal', 'smtp_bcc'] as const)('%s has no content proof', (kind) => {
    const outcome = evaluateIntakeProof(
      evidence({
        kind,
        network: 'source_networks',
        tenantHeaderValues: ['forged'],
        headerTokens: ['forged', 'twice'],
        headerBlockComplete: false,
      }),
      policy({ expectedTenantId: null, headerTokenSha256: null }),
    );
    expect(outcome).toMatchObject({ result: 'pass', failedRule: null, failureCode: null });
    expect(outcome.document).toEqual({
      v: 1,
      network: 'source_networks',
      tls: true,
      clientCert: 'n/a',
      tenantHeader: 'n/a',
      headerToken: 'n/a',
      dkim: { result: 'n/a', domains: [] },
      result: 'pass',
    });
  });
});

describe('DKIM evidence of a journal report', () => {
  it('accepts linked domains, their parents and onmicrosoft.com tenant domains', () => {
    expect(intakeDkimDomainAcceptable('example.com', ['example.com'])).toBe(true);
    expect(intakeDkimDomainAcceptable('example.com', ['mail.example.com'])).toBe(true);
    expect(intakeDkimDomainAcceptable('mail.example.com', ['example.com'])).toBe(false);
    expect(intakeDkimDomainAcceptable('contoso.onmicrosoft.com', [])).toBe(true);
    expect(intakeDkimDomainAcceptable('a.b.onmicrosoft.com', [])).toBe(false);
    expect(intakeDkimDomainAcceptable('other.org', ['example.com'])).toBe(false);
  });

  it('classifies the strongest signature', () => {
    const linked = ['example.com'];
    expect(intakeDkimEvidence({ signatures: [], verifierError: false }, linked).result).toBe(
      'none',
    );
    expect(
      intakeDkimEvidence(
        { signatures: [signature({ domain: 'other.org' }), signature()], verifierError: false },
        linked,
      ),
    ).toEqual({ result: 'aligned_pass', domains: ['other.org', 'example.com'] });
    expect(
      intakeDkimEvidence(
        { signatures: [signature({ domain: 'other.org' })], verifierError: false },
        linked,
      ).result,
    ).toBe('unaligned_pass');
    expect(
      intakeDkimEvidence(
        { signatures: [signature({ bodyLengthLimited: true })], verifierError: false },
        linked,
      ).result,
    ).toBe('fail');
    expect(
      intakeDkimEvidence(
        {
          signatures: [signature({ status: 'temperror' }), signature({ status: 'fail' })],
          verifierError: false,
        },
        linked,
      ).result,
    ).toBe('temperror');
  });

  it('keeps at most five domains', () => {
    const many = Array.from({ length: 8 }, (_, i) => signature({ domain: `d${i}.example` }));
    expect(intakeDkimEvidence({ signatures: many, verifierError: false }, []).domains).toHaveLength(
      5,
    );
  });
});

describe('token hashing', () => {
  it('hashes the trimmed lower-case token and compares digests in constant time', () => {
    expect(journalTokenSha256(` ${TOKEN.toUpperCase()}\t`)).toBe(sha(TOKEN));
    expect(sha256HexEquals(sha(TOKEN), sha(TOKEN))).toBe(true);
    expect(sha256HexEquals(sha(TOKEN), sha(OLD_TOKEN))).toBe(false);
    expect(sha256HexEquals('not-hex', sha(TOKEN))).toBe(false);
    expect(sha256HexEquals(null, sha(TOKEN))).toBe(false);
  });
});

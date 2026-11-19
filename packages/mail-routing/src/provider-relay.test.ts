import { describe, expect, it } from 'vitest';
import {
  classifyDkimSignature,
  DEFAULT_PROVIDER_RELAY_PROOF,
  type DkimSignatureEvidence,
  dkimDomainAligned,
  dkimReplayCandidates,
  egressRangesFromCidrs,
  evaluateProviderProof,
  generateProbeToken,
  type IpBytes,
  isProbeAddress,
  isProbeDomain,
  parseProviderRelayProofPolicy,
  probeAddress,
  probeTokenOf,
  probeTokenSha256,
  ProviderEgressIndex,
  type ProviderProofEvidence,
  ProviderRelayProofPolicyError,
  providerRelayProofIssues,
  providerRelayProofPolicySchema,
} from './provider-relay';

const v4 = (text: string): IpBytes => ({
  version: 4,
  bytes: Uint8Array.from(text.split('.').map(Number)),
});
const v6 = (groups: number[]): IpBytes => {
  const bytes = new Uint8Array(16);
  groups.forEach((group, i) => {
    bytes[i * 2] = group >> 8;
    bytes[i * 2 + 1] = group & 0xff;
  });
  return { version: 6, bytes };
};

describe('ProviderEgressIndex (D7.2)', () => {
  const index = ProviderEgressIndex.build([
    ...egressRangesFromCidrs('microsoft_365', [
      '40.92.0.0/15',
      '104.47.0.0/17',
      '2a01:111:f400::/48',
    ]),
    ...egressRangesFromCidrs('google_workspace', ['209.85.128.0/17', '209.85.200.0/24']),
  ]);

  it('matches IPv4 addresses inside and at the boundaries of a range', () => {
    expect(index.providersFor(v4('40.92.0.0'))).toEqual(['microsoft_365']);
    expect(index.providersFor(v4('40.93.255.255'))).toEqual(['microsoft_365']);
    expect(index.providersFor(v4('40.94.0.0'))).toEqual([]);
    expect(index.providersFor(v4('40.91.255.255'))).toEqual([]);
    expect(index.providersFor(v4('104.47.127.255'))).toEqual(['microsoft_365']);
    expect(index.providersFor(v4('104.47.128.0'))).toEqual([]);
  });

  it('matches IPv6 and never mixes IP versions', () => {
    expect(index.providersFor(v6([0x2a01, 0x111, 0xf400, 0, 0, 0, 0, 1]))).toEqual([
      'microsoft_365',
    ]);
    expect(index.providersFor(v6([0x2a01, 0x111, 0xf401, 0, 0, 0, 0, 1]))).toEqual([]);
    // The IPv4 bytes of a range, read as a v6 prefix, never match.
    expect(index.contains('microsoft_365', { version: 6, bytes: v4('40.92.0.1').bytes })).toBe(
      false,
    );
  });

  it('merges overlapping ranges (a nested range never hides the outer one)', () => {
    expect(index.providersFor(v4('209.85.200.1'))).toEqual(['google_workspace']);
    expect(index.providersFor(v4('209.85.255.255'))).toEqual(['google_workspace']);
    expect(index.providersFor(v4('209.85.128.0'))).toEqual(['google_workspace']);
    const overlapping = ProviderEgressIndex.build(
      egressRangesFromCidrs('google_workspace', [
        '10.0.0.0/16',
        '10.0.128.0/17',
        '10.0.255.0/24',
        '10.1.0.0/16',
      ]),
    );
    expect(overlapping.contains('google_workspace', v4('10.0.200.1'))).toBe(true);
    expect(overlapping.contains('google_workspace', v4('10.1.255.255'))).toBe(true);
    expect(overlapping.contains('google_workspace', v4('10.2.0.0'))).toBe(false);
    expect(overlapping.count('google_workspace')).toBe(4);
  });

  it('reports every provider whose ranges overlap the address', () => {
    const both = ProviderEgressIndex.build([
      ...egressRangesFromCidrs('microsoft_365', ['172.31.250.0/24']),
      ...egressRangesFromCidrs('google_workspace', ['172.31.250.71/32']),
    ]);
    expect(both.providersFor(v4('172.31.250.71'))).toEqual(['microsoft_365', 'google_workspace']);
    expect(both.providersFor(v4('172.31.250.70'))).toEqual(['microsoft_365']);
  });

  it('counts loaded ranges per provider; the empty index matches nothing', () => {
    expect(index.count('microsoft_365')).toBe(3);
    expect(index.count('google_workspace')).toBe(2);
    expect(ProviderEgressIndex.empty().providersFor(v4('40.92.0.1'))).toEqual([]);
    expect(ProviderEgressIndex.empty().count('microsoft_365')).toBe(0);
  });

  it('refuses malformed ranges', () => {
    expect(() =>
      ProviderEgressIndex.build([
        {
          provider: 'microsoft_365',
          ipVersion: 4,
          rangeStart: new Uint8Array(16),
          rangeEnd: new Uint8Array(16),
        },
      ]),
    ).toThrow();
    expect(() =>
      ProviderEgressIndex.build([
        {
          provider: 'microsoft_365',
          ipVersion: 4,
          rangeStart: v4('10.0.0.2').bytes,
          rangeEnd: v4('10.0.0.1').bytes,
        },
      ]),
    ).toThrow();
    expect(() => egressRangesFromCidrs('microsoft_365', ['10.0.0.1/8'])).toThrow();
  });
});

// --- Proof policy ---------------------------------------------------------------------------

describe('provider-relay-proof/1 policy (D8 bounds)', () => {
  it('defaults per provider', () => {
    expect(parseProviderRelayProofPolicy('microsoft_365', null)).toEqual({
      tenantHeader: 'required',
      dkimAligned: 'required',
    });
    expect(parseProviderRelayProofPolicy('google_workspace', undefined)).toEqual({
      dkimAligned: 'required',
      dkimMaxAgeSeconds: 3600,
      dkimReplayMax: 5,
    });
    for (const provider of ['microsoft_365', 'google_workspace'] as const) {
      expect(providerRelayProofIssues(provider, DEFAULT_PROVIDER_RELAY_PROOF[provider])).toEqual(
        [],
      );
    }
  });

  it('allows the Microsoft tenant header off only with aligned DKIM and its replay bounds', () => {
    expect(
      parseProviderRelayProofPolicy('microsoft_365', {
        tenantHeader: 'off',
        dkimAligned: 'required',
        dkimMaxAgeSeconds: 3600,
        dkimReplayMax: 5,
      }),
    ).toEqual({
      tenantHeader: 'off',
      dkimAligned: 'required',
      dkimMaxAgeSeconds: 3600,
      dkimReplayMax: 5,
    });
    // DKIM as the only proof without a freshness window or replay limit: unbounded replay.
    expect(() =>
      parseProviderRelayProofPolicy('microsoft_365', {
        tenantHeader: 'off',
        dkimAligned: 'required',
      }),
    ).toThrow(/dkimMaxAgeSeconds is required when tenantHeader is off/);
    expect(
      providerRelayProofIssues('microsoft_365', {
        tenantHeader: 'off',
        dkimAligned: 'required',
        dkimMaxAgeSeconds: 600,
      }),
    ).toEqual(['dkimReplayMax is required when tenantHeader is off']);
    expect(() =>
      parseProviderRelayProofPolicy('microsoft_365', { tenantHeader: 'off', dkimAligned: 'off' }),
    ).toThrow(ProviderRelayProofPolicyError);
    // Header only is allowed (one rule is required).
    expect(
      providerRelayProofIssues('microsoft_365', { tenantHeader: 'required', dkimAligned: 'off' }),
    ).toEqual([]);
  });

  it('never allows DKIM off for Google, nor dropping its freshness and replay bounds', () => {
    expect(() =>
      parseProviderRelayProofPolicy('google_workspace', {
        dkimAligned: 'off',
        dkimMaxAgeSeconds: 3600,
        dkimReplayMax: 5,
      }),
    ).toThrow(ProviderRelayProofPolicyError);
    expect(() =>
      parseProviderRelayProofPolicy('google_workspace', { dkimAligned: 'required' }),
    ).toThrow(/dkimMaxAgeSeconds is required/);
    expect(() =>
      parseProviderRelayProofPolicy('google_workspace', {
        tenantHeader: 'required',
        dkimAligned: 'required',
        dkimMaxAgeSeconds: 600,
        dkimReplayMax: 1,
      }),
    ).toThrow(/only to Microsoft 365/);
    expect(
      parseProviderRelayProofPolicy('google_workspace', {
        dkimAligned: 'required',
        dkimMaxAgeSeconds: 600,
        dkimReplayMax: 1,
      }),
    ).toEqual({ dkimAligned: 'required', dkimMaxAgeSeconds: 600, dkimReplayMax: 1 });
  });

  it('bounds the numbers and refuses unknown fields', () => {
    const parse = (value: unknown) => providerRelayProofPolicySchema.safeParse(value).success;
    expect(parse({ dkimAligned: 'required', dkimMaxAgeSeconds: 299 })).toBe(false);
    expect(parse({ dkimAligned: 'required', dkimMaxAgeSeconds: 86_401 })).toBe(false);
    expect(parse({ dkimAligned: 'required', dkimReplayMax: 0 })).toBe(false);
    expect(parse({ dkimAligned: 'required', dkimReplayMax: 101 })).toBe(false);
    expect(parse({ dkimAligned: 'required', extra: true })).toBe(false);
    expect(parse({ tenantHeader: 'maybe', dkimAligned: 'required' })).toBe(false);
    expect(() => parseProviderRelayProofPolicy('microsoft_365', 'garbage')).toThrow(
      ProviderRelayProofPolicyError,
    );
    expect(
      providerRelayProofIssues('microsoft_365', {
        tenantHeader: 'required',
        dkimAligned: 'off',
        dkimReplayMax: 2,
      }),
    ).toContain('dkimMaxAgeSeconds and dkimReplayMax need dkimAligned required');
  });
});

// --- Proof evaluation -----------------------------------------------------------------------

const NOW = new Date('2026-11-18T10:00:00.000Z');
const TENANT = '11111111-2222-3333-4444-555555555555';

function sig(overrides: Partial<DkimSignatureEvidence> = {}): DkimSignatureEvidence {
  return {
    status: 'pass',
    domain: 'acme.test',
    algorithm: 'rsa-sha256',
    bodyLengthLimited: false,
    signedHeaders: ['from', 'to', 'subject'],
    keyBits: 2048,
    signedAt: new Date(NOW.getTime() - 60_000),
    signatureId: 'a'.repeat(64),
    ...overrides,
  };
}

function evidence(overrides: Partial<ProviderProofEvidence> = {}): ProviderProofEvidence {
  return {
    provider: 'microsoft_365',
    expectedTenantId: TENANT,
    tenantHeaderValues: [TENANT],
    headerFromDomain: 'acme.test',
    linkedDomains: ['acme.test'],
    signatures: [sig()],
    headerBlockComplete: true,
    verifierError: false,
    now: NOW,
    ...overrides,
  };
}

const M365 = DEFAULT_PROVIDER_RELAY_PROOF.microsoft_365;
const GOOGLE = DEFAULT_PROVIDER_RELAY_PROOF.google_workspace;

const google = (overrides: Partial<ProviderProofEvidence> = {}): ProviderProofEvidence =>
  evidence({
    provider: 'google_workspace',
    expectedTenantId: 'C01abcdef',
    tenantHeaderValues: [],
    replayCounts: new Map([['a'.repeat(64), 1]]),
    ...overrides,
  });

describe('evaluateProviderProof (D8)', () => {
  it('passes Microsoft 365 with the tenant header and an aligned DKIM pass', () => {
    const outcome = evaluateProviderProof(evidence(), M365);
    expect(outcome).toMatchObject({
      result: 'pass',
      tenantHeader: 'match',
      dkim: 'aligned_pass',
      failureCode: null,
      dkimDomains: ['acme.test'],
      dkimAgeSeconds: 60,
    });
    expect(outcome.rules).toEqual([
      { rule: 'tenant_header', result: 'pass' },
      { rule: 'dkim_aligned', result: 'pass' },
    ]);
  });

  it('compares tenant ids case-insensitively', () => {
    expect(
      evaluateProviderProof(evidence({ tenantHeaderValues: [TENANT.toUpperCase()] }), M365).result,
    ).toBe('pass');
  });

  it.each<[string, Partial<ProviderProofEvidence>, string, string]>([
    ['no tenant header', { tenantHeaderValues: [] }, 'absent', 'tenant_header_absent'],
    [
      'another tenant',
      { tenantHeaderValues: ['99999999-2222-3333-4444-555555555555'] },
      'mismatch',
      'tenant_header_mismatch',
    ],
    [
      'a forged second value',
      { tenantHeaderValues: [TENANT, '99999999-2222-3333-4444-555555555555'] },
      'mismatch',
      'tenant_header_mismatch',
    ],
    ['an unverified connection', { expectedTenantId: null }, 'mismatch', 'tenant_header_mismatch'],
  ])('fails the tenant header rule with %s', (_, overrides, tenantHeader, code) => {
    const outcome = evaluateProviderProof(evidence(overrides), M365);
    expect(outcome).toMatchObject({ result: 'fail', tenantHeader, failureCode: code });
    expect(outcome.rules[0]).toEqual({ rule: 'tenant_header', result: 'fail' });
  });

  it('a tenant header failure is permanent even when DKIM could not be checked', () => {
    expect(
      evaluateProviderProof(
        evidence({ tenantHeaderValues: [], signatures: [sig({ status: 'temperror' })] }),
        M365,
      ),
    ).toMatchObject({ result: 'fail', failureCode: 'tenant_header_absent', dkim: 'temperror' });
  });

  it.each<[string, DkimSignatureEvidence[], string, string]>([
    ['unsigned', [], 'none', 'dkim_none'],
    ['a failed signature', [sig({ status: 'fail' })], 'fail', 'dkim_failed'],
    ['a neutral signature', [sig({ status: 'neutral' })], 'fail', 'dkim_failed'],
    [
      'a signature of another domain',
      [sig({ domain: 'other.test' })],
      'unaligned_pass',
      'dkim_unaligned',
    ],
    ['a sibling domain', [sig({ domain: 'b.acme.test' })], 'unaligned_pass', 'dkim_unaligned'],
    ['an l= tag', [sig({ bodyLengthLimited: true })], 'fail', 'dkim_weak'],
    ['h= without from', [sig({ signedHeaders: ['to', 'subject'] })], 'fail', 'dkim_weak'],
    ['a short key', [sig({ keyBits: 768 })], 'fail', 'dkim_weak'],
    ['an unknown key size', [sig({ keyBits: null })], 'fail', 'dkim_weak'],
    ['rsa-sha1', [sig({ algorithm: 'rsa-sha1' })], 'fail', 'dkim_weak'],
  ])('fails the DKIM rule when %s', (_, signatures, dkim, code) => {
    expect(evaluateProviderProof(evidence({ signatures }), M365)).toMatchObject({
      result: 'fail',
      dkim,
      failureCode: code,
      tenantHeader: 'match',
    });
  });

  it('accepts a parent-domain signature when the parent is linked, never an unlinked one', () => {
    const parent = evidence({ headerFromDomain: 'mail.acme.test' });
    expect(evaluateProviderProof(parent, M365).result).toBe('pass');
    expect(
      evaluateProviderProof(
        evidence({ headerFromDomain: 'mail.acme.test', linkedDomains: ['mail.acme.test'] }),
        M365,
      ),
    ).toMatchObject({ result: 'fail', failureCode: 'dkim_unaligned' });
    expect(dkimDomainAligned('acme.test', 'notacme.test')).toBe(false);
    expect(dkimDomainAligned('ACME.test.', 'x.acme.test')).toBe(true);
  });

  it('accepts ed25519 without a modulus and any one aligned pass among several signatures', () => {
    expect(
      evaluateProviderProof(
        evidence({ signatures: [sig({ algorithm: 'ed25519-sha256', keyBits: null })] }),
        M365,
      ).result,
    ).toBe('pass');
    expect(
      evaluateProviderProof(
        evidence({
          signatures: [sig({ domain: 'onmicrosoft.test', signatureId: 'b'.repeat(64) }), sig()],
        }),
        M365,
      ),
    ).toMatchObject({ result: 'pass', dkimDomains: ['onmicrosoft.test', 'acme.test'] });
  });

  it('is temperror when no signature passed but one could not be checked, or the verifier failed', () => {
    expect(
      evaluateProviderProof(
        evidence({ signatures: [sig({ status: 'fail' }), sig({ status: 'temperror' })] }),
        M365,
      ),
    ).toMatchObject({ result: 'temperror', dkim: 'temperror', failureCode: 'dkim_temperror' });
    expect(evaluateProviderProof(evidence({ verifierError: true }), M365)).toMatchObject({
      result: 'temperror',
      failureCode: 'verifier_error',
    });
  });

  it('fails a header block cut by the scan limit', () => {
    expect(evaluateProviderProof(evidence({ headerBlockComplete: false }), M365)).toMatchObject({
      result: 'fail',
      failureCode: 'header_block_truncated',
    });
  });

  it('honours a Microsoft override without the tenant header', () => {
    const policy = { tenantHeader: 'off', dkimAligned: 'required' } as const;
    expect(evaluateProviderProof(evidence({ tenantHeaderValues: [] }), policy)).toMatchObject({
      result: 'pass',
      tenantHeader: 'not_applicable',
    });
  });

  it('honours a Microsoft override with the tenant header only', () => {
    const policy = { tenantHeader: 'required', dkimAligned: 'off' } as const;
    expect(evaluateProviderProof(evidence({ signatures: [] }), policy)).toMatchObject({
      result: 'pass',
      dkim: 'none',
    });
  });

  describe('Google Workspace freshness and replay', () => {
    it('passes a fresh, aligned, first-seen signature (no tenant header rule)', () => {
      expect(evaluateProviderProof(google(), GOOGLE)).toMatchObject({
        result: 'pass',
        tenantHeader: 'not_applicable',
        dkim: 'aligned_pass',
      });
      expect(evaluateProviderProof(google(), GOOGLE).rules.map((r) => r.rule)).toEqual([
        'dkim_aligned',
        'dkim_fresh',
        'dkim_replay',
      ]);
    });

    it.each<[string, Date | null]>([
      ['older than an hour', new Date(NOW.getTime() - 3601_000)],
      ['more than 300 s in the future', new Date(NOW.getTime() + 301_000)],
      ['without t=', null],
    ])('fails as stale when t= is %s', (_, signedAt) => {
      expect(
        evaluateProviderProof(google({ signatures: [sig({ signedAt })] }), GOOGLE),
      ).toMatchObject({ result: 'fail', dkim: 'stale', failureCode: 'dkim_stale' });
    });

    it('accepts the window boundaries', () => {
      for (const offset of [-3600_000, 300_000]) {
        const signedAt = new Date(NOW.getTime() + offset);
        expect(
          evaluateProviderProof(google({ signatures: [sig({ signedAt })] }), GOOGLE).result,
        ).toBe('pass');
      }
    });

    it('fails the sixth use of a signature, passes the fifth', () => {
      const at = (count: number) =>
        evaluateProviderProof(google({ replayCounts: new Map([['a'.repeat(64), count]]) }), GOOGLE);
      expect(at(5).result).toBe('pass');
      expect(at(6)).toMatchObject({
        result: 'fail',
        dkim: 'replayed',
        failureCode: 'dkim_replayed',
      });
    });

    it('is temperror when the replay counter is unavailable or missing', () => {
      expect(evaluateProviderProof(google({ replayError: true }), GOOGLE)).toMatchObject({
        result: 'temperror',
        failureCode: 'replay_counter_error',
      });
      expect(evaluateProviderProof(google({ replayCounts: new Map() }), GOOGLE).result).toBe(
        'temperror',
      );
    });

    it('lists only aligned, fresh, distinct signatures as replay candidates', () => {
      const stale = sig({
        signatureId: 'c'.repeat(64),
        signedAt: new Date(NOW.getTime() - 7200_000),
      });
      const unaligned = sig({ signatureId: 'd'.repeat(64), domain: 'gmail.test' });
      const candidates = dkimReplayCandidates(
        google({ signatures: [sig(), sig(), stale, unaligned] }),
        GOOGLE,
      );
      expect(candidates.map((c) => c.signatureId)).toEqual(['a'.repeat(64)]);
      expect(dkimReplayCandidates(evidence(), M365)).toEqual([]);
    });
  });

  it('bounds the reported DKIM domains to five', () => {
    const signatures = Array.from({ length: 7 }, (_, i) =>
      sig({ domain: `d${i}.test`, signatureId: String(i).repeat(64) }),
    );
    expect(evaluateProviderProof(evidence({ signatures }), M365).dkimDomains).toHaveLength(5);
  });

  it('classifies single signatures', () => {
    const context = { headerFromDomain: 'acme.test', linkedDomains: new Set(['acme.test']) };
    expect(classifyDkimSignature(sig(), context)).toBe('aligned_pass');
    expect(classifyDkimSignature(sig({ status: 'temperror' }), context)).toBe('temperror');
    expect(classifyDkimSignature(sig(), { ...context, headerFromDomain: null })).toBe(
      'unaligned_pass',
    );
  });
});

// --- Probe addresses ------------------------------------------------------------------------

describe('probe addresses (D10)', () => {
  const DOMAIN = 'probe.mail-gateway.test';
  const TOKEN = 'abcdefghijklmnopqrstuvwxyz';

  it('parses the token of a probe address', () => {
    expect(probeTokenOf(`eg-probe-${TOKEN}@${DOMAIN}`, DOMAIN)).toBe(TOKEN);
    expect(probeTokenOf(`EG-PROBE-${TOKEN.toUpperCase()}@PROBE.Mail-Gateway.test`, DOMAIN)).toBe(
      TOKEN,
    );
    expect(isProbeAddress(probeAddress(TOKEN, DOMAIN), DOMAIN)).toBe(true);
  });

  it.each([
    `eg-probe-${TOKEN}@other.test`,
    `eg-probe-${TOKEN}@sub.${DOMAIN}`,
    `eg-probe-${TOKEN.slice(1)}@${DOMAIN}`,
    `eg-probe-${TOKEN}0@${DOMAIN}`,
    `probe-${TOKEN}@${DOMAIN}`,
    `eg-probe-${TOKEN.replace('a', '1')}@${DOMAIN}`,
    `@${DOMAIN}`,
    DOMAIN,
  ])('refuses %s', (address) => {
    expect(probeTokenOf(address, DOMAIN)).toBeNull();
  });

  it('recognizes the probe domain and its subdomains', () => {
    expect(isProbeDomain(DOMAIN, DOMAIN)).toBe(true);
    expect(isProbeDomain(`x.${DOMAIN.toUpperCase()}.`, DOMAIN)).toBe(true);
    expect(isProbeDomain('mail-gateway.test', DOMAIN)).toBe(false);
    expect(isProbeDomain(`notprobe.mail-gateway.test`, DOMAIN)).toBe(false);
  });

  it('hashes the token text and generates 26-character tokens', () => {
    expect(probeTokenSha256('a'.repeat(26))).toBe(
      '9976d549a25115dab4e36d0c1fb8f31cb07da87dd83275977360eb7dc09e88de',
    );
    expect(generateProbeToken(() => Uint8Array.from({ length: 16 }, (_, i) => i))).toBe(
      'aaaqeayeaudaocajbifqydiob4',
    );
    expect(generateProbeToken()).toMatch(/^[a-z2-7]{26}$/);
    expect(() => probeTokenSha256('short')).toThrow();
  });
});

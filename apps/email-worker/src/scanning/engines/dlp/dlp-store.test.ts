import type { PrismaClient } from '@email-gateway/database';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { aadhaarEnabled, InconsistentDlpReadError, PrismaDlpStore } from './dlp-store';

const ORG = 7n;
const AT = new Date('2026-11-07T05:00:00.000Z');
const NOW = new Date('2026-11-07T06:00:00.000Z');
const scope = {
  organizationId: ORG,
  messageId: 11n,
  receivedAt: AT,
  direction: 'outbound' as const,
};
const LIMITS = {
  policies: 20,
  rulesPerPolicy: 50,
  exceptions: 500,
  patterns: 50,
  dictionaries: 20,
  dictionaryMaxTerms: 1000,
  patternMaxLength: 256,
};

interface TenantRows {
  domains?: unknown[];
  policies?: unknown[];
  exceptions?: unknown[];
  patterns?: unknown[];
  dictionaries?: unknown[];
  compliance?: unknown;
}

function prisma(over: {
  message?: unknown;
  attachments?: unknown[];
  tenant?: TenantRows;
  calls?: { tenant: number };
}): PrismaClient {
  const t = over.tenant ?? {};
  return {
    emailMessage: { findFirst: () => Promise.resolve(over.message ?? null) },
    emailMessageParse: { findFirst: () => Promise.resolve(null) },
    emailAttachment: { findMany: () => Promise.resolve(over.attachments ?? []) },
    domain: {
      findMany: () => {
        if (over.calls) over.calls.tenant += 1;
        return Promise.resolve(t.domains ?? []);
      },
    },
    dlpPolicy: { findMany: () => Promise.resolve(t.policies ?? []) },
    dlpException: { findMany: () => Promise.resolve(t.exceptions ?? []) },
    dlpCustomPattern: { findMany: () => Promise.resolve(t.patterns ?? []) },
    dlpKeywordDictionary: { findMany: () => Promise.resolve(t.dictionaries ?? []) },
    dlpComplianceSettings: { findUnique: () => Promise.resolve(t.compliance ?? null) },
  } as unknown as PrismaClient;
}

const store = (p: PrismaClient, ttlMs = 30_000) =>
  new PrismaDlpStore(p, LIMITS, { ttlMs, now: () => NOW });

const message = (over: Record<string, unknown> = {}) => ({
  id: 11n,
  receivedAt: AT,
  organizationId: ORG,
  direction: 'outbound',
  subject: 's',
  envelopeFrom: 'a@b.test',
  headerFrom: 'a@b.test',
  recipientCount: 1,
  ...over,
});

const policy = (over: Record<string, unknown> = {}) => ({
  id: 3n,
  publicId: '0196f3a0-0000-7000-8000-0000000000a1',
  organizationId: ORG,
  enabled: true,
  mode: 'enforce',
  priority: 10,
  directions: ['outbound'],
  version: 2,
  rules: [
    {
      id: 4n,
      publicId: '0196f3a0-0000-7000-8000-0000000000b1',
      organizationId: ORG,
      policyId: 3n,
      enabled: true,
      priority: 1,
      conditions: { selectors: { categories: ['payment_card'] } },
      action: 'block',
      version: 1,
    },
  ],
  ...over,
});

describe('PrismaDlpStore echo checks (step 4.5 §6)', () => {
  it('a message row of another organization, time or direction is a wrong read', async () => {
    for (const forged of [
      message({ organizationId: 8n }),
      message({ receivedAt: new Date(AT.getTime() + 1) }),
      message({ direction: 'inbound' }),
      message({ id: 12n }),
    ]) {
      await expect(store(prisma({ message: forged })).loadMessage(scope)).rejects.toBeInstanceOf(
        InconsistentDlpReadError,
      );
    }
    await expect(store(prisma({})).loadMessage(scope)).rejects.toMatchObject({ read: 'message' });
    await expect(store(prisma({ message: message() })).loadMessage(scope)).resolves.toMatchObject({
      recipientCount: 1,
    });
  });

  it('attachment rows must echo the message and be strictly ordered by part index', async () => {
    const row = (partIndex: number, over: Record<string, unknown> = {}) => ({
      messageId: 11n,
      receivedAt: AT,
      organizationId: ORG,
      partIndex,
      filename: 'f',
      declaredContentType: null,
      sizeBytes: 1,
      sha256: 'a'.repeat(64),
      objectKey: null,
      flags: [],
      ...over,
    });
    await expect(
      store(prisma({ attachments: [row(1), row(1)] })).loadAttachments(scope, 5),
    ).rejects.toMatchObject({ read: 'attachments', check: 'part order' });
    await expect(
      store(prisma({ attachments: [row(1, { organizationId: 9n })] })).loadAttachments(scope, 5),
    ).rejects.toMatchObject({ read: 'attachments' });
    await expect(
      store(prisma({ attachments: [row(1), row(2)] })).loadAttachments(scope, 5),
    ).resolves.toHaveLength(2);
  });

  it('tenant data: public ids in snapshots, internal ids beside them; forged rows refused', async () => {
    const data = await store(prisma({ tenant: { policies: [policy()] } })).tenantData(ORG);
    expect(data.policies[0]).toMatchObject({
      id: '0196f3a0-0000-7000-8000-0000000000a1',
      directions: ['outbound'],
    });
    expect(data.policies[0]!.rules[0]).toMatchObject({
      id: '0196f3a0-0000-7000-8000-0000000000b1',
      action: 'block',
    });
    expect(data.internalIds.get('0196f3a0-0000-7000-8000-0000000000b1')).toBe(4n);
    for (const tenant of [
      { policies: [policy({ organizationId: 8n })] },
      { policies: [policy({ rules: [{ ...policy().rules[0], policyId: 99n }] })] },
      { policies: [policy({ enabled: false })] },
      { domains: [{ organizationId: ORG, name: 'x.test', status: 'pending', deletedAt: null }] },
      {
        exceptions: [
          {
            publicId: 'e',
            organizationId: ORG,
            scope: 'recipient_domain',
            value: 'x.test',
            policyId: null,
            ruleId: null,
            filters: null,
            expiresAt: new Date(NOW.getTime() - 1),
            enabled: true,
            version: 1,
            policy: null,
            rule: null,
          },
        ],
      },
      { compliance: { organizationId: 8n, aadhaarEnabled: true } },
    ]) {
      await expect(store(prisma({ tenant })).tenantData(ORG)).rejects.toMatchObject({
        read: 'tenant',
      });
    }
  });

  it('caches tenant data per organization within the TTL', async () => {
    const calls = { tenant: 0 };
    const cached = store(prisma({ calls }));
    await cached.tenantData(ORG);
    await cached.tenantData(ORG);
    expect(calls.tenant).toBe(1);
    const uncached = store(prisma({ calls }), 0);
    await uncached.tenantData(ORG);
    await uncached.tenantData(ORG);
    expect(calls.tenant).toBe(3);
  });

  it('an invalid stored pattern is skipped and reported (dlp.custom.pattern_invalid)', async () => {
    let invalid = 0;
    const s = new PrismaDlpStore(
      prisma({
        tenant: {
          patterns: [
            {
              publicId: '0196f3a0-0000-7000-8000-0000000000d1',
              organizationId: ORG,
              enabled: true,
              pattern: '(a)\\1',
              caseInsensitive: false,
              validator: 'none',
              contextKeywords: [],
              requireContext: false,
              severity: 'high',
              baseConfidence: '0.80',
              maskStyle: 'last4',
              version: 1,
            },
          ],
        },
      }),
      LIMITS,
      { ttlMs: 0, now: () => NOW, onInvalidTenantRow: (n) => (invalid += n) },
    );
    const data = await s.tenantData(ORG);
    expect(data.patterns).toEqual([]);
    expect(data.invalidPatterns).toEqual(['0196f3a0-0000-7000-8000-0000000000d1']);
    expect(invalid).toBe(1);
  });

  describe('custom patterns across reloads (D9, closer review 2026-11-08)', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    const accepted = (over: Record<string, unknown> = {}) => ({
      publicId: '0196f3a0-0000-7000-8000-0000000000d2',
      organizationId: ORG,
      enabled: true,
      pattern: 'PRJ-[0-9]{6}',
      caseInsensitive: false,
      validator: 'none',
      contextKeywords: [],
      requireContext: false,
      severity: 'high',
      baseConfidence: '0.80',
      maskStyle: 'last4',
      version: 1,
      ...over,
    });

    it('a slow clock at reload never invalidates a pattern the api accepted', async () => {
      // Every clock read is 10 s after the previous one: a wall-clock cost probe would refuse
      // the pattern (`pattern_too_slow`); the worker runs only the deterministic checks.
      let t = 0;
      vi.spyOn(performance, 'now').mockImplementation(() => (t += 10_000));
      let invalid = 0;
      const s = new PrismaDlpStore(prisma({ tenant: { patterns: [accepted()] } }), LIMITS, {
        ttlMs: 0,
        now: () => NOW,
        onInvalidTenantRow: (n) => (invalid += n),
      });
      for (let reload = 0; reload < 3; reload += 1) {
        const data = await s.tenantData(ORG);
        expect(data.patterns.map((p) => p.id)).toEqual(['0196f3a0-0000-7000-8000-0000000000d2']);
        expect(data.invalidPatterns).toEqual([]);
      }
      expect(invalid).toBe(0);
    });

    it('compiles each row version once per process; a new version is compiled again', async () => {
      const rows = [accepted()];
      const s = new PrismaDlpStore(prisma({ tenant: { patterns: rows } }), LIMITS, {
        ttlMs: 0,
        now: () => NOW,
      });
      const first = (await s.tenantData(ORG)).patterns[0]!.compiled;
      const again = (await s.tenantData(ORG)).patterns[0]!.compiled;
      expect(again).toBe(first);
      rows[0] = accepted({ version: 2, pattern: 'PRJ-[0-9]{7}' });
      const edited = (await s.tenantData(ORG)).patterns[0]!;
      expect(edited.version).toBe(2);
      expect(edited.compiled).not.toBe(first);
      expect(edited.compiled.input.pattern).toBe('PRJ-[0-9]{7}');
    });
  });
});

describe('Aadhaar gating (D17)', () => {
  const row = {
    aadhaarEnabled: true,
    aadhaarBasis: 'regulatory_obligation',
    aadhaarReference: 'REF',
    aadhaarAttested: true,
    aadhaarReviewDueAt: new Date('2027-01-01T00:00:00Z'),
  };
  it('runs only with an enabled, attested, referenced basis whose review is not due', () => {
    expect(aadhaarEnabled(row, NOW)).toBe(true);
    expect(aadhaarEnabled(null, NOW)).toBe(false);
    expect(aadhaarEnabled({ ...row, aadhaarEnabled: false }, NOW)).toBe(false);
    expect(aadhaarEnabled({ ...row, aadhaarAttested: false }, NOW)).toBe(false);
    expect(aadhaarEnabled({ ...row, aadhaarBasis: null }, NOW)).toBe(false);
    expect(aadhaarEnabled({ ...row, aadhaarReference: '' }, NOW)).toBe(false);
    expect(aadhaarEnabled({ ...row, aadhaarReviewDueAt: NOW }, NOW)).toBe(false);
  });
});

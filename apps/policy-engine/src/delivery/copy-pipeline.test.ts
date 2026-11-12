import { resolveUrlSettings, URL_PLATFORM_DEFAULTS } from '@email-gateway/security-contracts';
import { normalizeUrl } from '@email-gateway/url-security';
import { describe, expect, it } from 'vitest';
import {
  applyCopyEdits,
  type BodyEditPlan,
  policyCopyKey,
  PolicyUrlRewriteError,
} from './policy-copy';
import {
  type CopyFacts,
  parseComplete,
  planPolicyUrlRewrite,
  type PolicyUrlRewriteConfig,
  structureTypes,
} from './policy-url-rewrite';

const LINK = 'https://example.org/landing';
const EML = [
  'From: Alice <alice@partner.example>',
  'To: bob@corp.example',
  'Subject: hello',
  'X-EG-Quarantine-Release: forged',
  '',
  `Hello Bob. See ${LINK} today.`,
  '',
].join('\r\n');
const LIMITS = { maxMessageBytes: 1_048_576, maxHeaderBytes: 16_384 };
const sha = (() => {
  const n = normalizeUrl(LINK);
  if (!n.ok) throw new Error('url');
  return n.url.sha256;
})();

const config: PolicyUrlRewriteConfig = {
  enabled: true,
  key: { id: 3, key: Buffer.alloc(32, 9) },
  clickBaseUrl: 'https://click.test',
  defaultExpiryDays: 30,
  maxExpiryDays: 90,
  dkimSignedPolicy: 'rewrite',
  limits: { maxMessageBytes: 1_048_576, maxPartBytes: 524_288 },
};
const urlSettings = (
  resolveUrlSettings(URL_PLATFORM_DEFAULTS, null) as unknown as {
    settings: CopyFacts['urlSettings'];
  }
).settings;
const facts = (over: Partial<CopyFacts> = {}): CopyFacts => ({
  structure: [{ contentType: 'text/plain' }],
  contentComplete: true,
  urls: [{ urlSha256: sha, urlSeq: 0, truncated: false, eligible: true }],
  urlSettings,
  ...over,
});
const ctx = {
  direction: 'inbound',
  messageSizeBytes: EML.length,
  organizationId: 7n,
  messageId: 100n,
  receivedAt: new Date('2026-11-12T08:00:00.000Z'),
  now: new Date('2026-11-12T08:00:05.000Z'),
};

function rewritePlan(): NonNullable<BodyEditPlan['urlRewrite']> {
  const planned = planPolicyUrlRewrite(facts(), config, ctx);
  if (!('plan' in planned)) throw new Error('not planned');
  return planned.plan;
}

describe('applyCopyEdits: URL rewrite → banner → header edits (Q23, Q22, P21)', () => {
  it('applies the three steps in order on one copy', async () => {
    const out = await applyCopyEdits(
      Buffer.from(EML, 'latin1'),
      { headers: [{ name: 'X-EG-Policy-Warning', value: 'danger' }], subjectPrefix: '[EXT]' },
      {
        urlRewrite: rewritePlan(),
        banner: { level: 'danger', text: null, maxPartBytes: 65_536 },
        structure: [{ contentType: 'text/plain' }],
      },
      LIMITS,
    );
    expect(out).toMatchObject({
      result: 'written',
      banner: 'applied',
      urlRewrite: { status: 'rewritten', skipReason: null },
    });
    const text = out.output!.toString('latin1');
    expect(text.startsWith('X-EG-Policy-Warning: danger\r\n')).toBe(true);
    expect(text).toContain('Subject: [EXT] hello\r\n');
    // The release header of a sender is never kept.
    expect(text).not.toContain('X-EG-Quarantine-Release');
    const body = text.slice(text.indexOf('\r\n\r\n') + 4);
    // The banner is first in the body, the link points at the click service (rewritten before).
    expect(body.startsWith('[DANGER] ')).toBe(true);
    expect(body).not.toContain(LINK);
    expect(body).toMatch(/https:\/\/click\.test\/\S+/);
  });

  it('a deterministic rewrite skip under requireUrlRewrite stops before anything is built', async () => {
    const plan = rewritePlan();
    const signed = [
      'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; boundary="b"',
      '',
      '--b',
      'Content-Type: text/plain',
      '',
      `x ${LINK}`,
      '--b',
      'Content-Type: application/pkcs7-signature',
      '',
      'AAAA',
      '--b--',
      '',
    ].join('\r\n');
    const out = await applyCopyEdits(
      Buffer.from(signed, 'latin1'),
      { headers: [], subjectPrefix: null },
      {
        urlRewrite: plan,
        banner: { level: 'warning', text: 'x', maxPartBytes: 65_536 },
        structure: [
          { contentType: 'multipart/signed' },
          { contentType: 'text/plain' },
          { contentType: 'application/pkcs7-signature' },
        ],
        requireUrlRewrite: true,
      },
      LIMITS,
    );
    expect(out).toMatchObject({
      output: null,
      result: 'unchanged',
      urlRewrite: { status: 'skipped', skipReason: 'signed_smime' },
    });
  });

  it('a skipped rewrite without requireUrlRewrite is recorded; the banner still applies', async () => {
    const out = await applyCopyEdits(
      Buffer.from(EML.replace(LINK, 'nothing'), 'latin1'),
      { headers: [], subjectPrefix: null },
      {
        urlRewrite: rewritePlan(),
        banner: { level: 'caution', text: null, maxPartBytes: 65_536 },
        structure: [{ contentType: 'text/plain' }],
      },
      LIMITS,
    );
    expect(out).toMatchObject({
      result: 'written',
      banner: 'applied',
      urlRewrite: { status: 'skipped', skipReason: 'no_urls' },
    });
  });

  it('nothing to change → unchanged; size limits → refused with the steps recorded', async () => {
    const signedStructure = [{ contentType: 'multipart/encrypted' }];
    expect(
      await applyCopyEdits(
        Buffer.from(EML, 'latin1'),
        { headers: [], subjectPrefix: null },
        {
          urlRewrite: null,
          banner: { level: 'warning', text: null, maxPartBytes: 65_536 },
          structure: signedStructure,
        },
        LIMITS,
      ),
    ).toMatchObject({ result: 'unchanged', banner: 'skipped_encrypted', output: null });
    expect(
      await applyCopyEdits(
        Buffer.from(EML, 'latin1'),
        { headers: [{ name: 'X-EG-Policy-Tag', value: 'x' }], subjectPrefix: null },
        {
          urlRewrite: rewritePlan(),
          banner: { level: 'warning', text: null, maxPartBytes: 65_536 },
          structure: null,
        },
        { maxMessageBytes: 10, maxHeaderBytes: 16_384 },
      ),
    ).toMatchObject({
      result: 'too_large',
      banner: 'skipped_too_large',
      urlRewrite: { status: 'skipped', skipReason: 'too_large' },
    });
    expect(
      await applyCopyEdits(
        Buffer.from(EML, 'latin1'),
        { headers: [{ name: 'X-EG-Policy-Tag', value: 'x' }], subjectPrefix: null },
        { urlRewrite: null, banner: null, structure: null },
        { maxMessageBytes: 1_048_576, maxHeaderBytes: 20 },
      ),
    ).toMatchObject({ result: 'header_too_large', banner: null, urlRewrite: null });
  });

  it('an unexpected rewrite failure is thrown (retryable), never a silent skip', async () => {
    const plan = {
      ...rewritePlan(),
      sign: () => {
        throw new Error('signer down');
      },
    };
    await expect(
      applyCopyEdits(
        Buffer.from(EML, 'latin1'),
        { headers: [], subjectPrefix: null },
        { urlRewrite: plan, banner: null, structure: [{ contentType: 'text/plain' }] },
        LIMITS,
      ),
    ).rejects.toBeInstanceOf(PolicyUrlRewriteError);
  });
});

describe('policyCopyKey (P21, Q13.6)', () => {
  const base = {
    organizationId: 7n,
    messageId: 100n,
    receivedAt: new Date('2026-11-12T08:00:00.000Z'),
    round: 0,
    baseKey: 'org/7/eml/x.eml',
    edits: { headers: [{ name: 'X-EG-Policy-Tag', value: 'a' }], subjectPrefix: null },
  };

  it('keeps the 5.2 key for header-only edits and differs with body edits or a release id', () => {
    const plain = policyCopyKey(base);
    expect(policyCopyKey({ ...base, body: { banner: null, urlRewrite: false } })).toBe(plain);
    const banner = policyCopyKey({
      ...base,
      body: { banner: { level: 'warning', text: null }, urlRewrite: false },
    });
    const rewrite = policyCopyKey({ ...base, body: { banner: null, urlRewrite: true } });
    const release = policyCopyKey({
      ...base,
      round: 1,
      releaseId: '0190f0f0-0000-7000-8000-000000000001',
    });
    expect(new Set([plain, banner, rewrite, release]).size).toBe(4);
    expect(release).toMatch(/^org\/7\/policy\/2026\/11\/12\/100\/r1-[0-9a-f]{32}\.eml$/);
    expect(
      policyCopyKey({ ...base, round: 1, releaseId: '0190f0f0-0000-7000-8000-000000000001' }),
    ).toBe(release);
  });
});

describe('policy URL rewrite planning (Q23)', () => {
  it.each([
    ['disabled by configuration', { enabled: false }, {}, {}, 'disabled'],
    ['parse incomplete', {}, { contentComplete: false }, {}, 'parse_incomplete'],
    ['too large', {}, {}, { messageSizeBytes: 2_000_000 }, 'too_large'],
    ['signed', {}, { structure: [{ contentType: 'multipart/signed' }] }, {}, 'signed_smime'],
    ['encrypted', {}, { structure: [{ contentType: 'application/pkcs7-mime' }] }, {}, 'encrypted'],
    ['no eligible url', {}, { urls: [] }, {}, 'no_urls'],
    ['structure unknown', {}, { structure: null }, {}, 'structure_mismatch'],
  ] as const)('%s → skip %s', (_label, c, f, x, skip) => {
    expect(
      planPolicyUrlRewrite(facts(f as Partial<CopyFacts>), { ...config, ...c }, { ...ctx, ...x }),
    ).toEqual({ skip });
  });

  it('signs tokens with the current key and the tenant expiry from the evaluation time', () => {
    const plan = rewritePlan();
    expect(plan.urlMap.get(sha)).toEqual({ seq: 0, truncated: false });
    expect(plan.clickBaseUrl).toBe('https://click.test');
    const token = plan.sign(0);
    expect(token).toMatch(/^[A-Za-z0-9_-]{62}$/);
    // Key id 3 in the second byte (sign-only current key).
    expect(Buffer.from(token, 'base64url')[1]).toBe(3);
  });

  it('reads parse completeness and structure like the url engine', () => {
    expect(parseComplete('parsed', [])).toBe(true);
    expect(parseComplete('parsed', ['attachment_count'])).toBe(true);
    expect(parseComplete('parsed', ['body_size'])).toBe(false);
    expect(parseComplete('parsed', ['header_anything'])).toBe(false);
    expect(parseComplete('parse_failed', [])).toBe(false);
    expect(structureTypes([{ index: 0, contentType: 'text/plain' }])).toEqual([
      { contentType: 'text/plain' },
    ]);
    expect(structureTypes([{ index: 0 }])).toBeNull();
    expect(structureTypes(null)).toBeNull();
  });
});

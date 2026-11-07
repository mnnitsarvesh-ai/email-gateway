import { describe, expect, it } from 'vitest';
import { computeAlignment, type AuthResultRow } from './alignment';
import { isFreemailDomain, loadFreemail } from './freemail';
import { BecProtectedSet, detectDomainLookalike } from './lookalike';
import { parseEnvelopeAddress, parseMailboxList } from './mailbox';
import { matchName, matchProfileNames, normalizeName } from './names';
import { loadBrands } from '@email-gateway/url-security';

describe('parseMailboxList', () => {
  it('parses a display name with an angle address', () => {
    const r = parseMailboxList('Anita Sharma <Anita.Sharma@Example.COM>');
    expect(r.mailboxes).toHaveLength(1);
    expect(r.mailboxes[0]).toMatchObject({
      displayName: 'Anita Sharma',
      address: 'Anita.Sharma@example.com',
      localPart: 'Anita.Sharma',
      domain: 'example.com',
      flags: [],
    });
    expect(r.flags).toEqual([]);
  });

  it('keeps commas inside quoted names and unescapes', () => {
    const r = parseMailboxList('"Sharma, Anita \\"CEO\\"" <a@example.com>, b@example.org');
    expect(r.mailboxes.map((m) => m.displayName)).toEqual(['Sharma, Anita "CEO"', null]);
    expect(r.mailboxes.map((m) => m.address)).toEqual(['a@example.com', 'b@example.org']);
    expect(r.flags).toEqual(['multiple']);
  });

  it('drops comments (nested) and accepts decoded display names', () => {
    const r = parseMailboxList('Ränder (team (finance)) <r@example.de> (work)');
    expect(r.mailboxes[0]).toMatchObject({ displayName: 'Ränder', address: 'r@example.de' });
    expect(r.flags).toEqual([]);
  });

  it('flags comments nested deeper than 4', () => {
    expect(parseMailboxList('a (1(2(3(4(5)))))<a@example.com>').flags).toContain('parse_error');
  });

  it('flattens groups and drops obsolete routes', () => {
    const r = parseMailboxList('Team: a@example.com, B <b@example.com>; c@example.net');
    expect(r.mailboxes.map((m) => m.address)).toEqual([
      'a@example.com',
      'b@example.com',
      'c@example.net',
    ]);
    expect(parseMailboxList('Undisclosed recipients:;').mailboxes).toEqual([]);
    expect(
      parseMailboxList('<@relay1.example,@relay2.example:x@example.com>').mailboxes[0]!.address,
    ).toBe('x@example.com');
  });

  it('handles a missing angle bracket form "Name addr@x" with a parse_error flag', () => {
    const r = parseMailboxList('John Miller john@example.com');
    expect(r.mailboxes[0]).toMatchObject({
      displayName: 'John Miller',
      address: 'john@example.com',
    });
    expect(r.mailboxes[0]!.flags).toContain('parse_error');
  });

  it('normalizes IDN domains to A-labels and flags them', () => {
    const r = parseMailboxList('Bücher <info@bücher.example>');
    expect(r.mailboxes[0]!.domain).toBe('xn--bcher-kva.example');
    expect(r.mailboxes[0]!.flags).toContain('idn');
  });

  it('reports malformed input without throwing', () => {
    for (const input of [
      '<unterminated@example.com',
      '"open quote <a@b.example>',
      'no address here',
      '@',
      '<>',
      ')(',
    ]) {
      const r = parseMailboxList(input);
      expect(r.flags).toContain('parse_error');
    }
    expect(parseMailboxList(null).mailboxes).toEqual([]);
  });

  it('bounds mailboxes (20) and display names (128 code points)', () => {
    const many = Array.from({ length: 30 }, (_, i) => `u${i}@example.com`).join(', ');
    const r = parseMailboxList(many);
    expect(r.mailboxes).toHaveLength(20);
    expect(r.truncated).toBe(true);
    const long = parseMailboxList(`${'n'.repeat(300)} <a@example.com>`);
    expect([...long.mailboxes[0]!.displayName!].length).toBe(128);
    expect(long.mailboxes[0]!.flags).toContain('display_name_truncated');
  });

  it('is linear on adversarial 2 048-character inputs', () => {
    const inputs = [
      '('.repeat(2048),
      '"'.repeat(2048),
      '<'.repeat(2048),
      'a@'.repeat(1024),
      ','.repeat(2048),
      '\\'.repeat(2048),
      'a '.repeat(1024),
      ':'.repeat(1024) + ';'.repeat(1024),
      'x'.repeat(10_000),
    ];
    for (const input of inputs) {
      const started = performance.now();
      const r = parseMailboxList(input);
      expect(performance.now() - started).toBeLessThan(200);
      expect(r.mailboxes.length).toBeLessThanOrEqual(20);
    }
    expect(parseMailboxList('x'.repeat(10_000)).truncated).toBe(true);
  });

  it('parses envelope addresses (null sender → null)', () => {
    expect(parseEnvelopeAddress('<bounce@Mailer.Example>')!.address).toBe('bounce@mailer.example');
    expect(parseEnvelopeAddress('<>')).toBeNull();
    expect(parseEnvelopeAddress('')).toBeNull();
    expect(parseEnvelopeAddress('garbage')!.flags).toEqual(['parse_error']);
  });
});

describe('normalizeName / matchName', () => {
  const profile = normalizeName('Anita Sharma');

  it('is case, punctuation and order insensitive (token set)', () => {
    expect(matchName(normalizeName('ANITA SHARMA'), profile)).toBe('exact');
    expect(matchName(normalizeName('Sharma, Anita'), profile)).toBe('token_set');
    expect(matchName(normalizeName('Anita Sharma (CEO)'), profile)).toBe('token_set');
    expect(matchName(normalizeName('Anita Kapoor'), profile)).toBeNull();
  });

  it('matches Cyrillic / Greek confusables through skeletons', () => {
    expect(matchName(normalizeName('Аnita Sharma'), profile)).toBe('confusable'); // Cyrillic А
    expect(matchName(normalizeName('Anita Shαrma'), profile)).toBe('confusable'); // Greek α
  });

  it('records invisible characters and mixed script', () => {
    const n = normalizeName('Anita​ Sharma');
    expect(n.invisibleChars).toBe(true);
    expect(matchName(n, profile)).toBe('exact');
    expect(normalizeName('Аnita').mixedScript).toBe(true);
    expect(normalizeName('Anita').mixedScript).toBe(false);
  });

  it('requires exact matches of at least 4 characters for single-token names', () => {
    expect(matchName(normalizeName('Globex'), normalizeName('Globex'))).toBe('exact');
    expect(matchName(normalizeName('Globex Billing'), normalizeName('Globex'))).toBeNull();
    expect(matchName(normalizeName('Raj'), normalizeName('Raj'))).toBeNull();
  });

  it('takes the best match over aliases', () => {
    const names = ['Rajesh Iyer', 'R Iyer'].map(normalizeName);
    expect(matchProfileNames(normalizeName('Rajesh Iyer'), names)).toBe('exact');
    expect(matchProfileNames(normalizeName('Iyer R'), names)).toBe('token_set');
  });
});

const row = (over: Partial<AuthResultRow> = {}): AuthResultRow => ({
  spf: 'none',
  spfDomain: null,
  dkim: 'none',
  dkimSignatures: [],
  dmarc: 'none',
  dmarcPolicy: null,
  dmarcDomain: null,
  arc: null,
  ...over,
});

describe('computeAlignment', () => {
  it('DKIM relaxed alignment on the registrable domain', () => {
    const a = computeAlignment(
      row({ dkim: 'pass', dkimSignatures: [{ domain: 'mail.example.com', result: 'pass' }] }),
      'news.example.com',
      null,
    );
    expect(a).toMatchObject({
      dkimAligned: true,
      authenticatedAsFrom: true,
      dkimAlignedDomain: 'example.com',
    });
    expect(
      computeAlignment(
        row({ dkimSignatures: [{ domain: 'esp.example', result: 'pass' }] }),
        'example.com',
        null,
      ).dkimAligned,
    ).toBe(false);
    expect(
      computeAlignment(
        row({ dkimSignatures: [{ domain: 'example.com', result: 'fail' }] }),
        'example.com',
        null,
      ).dkimAligned,
    ).toBe(false);
  });

  it('SPF alignment via spf_domain, else the envelope domain', () => {
    expect(
      computeAlignment(row({ spf: 'pass', spfDomain: 'example.com' }), 'example.com', null)
        .spfAligned,
    ).toBe(true);
    expect(
      computeAlignment(row({ spf: 'pass' }), 'example.com', 'bounce.example.com').spfAligned,
    ).toBe(true);
    expect(
      computeAlignment(row({ spf: 'pass', spfDomain: 'esp.example' }), 'example.com', null),
    ).toMatchObject({
      spfAligned: false,
      spfPassDomain: 'esp.example',
    });
    expect(
      computeAlignment(row({ spf: 'softfail', spfDomain: 'example.com' }), 'example.com', null)
        .spfAligned,
    ).toBe(false);
  });

  it('DMARC pass authenticates; no row authenticates nothing', () => {
    expect(computeAlignment(row({ dmarc: 'pass' }), 'example.com', null).authenticatedAsFrom).toBe(
      true,
    );
    expect(computeAlignment(null, 'example.com', null).authenticatedAsFrom).toBe(false);
  });
});

describe('free-mail list', () => {
  const list = loadFreemail();
  it('has about 120+ registrable domains and a version', () => {
    expect(list.domains.size).toBeGreaterThanOrEqual(120);
    expect(list.version).toMatch(/^[0-9a-f]{8}$/);
    expect(isFreemailDomain('gmail.com', list)).toBe(true);
    expect(isFreemailDomain('mail.yahoo.co.in', list)).toBe(true);
    expect(isFreemailDomain('example.com', list)).toBe(false);
    expect(isFreemailDomain('example.com', list, new Set(['example.com']))).toBe(true);
  });
  it('refuses non-registrable entries', () => {
    expect(() => loadFreemail('co.uk\n')).toThrow(/not a registrable domain/);
  });
});

describe('lookalike attribution', () => {
  const set = new BecProtectedSet({
    brands: loadBrands(),
    tenantDomains: ['acmecorp.test'],
    vendorDomains: [{ vendorId: 'v-1', domains: ['globexsupplies.test'] }],
    extraDomains: ['examplebank.test'],
  });
  it('attributes vendor, tenant, brand and extra findings', () => {
    const vendor = detectDomainLookalike('globexsuppiles.test', 'globexsuppiles.test', set);
    expect(vendor.findings[0]).toMatchObject({
      attributedKind: 'vendor',
      vendorId: 'v-1',
      rule: 'L2',
    });
    const tenant = detectDomainLookalike('acmec0rp.test', 'acmec0rp.test', set);
    expect(tenant.findings[0]).toMatchObject({
      attributedKind: 'tenant',
      rule: 'L1',
      highConfidence: true,
    });
    const extra = detectDomainLookalike('examp1ebank.test', 'examp1ebank.test', set);
    expect(extra.findings[0]).toMatchObject({ attributedKind: 'extra', vendorId: null });
    const brand = detectDomainLookalike(
      'paypal-secure-login.test',
      'paypal-secure-login.test',
      set,
    );
    expect(brand.findings.some((f) => f.attributedKind === 'brand' && f.rule === 'L3')).toBe(true);
    expect(detectDomainLookalike('acmecorp.test', 'acmecorp.test', set).findings).toEqual([]);
    expect(detectDomainLookalike(null, null, set).findings).toEqual([]);
  });
});

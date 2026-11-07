import { describe, expect, it } from 'vitest';
import type { AuthResultRow } from '../identity/alignment';
import { loadBecStaticData } from '../static-data';
import {
  AI_FEATURE_NAMES,
  AI_INDICATORS,
  BEC_MAPPER_CODES,
  BEC_RULE_BY_ID,
  BEC_RULE_IDS,
  BEC_RULES,
  BEC_SUPPRESSIBLE_CODES,
  type BecRuleId,
} from './codes';
import { BEC_DEFAULT_RULE_SETTINGS } from './defaults';
import { evaluateBecRules } from './evaluate';
import type { BecEvaluationInput, BecRuleSettings, BecTenantData, HistorySnapshot } from './types';

const data = loadBecStaticData();
const NOW = new Date('2026-11-03T00:00:00Z');
const RECEIVED = new Date('2026-11-02T09:15:00.000Z');

const pass = (d: string): AuthResultRow => ({
  spf: 'pass',
  spfDomain: d,
  dkim: 'pass',
  dkimSignatures: [{ domain: d, result: 'pass', selector: 's1' }],
  dmarc: 'pass',
  dmarcPolicy: 'reject',
  dmarcDomain: d,
  arc: null,
});
const noAuth = (d: string): AuthResultRow => ({
  spf: 'none',
  spfDomain: null,
  dkim: 'none',
  dkimSignatures: [],
  dmarc: 'none',
  dmarcPolicy: null,
  dmarcDomain: d,
  arc: null,
});

const tenant = (over: Partial<BecTenantData> = {}): BecTenantData => ({
  tenantDomains: ['acmecorp.test'],
  executives: [
    {
      publicId: 'exec-1',
      name: 'Anita Sharma',
      aliases: ['A Sharma CEO'],
      knownAddresses: ['anita.sharma@acmecorp.test'],
    },
  ],
  vendors: [
    {
      publicId: 'vendor-1',
      name: 'Globex Supplies',
      aliases: ['Globex'],
      domains: ['globexsupplies.test'],
      knownSenders: ['billing@globexsupplies.test'],
      paymentChangeSensitive: true,
    },
  ],
  trustedSenders: [],
  suppressions: [],
  freemailExtraDomains: [],
  extraProtectedDomains: [],
  ...over,
});

interface Over {
  from?: string | string[] | null;
  headers?: Record<string, string[]>;
  envelopeFrom?: string | null;
  auth?: BecEvaluationInput['auth'] | AuthResultRow;
  url?: BecEvaluationInput['url'];
  text?: string;
  subject?: string;
  html?: string;
  tenant?: Partial<BecTenantData>;
  history?: BecEvaluationInput['history'];
  direction?: 'inbound' | 'outbound' | 'internal';
  parseIncomplete?: boolean;
  headersIncomplete?: boolean;
  settings?: Partial<BecRuleSettings>;
  clientIp?: string;
}

function run(over: Over = {}) {
  const from = over.from === undefined ? ['John Miller <john.miller@partnerco.test>'] : over.from;
  const headers: Record<string, string[]> = {
    ...(from === null ? {} : { From: Array.isArray(from) ? from : [from] }),
    ...over.headers,
  };
  const auth =
    over.auth === undefined
      ? { state: 'available' as const, row: pass('partnerco.test') }
      : 'state' in over.auth
        ? over.auth
        : { state: 'available' as const, row: over.auth };
  const input: BecEvaluationInput = {
    headers,
    envelope: {
      direction: over.direction ?? 'inbound',
      envelopeFrom:
        over.envelopeFrom === undefined ? 'john.miller@partnerco.test' : over.envelopeFrom,
      recipients: ['finance@acmecorp.test'],
      clientIp: over.clientIp ?? '198.51.100.23',
      receivedAt: RECEIVED,
    },
    auth,
    url: over.url ?? { state: 'available', rows: [] },
    text: {
      subject: over.subject ?? 'Hello',
      textBody: { content: over.text ?? 'See you at the meeting on Thursday.', truncated: false },
      htmlBody: over.html === undefined ? null : { content: over.html, truncated: false },
      parseIncomplete: over.parseIncomplete ?? false,
    },
    tenant: tenant(over.tenant),
    history: over.history ?? 'disabled',
    ...(over.headersIncomplete === undefined ? {} : { headersIncomplete: over.headersIncomplete }),
  };
  return evaluateBecRules(input, { ...BEC_DEFAULT_RULE_SETTINGS, ...over.settings }, data, {
    now: NOW,
  });
}

const ids = (r: ReturnType<typeof run>) =>
  r.firedRules.filter((x) => x.suppressed === null).map((x) => x.id);
const fires = (id: BecRuleId, over: Over) =>
  expect(ids(run(over)), `${id} should fire`).toContain(id);
const silent = (id: BecRuleId, over: Over) =>
  expect(ids(run(over)), `${id} should not fire`).not.toContain(id);

describe('baseline', () => {
  it('an authenticated external sender with neutral text is clean (C0)', () => {
    const r = run();
    expect(r.firedRules).toEqual([]);
    expect(r).toMatchObject({
      verdict: 'clean',
      score: 0,
      codes: ['clean.below_threshold'],
      rulesVersion: 'bec-map/1',
    });
    expect(Object.keys(r.features)).toEqual(AI_FEATURE_NAMES);
  });
});

describe('identity rules', () => {
  it('P1: envelope domain differs and From not DKIM-aligned', () => {
    fires('P1', {
      envelopeFrom: 'b@esp.test',
      auth: { ...noAuth('partnerco.test'), spf: 'pass', spfDomain: 'esp.test' },
    });
    silent('P1', { envelopeFrom: 'b@esp.test' }); // DKIM-aligned (bulk sender)
    silent('P1', { envelopeFrom: null, auth: noAuth('partnerco.test') });
    silent('P1', { envelopeFrom: 'b@mail.partnerco.test', auth: noAuth('partnerco.test') });
  });
  it('P2: a Return-Path header differing from the envelope sender', () => {
    fires('P2', { headers: { 'Return-Path': ['<x@evil.test>'] } });
    silent('P2', { headers: { 'Return-Path': ['<John.Miller@partnerco.test>'] } });
    silent('P2', {});
    fires('P2', { headers: { 'Return-Path': ['<>'] } });
    silent('P2', { headers: { 'Return-Path': ['<>'] }, envelopeFrom: null });
  });
  it('I1: missing, unparseable, multiple From', () => {
    fires('I1', { from: null });
    fires('I1', { from: 'not an address' });
    fires('I1', { from: 'a@partnerco.test, b@partnerco.test' });
    fires('I1', { from: ['a@partnerco.test', 'b@partnerco.test'] });
    silent('I1', {});
  });
  it('I2: Sender header on another registrable domain', () => {
    fires('I2', { headers: { Sender: ['agent@other.test'] } });
    silent('I2', { headers: { Sender: ['agent@mail.partnerco.test'] } });
  });
  it('I3: auth available and not authenticated as From; never without the auth row', () => {
    fires('I3', { auth: noAuth('partnerco.test') });
    silent('I3', {});
    silent('I3', { auth: { state: 'failed' } });
  });
  it('D1: an address or known-suffix domain in the display name', () => {
    fires('D1', { from: '"ceo@acmecorp.test" <x@partnerco.test>' });
    fires('D1', { from: '"PayPal.com Support" <x@partnerco.test>' });
    silent('D1', { from: '"john.miller@partnerco.test" <john.miller@partnerco.test>' });
    silent('D1', { from: '"J.Miller" <john.miller@partnerco.test>' }); // no known public suffix
    silent('D1', { from: '"partnerco.test team" <john.miller@partnerco.test>' });
  });
  it('D2: brand or tenant label in the display name from a non-official domain', () => {
    fires('D2', { from: 'Microsoft Security <alerts@partnerco.test>' });
    fires('D2', { from: 'Acmecorp IT <it@partnerco.test>' });
    silent('D2', {
      from: 'Microsoft <noreply@microsoft.com>',
      auth: pass('microsoft.com'),
      envelopeFrom: null,
    });
    silent('D2', { from: 'Microsofty Fans <a@partnerco.test>' });
  });
  it('D3: invisible characters or mixed script in the display name', () => {
    fires('D3', { from: '"John​ Miller" <john.miller@partnerco.test>' });
    fires('D3', { from: '"Jоhn Miller" <john.miller@partnerco.test>' }); // Cyrillic о
    silent('D3', {});
  });
  it('R1: Reply-To on another, non-tenant, non-vendor domain', () => {
    fires('R1', { headers: { 'Reply-To': ['x@other.test'] } });
    silent('R1', { headers: { 'Reply-To': ['x@acmecorp.test'] } });
    silent('R1', { headers: { 'Reply-To': ['x@sub.partnerco.test'] } });
    silent('R1', {
      from: 'Globex <billing@globexsupplies.test>',
      envelopeFrom: 'billing@globexsupplies.test',
      auth: pass('globexsupplies.test'),
      tenant: {
        vendors: [
          {
            publicId: 'v',
            name: 'Globex Supplies',
            aliases: [],
            domains: ['globexsupplies.test', 'globex-billing.test'],
            knownSenders: [],
            paymentChangeSensitive: true,
          },
        ],
      },
      headers: { 'Reply-To': ['ar@globex-billing.test'] },
    });
  });
  it('R2: Reply-To on free-mail while From is not free-mail', () => {
    fires('R2', { headers: { 'Reply-To': ['x@gmail.com'] } });
    silent('R2', {
      from: 'a@gmail.com',
      envelopeFrom: 'a@gmail.com',
      auth: pass('gmail.com'),
      headers: { 'Reply-To': ['b@gmail.com'] },
    });
    fires('R2', {
      tenant: { freemailExtraDomains: ['mailbox.test'] },
      headers: { 'Reply-To': ['x@mailbox.test'] },
    });
  });
  it('R3: Reply-To high-confidence lookalike of a tenant / vendor / brand domain', () => {
    fires('R3', { headers: { 'Reply-To': ['x@acmec0rp.test'] } });
    fires('R3', { headers: { 'Reply-To': ['x@globexsuppiles.test'] } });
    fires('R3', { headers: { 'Reply-To': ['x@acmecorp.example'] } }); // L5 of a tenant domain
    silent('R3', { headers: { 'Reply-To': ['x@other.test'] } });
  });
});

describe('authentication rules', () => {
  it('A1 dmarc fail, A2 spf fail, A3 dkim fail, A4 none, A5 temperror', () => {
    fires('A1', { auth: { ...noAuth('partnerco.test'), dmarc: 'fail' } });
    silent('A1', { auth: { ...pass('partnerco.test') } });
    fires('A2', { auth: { ...pass('partnerco.test'), spf: 'fail' } });
    silent('A2', { auth: { ...pass('partnerco.test'), spf: 'softfail' } });
    fires('A3', { auth: { ...pass('partnerco.test'), dkim: 'fail' } });
    fires('A3', {
      auth: {
        ...noAuth('partnerco.test'),
        dkimSignatures: [{ domain: 'partnerco.test', result: 'fail' }],
      },
    });
    silent('A3', {
      auth: {
        ...noAuth('partnerco.test'),
        dkimSignatures: [{ domain: 'other.test', result: 'fail' }],
      },
    });
    fires('A4', { auth: noAuth('partnerco.test') });
    silent('A4', { auth: { ...noAuth('partnerco.test'), spf: 'pass' } });
    silent('A4', { auth: { ...noAuth('partnerco.test'), dmarc: 'fail' } });
    fires('A5', { auth: { ...pass('partnerco.test'), spf: 'temperror' } });
    fires('A5', { auth: { ...pass('partnerco.test'), dmarc: 'permerror' } });
    silent('A5', {});
  });
  it('A6: the tenant domain in From without authentication', () => {
    fires('A6', {
      from: 'ceo@acmecorp.test',
      envelopeFrom: 'ceo@acmecorp.test',
      auth: noAuth('acmecorp.test'),
    });
    silent('A6', {
      from: 'ceo@acmecorp.test',
      envelopeFrom: 'ceo@acmecorp.test',
      auth: pass('acmecorp.test'),
    });
    silent('A6', {
      from: 'ceo@acmecorp.test',
      envelopeFrom: 'ceo@acmecorp.test',
      auth: { state: 'missing' },
    });
  });
});

describe('lookalike rules', () => {
  it('L1 tenant, L2 vendor (From or envelope), L3 brand, L4 mixed script', () => {
    fires('L1', {
      from: 'it@acmec0rp.test',
      envelopeFrom: 'it@acmec0rp.test',
      auth: pass('acmec0rp.test'),
    });
    fires('L1', { envelopeFrom: 'b@acmec0rp.test' });
    silent('L1', {});
    fires('L2', {
      from: 'ar@globexsuppiles.test',
      envelopeFrom: 'ar@globexsuppiles.test',
      auth: pass('globexsuppiles.test'),
    });
    silent('L2', {
      from: 'ar@globexsupplies.test',
      envelopeFrom: 'ar@globexsupplies.test',
      auth: pass('globexsupplies.test'),
    });
    fires('L3', {
      from: 'x@paypal-secure.test',
      envelopeFrom: 'x@paypal-secure.test',
      auth: pass('paypal-secure.test'),
    });
    silent('L3', { from: 'x@paypal.co', envelopeFrom: 'x@paypal.co', auth: pass('paypal.co') }); // L5 brand: informational
    fires('L4', {
      from: 'x@xn--pypal-4ve.com',
      envelopeFrom: null,
      auth: noAuth('xn--pypal-4ve.com'),
    });
    silent('L4', {});
  });
});

describe('impersonation rules', () => {
  const exec = 'Anita Sharma';
  it('X1: executive name from an unknown address, or known but unauthenticated', () => {
    fires('X1', { from: `${exec} <anita@partnerco.test>` });
    fires('X1', {
      from: `${exec} <anita.sharma@acmecorp.test>`,
      envelopeFrom: 'anita.sharma@acmecorp.test',
      auth: noAuth('acmecorp.test'),
    });
    silent('X1', {
      from: `${exec} <anita.sharma@acmecorp.test>`,
      envelopeFrom: 'anita.sharma@acmecorp.test',
      auth: pass('acmecorp.test'),
    });
    silent('X1', { from: 'Anita Kapoor <anita@partnerco.test>' });
  });
  it('X2: X1 from free-mail', () => {
    fires('X2', {
      from: `${exec} <a.s@gmail.com>`,
      envelopeFrom: 'a.s@gmail.com',
      auth: pass('gmail.com'),
    });
    silent('X2', { from: `${exec} <anita@partnerco.test>` });
  });
  it('X3: executive name with an external or free-mail Reply-To', () => {
    fires('X3', {
      from: `${exec} <anita.sharma@acmecorp.test>`,
      envelopeFrom: 'anita.sharma@acmecorp.test',
      auth: pass('acmecorp.test'),
      headers: { 'Reply-To': ['anita.private@gmail.com'] },
    });
    silent('X3', {
      from: `${exec} <anita.sharma@acmecorp.test>`,
      envelopeFrom: 'anita.sharma@acmecorp.test',
      auth: pass('acmecorp.test'),
      headers: { 'Reply-To': ['assistant@acmecorp.test'] },
    });
  });
  it('V1: vendor name from a non-vendor domain', () => {
    fires('V1', { from: 'Globex Supplies <ar@partnerco.test>' });
    silent('V1', {
      from: 'Globex Supplies <billing@globexsupplies.test>',
      envelopeFrom: 'billing@globexsupplies.test',
      auth: pass('globexsupplies.test'),
    });
  });
  it('V2: vendor domain without authentication', () => {
    fires('V2', {
      from: 'billing@globexsupplies.test',
      envelopeFrom: 'billing@globexsupplies.test',
      auth: noAuth('globexsupplies.test'),
    });
    silent('V2', {
      from: 'billing@globexsupplies.test',
      envelopeFrom: 'billing@globexsupplies.test',
      auth: pass('globexsupplies.test'),
    });
  });
  it('V3: vendor domain, known senders listed, unknown sender', () => {
    fires('V3', {
      from: 'someone@globexsupplies.test',
      envelopeFrom: 'someone@globexsupplies.test',
      auth: pass('globexsupplies.test'),
    });
    silent('V3', {
      from: 'Billing@Globexsupplies.test',
      envelopeFrom: 'billing@globexsupplies.test',
      auth: pass('globexsupplies.test'),
    });
  });
  it('V4: matched payment-sensitive vendor and C2 or C5', () => {
    const vendorMail = {
      from: 'billing@globexsupplies.test',
      envelopeFrom: 'billing@globexsupplies.test',
      auth: pass('globexsupplies.test'),
    };
    fires('V4', { ...vendorMail, text: 'Please note our new bank details.' });
    fires('V4', {
      from: 'ar@globexsuppiles.test',
      envelopeFrom: 'ar@globexsuppiles.test',
      auth: pass('globexsuppiles.test'),
      text: 'updated invoice attached',
    });
    fires('V4', {
      from: 'Globex Supplies <ar@gmail.com>',
      envelopeFrom: 'ar@gmail.com',
      auth: pass('gmail.com'),
      text: 'new bank details',
    });
    silent('V4', { ...vendorMail, text: 'Order confirmed.' });
    silent('V4', {
      ...vendorMail,
      text: 'new bank details',
      tenant: {
        vendors: [
          {
            publicId: 'v',
            name: 'Globex Supplies',
            aliases: [],
            domains: ['globexsupplies.test'],
            knownSenders: [],
            paymentChangeSensitive: false,
          },
        ],
      },
    });
    silent('V4', { text: 'new bank details' }); // no vendor matched
  });
});

describe('content rules', () => {
  const cases: Array<[BecRuleId, string]> = [
    ['C1', 'Please make the payment.'],
    ['C2', 'We have new bank details.'],
    ['C3', 'Buy gift cards please.'],
    ['C4', 'Process the transfer via NEFT.'],
    ['C5', 'Here is the updated invoice.'],
    ['C6', 'Change my direct deposit please.'],
    ['C7', 'This is urgent.'],
    ['C8', 'Keep this confidential.'],
    ['C9', 'Verify your account now.'],
  ];
  it.each(cases)('%s fires on its lexicon category and not on neutral text', (id, text) => {
    fires(id, { text });
    silent(id, {});
  });
  it('C10: financial identifiers (counts only)', () => {
    const r = run({ text: 'IBAN DE89 3704 0044 0532 0130 00, amount €2,500' });
    const c10 = r.firedRules.find((x) => x.id === 'C10')!;
    expect(c10.evidence[0]!.patterns).toMatchObject({ iban: 1, amount: 1 });
    silent('C10', { text: 'Meeting at 10 in room 4.' });
  });
  it('keyword evidence holds lexicon ids and source spans, never text', () => {
    const r = run({ text: 'Please keep this confidential.' });
    const ev = r.firedRules.find((x) => x.id === 'C8')!.evidence[0]!;
    expect(ev.keywords).toMatchObject({ category: 'secrecy', language: 'en' });
    expect(ev.keywords!.spans).toContainEqual({ source: 'text', start: 7, end: 29 }); // "keep this confidential"
    expect(ev.keywords!.lexiconIds.every((id) => /^en\.secrecy\.\d{3}$/.test(id))).toBe(true);
    expect(JSON.stringify(r.firedRules)).not.toContain('confidential');
  });
  it('authority is informational (feature only)', () => {
    const r = run({ text: 'Message from the CEO.' });
    expect(r.firedRules).toEqual([]);
    expect(r.features.lex_authority).toBeGreaterThan(0);
  });
});

describe('link rules', () => {
  const urls = (
    rows: Array<{
      verdict: 'clean' | 'unknown' | 'suspicious' | 'malicious';
      reasonCodes: string[];
    }>,
  ) => ({
    state: 'available' as const,
    rows: rows.map((r, i) => ({ urlSeq: i + 1, ...r })),
  });
  it('K1: phishing high confidence / dynamic phishing / credential form + lookalike', () => {
    fires('K1', {
      url: urls([{ verdict: 'malicious', reasonCodes: ['url.phishing_high_confidence'] }]),
    });
    fires('K1', { url: urls([{ verdict: 'malicious', reasonCodes: ['url.dynamic_phishing'] }]) });
    fires('K1', {
      url: urls([
        { verdict: 'suspicious', reasonCodes: ['url.credential_form', 'url.lookalike_homoglyph'] },
      ]),
    });
    silent('K1', { url: urls([{ verdict: 'suspicious', reasonCodes: ['url.credential_form'] }]) });
  });
  it('K2: credential form without K1', () => {
    fires('K2', {
      url: urls([{ verdict: 'suspicious', reasonCodes: ['url.credential_form_cross_origin'] }]),
    });
    silent('K2', {
      url: urls([
        {
          verdict: 'malicious',
          reasonCodes: ['url.phishing_high_confidence', 'url.credential_form'],
        },
      ]),
    });
  });
  it('K3: lookalike / mixed-script URL codes', () => {
    fires('K3', { url: urls([{ verdict: 'suspicious', reasonCodes: ['url.mixed_script'] }]) });
    fires('K3', {
      url: urls([{ verdict: 'suspicious', reasonCodes: ['url.lookalike_tld_swap'] }]),
    });
    silent('K3', { url: urls([{ verdict: 'clean', reasonCodes: ['clean.no_findings'] }]) });
  });
  it('K4: malicious URL verdict without K1', () => {
    fires('K4', { url: urls([{ verdict: 'malicious', reasonCodes: ['url.feed_malicious'] }]) });
    silent('K4', {
      url: urls([{ verdict: 'malicious', reasonCodes: ['url.phishing_high_confidence'] }]),
    });
  });
  it('evidence lists url_seq values (≤ 5)', () => {
    const r = run({
      url: urls(
        Array.from({ length: 8 }, () => ({
          verdict: 'malicious' as const,
          reasonCodes: ['url.feed_malicious'],
        })),
      ),
    });
    expect(r.firedRules.find((x) => x.id === 'K4')!.evidence[0]!.urls).toEqual([1, 2, 3, 4, 5]);
  });
});

describe('history rules', () => {
  const day = 86_400_000;
  const row = (
    count: number,
    firstDaysAgo: number,
    infra: Array<{ fp: string; count: number }> = [],
  ) => ({
    messageCount: count,
    firstSeenAt: new Date(RECEIVED.getTime() - firstDaysAgo * day),
    lastSeenAt: new Date(RECEIVED.getTime() - day),
    infra: infra.map((i) => ({ ...i, lastSeenAt: new Date(RECEIVED.getTime() - day) })),
  });
  const snapshot = (over: Partial<HistorySnapshot> = {}): HistorySnapshot => ({
    sender: row(5, 30, [{ fp: 'fp-known', count: 5 }]),
    pairs: [row(3, 30)],
    fingerprintHash: 'fp-known',
    ...over,
  });
  it('H1: never seen, or first seen at this message (rescans see the same history)', () => {
    fires('H1', { history: snapshot({ sender: null }) });
    fires('H1', {
      history: snapshot({ sender: { ...row(1, 0), firstSeenAt: RECEIVED, lastSeenAt: RECEIVED } }),
    });
    silent('H1', { history: snapshot() });
    silent('H1', { history: 'disabled' });
  });
  it('H2: H1 and a lookalike (L1/L2/R3)', () => {
    fires('H2', {
      history: snapshot({ sender: null }),
      from: 'it@acmec0rp.test',
      envelopeFrom: 'it@acmec0rp.test',
      auth: pass('acmec0rp.test'),
    });
    silent('H2', { history: snapshot({ sender: null }) });
  });
  it('H3: a reply without any pair history', () => {
    const reply = { headers: { 'In-Reply-To': ['<a@b>'] } };
    fires('H3', { ...reply, history: snapshot({ pairs: [null] }) });
    fires('H3', {
      ...reply,
      history: snapshot({ pairs: [{ ...row(1, 0), firstSeenAt: RECEIVED }] }),
    });
    silent('H3', { ...reply, history: snapshot() });
    silent('H3', { history: snapshot({ pairs: [null] }) });
  });
  it('H4: an established sender (≥ 3 earlier messages) from new infrastructure', () => {
    fires('H4', { history: snapshot({ fingerprintHash: 'fp-new' }) });
    silent('H4', { history: snapshot() });
    silent('H4', {
      history: snapshot({
        sender: row(2, 30, [{ fp: 'fp-known', count: 2 }]),
        fingerprintHash: 'fp-new',
      }),
    });
    silent('H4', { history: snapshot({ fingerprintHash: null }) });
  });
  it('H5: H1 and a payment cue (C1–C6)', () => {
    fires('H5', { history: snapshot({ sender: null }), text: 'please make the payment' });
    silent('H5', { history: snapshot({ sender: null }), text: 'urgent' });
  });
  it('history evidence buckets prior messages, never hashes', () => {
    const r = run({ history: snapshot({ fingerprintHash: 'fp-new' }) });
    expect(r.firedRules.find((x) => x.id === 'H4')!.evidence[0]!.history).toEqual({
      firstContact: false,
      priorMessages: '3-9',
    });
    expect(JSON.stringify(r)).not.toContain('fp-new');
  });
});

describe('engine rules E0/E1/C0 and verdicts', () => {
  it('E0: not inbound → skipped / bec.not_inbound', () => {
    const r = run({ direction: 'outbound', text: 'buy gift cards' });
    expect(r).toMatchObject({ verdict: 'skipped', codes: ['bec.not_inbound'], firedRules: [] });
  });
  it('E1: unavailable inputs make the verdict at least unknown, never clean', () => {
    expect(run({ auth: { state: 'not_in_round' } })).toMatchObject({
      verdict: 'unknown',
      codes: ['bec.input_unavailable.auth'],
    });
    expect(run({ url: { state: 'failed' } })).toMatchObject({
      verdict: 'unknown',
      codes: ['bec.input_unavailable.url'],
    });
    expect(run({ parseIncomplete: true })).toMatchObject({
      verdict: 'unknown',
      codes: ['bec.content_incomplete'],
    });
    // §2.0 invariant 1: a Reply-To after the stored header cap was never examined.
    expect(run({ headersIncomplete: true })).toMatchObject({
      verdict: 'unknown',
      codes: ['bec.content_incomplete'],
    });
    expect(run({ headersIncomplete: false }).verdict).toBe('clean');
    expect(run({ headersIncomplete: true, parseIncomplete: true }).codes).toEqual([
      'bec.content_incomplete',
    ]);
    expect(run({ history: 'error' })).toMatchObject({
      verdict: 'unknown',
      codes: ['bec.history_unavailable'],
    });
    expect(run({ history: 'disabled' }).verdict).toBe('clean');
    const both = run({ auth: { state: 'failed' }, url: { state: 'not_in_round' } });
    expect(both.codes).toEqual(['bec.input_unavailable.auth', 'bec.input_unavailable.url']);
  });
  it('E1 does not lower a suspicious verdict', () => {
    expect(
      run({ auth: { state: 'failed' }, from: 'Anita Sharma <a@partnerco.test>' }).verdict,
    ).toBe('suspicious');
  });
  it('threshold boundaries (suspicious at 40, malicious at 80 with identity + intent)', () => {
    // R1 15 + R2 20 = 35 → clean; + C7 10 = 45 → suspicious
    expect(run({ headers: { 'Reply-To': ['x@gmail.com'] } }).score).toBe(35);
    expect(run({ headers: { 'Reply-To': ['x@gmail.com'] } }).verdict).toBe('clean');
    expect(
      run({ headers: { 'Reply-To': ['x@gmail.com'] }, settings: { suspiciousScore: 35 } }).verdict,
    ).toBe('suspicious');
    const r = run({ headers: { 'Reply-To': ['x@gmail.com'] }, text: 'urgent' });
    expect(r).toMatchObject({ score: 45, verdict: 'suspicious' });
  });
  it('malicious requires identity and intent evidence', () => {
    const noIntent = run({
      from: 'Anita Sharma <a.s@gmail.com>',
      envelopeFrom: 'a.s@gmail.com',
      auth: noAuth('gmail.com'),
      headers: { 'Reply-To': ['x@other.test'] },
      text: 'urgent, keep this confidential',
    });
    expect(noIntent.score).toBeGreaterThanOrEqual(80);
    expect(noIntent).toMatchObject({
      identityEvidence: true,
      intentEvidence: false,
      verdict: 'suspicious',
    });
    const withIntent = run({
      from: 'Anita Sharma <a.s@gmail.com>',
      envelopeFrom: 'a.s@gmail.com',
      auth: pass('gmail.com'),
      text: 'buy gift cards, keep this confidential, urgent',
    });
    expect(withIntent).toMatchObject({
      verdict: 'malicious',
      identityEvidence: true,
      intentEvidence: true,
    });
    const noIdentity = run({
      text: 'buy gift cards, update my direct deposit, new bank details, make the payment',
      url: {
        state: 'available',
        rows: [{ urlSeq: 1, verdict: 'malicious', reasonCodes: ['url.feed_malicious'] }],
      },
      auth: noAuth('partnerco.test'),
      headers: { 'Reply-To': ['x@gmail.com'], Sender: ['s@x.test'] },
    });
    expect(noIdentity.score).toBeGreaterThanOrEqual(80);
    expect(noIdentity).toMatchObject({ identityEvidence: false, verdict: 'suspicious' });
  });
  it('category caps: intent 50, history 30, identity 40; total ≤ 100', () => {
    const intent = run({
      text: 'buy gift cards, update my direct deposit, new bank details, make the payment, urgent',
    });
    expect(intent.score).toBe(50);
    const identity = run({
      from: '"ceo@x.test ​" <a@partnerco.test>',
      auth: noAuth('partnerco.test'),
      envelopeFrom: 'b@esp.test',
      headers: { 'Reply-To': ['x@gmail.com'], Sender: ['s@y.test'], 'Return-Path': ['<z@q.test>'] },
    });
    const identitySum = identity.firedRules
      .filter((r) => r.category === 'identity')
      .reduce((s, r) => s + r.weight, 0);
    expect(identitySum).toBeGreaterThan(40);
    const authSum = identity.firedRules
      .filter((r) => r.category === 'auth')
      .reduce((s, r) => s + r.weight, 0);
    expect(identity.score).toBe(40 + authSum);
    const history = run({
      history: { sender: null, pairs: [null], fingerprintHash: null },
      headers: { 'In-Reply-To': ['<x@y>'] },
      text: 'make the payment',
      from: 'it@acmec0rp.test',
      envelopeFrom: 'it@acmec0rp.test',
      auth: pass('acmec0rp.test'),
    });
    const hist = history.firedRules
      .filter((r) => r.category === 'history')
      .reduce((s, r) => s + r.weight, 0);
    expect(hist).toBeGreaterThan(30);
    expect(history.score).toBe(Math.min(100, 30 + 40 + 15)); // history cap + L1 + C1
    const max = run({
      from: 'Anita Sharma <a.s@gmail.com>',
      envelopeFrom: 'a.s@gmail.com',
      auth: { ...noAuth('gmail.com'), dmarc: 'fail' },
      text: 'buy gift cards',
    });
    expect(max.score).toBe(100);
  });
  it('reason codes: severity desc, weight desc, code; engine codes last; ≤ 32', () => {
    const r = run({
      from: 'Anita Sharma <a.s@gmail.com>',
      envelopeFrom: 'a.s@gmail.com',
      auth: pass('gmail.com'),
      text: 'buy gift cards, urgent',
      url: { state: 'failed' },
    });
    expect(r.codes).toEqual([
      'bec.impersonation.executive_name',
      'bec.content.gift_card',
      'bec.impersonation.executive_freemail',
      'bec.content.urgency',
      'bec.input_unavailable.url',
    ]);
    expect(r.signals).toContainEqual({ name: 'bec:X1', score: 40, options: ['impersonation'] });
    const many = run({
      from: '"ceo@x.test ​ Microsoft" <a@acmec0rp.test>',
      envelopeFrom: 'b@globexsuppiles.test',
      auth: { ...noAuth('acmec0rp.test'), dmarc: 'fail', spf: 'fail', dkim: 'fail' },
      headers: {
        'Reply-To': ['x@gmail.com', 'y@acmec0rp.test'],
        Sender: ['s@y.test'],
        'Return-Path': ['<z@q.test>'],
        'In-Reply-To': ['<x@y>'],
      },
      text: 'buy gift cards, update my direct deposit, new bank details, make the payment, urgent, confidential, verify your account, updated invoice, wire transfer, IBAN DE89 3704 0044 0532 0130 00',
      url: {
        state: 'available',
        rows: [
          {
            urlSeq: 1,
            verdict: 'malicious',
            reasonCodes: ['url.phishing_high_confidence', 'url.lookalike_homoglyph'],
          },
        ],
      },
      history: { sender: null, pairs: [null], fingerprintHash: null },
    });
    expect(many.codes.length).toBeLessThanOrEqual(32);
    expect(many.verdict).toBe('malicious');
  });
});

describe('trusted senders (B7)', () => {
  const vendorMail = {
    from: 'Globex Supplies <billing@globexsupplies.test>',
    envelopeFrom: 'billing@globexsupplies.test',
    text: 'Reminder: overdue invoice, please make the payment. Urgent.',
    headers: { 'Reply-To': ['ar@other.test'] },
  };
  const trusted = {
    trustedSenders: [
      { publicId: 'ts-1', kind: 'domain' as const, value: 'globexsupplies.test', expiresAt: null },
    ],
  };

  it('T1 with authentication neutralizes only the listed categories', () => {
    const r = run({ ...vendorMail, auth: pass('globexsupplies.test'), tenant: trusted });
    const byId = new Map(r.firedRules.map((x) => [x.id, x]));
    expect(byId.get('T1')!.suppressed).toBeNull();
    for (const id of ['C1', 'C5', 'C7', 'V4', 'R1'] as const)
      expect(byId.get(id)!.suppressed).toBe('trust');
    expect(byId.get('T1')!.evidence[0]!.trusted).toEqual({ id: 'ts-1' });
    expect(byId.get('C5')!.suppressed).toBe('trust');
    expect(r.verdict).toBe('clean');
    expect(r.codes).toEqual(['bec.trusted_sender', 'clean.below_threshold']);
  });
  it('T1 never neutralizes A, L, R3, X or K rules', () => {
    const r = run({
      from: 'Anita Sharma <billing@globexsupplies.test>',
      envelopeFrom: 'billing@globexsupplies.test',
      auth: pass('globexsupplies.test'),
      tenant: trusted,
      headers: { 'Reply-To': ['x@acmec0rp.test'] },
      url: {
        state: 'available',
        rows: [
          {
            urlSeq: 1,
            verdict: 'malicious',
            reasonCodes: ['url.phishing_high_confidence', 'url.lookalike_homoglyph'],
          },
        ],
      },
    });
    for (const id of ['X1', 'R3', 'K1', 'K3'] as const) {
      expect(r.firedRules.find((x) => x.id === id)?.suppressed, id).toBeNull();
    }
    expect(r.verdict).not.toBe('clean');
    const auth = run({
      ...vendorMail,
      auth: { ...pass('globexsupplies.test'), spf: 'fail' },
      tenant: trusted,
    });
    expect(auth.firedRules.find((x) => x.id === 'A2')!.suppressed).toBeNull();
  });
  it('T2 without authentication: nothing is neutralized', () => {
    const r = run({ ...vendorMail, auth: noAuth('globexsupplies.test'), tenant: trusted });
    expect(r.firedRules.every((x) => x.suppressed === null)).toBe(true);
    expect(ids(r)).toContain('T2');
    expect(ids(r)).not.toContain('T1');
  });
  it('matches exact addresses and registrable-domain entries only; expired entries ignored', () => {
    const base = { ...vendorMail, auth: pass('globexsupplies.test') };
    expect(
      ids(
        run({
          ...base,
          tenant: {
            trustedSenders: [
              {
                publicId: 'a',
                kind: 'address',
                value: 'BILLING@globexsupplies.test',
                expiresAt: null,
              },
            ],
          },
        }),
      ),
    ).toContain('T1');
    expect(
      ids(
        run({
          ...base,
          tenant: {
            trustedSenders: [
              {
                publicId: 'a',
                kind: 'address',
                value: 'other@globexsupplies.test',
                expiresAt: null,
              },
            ],
          },
        }),
      ),
    ).not.toContain('T1');
    expect(
      ids(
        run({
          ...base,
          tenant: {
            trustedSenders: [
              { publicId: 'a', kind: 'domain', value: 'mail.globexsupplies.test', expiresAt: null },
            ],
          },
        }),
      ),
    ).not.toContain('T1');
    expect(
      ids(
        run({
          ...base,
          tenant: {
            trustedSenders: [
              {
                publicId: 'a',
                kind: 'domain',
                value: 'globexsupplies.test',
                expiresAt: new Date('2026-11-01T00:00:00Z'),
              },
            ],
          },
        }),
      ),
    ).not.toContain('T1');
  });
});

describe('feedback suppression (B11)', () => {
  const sup = (
    code: string,
    over: Partial<{
      senderScope: 'address' | 'domain';
      senderValue: string;
      expiresAt: Date;
      publicId: string;
    }> = {},
  ) => ({
    publicId: over.publicId ?? `s-${code}`,
    reasonCode: code,
    senderScope: over.senderScope ?? 'address',
    senderValue: over.senderValue ?? 'john.miller@partnerco.test',
    expiresAt: over.expiresAt ?? new Date('2026-12-01T00:00:00Z'),
  });
  const replyTo = { headers: { 'Reply-To': ['x@gmail.com'] } };

  it('suppresses only suppressible codes (S1 lists them)', () => {
    const r = run({
      ...replyTo,
      tenant: { suppressions: [sup('bec.reply_to.freemail'), sup('bec.reply_to.domain_mismatch')] },
    });
    expect(r.firedRules.find((x) => x.id === 'R2')!.suppressed).toBe('feedback');
    expect(r.firedRules.find((x) => x.id === 'R2')!.evidence.at(-1)).toEqual({
      suppression: { id: 's-bec.reply_to.freemail' },
    });
    expect(ids(r)).toContain('S1');
    expect(r.score).toBe(0);
    const s1 = r.firedRules.find((x) => x.id === 'S1')!;
    expect(s1.evidence.flatMap((e) => e.suppressedCodes)).toEqual([
      'bec.reply_to.freemail',
      'bec.reply_to.domain_mismatch',
    ]);
    const critical = run({
      from: 'Anita Sharma <a@partnerco.test>',
      tenant: { suppressions: [sup('bec.impersonation.executive_name')] },
    });
    expect(critical.firedRules.find((x) => x.id === 'X1')!.suppressed).toBeNull();
    expect(ids(critical)).not.toContain('S1');
  });
  it('honours expiry and scope; never a free-mail domain scope', () => {
    expect(
      ids(
        run({
          ...replyTo,
          tenant: {
            suppressions: [
              sup('bec.reply_to.freemail', { expiresAt: new Date('2026-11-01T00:00:00Z') }),
            ],
          },
        }),
      ),
    ).toContain('R2');
    expect(
      ids(
        run({
          ...replyTo,
          tenant: {
            suppressions: [sup('bec.reply_to.freemail', { senderValue: 'other@partnerco.test' })],
          },
        }),
      ),
    ).toContain('R2');
    expect(
      ids(
        run({
          ...replyTo,
          tenant: {
            suppressions: [
              sup('bec.reply_to.freemail', {
                senderScope: 'domain',
                senderValue: 'partnerco.test',
              }),
            ],
          },
        }),
      ),
    ).not.toContain('R2');
    const freemail = run({
      from: 'a@gmail.com',
      envelopeFrom: 'a@gmail.com',
      auth: pass('gmail.com'),
      text: 'urgent',
      tenant: {
        suppressions: [
          sup('bec.content.urgency', { senderScope: 'domain', senderValue: 'gmail.com' }),
        ],
      },
    });
    expect(ids(freemail)).toContain('C7');
  });
  it('caps the suppressed weight at 40 (weight desc, then code)', () => {
    // Candidates by weight desc, then code: R2 20, C8 15 (bec.content.secrecy < bec.reply_to.…),
    // R1 15, C7 10. 20 + 15 = 35; R1 (50) and C7 (45) would exceed 40 → not suppressed.
    const r = run({
      ...replyTo,
      text: 'urgent and confidential',
      tenant: {
        suppressions: [
          'bec.reply_to.freemail',
          'bec.reply_to.domain_mismatch',
          'bec.content.secrecy',
          'bec.content.urgency',
        ].map((c) => sup(c)),
      },
    });
    const suppressed = r.firedRules.filter((x) => x.suppressed === 'feedback').map((x) => x.id);
    expect(suppressed.sort()).toEqual(['C8', 'R2']);
    expect(
      r.firedRules.filter((x) => x.suppressed === 'feedback').reduce((s, x) => s + x.weight, 0),
    ).toBeLessThanOrEqual(40);
    const custom = run({
      ...replyTo,
      settings: { suppressionMaxWeight: 15 },
      tenant: { suppressions: [sup('bec.reply_to.freemail'), sup('bec.reply_to.domain_mismatch')] },
    });
    expect(custom.firedRules.filter((x) => x.suppressed === 'feedback').map((x) => x.id)).toEqual([
      'R1',
    ]);
  });
});

describe('shared lists', () => {
  it('rule ids, codes and weights are the B6 table', () => {
    expect(BEC_RULE_IDS).toHaveLength(50);
    expect(new Set(BEC_RULES.map((r) => r.code)).size).toBe(50);
    expect(BEC_RULE_BY_ID.get('A6')).toMatchObject({
      severity: 'critical',
      weight: 50,
      category: 'auth',
    });
    expect(BEC_MAPPER_CODES).toHaveLength(50 + 5 + 1 + 4);
    expect(BEC_MAPPER_CODES).toContain('clean.below_threshold');
    expect(BEC_SUPPRESSIBLE_CODES).toHaveLength(19);
    for (const code of BEC_SUPPRESSIBLE_CODES) expect(BEC_MAPPER_CODES).toContain(code);
    expect(AI_INDICATORS).toHaveLength(15);
    expect(AI_FEATURE_NAMES).toHaveLength(49 + 10 + 4 + 7);
    expect(new Set(AI_FEATURE_NAMES).size).toBe(AI_FEATURE_NAMES.length);
  });
  it('every emitted code is a mapper code', () => {
    const r = run({
      from: 'Anita Sharma <a.s@gmail.com>',
      envelopeFrom: 'a.s@gmail.com',
      auth: { state: 'failed' },
      text: 'buy gift cards',
    });
    for (const code of r.codes) expect(BEC_MAPPER_CODES).toContain(code);
  });
});

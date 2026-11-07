import {
  DLP_DETECTORS,
  DLP_DETECTOR_IDS,
  DLP_REASON_CODES,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { buildCorpus } from '../corpus';
import { detect, type DlpTextSegment } from '../detect';
import { DlpDictionarySet } from '../dictionaries';
import { NOW, platformSettings, runFixture } from '../test-support/pipeline.test-support';
import { gstinCheckChar, luhnCheckDigit, verhoeffCheckDigit } from '../validators';
import { aadhaarShape, hasExpiryNear, indianMobile } from './numbers';
import { calendarValid, codeIndicatorLine, parseNumericDate, td3Valid } from './structure';
import { apiTokenKind, jwtAlg } from './tokens';
import type { ScoredCandidate } from './types';

// Synthetic credentials, assembled at runtime so secret scanners (GitHub push protection) do not
// flag the source as holding real AWS keys.
const FAKE_AWS_KEY_ID = ['AKIA', 'QWERTYUIOPASDFGH'].join('');
const FAKE_AWS_SECRET = ['Ab3dEf/Gh1jKl+Mn0p', 'QrStUvWxYz12345678AbCd'].join('');

const dictionaries = DlpDictionarySet.create();

async function scan(
  text: string,
  options: {
    aadhaar?: boolean;
    kind?: DlpTextSegment['kind'];
    format?: DlpTextSegment['format'];
    envelope?: string[];
  } = {},
): Promise<ScoredCandidate[]> {
  const detection = await detect({
    segments: [
      {
        source: { kind: 'body_text' },
        format: options.format ?? 'text',
        kind: options.kind ?? 'text',
        text,
      },
    ],
    settings: platformSettings(),
    aadhaarEnabled: options.aadhaar ?? false,
    dictionaries,
    envelopeAddresses: options.envelope ?? [],
    now: NOW,
  });
  return detection.candidates;
}

const reportable = async (text: string, options?: Parameters<typeof scan>[1]) =>
  (await scan(text, options)).filter((c) => c.reportable).map((c) => c.detector);

const card = (prefix: string, length: number) => {
  const payload =
    prefix +
    '7'.repeat(Math.max(0, length - prefix.length - 4)) +
    '351'.slice(
      0,
      Math.max(0, length - prefix.length - 1 - Math.max(0, length - prefix.length - 4)),
    );
  const body = payload.slice(0, length - 1);
  return body + String(luhnCheckDigit(body));
};
const aadhaar = (payload: string) => payload + String(verhoeffCheckDigit(payload));

describe('PC1 payment cards', () => {
  it('fires on grouped and plain Luhn-valid brand numbers with context', async () => {
    expect(await reportable('Card: 4532 0151 1283 0366 exp 09/27')).toEqual(['PC1']);
    expect(await reportable('credit card 4532-0151-1283-0366')).toEqual(['PC1']);
    expect(await reportable('Amex card 3782 822463 10005')).toEqual([]); // packaged test number
    const amex = card('3714', 15);
    expect(
      await reportable(`Amex card ${amex.slice(0, 4)} ${amex.slice(4, 10)} ${amex.slice(10)}`),
    ).toEqual(['PC1']);
    const thirteen = card('4', 13);
    expect(await reportable(`visa card ${thirteen}`)).toEqual(['PC1']);
    const nineteen = card('4', 19);
    expect(await reportable(`visa card ${nineteen}`)).toEqual(['PC1']);
    const mc2 = card('2221', 16);
    expect(await reportable(`mastercard ${mc2}`)).toEqual(['PC1']);
  });

  it('does not fire on bad Luhn, wrong grouping, mixed separators, longer runs, test numbers or unknown IINs', async () => {
    expect(await scan('card 4532 0151 1283 0367')).toEqual([]);
    expect(await scan('card 45320 1511 2830 366')).toEqual([]);
    expect(await scan('card 4532-0151 1283-0366')).toEqual([]);
    expect(await scan('card 14532015112830366')).toEqual([]);
    expect(await scan('card 4532015112830366X')).toEqual([]);
    expect(await scan('card 4111 1111 1111 1111')).toEqual([]);
    expect(await scan(`card ${card('18', 16)}`)).toEqual([]);
  });

  it('scores per D7: bare 0.45, order id 0.15, worked example 0.95', async () => {
    expect((await scan('value 4532015112830366 here'))[0]!.confidence).toBe(0.45);
    expect((await scan('Order ID 4532015112830366'))[0]!.confidence).toBe(0.15);
    expect((await scan('Card: 4532 0151 1283 0366 exp 09/27'))[0]!.confidence).toBe(0.95);
  });

  it('recognizes expiries', () => {
    expect(hasExpiryNear('exp 09/27', 0, 9)).toBe(true);
    expect(hasExpiryNear('exp 13/27', 0, 9)).toBe(false);
    expect(hasExpiryNear('exp 09/2027', 0, 11)).toBe(true);
    expect(hasExpiryNear('ratio 109/27', 0, 12)).toBe(false);
  });
});

describe('NI2 Aadhaar (gated, D17)', () => {
  const valid = aadhaar('23456789012');
  it('runs only with the compliance basis', async () => {
    expect(
      await scan(`Aadhaar: ${valid.slice(0, 4)} ${valid.slice(4, 8)} ${valid.slice(8)}`),
    ).toEqual([]);
    const on = await scan(`Aadhaar: ${valid.slice(0, 4)} ${valid.slice(4, 8)} ${valid.slice(8)}`, {
      aadhaar: true,
    });
    expect(on.map((c) => [c.detector, c.confidence, c.reportable])).toEqual([['NI2', 1, true]]);
  });
  it('rejects leading 0/1, failing Verhoeff, bad grouping and longer runs', async () => {
    expect(await scan(`aadhaar ${aadhaar('03456789012')}`, { aadhaar: true })).toEqual([]);
    expect(await scan(`aadhaar ${aadhaar('13456789012')}`, { aadhaar: true })).toEqual([]);
    expect(await scan('aadhaar 2345 6789 0123', { aadhaar: true })).toEqual([]);
    expect(await scan(`aadhaar ${valid.slice(0, 6)} ${valid.slice(6)}`, { aadhaar: true })).toEqual(
      [],
    );
    expect(await scan(`aadhaar 9${valid}`, { aadhaar: true })).toEqual([]);
    expect(aadhaarShape({ digits: valid, groups: [12], separator: '' })).toBe('plain');
    expect(aadhaarShape({ digits: valid, groups: [4, 4, 4], separator: 'mixed' })).toBeNull();
  });
  it('contiguous without context is 0.55, not reportable', async () => {
    expect((await scan(`number ${valid} noted`, { aadhaar: true }))[0]!.confidence).toBe(0.55);
  });
});

describe('PI2 Indian mobile', () => {
  it('parses the prefixes', () => {
    expect(indianMobile({ digits: '9123456780', groups: [10], plus: false })?.number).toBe(
      '9123456780',
    );
    expect(indianMobile({ digits: '919123456780', groups: [2, 5, 5], plus: true })).toEqual({
      number: '9123456780',
      plus91: true,
    });
    expect(indianMobile({ digits: '919123456780', groups: [12], plus: true })?.plus91).toBe(true);
    expect(indianMobile({ digits: '09123456780', groups: [11], plus: false })?.number).toBe(
      '9123456780',
    );
    expect(indianMobile({ digits: '5123456780', groups: [10], plus: false })).toBeNull();
    expect(indianMobile({ digits: '9123456780', groups: [4, 6], plus: false })).toBeNull();
  });
  it('fires with context; descending runs and fax lines do not', async () => {
    expect(await reportable('Mobile: +91 91234 56780')).toEqual(['PI2']);
    expect(await reportable('Call +91 98765 43210')).toEqual([]); // descending run, never a candidate
    expect((await scan('Fax: +91 91234 56780'))[0]!.reportable).toBe(false);
  });
});

describe('BA1 / BA2 / BA3 bank accounts', () => {
  it('IBAN compact and print form; wrong checksum refused', async () => {
    expect(await reportable('GB82WEST12345698765432')).toEqual(['BA1']);
    expect(await reportable('IBAN GB82 WEST 1234 5698 7654 32')).toEqual(['BA1']);
    expect(await scan('IBAN GB82 WEST 1234 5698 7654 33')).toEqual([]);
    expect(await scan('gb82west12345698765432')).toEqual([]);
  });
  it('IFSC + account number within the window (either order)', async () => {
    expect(await reportable('IFSC HDFC0001234 a/c 50100234567812')).toEqual(['BA2']);
    expect(await reportable('a/c 50100234567812 IFSC HDFC0001234')).toEqual(['BA2']);
    expect(await scan(`a/c 50100234567812 ${'x'.repeat(80)} HDFC0001234`)).toEqual([]);
    expect(await scan('a/c 50100234567812')).toEqual([]);
  });
  it('SWIFT requires context and an ISO country', async () => {
    expect(await reportable('SWIFT: DEUTDEFF500')).toEqual(['BA3']);
    expect(await reportable('BIC DEUTDEFF')).toEqual(['BA3']);
    expect((await scan('DEUTDEFF500'))[0]!.reportable).toBe(false);
    expect(await scan('swift DEUTZZFF')).toEqual([]);
  });
});

describe('NI1 PAN, PP1 passport, PI4 GSTIN', () => {
  it('PAN: entity character, uppercase whole token, code penalty', async () => {
    expect((await scan('PAN: ABCPD1234E'))[0]!.confidence).toBe(0.85);
    expect(await scan('PAN: ABCXD1234E')).toEqual([]);
    expect(await scan('pan: abcpd1234e')).toEqual([]);
    expect(await scan('PAN: ABCPD1234EF')).toEqual([]);
    const code = await scan('const PAN = "ABCPD1234E";');
    expect(code.map((c) => [c.confidence, c.reportable])).toEqual([[0.2, false]]);
  });
  it('passport requires context', async () => {
    expect(await reportable('Passport no K1234567')).toEqual(['PP1']);
    expect((await scan('Room K1234567'))[0]!.reportable).toBe(false);
    expect(await scan('passport Q1234567')).toEqual([]);
    expect(await scan('passport K0234567')).toEqual([]);
  });
  it('GSTIN with its check character', async () => {
    const g = `27ABCPD1234E1Z${gstinCheckChar('27ABCPD1234E1Z')!}`;
    expect(await reportable(`GSTIN ${g}`)).toEqual(['PI4']);
    expect(await scan(`GSTIN ${g.slice(0, 14)}${g[14] === 'A' ? 'B' : 'A'}`)).toEqual([]);
  });
});

describe('PP2 MRZ', () => {
  const line1 = 'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<';
  const line2 = 'L898902C36UTO7408122F1204159ZE184226B<<<<<10';
  it('accepts the ICAO specimen and refuses a bad check digit', async () => {
    expect(td3Valid(line2)).toBe(true);
    expect(await reportable(`${line1}\n${line2}`)).toEqual(['PP2']);
    expect(await scan(`${line1}\n${line2.slice(0, 9)}7${line2.slice(10)}`)).toEqual([]);
  });
});

describe('PI1 e-mail, PI3 date of birth', () => {
  it('counts addresses with a registrable domain, never the envelope addresses', async () => {
    expect(await reportable('Write to anita.rao@example.test today')).toEqual(['PI1']);
    expect(
      await scan('Write to anita.rao@example.test', { envelope: ['Anita.Rao@example.test'] }),
    ).toEqual([]);
    expect(await scan('user@localhost and a@b')).toEqual([]);
  });
  it('dates need context, calendar validity and a past year', async () => {
    expect(await reportable('DOB: 12/03/1985')).toEqual(['PI3']);
    expect(await reportable('Date of birth 1985-03-12')).toEqual(['PI3']);
    expect(await reportable('born on 5 Mar 1985')).toEqual(['PI3']);
    expect(await scan('DOB: 31/02/1985')).toEqual([]);
    expect(await scan('DOB: 12/03/2030')).toEqual([]);
    expect(await scan('DOB: 12/03/1899')).toEqual([]);
    expect((await scan('Meeting 12/03/1985'))[0]!.reportable).toBe(false);
    expect(parseNumericDate('1985-03-12')).toEqual({ year: 1985, month: 3, day: 12 });
    expect(parseNumericDate('12-03/1985')).toBeNull();
    expect(calendarValid(2024, 2, 29)).toBe(true);
    expect(calendarValid(2023, 2, 29)).toBe(false);
  });
});

describe('CF1 / CF2 keyword detectors', () => {
  it('labels, disclaimers, identifiers', async () => {
    expect(await reportable('TOP SECRET')).toEqual(['CF1', 'CF1']);
    expect(await reportable('गोपनीय दस्तावेज़')).toEqual(['CF1']);
    expect(
      (await scan('This email is confidential and intended solely for the recipient.'))[0]!
        .confidence,
    ).toBe(0.2);
    expect(await scan('aws_secret_access_key')).toEqual([]);
  });
  it('business terms: one term 0.5, two distinct 0.7', async () => {
    expect((await scan('the term sheet is ready')).map((c) => c.confidence)).toEqual([0.5]);
    expect((await scan('the term sheet and the customer list')).map((c) => c.confidence)).toEqual([
      0.7, 0.7,
    ]);
    expect(await reportable('grahak suchi aur mulya suchi')).toEqual(['CF2', 'CF2']);
  });
});

describe('SC1 source code, FI1 financial documents', () => {
  it('classifies code segments of at least 200 characters', async () => {
    expect(codeIndicatorLine('    return a + b;')).toBe(true);
    expect(codeIndicatorLine('If you have questions, call us.')).toBe(false);
    const js = Array.from({ length: 12 }, (_, i) => `const value${i} = compute(${i});`).join('\n');
    const found = (await scan(js)).filter((c) => c.detector === 'SC1');
    expect(found).toHaveLength(1);
    expect(found[0]!.reportable).toBe(true);
    expect(found[0]!.extra.language).toBe('javascript');
    expect((await scan('short code();')).filter((c) => c.detector === 'SC1')).toEqual([]);
    const prose =
      'The team met today to plan the next release and discuss the roadmap for the year. '.repeat(
        5,
      );
    expect((await scan(prose)).filter((c) => c.detector === 'SC1' && c.reportable)).toEqual([]);
  });
  it('needs two financial terms and three amounts', async () => {
    expect(await reportable('Invoice total ₹ 1,200; tax invoice Rs. 216; paid INR 1,416')).toEqual([
      'FI1',
    ]);
    expect(await reportable('Invoice total ₹ 1,200; paid INR 1,416')).toEqual([]);
    expect(await reportable('Invoice ₹ 1,200 ₹ 1 ₹ 2')).toEqual([]);
  });
});

describe('CR1–CR5 credentials', () => {
  const body = 'MIIEowIBAAKCAQEA' + 'q'.repeat(60);
  it('PEM private keys with and without a body; GCP service accounts', async () => {
    const pem = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----`;
    const found = await scan(pem);
    expect(found.map((c) => [c.detector, c.confidence])).toEqual([['CR1', 0.95]]);
    expect(found[0]!.extra.keyType).toBe('RSA');
    expect((await scan('-----BEGIN PRIVATE KEY-----'))[0]!.confidence).toBe(0.6);
    expect(await scan('-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----')).toEqual([]);
    const gcp = `{"type": "service_account", "project_id": "demo", "private_key": "-----BEGIN PRIVATE KEY-----\\n${body}\\n-----END PRIVATE KEY-----\\n"}`;
    expect((await reportable(gcp)).filter((d) => d === 'CR1').length).toBeGreaterThanOrEqual(1);
  });
  it('AWS key id (not the documented example) and secret with context', async () => {
    expect(await reportable(`key ${FAKE_AWS_KEY_ID}`)).toEqual(['CR2']);
    expect(await scan('key AKIAIOSFODNN7EXAMPLE')).toEqual([]);
    expect(await scan(`key ${FAKE_AWS_KEY_ID.slice(0, -2)}1H`)).toEqual([]); // 1 is not base32
    const secret = FAKE_AWS_SECRET;
    expect(await reportable(`aws secret access key: ${secret}`)).toEqual(['CR3']);
    expect(await reportable(`${FAKE_AWS_KEY_ID} ${secret}`)).toEqual(['CR2', 'CR3']);
    expect((await scan(`random ${secret}`))[0]!.reportable).toBe(false);
    expect(await scan('commit 3f786850e387550fdab836ed7e6dc881de23001b')).toEqual([]);
  });
  it('JWT needs a JSON header with alg; API tokens need exact lengths', async () => {
    const jwt = `${Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url')}.${Buffer.from('{"sub":"1"}').toString('base64url')}.c2ln`;
    expect(jwtAlg(jwt)).toBe('HS256');
    expect(await reportable(`token ${jwt}`)).toEqual(['CR4']);
    expect(jwtAlg('eyJub3QganNvbg.eyJhYmM.c2ln')).toBeNull();
    expect(apiTokenKind(`ghp_${'a1'.repeat(18)}`)).toBe('github');
    expect(apiTokenKind(`ghp_${'a1'.repeat(17)}`)).toBeNull();
    expect(apiTokenKind(`github_pat_${'A'.repeat(82)}`)).toBe('github');
    expect(apiTokenKind(`xoxb-${'1234567890-'.repeat(3)}abc`)).toBe('slack');
    expect(apiTokenKind(`AIza${'B'.repeat(35)}`)).toBe('google');
    expect(apiTokenKind(`sk_live_${'x9'.repeat(12)}`)).toBe('stripe');
    expect(apiTokenKind(`sk_test_${'x9'.repeat(12)}`)).toBeNull();
    expect(await reportable(`AccountKey=${'A'.repeat(86)}==;`)).toEqual(['CR5']);
  });
});

describe('detector codes (dlp-map/1)', () => {
  it('every emitted candidate uses a code of DLP_REASON_CODES', async () => {
    const corpus = await buildCorpus();
    const seen = new Set<string>();
    for (const fixture of [...corpus.fixtures, ...corpus.notExtracted]) {
      const run = await runFixture(fixture, corpus);
      for (const c of run.detection.candidates) seen.add(DLP_DETECTORS[c.detector].code);
      for (const code of run.detection.coverageCodes) seen.add(code);
    }
    for (const code of seen) expect(DLP_REASON_CODES, code).toContain(code);
    // The corpus exercises every one of the 23 detectors.
    expect(
      [...seen].filter((c) => DLP_DETECTOR_IDS.some((id) => DLP_DETECTORS[id].code === c)),
    ).toHaveLength(DLP_DETECTOR_IDS.length);
  });
});

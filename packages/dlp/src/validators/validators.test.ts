import { describe, expect, it } from 'vitest';
import {
  IBAN_LENGTHS,
  ISO3166_ALPHA2,
  PATTERN_VALIDATORS,
  TEST_CARD_NUMBERS,
  compactValue,
  gstinCheckChar,
  gstinValid,
  ibanLengthValid,
  ifscValid,
  iinBrand,
  isIso3166Alpha2,
  luhnCheckDigit,
  luhnValid,
  mod97Valid,
  mrzCheckDigit,
  mrzFieldValid,
  trivialDigitRun,
  verhoeffCheckDigit,
  verhoeffValid,
} from './index';

describe('Luhn (D6)', () => {
  it('accepts published vectors and rejects single-digit errors', () => {
    for (const n of [
      '79927398713',
      '4532015112830366',
      '378282246310005',
      '4222222222222',
      '6011111111111117',
    ]) {
      expect(luhnValid(n), n).toBe(true);
    }
    expect(luhnValid('79927398710')).toBe(false);
    expect(luhnValid('4532015112830367')).toBe(false);
    expect(luhnValid('')).toBe(false);
    expect(luhnValid('4532-0151')).toBe(false);
    expect(luhnCheckDigit('7992739871')).toBe(3);
  });
});

describe('Verhoeff (D6, Aadhaar)', () => {
  it('validates check digits, catches every single-digit error and adjacent transposition', () => {
    expect(verhoeffValid('2363')).toBe(true);
    expect(verhoeffCheckDigit('236')).toBe(3);
    expect(verhoeffValid('234567890124')).toBe(true);
    // The design's example 2345 6789 0123 fails Verhoeff (recorded in §12): no candidate.
    expect(verhoeffValid('234567890123')).toBe(false);
    const valid = '234567890124';
    for (let i = 0; i < valid.length; i += 1) {
      for (let d = 0; d <= 9; d += 1) {
        if (String(d) === valid[i]) continue;
        expect(verhoeffValid(valid.slice(0, i) + String(d) + valid.slice(i + 1))).toBe(false);
      }
      if (i + 1 < valid.length && valid[i] !== valid[i + 1]) {
        const swapped = valid.slice(0, i) + valid[i + 1] + valid[i] + valid.slice(i + 2);
        expect(verhoeffValid(swapped)).toBe(false);
      }
    }
    expect(verhoeffValid('x123')).toBe(false);
  });
});

describe('IBAN (ISO 13616 registry + mod 97)', () => {
  it('accepts valid IBANs of several countries and rejects wrong length or checksum', () => {
    for (const iban of [
      'GB82WEST12345698765432',
      'DE89370400440532013000',
      'FR1420041010050500013M02606',
      'NL91ABNA0417164300',
      'CH9300762011623852957',
      'NO9386011117947',
      'BE68539007547034',
    ]) {
      expect(mod97Valid(iban), iban).toBe(true);
    }
    expect(mod97Valid('GB82WEST12345698765433')).toBe(false);
    // Valid checksum shape but the wrong length for the country.
    expect(ibanLengthValid('GB82WEST1234569876543')).toBe(false);
    expect(ibanLengthValid('DE8937040044053201300')).toBe(false);
    expect(mod97Valid('XX82WEST12345698765432')).toBe(false);
    expect(IBAN_LENGTHS.GB).toBe(22);
    expect(Object.keys(IBAN_LENGTHS).length).toBeGreaterThanOrEqual(80);
  });
});

describe('GSTIN (mod 36) and PAN entity', () => {
  it('computes the check character and validates structure', () => {
    const first14 = '27ABCPD1234E1Z';
    const check = gstinCheckChar(first14)!;
    expect(check).toMatch(/^[0-9A-Z]$/);
    expect(gstinValid(first14 + check)).toBe(true);
    const wrong = check === 'A' ? 'B' : 'A';
    expect(gstinValid(first14 + wrong)).toBe(false);
    // State code 00 and 40 are not states; 97 / 99 are.
    expect(gstinValid(`00ABCPD1234E1Z${gstinCheckChar('00ABCPD1234E1Z')}`)).toBe(false);
    expect(gstinValid(`40ABCPD1234E1Z${gstinCheckChar('40ABCPD1234E1Z')}`)).toBe(false);
    expect(gstinValid(`99ABCPD1234E1Z${gstinCheckChar('99ABCPD1234E1Z')}`)).toBe(true);
    // Embedded PAN entity must be one of PCHABGJLFT.
    expect(gstinValid(`27ABCXD1234E1Z${gstinCheckChar('27ABCXD1234E1Z')}`)).toBe(false);
    expect(gstinCheckChar('short')).toBeNull();
  });
});

describe('MRZ 7-3-1', () => {
  it('matches the ICAO 9303 specimen', () => {
    // ICAO 9303 part 4 specimen: L898902C3 → 6; 740812 → 2; 120415 → 9.
    expect(mrzCheckDigit('L898902C3')).toBe(6);
    expect(mrzCheckDigit('740812')).toBe(2);
    expect(mrzCheckDigit('120415')).toBe(9);
    expect(mrzFieldValid('740812', '2')).toBe(true);
    expect(mrzFieldValid('740812', '3')).toBe(false);
    expect(mrzCheckDigit('ab')).toBeNull();
  });
});

describe('IIN brands and lengths (PC1)', () => {
  it('maps prefixes to brands with their lengths (longest prefix wins)', () => {
    expect(iinBrand('4532015112830366')).toBe('visa');
    expect(iinBrand('4222222222222')).toBe('visa'); // 13 digits
    expect(iinBrand('4' + '1'.repeat(18))).toBe('visa'); // 19 digits
    expect(iinBrand('41111111111111')).toBeNull(); // Visa with 14 digits
    expect(iinBrand('378282246310005')).toBe('amex'); // 15
    expect(iinBrand('3782822463100051')).toBeNull(); // Amex with 16
    expect(iinBrand('2221000000000009')).toBe('mastercard'); // 2-series
    expect(iinBrand('2720990000000007')).toBe('mastercard');
    expect(iinBrand('2721000000000000')).toBeNull();
    expect(iinBrand('5105105105105100')).toBe('mastercard');
    expect(iinBrand('6011111111111117')).toBe('discover');
    expect(iinBrand('6521000000000000')).toBe('rupay');
    expect(iinBrand('6011000000000000')).toBe('discover'); // 6011 beats RuPay 60
    expect(iinBrand('6070000000000000')).toBe('rupay');
    expect(iinBrand('3530111333300000')).toBe('jcb');
    expect(iinBrand('30569309025904')).toBe('diners');
    expect(iinBrand('6200000000000005')).toBe('unionpay');
    expect(iinBrand('5600000000000')).toBe('maestro');
    expect(iinBrand('1800000000000000')).toBeNull();
  });

  it('packages at least 30 test card numbers', () => {
    expect(TEST_CARD_NUMBERS.size).toBeGreaterThanOrEqual(30);
    for (const n of [
      '4111111111111111',
      '4242424242424242',
      '4000056655665556',
      '5555555555554444',
      '5105105105105100',
      '378282246310005',
      '371449635398431',
      '6011111111111117',
      '3530111333300000',
      '30569309025904',
    ]) {
      expect(TEST_CARD_NUMBERS.has(n), n).toBe(true);
    }
  });

  it('detects trivial digit runs', () => {
    expect(trivialDigitRun('1111111111111111')).toBe(true);
    expect(trivialDigitRun('1234567890123456')).toBe(true);
    expect(trivialDigitRun('9876543210')).toBe(true);
    expect(trivialDigitRun('4532015112830366')).toBe(false);
  });
});

describe('IFSC, ISO 3166 and pattern validators', () => {
  it('validates IFSC structure', () => {
    expect(ifscValid('HDFC0001234')).toBe(true);
    expect(ifscValid('HDFC1001234')).toBe(false);
    expect(ifscValid('HDF00001234')).toBe(false);
  });
  it('knows the ISO 3166 alpha-2 codes', () => {
    expect(ISO3166_ALPHA2.size).toBeGreaterThanOrEqual(249);
    expect(isIso3166Alpha2('IN')).toBe(true);
    expect(isIso3166Alpha2('DE')).toBe(true);
    expect(isIso3166Alpha2('ZZ')).toBe(false);
  });
  it('exposes the tenant validators keyed by DLP_PATTERN_VALIDATORS', () => {
    expect(PATTERN_VALIDATORS.none('anything')).toBe(true);
    expect(PATTERN_VALIDATORS.luhn('4532015112830366')).toBe(true);
    expect(PATTERN_VALIDATORS.verhoeff('234567890124')).toBe(true);
    expect(PATTERN_VALIDATORS.mod97('GB82WEST12345698765432')).toBe(true);
    expect(PATTERN_VALIDATORS.gstin('27ABCPD1234E1Z' + gstinCheckChar('27ABCPD1234E1Z')!)).toBe(
      true,
    );
    expect(compactValue('gb82 west-1234')).toBe('GB82WEST1234');
  });
});

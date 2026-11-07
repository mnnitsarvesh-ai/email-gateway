import { createHash } from 'node:crypto';
import type { DlpDetectorId } from '@email-gateway/security-contracts';
import {
  IBAN_LENGTHS,
  gstinCheckChar,
  iinBrand,
  luhnCheckDigit,
  mod97Valid,
  mrzCheckDigit,
  verhoeffCheckDigit,
  verhoeffValid,
  TEST_CARD_NUMBERS,
  trivialDigitRun,
} from '../validators';

/**
 * Synthetic value generators of the fixture corpus (step 4.5 §9): every value comes from a
 * seeded PRNG and is recorded in the manifest, so a unit test can assert that every value in
 * the corpus is synthetic by construction. Card numbers use real brand prefixes with a valid
 * Luhn digit but random account digits (not issued numbers); Aadhaar-like numbers are random
 * Verhoeff-valid 12-digit strings; PAN, GSTIN, passport and MRZ values are invented; e-mail
 * domains are `example.test`. Never real personal data.
 */

export class Prng {
  private state: number;
  constructor(seed: number) {
    this.state = seed >>> 0;
  }
  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  int(min: number, max: number): number {
    return min + Math.floor(this.next() * (max - min + 1));
  }
  digits(n: number): string {
    let out = '';
    for (let i = 0; i < n; i += 1) out += String(this.int(0, 9));
    return out;
  }
  letters(n: number, alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'): string {
    let out = '';
    for (let i = 0; i < n; i += 1) out += alphabet[this.int(0, alphabet.length - 1)];
    return out;
  }
  pick<T>(list: readonly T[]): T {
    return list[this.int(0, list.length - 1)]!;
  }
}

export interface ManifestEntry {
  detector: DlpDetectorId | 'none';
  value: string;
  note?: string;
}

/** Every synthetic value generated for the corpus, in generation order. */
export class Manifest {
  readonly entries: ManifestEntry[] = [];
  add(detector: ManifestEntry['detector'], value: string, note?: string): string {
    this.entries.push(note ? { detector, value, note } : { detector, value });
    return value;
  }
  has(value: string): boolean {
    return this.entries.some((e) => e.value === value);
  }
}

const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export class Synthetic {
  readonly manifest = new Manifest();
  constructor(readonly rng: Prng) {}

  /** A Luhn-valid card number of a brand prefix (not a packaged test number, not trivial). */
  card(prefix = '4532', length = 16): string {
    for (;;) {
      const payload = prefix + this.rng.digits(length - prefix.length - 1);
      const value = payload + String(luhnCheckDigit(payload));
      if (iinBrand(value) && !TEST_CARD_NUMBERS.has(value) && !trivialDigitRun(value)) {
        return this.manifest.add('PC1', value);
      }
    }
  }

  /** A Verhoeff-valid Aadhaar-like number (first digit 2–9). */
  aadhaar(): string {
    for (;;) {
      const payload = String(this.rng.int(2, 9)) + this.rng.digits(10);
      const value = payload + String(verhoeffCheckDigit(payload));
      if (verhoeffValid(value) && !trivialDigitRun(value)) return this.manifest.add('NI2', value);
    }
  }

  /** A 12-digit number failing Verhoeff (first digit 2–9). */
  aadhaarInvalid(): string {
    for (;;) {
      const value = String(this.rng.int(2, 9)) + this.rng.digits(11);
      if (!verhoeffValid(value)) return this.manifest.add('none', value, 'verhoeff-invalid');
    }
  }

  pan(entity = 'P'): string {
    return this.manifest.add(
      'NI1',
      this.rng.letters(3) + entity + this.rng.letters(1) + this.rng.digits(4) + this.rng.letters(1),
    );
  }

  gstin(): string {
    const state = String(this.rng.int(1, 38)).padStart(2, '0');
    const pan =
      this.rng.letters(3) + 'C' + this.rng.letters(1) + this.rng.digits(4) + this.rng.letters(1);
    const first14 = `${state}${pan}${this.rng.int(1, 9)}Z`;
    return this.manifest.add('PI4', first14 + gstinCheckChar(first14)!);
  }

  iban(country = 'GB'): string {
    const length = IBAN_LENGTHS[country]!;
    for (;;) {
      const bban =
        country === 'GB' ? this.rng.letters(4) + this.rng.digits(14) : this.rng.digits(length - 4);
      for (let check = 2; check <= 98; check += 1) {
        const value = `${country}${String(check).padStart(2, '0')}${bban}`;
        if (mod97Valid(value)) return this.manifest.add('BA1', value);
      }
    }
  }

  ifsc(): string {
    return this.manifest.add(
      'none',
      this.rng.letters(4) + '0' + this.rng.letters(2) + this.rng.digits(4),
      'ifsc',
    );
  }

  accountNumber(length = 14): string {
    for (;;) {
      const value = String(this.rng.int(1, 9)) + this.rng.digits(length - 1);
      if (!trivialDigitRun(value)) return this.manifest.add('BA2', value);
    }
  }

  swift(): string {
    return this.manifest.add(
      'BA3',
      `${this.rng.letters(4)}IN${this.rng.letters(2, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789')}`,
    );
  }

  passport(): string {
    return this.manifest.add(
      'PP1',
      this.rng.letters(1, 'ABCDEFGHJKLMNPRSTUVW') + String(this.rng.int(1, 9)) + this.rng.digits(6),
    );
  }

  /** A TD3 MRZ (2 × 44) with valid check digits. */
  mrzTd3(): { lines: [string, string]; documentNumber: string } {
    const surname = this.rng.letters(6);
    const given = this.rng.letters(5);
    let line1 = `P<IND${surname}<<${given}`;
    line1 = (line1 + '<'.repeat(44)).slice(0, 44);
    const documentNumber = this.rng.letters(1) + this.rng.digits(7) + '<';
    const birth = `${String(this.rng.int(60, 99))}${String(this.rng.int(1, 12)).padStart(2, '0')}${String(this.rng.int(1, 28)).padStart(2, '0')}`;
    const expiry = `${String(this.rng.int(30, 35))}${String(this.rng.int(1, 12)).padStart(2, '0')}${String(this.rng.int(1, 28)).padStart(2, '0')}`;
    const personal = '<'.repeat(14);
    const d = (s: string) => String(mrzCheckDigit(s));
    const body =
      documentNumber +
      d(documentNumber) +
      'IND' +
      birth +
      d(birth) +
      this.rng.pick(['M', 'F']) +
      expiry +
      d(expiry) +
      personal +
      '<';
    const line2 = body + d(body.slice(0, 10) + body.slice(13, 20) + body.slice(21, 43));
    this.manifest.add('PP2', `${line1}\n${line2}`);
    return { lines: [line1, line2], documentNumber: documentNumber.replace(/</g, '') };
  }

  mobile(): string {
    for (;;) {
      const value = String(this.rng.int(6, 9)) + this.rng.digits(9);
      if (!trivialDigitRun(value)) return this.manifest.add('PI2', value);
    }
  }

  email(): string {
    return this.manifest.add(
      'PI1',
      `${this.rng.letters(6, 'abcdefghijklmnopqrstuvwxyz')}.${this.rng.letters(4, 'abcdefghijklmnopqrstuvwxyz')}@example.test`,
    );
  }

  dob(): string {
    const value = `${String(this.rng.int(1, 28)).padStart(2, '0')}/${String(this.rng.int(1, 12)).padStart(2, '0')}/${this.rng.int(1950, 2004)}`;
    return this.manifest.add('PI3', value);
  }

  awsKeyId(): string {
    return this.manifest.add(
      'CR2',
      `AKIA${this.rng.letters(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')}`,
    );
  }

  awsSecret(): string {
    for (;;) {
      const value = this.rng.letters(40, BASE64);
      if (/[A-Z]/.test(value) && /[a-z]/.test(value) && /[0-9/+]/.test(value))
        return this.manifest.add('CR3', value);
    }
  }

  jwt(): string {
    const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const header = b64({ alg: 'HS256', typ: 'JWT' });
    const payload = b64({ sub: this.rng.digits(8), iat: 1_700_000_000 + this.rng.int(0, 1000) });
    const signature = createHash('sha256').update(this.rng.digits(16)).digest('base64url');
    return this.manifest.add('CR4', `${header}.${payload}.${signature}`);
  }

  githubToken(): string {
    return this.manifest.add('CR5', `ghp_${this.rng.letters(36, ALNUM)}`);
  }

  /** A PEM block shaped like an RSA private key with a random (non-key) base64 body. */
  pemPrivateKey(label = 'RSA PRIVATE KEY'): string {
    const lines: string[] = [];
    for (let i = 0; i < 6; i += 1) lines.push(this.rng.letters(64, BASE64));
    return this.manifest.add(
      'CR1',
      `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`,
    );
  }
}

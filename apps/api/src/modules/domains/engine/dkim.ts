import { generateKeyPair, randomInt } from 'node:crypto';
import { promisify } from 'node:util';
import type { DnsResult } from '../../../dns/dns-resolver';
import type { DkimAlgorithm, DnsCheckOutcome } from './types';

const generateKeyPairAsync = promisify(generateKeyPair);

export interface DkimKeyPair {
  algorithm: DkimAlgorithm;
  /** RSA: base64 SPKI DER. Ed25519: base64 of the raw 32-byte public key (RFC 8463). */
  publicKeyDns: string;
  /** PKCS#8 PEM. Secret: encrypt with SecretBox before storing; never log or return it. */
  privateKeyPem: string;
}

/** DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): 12 bytes, then the raw key. */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Generates a DKIM key pair off the event loop (libuv thread pool): RSA 2048 bits with public
 * exponent 65537, or Ed25519 (ADR-0018). Call outside database transactions.
 */
export async function generateDkimKeyPair(algorithm: DkimAlgorithm): Promise<DkimKeyPair> {
  if (algorithm === 'rsa_2048') {
    const { publicKey, privateKey } = await generateKeyPairAsync('rsa', {
      modulusLength: 2048,
      publicExponent: 65537,
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { algorithm, publicKeyDns: publicKey.toString('base64'), privateKeyPem: privateKey };
  }
  if (algorithm === 'ed25519') {
    const { publicKey, privateKey } = await generateKeyPairAsync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    if (
      publicKey.length !== ED25519_SPKI_PREFIX.length + 32 ||
      !publicKey.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
    ) {
      throw new Error('Unexpected Ed25519 public key encoding');
    }
    return {
      algorithm,
      publicKeyDns: publicKey.subarray(ED25519_SPKI_PREFIX.length).toString('base64'),
      privateKeyPem: privateKey,
    };
  }
  throw new Error('Unsupported DKIM algorithm');
}

/** `k=` tag value for an algorithm. */
export function dkimKeyType(algorithm: DkimAlgorithm): 'rsa' | 'ed25519' {
  return algorithm === 'rsa_2048' ? 'rsa' : 'ed25519';
}

/** The TXT value at `<selector>._domainkey.<domain>`. */
export function dkimTxtValue(algorithm: DkimAlgorithm, publicKeyDns: string): string {
  return `v=DKIM1; k=${dkimKeyType(algorithm)}; p=${publicKeyDns}`;
}

/** Host of a selector's record. */
export function dkimRecordHost(selector: string, domain: string): string {
  return `${selector}._domainkey.${domain}`;
}

const SELECTOR_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
/** Length of every generated selector (`eg` + algorithm letter + `yyyymmdd` + 4 characters). */
export const DKIM_SELECTOR_LENGTH = 15;

/**
 * `eg<r|e><yyyymmdd><4 random [a-z0-9]>` (UTC date), e.g. `egr20261102k3f9`. Callers retry on
 * a collision with an existing selector of the domain.
 */
export function generateDkimSelector(algorithm: DkimAlgorithm, now: Date): string {
  const date = now.toISOString().slice(0, 10).replaceAll('-', '');
  let suffix = '';
  for (let i = 0; i < 4; i++) suffix += SELECTOR_ALPHABET[randomInt(SELECTOR_ALPHABET.length)];
  return `eg${algorithm === 'rsa_2048' ? 'r' : 'e'}${date}${suffix}`;
}

export interface ParsedDkimRecord {
  /** Tag names lower-case; `p` with all whitespace removed. */
  tags: Record<string, string>;
  /** `k`, defaulting to `rsa` (RFC 6376 §3.6.1). */
  keyType: string;
  /** Public key data (whitespace removed); empty string = key revoked. */
  publicKey: string | null;
  /** `t=y`: the domain is testing DKIM. */
  testing: boolean;
  errors: string[];
}

/** Parses a DKIM key record (RFC 6376 §3.6.1 tag list). */
export function parseDkimRecord(record: string): ParsedDkimRecord {
  const tags: Record<string, string> = {};
  const order: string[] = [];
  const errors: string[] = [];
  for (const part of record.split(';')) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) {
      errors.push('syntax');
      continue;
    }
    const name = trimmed.slice(0, eq).trim().toLowerCase();
    if (!/^[a-z][a-z0-9_]*$/.test(name) || name in tags) {
      errors.push('syntax');
      continue;
    }
    tags[name] = trimmed.slice(eq + 1).trim();
    order.push(name);
  }
  if (tags.v !== undefined && (order[0] !== 'v' || tags.v !== 'DKIM1')) errors.push('v');
  if (tags.p === undefined) errors.push('p');
  const publicKey = tags.p === undefined ? null : tags.p.replace(/\s+/g, '');
  if (publicKey !== null) tags.p = publicKey;
  if (publicKey && !/^[A-Za-z0-9+/]+={0,2}$/.test(publicKey)) errors.push('p');
  const flags = (tags.t ?? '').split(':').map((f) => f.trim().toLowerCase());
  return {
    tags,
    keyType: (tags.k ?? 'rsa').toLowerCase(),
    publicKey,
    testing: flags.includes('y'),
    errors,
  };
}

export interface DkimEvaluation {
  outcome: DnsCheckOutcome;
  observedValue: string | null;
  warnings: string[];
}

/**
 * Evaluates the TXT answer at a selector (D9): a record whose tags parse, whose `p` equals the
 * expected key and whose `k` matches → valid; another key (`dkim_public_key_mismatch`) or an
 * empty `p` (`dkim_key_revoked_in_dns`) → invalid; `t=y` adds `dkim_testing_mode`.
 */
export function evaluateDkim(
  result: DnsResult<string>,
  expected: { algorithm: DkimAlgorithm; publicKeyDns: string },
): DkimEvaluation {
  switch (result.outcome) {
    case 'indeterminate':
      return { outcome: 'indeterminate', observedValue: null, warnings: [] };
    case 'nxdomain':
    case 'nodata':
      return { outcome: 'missing', observedValue: null, warnings: [] };
    default:
      break;
  }
  const expectedKey = expected.publicKeyDns.replace(/\s+/g, '');
  const expectedType = dkimKeyType(expected.algorithm);
  const parsed = result.records.map(parseDkimRecord);
  const match = parsed.find(
    (r) => r.errors.length === 0 && r.publicKey === expectedKey && r.keyType === expectedType,
  );
  const observedValue = result.records.join('\n');
  if (match) {
    return {
      outcome: 'valid',
      observedValue,
      warnings: match.testing ? ['dkim_testing_mode'] : [],
    };
  }
  const warnings = parsed.some((r) => r.publicKey === '')
    ? ['dkim_key_revoked_in_dns']
    : ['dkim_public_key_mismatch'];
  if (parsed.some((r) => r.testing)) warnings.push('dkim_testing_mode');
  return { outcome: 'invalid', observedValue, warnings };
}

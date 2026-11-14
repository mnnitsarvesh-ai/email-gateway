import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  classifyHeader,
  isRevealableHeader,
  MASKED_HEADER_NAMES,
  maskAddress,
  maskAddressesInNullableText,
  maskAddressesInText,
  SAFE_HEADER_NAMES,
  STORED_HEADER_NAMES,
} from './sensitive-masking';

/**
 * The step 3.1 stored allow-list, read from its source of truth
 * (`STORED_HEADER_NAMES` of packages/mime-parser/src/headers.ts; the api does not depend on the
 * parser package).
 */
const PARSER_STORED_HEADER_NAMES: string[] = (() => {
  const source = readFileSync(
    resolve(__dirname, '../../../../../../packages/mime-parser/src/headers.ts'),
    'utf8',
  );
  const block = /export const STORED_HEADER_NAMES = \[([^\]]*)\] as const;/.exec(source);
  if (!block) throw new Error('STORED_HEADER_NAMES not found');
  return [...block[1]!.matchAll(/'([^']+)'/g)].map((m) => m[1]!);
})();

describe('maskAddress (§3.4)', () => {
  it.each([
    ['', ''],
    ['finance.team@acme.example', 'f***@acme.example'],
    ['a@b.example', 'a***@b.example'],
    ['@acme.example', '***@acme.example'],
    ['postmaster', 'p***'],
    ['x', 'x***'],
    // The domain is kept as stored (case, IDN form).
    ['Alice@ACME.Example', 'A***@ACME.Example'],
    ['user@xn--bcher-kva.example', 'u***@xn--bcher-kva.example'],
    ['jörg@bücher.example', 'j***@bücher.example'],
    // Code points, never UTF-16 units: an astral first character is kept whole.
    ['😀mail@acme.example', '😀***@acme.example'],
    ['𝒶lice@acme.example', '𝒶***@acme.example'],
    ['Ωmega@acme.example', 'Ω***@acme.example'],
    // A quoted local part with an `@`: the last `@` separates the domain.
    ['"a@b"@acme.example', '"***@acme.example'],
    ['"john doe"@acme.example', '"***@acme.example'],
    // A null sender or a domain-only value.
    ['@', '***@'],
    ['user@', 'u***@'],
  ])('%j → %j', (input, expected) => {
    expect(maskAddress(input)).toBe(expected);
  });

  it('never leaks more than the first code point of the local part', () => {
    const masked = maskAddress('very.long.local.part+tag@corp.example');
    expect(masked).toBe('v***@corp.example');
    expect(masked).not.toContain('long');
    expect(masked).not.toContain('tag');
  });
});

describe('maskAddressesInText (§3.4, E9)', () => {
  it.each([
    // No address: unchanged (no false positive).
    ['250 2.0.0 Ok: queued as 4XbT2c1LkPz9', '250 2.0.0 Ok: queued as 4XbT2c1LkPz9'],
    ['delivered to user@localhost', 'delivered to user@localhost'],
    ['', ''],
    ['an @ sign alone and a@ and @b.example', 'an @ sign alone and a@ and @b.example'],
    // One address in angle brackets (the usual SMTP reply).
    [
      '550 5.1.1 <john.doe@example.com>: Recipient address rejected',
      '550 5.1.1 <j***@example.com>: Recipient address rejected',
    ],
    // Several addresses in one reply.
    [
      '250 2.1.5 alice@acme.example, bob.smith@acme.example and carol+x@sub.acme.example',
      '250 2.1.5 a***@acme.example, b***@acme.example and c***@sub.acme.example',
    ],
    // IDN domains: A-label and U-label.
    ['rcpt jörg@xn--bcher-kva.example', 'rcpt j***@xn--bcher-kva.example'],
    ['rcpt jörg@bücher.example ok', 'rcpt j***@bücher.example ok'],
    // Quoted local parts.
    ['<"john doe"@example.com> unknown', '<"***@example.com> unknown'],
    // RFC 5322 atext symbols in the local part.
    ["o'brien!x#y$z&w*v/u=t?s^r`q{p|o}n~m@example.com", 'o***@example.com'],
    // mailto and URL-like contexts keep their prefix.
    ['mailto:help.desk@example.org?subject=x', 'mailto:h***@example.org?subject=x'],
    // A trailing dot or bracket is not part of the domain.
    ['to admin@example.net.', 'to a***@example.net.'],
    // Unicode local parts and code points.
    // An emoji is not a local-part character: the address starts after it.
    ['😀user@example.com', '😀u***@example.com'],
    ['Ünïcode.user@example.com', 'Ü***@example.com'],
    ['𝒶lice@example.com', '𝒶***@example.com'],
    // Rspamd symbol options shapes.
    ['FROM_NEQ_ENVFROM: billing@vendor.example', 'FROM_NEQ_ENVFROM: b***@vendor.example'],
    ['vendor.example', 'vendor.example'],
  ])('%j → %j', (input, expected) => {
    expect(maskAddressesInText(input)).toBe(expected);
  });

  it('is idempotent and never re-reveals', () => {
    const once = maskAddressesInText('550 <john.doe@example.com> and jane@example.com');
    expect(maskAddressesInText(once)).toBe(once);
    expect(once).not.toMatch(/john|jane|doe/);
  });

  it('scans a long hostile run in linear time', () => {
    const run = 'a'.repeat(2048);
    const started = performance.now();
    expect(maskAddressesInText(run)).toBe(run);
    expect(maskAddressesInText(`${run}@example.com`)).toBe('a***@example.com');
    expect(performance.now() - started).toBeLessThan(250);
  });

  it('maps null to null', () => {
    expect(maskAddressesInNullableText(null)).toBeNull();
    expect(maskAddressesInNullableText('to a@b.example')).toBe('to a***@b.example');
  });
});

describe('header classification (§2 E7)', () => {
  it.each([
    ['From', 'safe'],
    ['Sender', 'safe'],
    ['Reply-To', 'safe'],
    ['Return-Path', 'safe'],
    ['Date', 'safe'],
    ['Message-ID', 'safe'],
    ['In-Reply-To', 'safe'],
    ['References', 'safe'],
    ['Authentication-Results', 'safe'],
    ['from', 'safe'],
    ['MESSAGE-ID', 'safe'],
    [' reply-to ', 'safe'],
    ['To', 'masked'],
    ['Cc', 'masked'],
    ['Subject', 'masked'],
    ['to', 'masked'],
    ['SUBJECT', 'masked'],
    // Fail closed: names outside the 3.1 allow-list, misspellings, empty.
    ['Bcc', 'masked'],
    ['X-Original-To', 'masked'],
    ['Delivered-To', 'masked'],
    ['List-Unsubscribe', 'masked'],
    ['Fromm', 'masked'],
    ['', 'masked'],
  ] as const)('%j is %s', (name, expected) => {
    expect(classifyHeader(name)).toBe(expected);
  });

  it('safe + masked names are exactly the step 3.1 stored allow-list', () => {
    expect(STORED_HEADER_NAMES).toEqual(PARSER_STORED_HEADER_NAMES);
    expect([...SAFE_HEADER_NAMES, ...MASKED_HEADER_NAMES].sort()).toEqual(
      [...STORED_HEADER_NAMES].sort(),
    );
    expect(
      SAFE_HEADER_NAMES.some((n) => (MASKED_HEADER_NAMES as readonly string[]).includes(n)),
    ).toBe(false);
  });

  it('the reveal returns exactly To, Cc and Subject rows', () => {
    expect(STORED_HEADER_NAMES.filter(isRevealableHeader)).toEqual(['To', 'Cc', 'Subject']);
    expect(isRevealableHeader('cc')).toBe(true);
    expect(isRevealableHeader('Bcc')).toBe(false);
    expect(isRevealableHeader('From')).toBe(false);
  });
});

import { buildGatewayTrace } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { FROM_MISMATCH, LMTP_OK, LMTP_TEMPFAIL, LOOP } from '../shared/replies';
import {
  addressDomain,
  fromMatchesSender,
  groupByOrganization,
  type IngestRecipient,
  isLooping,
  type OrganizationOutcome,
  parseAddressList,
  repliesFor,
  splitRecipient,
} from './tenant-split';

const rcpt = (address: string, organizationId: bigint, domainId: bigint): IngestRecipient => ({
  address,
  domain: address.split('@')[1]!,
  organizationId,
  domainId,
});

describe('groupByOrganization', () => {
  it('groups in order of each organization’s first recipient and keeps RCPT positions', () => {
    const groups = groupByOrganization([
      rcpt('a@one.test', 1n, 10n),
      rcpt('b@two.test', 2n, 20n),
      rcpt('c@one-alias.test', 1n, 11n),
      rcpt('d@two.test', 2n, 20n),
    ]);
    expect(groups.map((g) => [g.organizationId, g.domainId, g.indexes])).toEqual([
      [1n, 10n, [0, 2]],
      [2n, 20n, [1, 3]],
    ]);
    expect(groups[0]!.recipients.map((r) => r.address)).toEqual(['a@one.test', 'c@one-alias.test']);
  });
});

describe('splitRecipient', () => {
  it('lower-cases only the domain', () => {
    expect(splitRecipient('John.Doe@Example.TEST')).toEqual({
      address: 'John.Doe@example.test',
      domain: 'example.test',
    });
    expect(splitRecipient('"a@b"@Example.test')?.domain).toBe('example.test');
  });

  it('rejects addresses without local part or domain, and oversized ones', () => {
    for (const bad of ['postmaster', '@example.test', 'a@', `${'x'.repeat(320)}@example.test`]) {
      expect(splitRecipient(bad), bad).toBeNull();
    }
  });
});

describe('loop guard (D14)', () => {
  const secret = 's'.repeat(40);
  const options = { secret, gatewayId: 'gw-test', maxPasses: 1, direction: 'inbound' as const };
  const trace = (organizationId: bigint, direction: 'in' | 'out', gatewayId = 'gw-test') =>
    buildGatewayTrace({ secret, gatewayId, organizationId, direction });

  it('detects a valid trace for the same organization and direction', () => {
    expect(isLooping([trace(7n, 'in')], 7n, options)).toBe(true);
  });

  it('ignores other organizations, the other direction, other gateways and forgeries', () => {
    expect(isLooping([trace(8n, 'in')], 7n, options)).toBe(false);
    expect(isLooping([trace(7n, 'out')], 7n, options)).toBe(false);
    expect(isLooping([trace(7n, 'in', 'gw-other')], 7n, options)).toBe(false);
    const forged = trace(7n, 'in').replace(/s=[A-Za-z0-9_-]+$/, 's=AAAAAAAAAAAAAAAAAAAAAA');
    expect(isLooping([forged, 'garbage', ''], 7n, options)).toBe(false);
    expect(isLooping([], 7n, options)).toBe(false);
  });

  it('honours SMTP_LOOP_MAX_PASSES', () => {
    const two = { ...options, maxPasses: 2 };
    expect(isLooping([trace(7n, 'in')], 7n, two)).toBe(false);
    expect(isLooping([trace(7n, 'in'), trace(7n, 'in')], 7n, two)).toBe(true);
  });

  it('checks outbound traces on the outbound listener', () => {
    expect(isLooping([trace(7n, 'out')], 7n, { ...options, direction: 'outbound' })).toBe(true);
  });
});

describe('outbound From check (D7 step 5)', () => {
  it('accepts exactly one address in the envelope sender domain (case and IDN normalized)', () => {
    expect(fromMatchesSender(['Alice <alice@Acme.TEST>'], 'bounce+x@acme.test')).toBe(true);
    expect(fromMatchesSender(['alice@acme.test (Alice)'], 'alice@ACME.test')).toBe(true);
    expect(fromMatchesSender(['"Doe, John" <john@bücher.test>'], 'x@xn--bcher-kva.test')).toBe(
      true,
    );
    expect(fromMatchesSender(['=?UTF-8?Q?J=C3=B6rg?= <j@acme.test>'], 'j@acme.test')).toBe(true);
  });

  it('refuses another domain, subdomains, several addresses, several From headers, none', () => {
    expect(fromMatchesSender(['alice@evil.test'], 'alice@acme.test')).toBe(false);
    expect(fromMatchesSender(['alice@mail.acme.test'], 'alice@acme.test')).toBe(false);
    expect(fromMatchesSender(['a@acme.test, b@acme.test'], 'a@acme.test')).toBe(false);
    expect(fromMatchesSender(['a@acme.test', 'b@acme.test'], 'a@acme.test')).toBe(false);
    expect(fromMatchesSender([], 'a@acme.test')).toBe(false);
    expect(fromMatchesSender(['undisclosed:;'], 'a@acme.test')).toBe(false);
    expect(fromMatchesSender(['a@acme.test'], '')).toBe(false);
    expect(fromMatchesSender(['"evil@acme.test" <x@evil.test>'], 'a@acme.test')).toBe(false);
  });

  it('parses address lists with groups, comments and quoted commas', () => {
    expect(parseAddressList('Team: a@x.test, "B, b" <b@y.test>; c@z.test (C, c)')).toEqual([
      'a@x.test',
      'b@y.test',
      'c@z.test',
    ]);
    expect(addressDomain('x@Bücher.TEST')).toBe('xn--bcher-kva.test');
    expect(addressDomain('nodomain')).toBeNull();
  });
});

describe('replies (D7 step 7)', () => {
  it('maps each organization’s outcome to its recipients in RCPT order', () => {
    const groups = groupByOrganization([
      rcpt('a@one.test', 1n, 10n),
      rcpt('b@two.test', 2n, 20n),
      rcpt('c@three.test', 3n, 30n),
      rcpt('d@one.test', 1n, 10n),
      rcpt('e@four.test', 4n, 40n),
      rcpt('f@five.test', 5n, 50n),
    ]);
    const outcomes = new Map<bigint, OrganizationOutcome>([
      [1n, 'stored'],
      [2n, 'tempfail'],
      [3n, 'loop'],
      [4n, 'duplicate'],
      [5n, 'from_mismatch'],
    ]);
    expect(repliesFor(6, groups, outcomes)).toEqual([
      LMTP_OK,
      LMTP_TEMPFAIL,
      LOOP,
      LMTP_OK,
      LMTP_OK,
      FROM_MISMATCH,
    ]);
  });

  it('never answers 250 for an organization without an outcome', () => {
    const groups = groupByOrganization([rcpt('a@one.test', 1n, 10n)]);
    expect(repliesFor(1, groups, new Map())).toEqual([LMTP_TEMPFAIL]);
  });
});

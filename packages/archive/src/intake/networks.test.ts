import { describe, expect, it } from 'vitest';
import { addressInCidrs, cidrsOverlap, parseCidr, validateIntakeNetworks } from './networks';

const PROVIDERS = ['203.0.113.0/24', '2001:db8:ffff::/48'];
const run = (cidrs: string[], allowPrivate = false) =>
  validateIntakeNetworks(cidrs, { allowPrivate, providerRanges: PROVIDERS });

describe('parseCidr', () => {
  it.each([
    ['198.51.100.0/24', '198.51.100.0/24', false],
    ['198.51.100.7', '198.51.100.7/32', false],
    ['198.51.100.7/24', '198.51.100.0/24', true],
    ['2001:DB8:10::/48', '2001:db8:10::/48', false],
    ['2001:db8:0:0:0:0:0:1', '2001:db8::1/128', false],
    ['::ffff:198.51.100.1', '::ffff:c633:6401/128', false],
    ['2001:db8:0:1:0:0:0:0/64', '2001:db8:0:1::/64', false],
    ['0.0.0.0/0', '0.0.0.0/0', false],
  ])('%s → %s', (input, text, hostBits) => {
    const p = parseCidr(input);
    expect(p?.text).toBe(text);
    expect(p?.hostBitsSet).toBe(hostBits);
  });

  it.each([
    '',
    '256.1.1.1',
    '1.2.3',
    '01.2.3.4',
    '1.2.3.4/33',
    '2001:db8::/129',
    '1::2::3',
    'x',
    '1.2.3.4/024',
    ':::',
  ])('%j is invalid', (input) => {
    expect(parseCidr(input)).toBeNull();
  });

  it('overlap and membership', () => {
    expect(cidrsOverlap(parseCidr('10.0.0.0/8')!, parseCidr('10.1.2.0/24')!)).toBe(true);
    expect(cidrsOverlap(parseCidr('10.0.0.0/8')!, parseCidr('11.0.0.0/8')!)).toBe(false);
    expect(cidrsOverlap(parseCidr('10.0.0.0/8')!, parseCidr('::/0')!)).toBe(false);
    expect(addressInCidrs('198.51.100.9', ['198.51.100.0/24'])).toBe(true);
    expect(addressInCidrs('::ffff:198.51.100.9', ['198.51.100.0/24'])).toBe(true);
    expect(addressInCidrs('[2001:db8:10::5]', ['2001:db8:10::/48'])).toBe(true);
    expect(addressInCidrs('198.51.101.9', ['198.51.100.0/24'])).toBe(false);
    expect(addressInCidrs('nonsense', ['198.51.100.0/24'])).toBe(false);
  });
});

describe('validateIntakeNetworks (intake-networks/1, D1)', () => {
  it('accepts public networks and canonicalizes them', () => {
    expect(run(['198.51.100.0/24', '2001:DB8:10::/48', '192.0.2.10'])).toEqual({
      ok: true,
      cidrs: ['198.51.100.0/24', '2001:db8:10::/48', '192.0.2.10/32'],
    });
  });

  it.each([
    [[], [{ code: 'count', index: null }]],
    [Array.from({ length: 33 }, (_, i) => `198.51.${i}.0/24`), [{ code: 'count', index: null }]],
    [['nonsense'], [{ code: 'invalid', index: 0 }]],
    [['198.51.100.1/24'], [{ code: 'host_bits_set', index: 0 }]],
    [['198.0.0.0/15'], [{ code: 'too_broad', index: 0 }]],
    [['0.0.0.0/0'], [{ code: 'too_broad', index: 0 }]],
    [['2001:db8::/31'], [{ code: 'too_broad', index: 0 }]],
    [['10.1.0.0/16'], [{ code: 'private_not_allowed', index: 0 }]],
    [['172.20.0.0/24'], [{ code: 'private_not_allowed', index: 0 }]],
    [['fd00:1::/48'], [{ code: 'private_not_allowed', index: 0 }]],
    [['::ffff:0:0/96'], [{ code: 'private_not_allowed', index: 0 }]],
    [['203.0.113.128/25'], [{ code: 'provider_overlap', index: 0 }]],
    [['203.0.0.0/16'], [{ code: 'provider_overlap', index: 0 }]],
    [['2001:db8:ffff:1::/64'], [{ code: 'provider_overlap', index: 0 }]],
    [['198.51.100.0/24', '198.51.100.0/24'], [{ code: 'duplicate', index: 1 }]],
  ])('%j → %j', (cidrs, issues) => {
    expect(run(cidrs)).toEqual({ ok: false, issues });
  });

  it('allows private ranges only with allowPrivate (local and CI)', () => {
    expect(run(['172.20.0.0/16', '127.0.0.1'], true)).toEqual({
      ok: true,
      cidrs: ['172.20.0.0/16', '127.0.0.1/32'],
    });
    // Provider overlap is refused even with allowPrivate.
    expect(run(['203.0.113.0/24'], true)).toMatchObject({ ok: false });
  });

  it('refuses an invalid provider range instead of skipping it', () => {
    expect(() =>
      validateIntakeNetworks(['198.51.100.0/24'], { allowPrivate: false, providerRanges: ['x'] }),
    ).toThrow(RangeError);
  });
});

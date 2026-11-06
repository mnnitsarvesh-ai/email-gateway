import { describe, expect, it } from 'vitest';
import { clientNetwork } from './client-network';

describe('clientNetwork', () => {
  it.each([
    ['198.51.100.23', '198.51.100.0/24'],
    ['::ffff:198.51.100.23', '198.51.100.0/24'],
    ['2001:db8:abcd:12::1', '2001:db8:abcd::/48'],
    ['2001:db8::1', '2001:db8:0::/48'],
    ['not-an-ip', 'unknown'],
    [undefined, 'unknown'],
  ])('%s → %s', (input, expected) => {
    expect(clientNetwork(input)).toBe(expected);
  });
});

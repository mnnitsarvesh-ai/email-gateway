import { describe, expect, it } from 'vitest';
import { clientIp } from './client-ip';

describe('clientIp', () => {
  it('returns the Express-resolved address', () => {
    expect(clientIp({ ip: '203.0.113.7' })).toBe('203.0.113.7');
    expect(clientIp({ ip: '2001:db8::1' })).toBe('2001:db8::1');
  });

  it('unwraps IPv4-mapped IPv6 addresses', () => {
    expect(clientIp({ ip: '::ffff:127.0.0.1' })).toBe('127.0.0.1');
  });

  it('returns null when unknown', () => {
    expect(clientIp({ ip: undefined })).toBeNull();
    expect(clientIp({ ip: '' })).toBeNull();
  });

  it('fits the 45-character columns', () => {
    expect(clientIp({ ip: 'x'.repeat(100) })).toHaveLength(45);
  });
});

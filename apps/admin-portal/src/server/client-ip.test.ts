// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { clientIpFromHeaders, normalizeIp } from './client-ip';

const h = (xff: string | null) => {
  const headers = new Headers();
  if (xff !== null) headers.set('x-forwarded-for', xff);
  return headers;
};

describe('client IP for X-EG-Client-IP (P5, ADR-0060)', () => {
  it('hops=0 (local/ci): the socket peer Next filled in (it never appends)', () => {
    expect(clientIpFromHeaders(h('127.0.0.1'), 0)).toBe('127.0.0.1');
    expect(clientIpFromHeaders(h('::1'), 0)).toBe('::1');
    expect(clientIpFromHeaders(h('::ffff:192.0.2.7'), 0)).toBe('192.0.2.7');
    expect(clientIpFromHeaders(h('198.51.100.1, 203.0.113.50'), 0)).toBe('203.0.113.50');
  });

  it('hops=1: the entry the trusted proxy appended (the last one)', () => {
    expect(clientIpFromHeaders(h('198.51.100.1, 203.0.113.50'), 1)).toBe('203.0.113.50');
    expect(clientIpFromHeaders(h('203.0.113.50'), 1)).toBe('203.0.113.50');
  });

  it('hops=2: one further back; too few entries → none', () => {
    expect(clientIpFromHeaders(h('spoofed, 203.0.113.50, 10.0.0.2'), 2)).toBe('203.0.113.50');
    expect(clientIpFromHeaders(h('10.0.0.2'), 2)).toBeNull();
  });

  it('omits the header when nothing valid is available', () => {
    expect(clientIpFromHeaders(h(null), 1)).toBeNull();
    expect(clientIpFromHeaders(h('not-an-ip'), 1)).toBeNull();
    expect(clientIpFromHeaders(h(' , '), 1)).toBeNull();
    expect(normalizeIp('[2001:db8::1]')).toBe('2001:db8::1');
    expect(normalizeIp('1'.repeat(46))).toBeNull();
  });
});

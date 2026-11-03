import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  buildGatewayTrace,
  countGatewayPasses,
  GATEWAY_TRACE_HEADER,
  type GatewayTraceKey,
} from './gateway-trace';

const secret = 'a'.repeat(16) + 'b'.repeat(16) + 'c'.repeat(32);
const key: GatewayTraceKey = {
  secret,
  gatewayId: 'gw-local',
  organizationId: 42n,
  direction: 'in',
};
const now = new Date('2026-11-02T10:00:00.900Z');

describe('buildGatewayTrace', () => {
  it('exports the header name', () => {
    expect(GATEWAY_TRACE_HEADER).toBe('X-Gateway-Trace');
  });

  it('builds the D14 value with a truncated, unpadded base64url HMAC-SHA256', () => {
    const value = buildGatewayTrace({ ...key, now });
    const t = Math.floor(now.getTime() / 1000);
    const sig = createHmac('sha256', secret)
      .update(`v1|gw-local|in|${t}|42`)
      .digest()
      .subarray(0, 16)
      .toString('base64url');
    expect(value).toBe(`v=1; g=gw-local; d=in; t=${t}; s=${sig}`);
    expect(sig).toHaveLength(22);
    expect(value).not.toContain('42;');
    expect(value).not.toContain('=;');
  });

  it('is deterministic per input and accepts a decimal string organization id', () => {
    expect(buildGatewayTrace({ ...key, now })).toBe(
      buildGatewayTrace({ ...key, organizationId: '42', now }),
    );
    expect(buildGatewayTrace({ ...key, now })).not.toBe(
      buildGatewayTrace({ ...key, organizationId: 43n, now }),
    );
  });

  it('uses the current time by default', () => {
    const before = Math.floor(Date.now() / 1000);
    const t = Number(/t=(\d+)/.exec(buildGatewayTrace(key))![1]);
    expect(t).toBeGreaterThanOrEqual(before);
    expect(t).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
  });

  it('validates the secret, gateway id, organization id and direction', () => {
    expect(() => buildGatewayTrace({ ...key, secret: 'short' })).toThrow('at least 32');
    expect(() => buildGatewayTrace({ ...key, gatewayId: '' })).toThrow('Gateway trace id');
    expect(() => buildGatewayTrace({ ...key, gatewayId: 'gw local' })).toThrow('Gateway trace id');
    expect(() => buildGatewayTrace({ ...key, gatewayId: 'g'.repeat(65) })).toThrow(
      'Gateway trace id',
    );
    expect(() => buildGatewayTrace({ ...key, gatewayId: 'gw;d=out' })).toThrow('Gateway trace id');
    for (const organizationId of ['0', '-1', '1.5', 'abc', '012', 0n]) {
      expect(() => buildGatewayTrace({ ...key, organizationId }), String(organizationId)).toThrow(
        'organization id',
      );
    }
    expect(() => buildGatewayTrace({ ...key, direction: 'sideways' as unknown as 'in' })).toThrow(
      'direction',
    );
    expect(() => buildGatewayTrace({ ...key, now: new Date(Number.NaN) })).toThrow('valid date');
  });
});

describe('countGatewayPasses', () => {
  const valid = buildGatewayTrace({ ...key, now });

  it('counts a valid trace of the same gateway, direction and organization', () => {
    expect(countGatewayPasses([valid], key)).toBe(1);
  });

  it('ignores a forged signature', () => {
    const forged = valid.replace(
      /s=([A-Za-z0-9_-])/,
      (_m, c: string) => `s=${c === 'A' ? 'B' : 'A'}`,
    );
    expect(forged).not.toBe(valid);
    expect(countGatewayPasses([forged], key)).toBe(0);
    // Signed with another secret.
    const otherSecret = buildGatewayTrace({ ...key, secret: 'z'.repeat(40), now });
    expect(countGatewayPasses([otherSecret], key)).toBe(0);
    // Timestamp changed after signing.
    expect(countGatewayPasses([valid.replace(/t=\d+/, 't=1')], key)).toBe(0);
  });

  it('ignores traces of another organization', () => {
    const other = buildGatewayTrace({ ...key, organizationId: 43n, now });
    expect(countGatewayPasses([other], key)).toBe(0);
    expect(countGatewayPasses([other], { ...key, organizationId: '43' })).toBe(1);
  });

  it('ignores traces of the other direction', () => {
    const outbound = buildGatewayTrace({ ...key, direction: 'out', now });
    expect(countGatewayPasses([outbound], key)).toBe(0);
    expect(countGatewayPasses([outbound], { ...key, direction: 'out' })).toBe(1);
  });

  it('ignores traces of another gateway id', () => {
    const otherGateway = buildGatewayTrace({ ...key, gatewayId: 'gw-other', now });
    expect(countGatewayPasses([otherGateway], key)).toBe(0);
    // Rewriting g does not help: the signature binds the gateway id.
    expect(countGatewayPasses([otherGateway.replace('g=gw-other', 'g=gw-local')], key)).toBe(0);
  });

  it('ignores malformed values without throwing', () => {
    const t = /t=(\d+)/.exec(valid)![1]!;
    const s = /s=([A-Za-z0-9_-]+)/.exec(valid)![1]!;
    const malformed = [
      '',
      '   ',
      'garbage',
      'v=1',
      `v=2; g=gw-local; d=in; t=${t}; s=${s}`,
      `g=gw-local; d=in; t=${t}; s=${s}`,
      `v=1; g=gw-local; d=in; t=${t}; s=${s}; x=1`,
      `v=1; g=gw-local; d=in; d=in; t=${t}; s=${s}`,
      `v=1; g=gw-local; d=in; t=-5; s=${s}`,
      `v=1; g=gw-local; d=in; t=${t}; s=${s}==`,
      `v=1; g=gw-local; d=in; t=${t}; s=${s.slice(1)}`,
      `v=1; g=gw-local; d=in; t=${t}; s=${s}`.repeat(20),
      `v=1; =gw-local; d=in; t=${t}; s=${s}`,
      42 as unknown as string,
    ];
    expect(countGatewayPasses(malformed, key)).toBe(0);
  });

  it('tolerates surrounding whitespace, folding and field spacing', () => {
    const [, g, d, t, s] = /v=1; g=(.+); d=(.+); t=(.+); s=(.+)/.exec(valid)!;
    const variants = [
      `  ${valid}  `,
      `v=1;g=${g};d=${d};t=${t};s=${s}`,
      `v=1; g=${g};\r\n d=${d}; t=${t};\r\n\ts=${s}`,
      `v=1; g=${g};\n d=${d}; t=${t}; s=${s};`,
      `s=${s}; t=${t}; d=${d}; g=${g}; v=1`,
    ];
    for (const variant of variants) expect(countGatewayPasses([variant], key), variant).toBe(1);
  });

  it('counts every valid value among several, ignoring the rest', () => {
    const later = buildGatewayTrace({ ...key, now: new Date(now.getTime() + 3_600_000) });
    const values = [
      valid,
      'garbage',
      buildGatewayTrace({ ...key, organizationId: 7n, now }),
      later,
      buildGatewayTrace({ ...key, direction: 'out', now }),
    ];
    expect(countGatewayPasses(values, key)).toBe(2);
    expect(countGatewayPasses([], key)).toBe(0);
  });

  it('validates its options like buildGatewayTrace', () => {
    expect(() => countGatewayPasses([valid], { ...key, secret: 'short' })).toThrow('at least 32');
    expect(() => countGatewayPasses([valid], { ...key, organizationId: 'x' })).toThrow(
      'organization id',
    );
  });
});

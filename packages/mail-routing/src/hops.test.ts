import { buildGatewayTrace } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { evaluateHops } from './hops';

const secret = 's'.repeat(40);
const gatewayId = 'gw-test';
const trace = (direction: 'in' | 'out', organizationId: bigint = 7n, key = secret) =>
  buildGatewayTrace({ secret: key, gatewayId, organizationId, direction });
const base = {
  receivedHeaderCount: 3,
  traceValues: [] as string[],
  organizationId: 7n,
  secret,
  gatewayId,
  maxReceived: 25,
  maxPasses: 4,
};

describe('evaluateHops', () => {
  it('passes a normal message', () => {
    expect(evaluateHops(base)).toEqual({ ok: true, passes: 0 });
    expect(evaluateHops({ ...base, traceValues: [trace('in'), trace('out')] })).toEqual({
      ok: true,
      passes: 2,
    });
  });

  it('stops at the Received: limit', () => {
    expect(evaluateHops({ ...base, receivedHeaderCount: 24 })).toMatchObject({ ok: true });
    expect(evaluateHops({ ...base, receivedHeaderCount: 25 })).toEqual({
      ok: false,
      reason: 'received_limit',
      passes: 0,
    });
  });

  it('counts valid passes of this organization in both directions', () => {
    const values = [trace('in'), trace('out'), trace('in'), trace('out')];
    expect(evaluateHops({ ...base, traceValues: values })).toEqual({
      ok: false,
      reason: 'gateway_passes',
      passes: 4,
    });
    expect(evaluateHops({ ...base, traceValues: values.slice(0, 3) })).toMatchObject({
      ok: true,
      passes: 3,
    });
  });

  it('ignores forged traces and traces of other organizations or gateways', () => {
    const values = [
      trace('in', 8n),
      trace('out', 8n),
      trace('in', 7n, 'x'.repeat(40)),
      buildGatewayTrace({ secret, gatewayId: 'other-gw', organizationId: 7n, direction: 'in' }),
      'v=1; g=gw-test; d=in; t=1; s=AAAAAAAAAAAAAAAAAAAAAA',
      'garbage',
      trace('in'),
    ];
    expect(evaluateHops({ ...base, traceValues: values })).toEqual({ ok: true, passes: 1 });
  });
});

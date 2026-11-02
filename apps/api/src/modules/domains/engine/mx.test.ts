import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { indeterminate, mxAnswer, negative } from '../../../../test/support/dns/dns-results';
import { TestDnsServer } from '../../../../test/support/dns/test-dns-server';
import type { MxAnswer } from '../../../dns/dns-resolver';
import { SystemDnsResolver } from '../../../dns/system-dns-resolver';
import { evaluateMx, formatMxRecords } from './mx';

const gateway = {
  mxHosts: [
    { priority: 10, host: 'mx1.mail-gateway.test' },
    { priority: 20, host: 'mx2.mail-gateway.test' },
  ],
};
const domain = 'acme.test';

describe('evaluateMx', () => {
  it('is valid when every exchange is a gateway host', () => {
    const result = evaluateMx(
      mxAnswer(domain, [
        [20, 'mx2.mail-gateway.test'],
        [10, 'mx1.mail-gateway.test'],
      ]),
      gateway,
    );
    expect(result).toEqual({
      outcome: 'valid',
      observed: [
        { priority: 10, exchange: 'mx1.mail-gateway.test' },
        { priority: 20, exchange: 'mx2.mail-gateway.test' },
      ],
      observedValue: '10 mx1.mail-gateway.test\n20 mx2.mail-gateway.test',
      warnings: [],
      propagation: [],
    });
  });

  it('is invalid with non-gateway hosts, and flags a possible bypass when mixed', () => {
    expect(evaluateMx(mxAnswer(domain, [[10, 'mail.acme.test']]), gateway)).toMatchObject({
      outcome: 'invalid',
      warnings: ['mx_non_gateway_hosts'],
    });
    expect(
      evaluateMx(
        mxAnswer(domain, [
          [10, 'mx1.mail-gateway.test'],
          [50, 'backup.acme.test'],
        ]),
        gateway,
      ),
    ).toMatchObject({
      outcome: 'invalid',
      warnings: ['mx_non_gateway_hosts', 'mx_gateway_bypass_possible'],
    });
  });

  it('treats a Null MX as a non-gateway host', () => {
    const result = evaluateMx(mxAnswer(domain, [[0, '']]), gateway);
    expect(result).toMatchObject({ outcome: 'invalid', observedValue: '0 .' });
  });

  it('maps NXDOMAIN/NODATA to missing with an empty observation', () => {
    expect(evaluateMx(negative<MxAnswer>(domain, 'nxdomain'), gateway)).toMatchObject({
      outcome: 'missing',
      observed: [],
      observedValue: null,
    });
    expect(evaluateMx(negative<MxAnswer>(domain, 'nodata'), gateway).outcome).toBe('missing');
  });

  it('is indeterminate when the primary is, whatever the upstreams say', () => {
    const result = evaluateMx(indeterminate<MxAnswer>(domain, 'timeout'), gateway, [
      mxAnswer(domain, [[10, 'mx1.mail-gateway.test']], 'system:b'),
    ]);
    expect(result).toMatchObject({
      outcome: 'indeterminate',
      observed: null,
      observedValue: null,
      propagation: [{ upstream: 'system:b', outcome: 'valid' }],
    });
  });

  it('requires propagation: a definitive disagreement makes a valid primary invalid', () => {
    const result = evaluateMx(mxAnswer(domain, [[10, 'mx1.mail-gateway.test']]), gateway, [
      mxAnswer(domain, [[10, 'old-mx.acme.test']], 'system:b'),
      negative<MxAnswer>(domain, 'nxdomain', 'system:c'),
    ]);
    expect(result).toMatchObject({
      outcome: 'invalid',
      warnings: ['mx_not_propagated'],
      propagation: [
        { upstream: 'system:b', outcome: 'invalid' },
        { upstream: 'system:c', outcome: 'missing' },
      ],
    });
  });

  it('notes indeterminate upstreams without failing the record', () => {
    const result = evaluateMx(mxAnswer(domain, [[10, 'mx1.mail-gateway.test']]), gateway, [
      indeterminate<MxAnswer>(domain, 'timeout', 'system:b'),
      mxAnswer(domain, [[10, 'mx1.mail-gateway.test']], 'system:c'),
    ]);
    expect(result).toMatchObject({
      outcome: 'valid',
      warnings: ['mx_propagation_unknown:system:b'],
    });
  });

  it('formats Null MX as a dot', () => {
    expect(formatMxRecords([{ priority: 0, exchange: '' }])).toBe('0 .');
  });
});

describe('evaluateMx with two test DNS servers (propagation)', () => {
  let primaryDns: TestDnsServer;
  let secondDns: TestDnsServer;
  let primary: SystemDnsResolver;
  let second: SystemDnsResolver;

  beforeAll(async () => {
    [primaryDns, secondDns] = await Promise.all([TestDnsServer.start(), TestDnsServer.start()]);
    primary = new SystemDnsResolver({ servers: [primaryDns.address], timeoutMs: 300, tries: 1 });
    second = new SystemDnsResolver({ servers: [secondDns.address], timeoutMs: 300, tries: 1 });
  });
  afterAll(async () => {
    await Promise.all([primaryDns.close(), secondDns.close()]);
  });
  beforeEach(() => {
    primaryDns.reset();
    secondDns.reset();
  });

  const check = async () =>
    evaluateMx(await primary.resolveMx(domain), gateway, [await second.resolveMx(domain)]);

  it('is invalid until the second upstream also sees the gateway MX', async () => {
    primaryDns.setMx(domain, [{ priority: 10, exchange: 'mx1.mail-gateway.test' }]);
    secondDns.setMx(domain, [{ priority: 10, exchange: 'mx.old-provider.test' }]);
    expect(await check()).toMatchObject({ outcome: 'invalid', warnings: ['mx_not_propagated'] });

    secondDns.setMx(domain, [{ priority: 10, exchange: 'mx1.mail-gateway.test' }]);
    expect(await check()).toMatchObject({
      outcome: 'valid',
      warnings: [],
      propagation: [{ upstream: `system:${secondDns.address}`, outcome: 'valid' }],
    });
  });

  it('keeps the primary outcome when the second upstream fails', async () => {
    primaryDns.setMx(domain, [{ priority: 10, exchange: 'mx1.mail-gateway.test' }]);
    secondDns.fail(domain, 'servfail');
    expect(await check()).toMatchObject({
      outcome: 'valid',
      warnings: [`mx_propagation_unknown:system:${secondDns.address}`],
    });
  });
});

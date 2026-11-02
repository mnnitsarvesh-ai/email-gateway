import { describe, expect, it } from 'vitest';
import { createDomainTestbed, ORG_A } from '../../../test/support/domains/domain-testbed';
import { toDnsRecordView, toDomainSummary, toStatusView } from './domain.mapper';
import { gatewayDnsConfigFrom } from './engine/gateway-dns-config';
import type { DnsRecordRow } from './repositories/dns-records.repository';

const bed = createDomainTestbed();
const gateway = gatewayDnsConfigFrom(bed.config);

function record(recordKey: string, patch: Partial<DnsRecordRow>): DnsRecordRow {
  return {
    id: 1n,
    domainId: 1n,
    recordKey,
    purpose: 'spf',
    recordType: 'TXT',
    host: 'acme.example.com',
    dkimKeyId: null,
    expectedValue: 'v=spf1 ~all',
    observedValue: null,
    status: 'pending',
    statusChangedAt: null,
    lastOutcome: null,
    lastError: null,
    evidence: null,
    lastCheckedAt: null,
    createdAt: new Date(),
    ...patch,
  };
}

describe('domain mappers', () => {
  const domain = bed.store.addDomain(ORG_A, 'xn--mnchen-3ya.example.com', { status: 'active' });

  it('serializes public ids, ISO dates and the Unicode name, never numeric ids', () => {
    const summary = toDomainSummary(domain);
    expect(summary).toMatchObject({
      id: domain.publicId,
      name: 'xn--mnchen-3ya.example.com',
      unicodeName: 'münchen.example.com',
      createdAt: domain.createdAt.toISOString(),
    });
    expect(() => JSON.stringify(summary)).not.toThrow();
    expect(JSON.stringify(summary)).not.toContain(`"${domain.id}"`);
  });

  it('refuses to serialize a deleted domain', () => {
    expect(() => toDomainSummary({ ...domain, status: 'deleted' })).toThrow();
  });

  it('splits MX values and names records relative to the domain', () => {
    const view = toDnsRecordView(
      record('mx:mx1.gw.test', {
        purpose: 'mx',
        recordType: 'MX',
        host: 'acme.example.com',
        expectedValue: '10 mx1.gw.test',
        evidence: { warnings: ['mx_non_gateway_hosts'] },
      }),
      'acme.example.com',
    );
    expect(view).toMatchObject({
      name: '@',
      value: 'mx1.gw.test',
      priority: 10,
      requirement: 'inbound',
      warnings: ['mx_non_gateway_hosts'],
    });
    const dmarc = toDnsRecordView(
      record('dmarc', { purpose: 'dmarc', host: '_dmarc.acme.example.com' }),
      'acme.example.com',
    );
    expect(dmarc).toMatchObject({ name: '_dmarc', priority: null, requirement: 'recommended' });
  });

  it('summarizes each check group with the worst status and stored evidence', () => {
    const checkedAt = new Date('2026-11-02T10:00:00Z');
    const view = toStatusView({
      domain,
      gateway,
      records: [
        record('verification', { purpose: 'verification', status: 'valid', lastOutcome: 'valid' }),
        record('mx:a', {
          purpose: 'mx',
          recordType: 'MX',
          status: 'valid',
          lastOutcome: 'valid',
          lastCheckedAt: checkedAt,
          evidence: {
            propagationOutcomes: [
              { upstream: 'system:10.0.0.1:53', outcome: 'missing' },
              { upstream: 42, outcome: 'nope' },
            ],
          },
        }),
        record('mx:b', {
          purpose: 'mx',
          recordType: 'MX',
          status: 'invalid',
          lastOutcome: 'invalid',
        }),
        record('spf', {
          status: 'missing',
          evidence: { lookupCount: 3, warnings: ['spf_ptr_mechanism'] },
        }),
        record('dkim:s1', { purpose: 'dkim', status: 'valid', lastOutcome: 'indeterminate' }),
        record('dmarc', {
          purpose: 'dmarc',
          status: 'valid',
          expectedValue: 'v=DMARC1; p=reject',
          evidence: { stage: 'quarantine', nextStep: 'go to reject' },
        }),
      ],
      dkimKeys: [
        {
          id: 1n,
          domainId: domain.id,
          selector: 's1',
          algorithm: 'rsa_2048',
          publicKey: 'AAAA',
          status: 'active',
          activatedAt: null,
          retireAfter: null,
          retiredAt: null,
          createdAt: new Date(),
        },
      ],
      mx: [{ priority: 10, host: 'a', pointsToGateway: true, lastSeenAt: new Date() }],
    });
    expect(view).toMatchObject({
      status: 'active',
      readyForActivation: false,
      mailFlowReady: false, // MX group is invalid
      checks: {
        ownership: { status: 'valid' },
        mx: {
          status: 'invalid',
          lastOutcome: 'invalid',
          lastCheckedAt: checkedAt.toISOString(),
          observed: [{ priority: 10, host: 'a', pointsToGateway: true }],
          propagation: [{ upstream: 'system:10.0.0.1:53', outcome: 'missing' }],
        },
        spf: { status: 'missing', lookupCount: 3, warnings: ['spf_ptr_mechanism'] },
        dkim: {
          status: 'valid',
          lastOutcome: 'indeterminate',
          selectors: [{ selector: 's1', keyStatus: 'active', recordStatus: 'valid' }],
        },
        dmarc: {
          stage: 'quarantine',
          recommendedValue: 'v=DMARC1; p=reject',
          nextStep: 'go to reject',
        },
      },
    });
  });

  it('reports never-checked groups as pending with the default DMARC guidance', () => {
    const view = toStatusView({ domain, gateway, records: [], dkimKeys: [], mx: [] });
    expect(view.checks.ownership).toEqual({
      status: 'pending',
      lastOutcome: null,
      lastCheckedAt: null,
      warnings: [],
    });
    expect(view.checks.dmarc.stage).toBe('missing');
    expect(view.checks.dmarc.recommendedValue).toMatch(/^v=DMARC1; p=none/);
    expect(view.checks.spf.lookupCount).toBeNull();
  });
});

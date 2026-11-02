import { describe, expect, it } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { createDomainTestbed, ORG_A } from '../../../../test/support/domains/domain-testbed';
import { needsKey } from './domain-configuration.service';

const scopeA = systemScope(ORG_A);

describe('DomainConfigurationService.ensure (D12)', () => {
  it('materializes a complete configuration and is idempotent', async () => {
    const bed = createDomainTestbed();
    const domain = bed.store.addDomain(ORG_A, 'cfg.example.com');
    await bed.configuration.ensure(scopeA, domain.id);
    const snapshot = () => ({
      verifications: bed.store.verificationsOf(domain.id).map((v) => [v.id, v.token, v.status]),
      keys: bed.store.keysOf(domain.id).map((k) => [k.id, k.selector, k.status]),
      records: bed.store.recordsOf(domain.id).map((r) => [r.id, r.recordKey, r.expectedValue]),
    });
    const first = snapshot();
    expect(first.verifications).toHaveLength(1);
    expect(first.verifications[0]![2]).toBe('pending');
    expect(first.keys).toHaveLength(1);
    expect(first.records.map((r) => r[1])).toEqual([
      'verification',
      'mx:mx1.mail-gateway.test',
      'mx:mx2.mail-gateway.test',
      'spf',
      `dkim:${String(first.keys[0]![1])}`,
      'dmarc',
    ]);
    const dkimRecord = bed.store.recordsOf(domain.id).find((r) => r.purpose === 'dkim')!;
    expect(dkimRecord.dkimKeyId).toBe(first.keys[0]![0]);

    await bed.configuration.ensure(scopeA, domain.id);
    await bed.configuration.ensure(scopeA, domain.id);
    expect(snapshot()).toEqual(first);
    expect(bed.store.domain(domain.id).status).toBe('pending_verification');
  });

  it('keeps the current SPF/DMARC recommendations and the check results', async () => {
    const bed = createDomainTestbed();
    const domain = bed.store.addDomain(ORG_A, 'keep.example.com');
    bed.store.addRecord(domain, 'spf', 'spf', {
      expectedValue: 'v=spf1 include:_spf.mail-gateway.test include:other.test ~all',
      status: 'valid',
    });
    await bed.configuration.ensure(scopeA, domain.id);
    expect(bed.store.recordsOf(domain.id).find((r) => r.recordKey === 'spf')).toMatchObject({
      expectedValue: 'v=spf1 include:_spf.mail-gateway.test include:other.test ~all',
      status: 'valid',
    });
  });

  it('reconciles MX rows with the configured gateway hosts and drops unpublished DKIM rows', async () => {
    const bed = createDomainTestbed({ GATEWAY_MX_HOSTS: '5:mx-new.mail-gateway.test' });
    const domain = bed.store.addDomain(ORG_A, 'mx.example.com', { status: 'active' });
    bed.store.addRecord(domain, 'mx:mx-old.mail-gateway.test', 'mx');
    const revoked = bed.store.addKey(domain, 'revoked1', { status: 'revoked' });
    bed.store.addRecord(domain, 'dkim:revoked1', 'dkim', { dkimKeyId: revoked.id });
    await bed.configuration.ensure(scopeA, domain.id);
    const keys = bed.store.recordsOf(domain.id).map((r) => r.recordKey);
    expect(keys).toContain('mx:mx-new.mail-gateway.test');
    expect(keys).not.toContain('mx:mx-old.mail-gateway.test');
    expect(keys).not.toContain('dkim:revoked1');
    expect(
      bed.store.recordsOf(domain.id).find((r) => r.recordKey.startsWith('mx:'))!.expectedValue,
    ).toBe('5 mx-new.mail-gateway.test');
    // An owned domain without verification gets a monitored, already verified row.
    expect(bed.store.verificationsOf(domain.id)[0]!.status).toBe('verified');
    expect(bed.store.domain(domain.id).status).toBe('active');
  });

  it('does nothing for deleted domains', async () => {
    const bed = createDomainTestbed();
    const domain = bed.store.addDomain(ORG_A, 'del.example.com', { status: 'deleted' });
    await bed.configuration.ensure(scopeA, domain.id);
    expect(bed.store.recordsOf(domain.id)).toEqual([]);
    expect(bed.store.keysOf(domain.id)).toEqual([]);
  });

  it('needs a key only when the algorithm has no pending or active one', () => {
    expect(needsKey([], 'rsa_2048')).toBe(true);
    expect(needsKey([{ algorithm: 'rsa_2048', status: 'rotating' }], 'rsa_2048')).toBe(true);
    expect(needsKey([{ algorithm: 'rsa_2048', status: 'active' }], 'rsa_2048')).toBe(false);
    expect(needsKey([{ algorithm: 'rsa_2048', status: 'pending' }], 'ed25519')).toBe(true);
  });
});

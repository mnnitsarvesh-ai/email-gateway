/**
 * `domain.dns.records_changed.v1` (step 6.2 §1.2, §4.1) against the real writer and an
 * in-process `TestDnsServer`: the domains module writes exactly one outbox row per check whose
 * stored record statuses change (in the check transaction, aggregate `domain`, strict payload of
 * ids and codes), none for a repeated identical check, none for an indeterminate (SERVFAIL)
 * check, and one naming only the failing record when a verified domain's SPF disappears.
 */
import { domainDnsRecordsChangedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { TestDnsServer } from '../test/support/dns/test-dns-server';
import type { IntegrationApp } from './support/app';
import {
  createDomainApp,
  DomainApi,
  domainEvents,
  domainRecordEvents,
  publishFromApi,
  publishGatewaySpf,
  uniqueDomainName,
} from './support/domains';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { bearer, loginWithMfa } from './support/http';

let dns: TestDnsServer;
let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let api: DomainApi;

beforeAll(async () => {
  dns = await TestDnsServer.start({ defaultTtl: 60 });
  publishGatewaySpf(dns);
  ctx = await createDomainApp(dns);
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  const user = await fx.createUser(org, { roles: ['organization_admin'] });
  api = new DomainApi(ctx, bearer((await loginWithMfa(ctx, fx, user)).accessToken));
}, 120_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
  await dns?.close();
});

describe('domain.dns.records_changed.v1 (step 6.2 §4.1)', () => {
  it('is written once per check that changes stored record statuses, never for repeats or indeterminate checks', async () => {
    const domain = await api.okCreate(uniqueDomainName('rc'));
    const records = await publishFromApi(api, dns, domain.id);
    const view = await api.okVerify(domain.id);
    expect(view.status).toBe('verified');

    const [first, ...rest] = await domainRecordEvents(ctx, domain.id);
    expect(rest).toEqual([]);
    expect(first).toMatchObject({
      organizationId: org.id,
      eventType: 'domain.dns.records_changed.v1',
      aggregateType: 'domain',
    });
    const payload = domainDnsRecordsChangedV1.parse(first!.payload);
    expect(payload).toMatchObject({
      domainPublicId: domain.id,
      name: domain.name,
      domainStatus: 'verified',
    });
    expect(payload.changes.length).toBeGreaterThanOrEqual(4);
    expect(payload.changes.every((c) => c.previousStatus === 'pending')).toBe(true);
    // The status event of the same transaction exists too (correlation of the same request).
    const [status] = await domainEvents(ctx, domain.id);
    expect(status!.correlationId).toBe(first!.correlationId);
    // Ids and codes only (record keys name the gateway MX host by design; TXT values never).
    const text = JSON.stringify(first!.payload);
    for (const record of records.filter((r) => r.type === 'TXT')) {
      expect(text).not.toContain(record.value);
    }
    expect(text).not.toMatch(/evidence|observed|expected/i);

    // The same DNS again: nothing changed, nothing written.
    await api.okVerify(domain.id);
    expect(await domainRecordEvents(ctx, domain.id)).toHaveLength(1);

    // SERVFAIL on the SPF host: indeterminate never changes a status.
    const spf = records.find((r) => r.purpose === 'spf')!;
    dns.fail(spf.host, 'servfail');
    await api.okVerify(domain.id);
    expect(await domainRecordEvents(ctx, domain.id)).toHaveLength(1);
    dns.clearFailure(spf.host);

    // The SPF record disappears: one event with exactly that transition.
    dns.remove(spf.host, 'TXT');
    await api.okVerify(domain.id);
    const events = await domainRecordEvents(ctx, domain.id);
    expect(events).toHaveLength(2);
    const failed = domainDnsRecordsChangedV1.parse(events[1]!.payload);
    expect(failed.domainStatus).toBe('verified');
    expect(failed.changes).toEqual([
      { recordKey: 'spf', purpose: 'spf', previousStatus: 'valid', status: 'missing' },
    ]);
    // Status events are unaffected (verified only).
    expect((await domainEvents(ctx, domain.id)).map((e) => e.eventType)).toEqual([
      'domain.status.changed.v1',
    ]);
  });
});

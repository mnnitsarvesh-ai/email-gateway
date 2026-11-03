import { randomInt } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  InSessionFixtures,
  type Services,
  socketmap,
  startServices,
} from './in-session-support/harness';

/**
 * Socketmap tables (step 2.2 D2, D11) in-process over TCP against the real MySQL writer and
 * Redis, including the outbox-tail cache invalidation (D5). Fixtures are removed afterwards.
 */
const fx = new InSessionFixtures();
let services: Services;
let port: number;

let org: bigint;
let active: { id: bigint; name: string };
let noInbound: string;
let noDestination: string;
let selfRouted: string;
let destinationHost: string;
let listDomain: string;
let m365: { id: bigint; name: string };
let cachedDomain: string;
let unsafe: string;
let mixedGateway: string;
const m365Host = () => `contoso-${fx.suffix}.mail.protection.outlook.com`;
let fingerprint: string;
const network: [number, number, number] = [100, randomInt(64, 128), randomInt(0, 256)];

beforeAll(async () => {
  org = await fx.organization('sm');
  const suspendedOrg = await fx.organization('sm-susp', 'suspended');
  active = await fx.domain(org, 'active');
  noInbound = (await fx.domain(org, 'noinbound', { inboundEnabled: false })).name;
  await fx.domain(suspendedOrg, 'orgsusp');
  destinationHost = `mx-${fx.suffix}.tenant-server.example`;
  await fx.destination(org, active.id, destinationHost, {
    port: 2525,
    priority: 20,
    tlsMode: 'opportunistic',
  });
  await fx.destination(org, active.id, `MX-${fx.suffix}.primary.example`, {
    priority: 5,
    tlsMode: 'verify',
  });
  await fx.destination(org, active.id, `disabled-${fx.suffix}.example`, {
    priority: 1,
    enabled: false,
  });
  // A second tenant domain sharing the 2525 destination with a stricter TLS mode.
  const shared = await fx.domain(org, 'shared');
  await fx.destination(org, shared.id, destinationHost, { port: 2525, tlsMode: 'required' });
  noDestination = (await fx.domain(org, 'nodest')).name;
  const self = await fx.domain(org, 'self');
  selfRouted = self.name;
  await fx.destination(org, self.id, 'mx.gateway.local');
  // Step 2.3: next-hop lists, presets, host safety.
  const list = await fx.domain(org, 'list');
  listDomain = list.name;
  await fx.destination(org, list.id, `c-${fx.suffix}.list.example`, { priority: 30 });
  await fx.destination(org, list.id, `a-${fx.suffix}.list.example`, { priority: 10 });
  await fx.destination(org, list.id, `b-${fx.suffix}.list.example`, { priority: 10, port: 2525 });
  m365 = await fx.domain(org, 'm365');
  await fx.destination(org, m365.id, m365Host(), {
    provider: 'microsoft_365',
    tlsMode: 'verify',
    tlsVerifyNames: 'nexthop:mail.protection.outlook.com:.mail.protection.outlook.com',
  });
  const cached = await fx.domain(org, 'cached');
  cachedDomain = cached.name;
  await fx.destination(org, cached.id, `alt4-${fx.suffix}.example`, { priority: 1 });
  const bad = await fx.domain(org, 'unsafe');
  unsafe = bad.name;
  await fx.destination(org, bad.id, '10.20.30.40', { priority: 1 });
  await fx.destination(org, bad.id, '169.254.169.254', { priority: 2 });
  await fx.destination(org, bad.id, 'mysql', { priority: 3 });
  await fx.destination(org, bad.id, `smtp-${fx.suffix}.corp.internal`, { priority: 4 });
  await fx.destination(org, bad.id, `ok-${fx.suffix}.unsafe.example`, { priority: 5 });
  const mixed = await fx.domain(org, 'mixedgw');
  mixedGateway = mixed.name;
  await fx.destination(org, mixed.id, `ok-${fx.suffix}.mixed.example`, { priority: 1 });
  await fx.destination(org, mixed.id, 'mx1.mail-gateway.test', { priority: 2 });
  await fx.sourceIpConnector(org, 'net', network);
  fingerprint = await fx.certificateConnector(org, 'cert');
  fx.extraRedisKeys.add(`sa:tls:v2:${destinationHost}`);
  fx.extraRedisKeys.add(`sa:tls:v2:mx-${fx.suffix}.primary.example`);
  // Negative cache entries of the shared non-tenant names and fingerprint probed below.
  for (const key of ['sa:dom:remote.example', `sa:conn:fp:${'ab'.repeat(32)}`]) {
    fx.extraRedisKeys.add(key);
  }

  services = await startServices({ SMTP_CACHE_INVALIDATION_POLL_MS: '200' });
  port = services.socketmapPort;
});

afterAll(async () => {
  await services?.close();
  await fx.cleanup();
});

describe('socketmap: relay_domain (D2)', () => {
  it('OK for an active inbound-enabled tenant domain, NOTFOUND otherwise', async () => {
    expect(await socketmap(port, 'relay_domain', active.name)).toBe('OK active');
    expect(await socketmap(port, 'relay_domain', active.name.toUpperCase())).toBe('OK active');
    expect(await socketmap(port, 'relay_domain', noInbound)).toBe('NOTFOUND ');
    expect(await socketmap(port, 'relay_domain', fx.name('orgsusp'))).toBe('NOTFOUND ');
    expect(await socketmap(port, 'relay_domain', `unknown-${fx.suffix}.test`)).toBe('NOTFOUND ');
    expect(await socketmap(port, 'relay_domain', `.${active.name}`)).toBe('NOTFOUND ');
    expect(await socketmap(port, 'relay_domain', `user@${active.name}`)).toBe('NOTFOUND ');
  });
});

describe('socketmap: transport and tls_policy (D11, step 2.3 R2/R3)', () => {
  it('routes a tenant domain to every enabled destination, in (priority, id) order', async () => {
    const list = `OK smtp:[mx-${fx.suffix}.primary.example]:25,[${destinationHost}]:2525`;
    expect(await socketmap(port, 'transport', active.name)).toBe(list);
    // What Postfix's trivial-rewrite actually sends: the full recipient address.
    expect(await socketmap(port, 'transport', `user@${active.name}`)).toBe(list);
  });

  it('answers a failover next-hop list ordered by priority, then insertion order', async () => {
    expect(await socketmap(port, 'transport', `u@${listDomain}`)).toBe(
      `OK smtp:[a-${fx.suffix}.list.example]:25,[b-${fx.suffix}.list.example]:2525,` +
        `[c-${fx.suffix}.list.example]:25`,
    );
  });

  it('skips private, metadata, single-label and internal hosts and keeps the valid one', async () => {
    expect(await socketmap(port, 'transport', `u@${unsafe}`)).toBe(
      `OK smtp:[ok-${fx.suffix}.unsafe.example]:25`,
    );
  });

  it('defers tenant domains without a destination or with any gateway host', async () => {
    for (const name of [noDestination, selfRouted, mixedGateway]) {
      expect(await socketmap(port, 'transport', `u@${name}`), name).toBe(
        'OK retry:4.4.1 Destination not configured',
      );
    }
  });

  it('NOTFOUND for non-tenant domains (MX resolution by Postfix)', async () => {
    expect(await socketmap(port, 'transport', 'remote.example')).toBe('NOTFOUND ');
  });

  it('answers the strictest TLS mode of a destination', async () => {
    expect(await socketmap(port, 'tls_policy', `[${destinationHost}]:2525`)).toBe(
      'OK encrypt protocols=>=TLSv1.2',
    );
    expect(await socketmap(port, 'tls_policy', `[mx-${fx.suffix}.primary.example]:25`)).toBe(
      'OK secure match=nexthop protocols=>=TLSv1.2',
    );
    expect(await socketmap(port, 'tls_policy', `[${destinationHost}]:25`)).toBe('NOTFOUND ');
    expect(await socketmap(port, 'tls_policy', 'remote.example')).toBe('NOTFOUND ');
  });

  it('answers a preset’s verify names (Microsoft 365)', async () => {
    expect(await socketmap(port, 'transport', `u@${m365.name}`)).toBe(`OK smtp:[${m365Host()}]:25`);
    expect(await socketmap(port, 'tls_policy', `[${m365Host()}]:25`)).toBe(
      'OK secure match=nexthop:mail.protection.outlook.com:.mail.protection.outlook.com ' +
        'protocols=>=TLSv1.2',
    );
  });

  it('serves the transport list from the v2 cache key (a 2.2 entry is never read)', async () => {
    await fx.redis.set(
      `sa:route:${cachedDomain}`,
      JSON.stringify({ host: 'stale.example', port: 25 }),
    );
    fx.extraRedisKeys.add(`sa:route:${cachedDomain}`);
    expect(await socketmap(port, 'transport', `u@${cachedDomain}`)).toBe(
      `OK smtp:[alt4-${fx.suffix}.example]:25`,
    );
    expect(await fx.redis.get(`sa:route:v2:${cachedDomain}`)).not.toBeNull();
  });
});

describe('socketmap: relay_client and relay_ccert (D11)', () => {
  it('relay_client: OK OK for an IP inside an active source_ip network only', async () => {
    const ip = fx.trackIp(`${network.join('.')}.42`);
    expect(await socketmap(port, 'relay_client', ip)).toBe('OK OK');
    expect(await socketmap(port, 'relay_client', network.join('.'))).toBe('NOTFOUND ');
    const outside = fx.trackIp(`${network[0]}.${network[1]}.${(network[2] + 1) % 256}.1`);
    expect(await socketmap(port, 'relay_client', outside)).toBe('NOTFOUND ');
  });

  it('relay_ccert: OK OK for the colon-separated upper-case fingerprint', async () => {
    const postfix = fingerprint.toUpperCase().match(/../g)!.join(':');
    expect(await socketmap(port, 'relay_ccert', postfix)).toBe('OK OK');
    expect(await socketmap(port, 'relay_ccert', 'AB:'.repeat(31) + 'AB')).toBe('NOTFOUND ');
  });

  it('PERM for unknown maps', async () => {
    expect(await socketmap(port, 'virtual_alias', 'x')).toBe('PERM Unknown map');
  });
});

describe('domain cache invalidation (D5)', () => {
  it('drops the cached view within one poll of a domain.status.changed outbox row', async () => {
    const domain = await fx.domain(org, 'invalidate');
    expect(await socketmap(port, 'relay_domain', domain.name)).toBe('OK active');
    expect(await fx.redis.get(`sa:dom:${domain.name}`)).not.toBeNull();
    await fx.prisma.domain.update({ where: { id: domain.id }, data: { status: 'suspended' } });
    // Still cached (TTL 60 s) until the event arrives.
    expect(await socketmap(port, 'relay_domain', domain.name)).toBe('OK active');
    await fx.domainStatusEvent(org, domain.id, domain.name, 'suspended');
    await expect
      .poll(() => socketmap(port, 'relay_domain', domain.name), { timeout: 5000, interval: 100 })
      .toBe('NOTFOUND ');
  });

  it('drops the route and TLS answers within one poll of a domain.routing.changed row', async () => {
    const domain = await fx.domain(org, 'reroute');
    const oldHost = `old-${fx.suffix}.reroute.example`;
    const newHost = `new-${fx.suffix}.reroute.example`;
    await fx.destination(org, domain.id, oldHost, { tlsMode: 'required' });
    expect(await socketmap(port, 'transport', `u@${domain.name}`)).toBe(`OK smtp:[${oldHost}]:25`);
    expect(await socketmap(port, 'tls_policy', `[${oldHost}]:25`)).toBe(
      'OK encrypt protocols=>=TLSv1.2',
    );
    // The api replaces the destinations in one transaction and writes the event.
    await fx.prisma.domainMailServer.deleteMany({ where: { domainId: domain.id } });
    await fx.destination(org, domain.id, newHost, { tlsMode: 'verify' });
    // Still cached (TTL 60 s) until the event arrives.
    expect(await socketmap(port, 'transport', `u@${domain.name}`)).toBe(`OK smtp:[${oldHost}]:25`);
    await fx.domainRoutingEvent(org, domain.id, domain.name, [oldHost, newHost]);
    await expect
      .poll(() => socketmap(port, 'transport', `u@${domain.name}`), {
        timeout: 5000,
        interval: 100,
      })
      .toBe(`OK smtp:[${newHost}]:25`);
    expect(await socketmap(port, 'tls_policy', `[${oldHost}]:25`)).toBe('NOTFOUND ');
    expect(await socketmap(port, 'tls_policy', `[${newHost}]:25`)).toBe(
      'OK secure match=nexthop protocols=>=TLSv1.2',
    );
  });
});

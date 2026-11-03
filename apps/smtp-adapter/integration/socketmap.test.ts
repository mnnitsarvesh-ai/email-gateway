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
  await fx.sourceIpConnector(org, 'net', network);
  fingerprint = await fx.certificateConnector(org, 'cert');
  fx.extraRedisKeys.add(`sa:tls:${destinationHost}:2525`);
  fx.extraRedisKeys.add(`sa:tls:mx-${fx.suffix}.primary.example:25`);
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

describe('socketmap: transport and tls_policy (D11)', () => {
  it('routes a tenant domain to its highest-priority enabled destination', async () => {
    expect(await socketmap(port, 'transport', active.name)).toBe(
      `OK smtp:[mx-${fx.suffix}.primary.example]:25`,
    );
    // What Postfix's trivial-rewrite actually sends: the full recipient address.
    expect(await socketmap(port, 'transport', `user@${active.name}`)).toBe(
      `OK smtp:[mx-${fx.suffix}.primary.example]:25`,
    );
  });

  it('defers tenant domains without a destination or routed to the gateway itself', async () => {
    expect(await socketmap(port, 'transport', noDestination)).toBe(
      'OK retry:4.4.1 Destination not configured',
    );
    expect(await socketmap(port, 'transport', selfRouted)).toBe(
      'OK retry:4.4.1 Destination not configured',
    );
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
    expect(await socketmap(port, 'tls_policy', 'remote.example')).toBe('NOTFOUND ');
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
});

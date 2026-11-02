/**
 * Domain onboarding end to end (step 2.1, design §9 `domains.test.ts`): real MySQL (writer +
 * replica) and Redis, the in-process API, and deterministic DNS from an in-process
 * `TestDnsServer` (`TestDohServer` for DoH mode). No test resolves a public name.
 *
 * Covers creation (records, encrypted DKIM keys, limits, name rules), verification (missing →
 * verified, NXDOMAIN/NODATA, SERVFAIL/timeout never change state), MX with propagation, SPF,
 * DKIM, DMARC, manual-verification limits, the lifecycle (activate, suspend, resume, delete,
 * re-add), "first to verify wins", DKIM rotation through retirement, audit and outbox rows, the
 * mail-path resolver and DoH mode.
 */
import { createPublicKey } from 'node:crypto';
import { resolveActiveDomain } from '@email-gateway/database';
import { domainStatusChangedV1, EventTypes } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SecretBox, SecretBoxError } from '../src/crypto/secret-box';
import { domainKvKeys } from '../src/modules/domains/domains.constants';
import { DomainCheckScheduler } from '../src/modules/domains/services/domain-check-scheduler.service';
import { TestDnsServer } from '../test/support/dns/test-dns-server';
import { TestDohServer } from '../test/support/dns/test-doh-server';
import type { IntegrationApp } from './support/app';
import {
  createDomainApp,
  DomainApi,
  type DomainBody,
  domainAudit,
  domainEvents,
  domainRow,
  GATEWAY_DMARC_RUA,
  GATEWAY_MX,
  GATEWAY_SPF_INCLUDE,
  jittered,
  publishFromApi,
  publishGatewaySpf,
  RESERVED_SUFFIX,
  resetVerifyLimit,
  SCHEDULE,
  secondsAfter,
  uniqueDomainName,
  VERIFICATION_LABEL,
} from './support/domains';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { bearer, loginWithMfa } from './support/http';

let dns: TestDnsServer;
let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let orgC: FixtureOrganization;
let apiA: DomainApi;
let apiB: DomainApi;
let apiC: DomainApi;

const POLL = { timeout: 10_000, interval: 200 };
const DAY_MS = 86_400_000;

async function adminApi(app: IntegrationApp, org: FixtureOrganization): Promise<DomainApi> {
  const user = await fx.createUser(org, { roles: ['organization_admin'] });
  const session = await loginWithMfa(app, fx, user);
  return new DomainApi(app, bearer(session.accessToken));
}

/** A new pending domain of org A. */
function newDomain(label = 'd', extra: Record<string, unknown> = {}): Promise<DomainBody> {
  return apiA.okCreate(uniqueDomainName(label), extra);
}

/** Publishes the ownership TXT and verifies: the domain is `verified`. */
async function verifiedDomain(label = 'v', api: DomainApi = apiA): Promise<DomainBody> {
  const domain = await api.okCreate(uniqueDomainName(label));
  await publishFromApi(api, dns, domain.id, ['verification']);
  const view = await api.okVerify(domain.id);
  expect(view.status).toBe('verified');
  return api.okGet(domain.id);
}

const recordOf = async (api: DomainApi, id: string, key: string) => {
  const { records } = await api.okRecords(id);
  const record = records.find((r) => r.key === key);
  if (!record) throw new Error(`no record ${key}`);
  return record;
};

beforeAll(async () => {
  dns = await TestDnsServer.start({ defaultTtl: 60 });
  publishGatewaySpf(dns);
  ctx = await createDomainApp(dns);
  fx = createFixtures(ctx);
  [orgA, orgB, orgC] = [
    await fx.createOrganization(),
    await fx.createOrganization(),
    await fx.createOrganization(),
  ];
  // The suite adds many domains to A; the plan's max_domains is tested separately.
  await ctx.prisma.organizationLimit.update({
    where: { organizationId_limitKey: { organizationId: orgA.id, limitKey: 'max_domains' } },
    data: { limitValue: 1000n },
  });
  apiA = await adminApi(ctx, orgA);
  apiB = await adminApi(ctx, orgB);
  apiC = await adminApi(ctx, orgC);
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
  await dns?.close();
});

describe('POST /domains', () => {
  it('creates the challenge, the DNS records and encrypted DKIM keys, never exposing key material', async () => {
    const name = uniqueDomainName('create');
    const before = Date.now();
    const res = await apiA.create({ name, dkim: { ed25519: true } }).expect(201);
    const created = res.body as DomainBody;

    expect(created).toMatchObject({
      name,
      unicodeName: name,
      status: 'pending_verification',
      statusReason: null,
      verifiedAt: null,
      activatedAt: null,
    });
    expect(secondsAfter(created.nextCheckAt, new Date(before))).toBeGreaterThanOrEqual(59);
    expect(secondsAfter(created.nextCheckAt, new Date(before))).toBeLessThan(90);
    expect(created.verification).toMatchObject({
      method: 'dns_txt',
      host: `${VERIFICATION_LABEL}.${name}`,
      status: 'pending',
      attempts: 0,
      lastOutcome: null,
    });
    expect(created.verification!.value).toMatch(/^emailgateway-verification=[0-9a-f]{40}$/);
    const ttlDays = secondsAfter(created.verification!.expiresAt, new Date(before)) / 86_400;
    expect(ttlDays).toBeGreaterThan(SCHEDULE.verificationTtlDays - 0.01);
    expect(ttlDays).toBeLessThan(SCHEDULE.verificationTtlDays + 0.01);

    // Keys: one RSA 2048 and one Ed25519, both pending, with D9 selectors.
    expect(created.dkimKeys).toHaveLength(2);
    const rsa = created.dkimKeys.find((k) => k.algorithm === 'rsa_2048')!;
    const ed = created.dkimKeys.find((k) => k.algorithm === 'ed25519')!;
    expect(rsa.selector).toMatch(/^egr\d{8}[a-z0-9]{4}$/);
    expect(ed.selector).toMatch(/^ege\d{8}[a-z0-9]{4}$/);
    for (const key of [rsa, ed]) {
      expect(key).toMatchObject({ status: 'pending', host: `${key.selector}._domainkey.${name}` });
    }

    // Records: shape, requirement, relative name, instructions.
    const records = created.dnsRecords!;
    expect(records.map((r) => r.key).sort()).toEqual(
      [
        'verification',
        ...GATEWAY_MX.map((mx) => `mx:${mx.exchange}`),
        'spf',
        `dkim:${rsa.selector}`,
        `dkim:${ed.selector}`,
        'dmarc',
      ].sort(),
    );
    const byKey = new Map(records.map((r) => [r.key, r]));
    expect(byKey.get('verification')).toMatchObject({
      purpose: 'verification',
      requirement: 'activation',
      type: 'TXT',
      host: `${VERIFICATION_LABEL}.${name}`,
      name: VERIFICATION_LABEL,
      value: created.verification!.value,
      priority: null,
      status: 'pending',
      lastOutcome: null,
      warnings: [],
    });
    for (const mx of GATEWAY_MX) {
      expect(byKey.get(`mx:${mx.exchange}`)).toMatchObject({
        purpose: 'mx',
        requirement: 'inbound',
        type: 'MX',
        host: name,
        name: '@',
        value: mx.exchange,
        priority: mx.priority,
      });
    }
    expect(byKey.get('spf')).toMatchObject({
      purpose: 'spf',
      requirement: 'outbound',
      type: 'TXT',
      name: '@',
      value: `v=spf1 include:${GATEWAY_SPF_INCLUDE} ~all`,
    });
    expect(byKey.get('spf')!.instructions).toMatch(/do not create a second SPF record/);
    expect(byKey.get('dmarc')).toMatchObject({
      purpose: 'dmarc',
      requirement: 'recommended',
      host: `_dmarc.${name}`,
      name: '_dmarc',
    });
    expect(byKey.get('dmarc')!.value).toMatch(/^v=DMARC1; p=none;/);
    expect(byKey.get('dmarc')!.value).toContain(`rua=${GATEWAY_DMARC_RUA}`);
    for (const record of records) expect(record.instructions.length).toBeGreaterThan(10);

    // The private keys are stored encrypted (ADR-0018) and bound to domain + selector.
    const row = await domainRow(ctx, created.id);
    const secretBox = ctx.get(SecretBox);
    for (const key of row.dkimKeys) {
      expect(key.status).toBe('pending');
      expect(key.privateKeyRef).toBeNull();
      expect(key.privateKeyCiphertext).toBeTruthy();
      const aad = `dkim:${created.id}:${key.selector}`;
      const pem = secretBox.decrypt(key.privateKeyCiphertext!, aad).plaintext;
      expect(pem).toMatch(/^-----BEGIN PRIVATE KEY-----\n/);
      const spki = createPublicKey(pem).export({ type: 'spki', format: 'der' });
      const published =
        key.algorithm === 'rsa_2048'
          ? spki.toString('base64')
          : spki.subarray(spki.length - 32).toString('base64');
      expect(key.publicKey).toBe(published);
      const record = byKey.get(`dkim:${key.selector}`)!;
      expect(record).toMatchObject({ purpose: 'dkim', requirement: 'outbound', type: 'TXT' });
      expect(record.value).toBe(
        `v=DKIM1; k=${key.algorithm === 'rsa_2048' ? 'rsa' : 'ed25519'}; p=${published}`,
      );
      // Wrong binding: undecryptable.
      expect(() =>
        secretBox.decrypt(key.privateKeyCiphertext!, `dkim:${created.id}:other`),
      ).toThrow(SecretBoxError);

      // Never in a response or a log line.
      const pemBody = pem.split('\n')[1]!;
      const responses = JSON.stringify([
        created,
        await apiA.okGet(created.id),
        await apiA.okRecords(created.id),
        await apiA.okStatus(created.id),
      ]);
      for (const secret of [pemBody, key.privateKeyCiphertext!]) {
        expect(responses).not.toContain(secret);
        expect(ctx.logs.join('\n')).not.toContain(secret);
      }
    }
    expect(JSON.stringify(created)).not.toMatch(/PRIVATE KEY|privateKey|ciphertext/i);
    expect(ctx.logs.join('\n')).not.toContain('PRIVATE KEY');

    // Audit; no status event for creation (events are for transitions).
    const audit = await domainAudit(ctx, created.id, 'domain.created');
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ organizationId: orgA.id, actorType: 'user' });
    expect(audit[0]!.metadata).toMatchObject({ name, algorithms: ['rsa_2048', 'ed25519'] });
    expect(JSON.stringify(audit[0]!.metadata)).not.toMatch(/emailgateway-verification|PRIVATE/);

    // The list (replica) shows it eventually.
    await expect
      .poll(async () => {
        const list = await apiA.list(`?q=${name}`).expect(200);
        return (list.body.data as Array<{ id: string }>).map((d) => d.id);
      }, POLL)
      .toEqual([created.id]);
  });

  it('normalizes IDN names and a trailing dot', async () => {
    const label = `bücher-${Date.now().toString(36)}`;
    const created = await apiA.okCreate(`${label.toUpperCase()}.Domains-IT.test.`);
    expect(created.name).toMatch(/^xn--bcher-[a-z0-9-]+\.domains-it\.test$/);
    expect(created.unicodeName).toBe(`${label}.domains-it.test`);
    // The same name in another spelling is a duplicate.
    const dup = await apiA.create({ name: created.unicodeName }).expect(409);
    expect(dup.body.message).toBe('Domain already exists');
  });

  it('rejects invalid and reserved names with 400', async () => {
    const invalid = [
      '',
      'not a domain',
      'single',
      '-leading.domains-it.test',
      '*.wild.domains-it.test',
      'under_score.domains-it.test',
      '192.0.2.1',
      `${'a'.repeat(64)}.domains-it.test`,
      `${'abcdefghi.'.repeat(25)}domains-it.test`,
    ];
    const reserved = [
      'localhost',
      'printer.local',
      'svc.internal',
      `x.${RESERVED_SUFFIX}`,
      GATEWAY_MX[0].exchange,
      'mail-gateway.test.example.arpa',
    ];
    for (const name of [...invalid, ...reserved]) {
      const res = await apiA.create({ name });
      expect({ name, status: res.status }).toEqual({ name, status: 400 });
    }
    const res = await apiA.create({ name: `x.${RESERVED_SUFFIX}` }).expect(400);
    expect(JSON.stringify(res.body.message)).toContain('reserved');
    await apiA.create({ name: 'ok.domains-it.test', unknown: true }).expect(400);
  });

  it('enforces max_domains (deleted domains do not count) and rejects duplicates', async () => {
    const org = await fx.createOrganization();
    const api = await adminApi(ctx, org);
    await ctx.prisma.organizationLimit.update({
      where: { organizationId_limitKey: { organizationId: org.id, limitKey: 'max_domains' } },
      data: { limitValue: 2n },
    });
    const first = await api.okCreate(uniqueDomainName('limit'));
    const dup = await api.create({ name: first.name }).expect(409);
    expect(dup.body.message).toBe('Domain already exists');

    await api.okCreate(uniqueDomainName('limit'));
    const over = await api.create({ name: uniqueDomainName('limit') }).expect(409);
    expect(over.body.message).toBe('Organization limit reached: max_domains');

    await api.remove(first.id).expect(204);
    await api.okCreate(uniqueDomainName('limit'));
  });
});

describe('ownership verification', () => {
  it('moves from missing to verified once the TXT record is published', async () => {
    const domain = await newDomain('verify');
    const host = domain.verification!.host;

    const missing = await apiA.okVerify(domain.id);
    expect(missing).toMatchObject({
      status: 'pending_verification',
      readyForActivation: false,
      mailFlowReady: false,
      checkFailures: 0,
    });
    expect(missing.checks.ownership).toMatchObject({ status: 'missing', lastOutcome: 'missing' });
    expect((await apiA.okGet(domain.id)).verification).toMatchObject({
      attempts: 1,
      lastOutcome: 'missing',
    });

    // Another token at the same host (another organization's claim) does not hurt.
    dns.setTxt(host, ['emailgateway-verification=' + '0'.repeat(40), domain.verification!.value]);
    const started = new Date();
    const verified = await apiA.okVerify(domain.id);
    expect(verified).toMatchObject({ status: 'verified', readyForActivation: true });
    expect(verified.checks.ownership).toMatchObject({ status: 'valid', lastOutcome: 'valid' });
    // Other records are not valid yet: rechecked at the "incomplete" interval.
    const [low, high] = jittered(SCHEDULE.recheckIncomplete);
    expect(secondsAfter(verified.nextCheckAt, started)).toBeGreaterThanOrEqual(low);
    expect(secondsAfter(verified.nextCheckAt, started)).toBeLessThanOrEqual(high);

    const detail = await apiA.okGet(domain.id);
    expect(detail.verifiedAt).not.toBeNull();
    expect(detail.verification).toMatchObject({ status: 'verified', attempts: 2 });
    const row = await domainRow(ctx, domain.id);
    expect(row.verifiedName).toBe(domain.name);

    const audit = await domainAudit(ctx, domain.id, 'domain.verified');
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toMatchObject({ from: 'pending_verification', to: 'verified' });
    const events = await domainEvents(ctx, domain.id);
    expect(events.map((e) => (e.payload as { status: string }).status)).toEqual(['verified']);

    // Verifying again is idempotent: no new transition, audit or event.
    await apiA.okVerify(domain.id);
    expect(await domainAudit(ctx, domain.id, 'domain.verified')).toHaveLength(1);
    expect(await domainEvents(ctx, domain.id)).toHaveLength(1);
  });

  it('treats NXDOMAIN and NODATA alike as missing', async () => {
    const nx = await newDomain('nx');
    const nodata = await newDomain('nodata');
    // NODATA: the name exists (it has an MX record) but no TXT.
    dns.setMx(nodata.verification!.host, [{ priority: 10, exchange: 'mx.elsewhere.test' }]);

    for (const [domain, outcome] of [
      [nx, 'nxdomain'],
      [nodata, 'nodata'],
    ] as const) {
      const view = await apiA.okVerify(domain.id);
      expect(view.status).toBe('pending_verification');
      expect(view.checks.ownership.status).toBe('missing');
      const row = await domainRow(ctx, domain.id);
      expect(row.verifications[0]!.evidence).toMatchObject({ query: { outcome } });
      expect(row.checkFailures).toBe(0);
    }
  });

  it('never changes state on SERVFAIL or timeouts; it backs off and retries', async () => {
    const domain = await newDomain('flaky');
    const host = domain.verification!.host;
    await apiA.okVerify(domain.id); // missing

    dns.fail(host, 'servfail');
    let started = new Date();
    let view = await apiA.okVerify(domain.id);
    expect(view.status).toBe('pending_verification');
    expect(view.checkFailures).toBe(1);
    expect(view.checks.ownership).toMatchObject({
      status: 'missing',
      lastOutcome: 'indeterminate',
    });
    let [low, high] = jittered(SCHEDULE.retryBase);
    expect(secondsAfter(view.nextCheckAt, started)).toBeGreaterThanOrEqual(low);
    expect(secondsAfter(view.nextCheckAt, started)).toBeLessThanOrEqual(high);
    let record = await recordOf(apiA, domain.id, 'verification');
    expect(record).toMatchObject({ status: 'missing', lastOutcome: 'indeterminate' });
    expect(record.lastError).toMatch(/^servfail: /);

    dns.fail(host, 'timeout');
    started = new Date();
    view = await apiA.okVerify(domain.id);
    expect(view.status).toBe('pending_verification');
    expect(view.checkFailures).toBe(2);
    [low, high] = jittered(SCHEDULE.retryBase * 2);
    expect(secondsAfter(view.nextCheckAt, started)).toBeGreaterThanOrEqual(low);
    expect(secondsAfter(view.nextCheckAt, started)).toBeLessThanOrEqual(high);
    record = await recordOf(apiA, domain.id, 'verification');
    expect(record).toMatchObject({ status: 'missing', lastOutcome: 'indeterminate' });
    expect(record.lastError).toMatch(/^timeout: /);
    const detail = await apiA.okGet(domain.id);
    expect(detail.verification).toMatchObject({ status: 'pending', lastOutcome: 'indeterminate' });
    expect(detail.verification!.lastError).toMatch(/^timeout: /);

    // Even with the record published, an indeterminate answer does not verify.
    dns.setTxt(host, [domain.verification!.value]);
    view = await apiA.okVerify(domain.id);
    expect(view.status).toBe('pending_verification');
    expect(view.checkFailures).toBe(3);

    dns.clearFailure(host);
    view = await apiA.okVerify(domain.id);
    expect(view).toMatchObject({ status: 'verified', checkFailures: 0 });

    // An owned domain whose ownership record cannot be resolved stays as it is.
    dns.fail(host, 'servfail');
    view = await apiA.okVerify(domain.id);
    expect(view.status).toBe('verified');
    expect(view.checks.ownership).toMatchObject({ status: 'valid', lastOutcome: 'indeterminate' });
    dns.clearFailure(host);

    // Indeterminate checks wrote no transition rows.
    expect((await domainAudit(ctx, domain.id)).map((a) => a.action)).toEqual([
      'domain.created',
      'domain.verified',
    ]);
    expect(await domainEvents(ctx, domain.id)).toHaveLength(1);
  });

  it('records the ownership record disappearing from an owned domain without changing its status', async () => {
    const domain = await verifiedDomain('gone');
    dns.remove(domain.verification!.host);
    const view = await apiA.okVerify(domain.id);
    expect(view.status).toBe('verified');
    expect(view.checks.ownership.status).toBe('missing');
    const audit = await domainAudit(ctx, domain.id, 'domain.ownership_record_missing');
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ actorType: 'user' });
    // Only on the valid → missing transition.
    await apiA.okVerify(domain.id);
    expect(await domainAudit(ctx, domain.id, 'domain.ownership_record_missing')).toHaveLength(1);
  });

  it('limits manual verification per domain (429 with Retry-After) and refuses concurrent checks (409)', async () => {
    const domain = await newDomain('limits');
    await resetVerifyLimit(ctx, domain.id);
    // Six per minute per domain, whatever the client address.
    for (let i = 0; i < 6; i++) await apiA.verify(domain.id).expect(200);
    const limited = await apiA.verify(domain.id).expect(429);
    const retryAfter = Number(limited.headers['retry-after']);
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(60);

    // A check holding the per-domain lock → 409.
    await resetVerifyLimit(ctx, domain.id);
    const row = await domainRow(ctx, domain.id);
    await ctx.kv.set(domainKvKeys.checkLock(row.id), 'another-check', 30);
    const busy = await apiA.verify(domain.id).expect(409);
    expect(busy.body.message).toBe('Verification already in progress');
    await ctx.kv.del(domainKvKeys.checkLock(row.id));

    // Two concurrent requests: one runs (slowed by a DNS timeout), the other is refused.
    await resetVerifyLimit(ctx, domain.id);
    dns.fail(domain.verification!.host, 'timeout');
    const results = await Promise.all([apiA.verify(domain.id), apiA.verify(domain.id)]);
    dns.clearFailure(domain.verification!.host);
    expect(results.map((r) => r.status).sort()).toEqual([200, 409]);
    // The lock is released afterwards.
    expect(await ctx.kv.exists(domainKvKeys.checkLock(row.id))).toBe(false);
  });

  it('lets the first organization to verify win; the other claims fail and are audited', async () => {
    const name = uniqueDomainName('contested');
    const a = await apiA.okCreate(name);
    const b = await apiB.okCreate(name); // a pending claim elsewhere does not block creation
    expect(b.verification!.value).not.toBe(a.verification!.value);
    dns.setTxt(a.verification!.host, [a.verification!.value, b.verification!.value]);

    expect((await apiA.okVerify(a.id)).status).toBe('verified');
    const lost = await apiB.okGet(b.id);
    expect(lost).toMatchObject({
      status: 'failed',
      statusReason: 'claimed_by_another_organization',
      nextCheckAt: null,
    });
    expect(JSON.stringify(lost)).not.toContain(orgA.publicId);
    const superseded = await domainAudit(ctx, b.id, 'domain.claim_superseded');
    expect(superseded).toHaveLength(1);
    expect(superseded[0]).toMatchObject({ organizationId: orgB.id, actorType: 'system' });
    expect(superseded[0]!.metadata).toMatchObject({
      from: 'pending_verification',
      to: 'failed',
      reason: 'claimed_by_another_organization',
    });
    const events = await domainEvents(ctx, b.id);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ organizationId: orgB.id });

    // Nobody else can add the owned name.
    const owned = await apiC.create({ name }).expect(409);
    expect(owned.body.message).toBe('Domain is already registered with another organization');

    // B retries: verification restarts and fails again (the name is owned elsewhere).
    const retried = await apiB.okVerify(b.id);
    expect(retried).toMatchObject({
      status: 'failed',
      statusReason: 'claimed_by_another_organization',
    });
    expect((await domainAudit(ctx, b.id)).map((r) => r.action)).toEqual([
      'domain.created',
      'domain.claim_superseded',
      'domain.verification_restarted',
      'domain.claim_superseded',
    ]);
    expect((await domainRow(ctx, a.id)).status).toBe('verified');
  });

  it('decides a simultaneous race between two organizations for exactly one winner', async () => {
    const name = uniqueDomainName('race');
    const a = await apiA.okCreate(name);
    const b = await apiB.okCreate(name);
    dns.setTxt(a.verification!.host, [a.verification!.value, b.verification!.value]);
    await resetVerifyLimit(ctx, a.id);
    await resetVerifyLimit(ctx, b.id);
    const [ra, rb] = await Promise.all([apiA.verify(a.id), apiB.verify(b.id)]);
    expect([ra.status, rb.status]).toEqual([200, 200]);
    const statuses = [
      (await domainRow(ctx, a.id)).status,
      (await domainRow(ctx, b.id)).status,
    ].sort();
    expect(statuses).toEqual(['failed', 'verified']);
    const owners = await ctx.prisma.domain.count({ where: { verifiedName: name } });
    expect(owners).toBe(1);
  });
});

describe('MX, SPF, DKIM and DMARC checks', () => {
  it('evaluates MX records: missing, valid, and invalid with non-gateway hosts', async () => {
    const domain = await verifiedDomain('mx');
    let view = await apiA.okVerify(domain.id);
    expect(view.checks.mx).toMatchObject({ status: 'missing', observed: [], propagation: [] });

    await publishFromApi(apiA, dns, domain.id, ['mx']);
    view = await apiA.okVerify(domain.id);
    expect(view.checks.mx.status).toBe('valid');
    expect(view.checks.mx.observed).toEqual(
      GATEWAY_MX.map((mx) => ({ priority: mx.priority, host: mx.exchange, pointsToGateway: true })),
    );
    expect(view.mailFlowReady).toBe(false); // not active yet

    dns.setMx(domain.name, [
      { priority: 5, exchange: 'mx.old-provider.test' },
      { priority: 10, exchange: GATEWAY_MX[0].exchange },
    ]);
    view = await apiA.okVerify(domain.id);
    expect(view.checks.mx.status).toBe('invalid');
    expect(view.checks.mx.warnings).toEqual(
      expect.arrayContaining(['mx_non_gateway_hosts', 'mx_gateway_bypass_possible']),
    );
    expect(view.checks.mx.observed).toEqual([
      { priority: 5, host: 'mx.old-provider.test', pointsToGateway: false },
      { priority: 10, host: GATEWAY_MX[0].exchange, pointsToGateway: true },
    ]);
    const row = await domainRow(ctx, domain.id);
    expect(row.mxRecords.map((m) => m.host)).toEqual([
      'mx.old-provider.test',
      GATEWAY_MX[0].exchange,
    ]);
    const mxRecord = await recordOf(apiA, domain.id, `mx:${GATEWAY_MX[1].exchange}`);
    expect(mxRecord.status).toBe('invalid');
    expect(mxRecord.observedValue).toContain('mx.old-provider.test');
  });

  it('merges SPF into an existing record, flags multiple records and the 10-lookup limit', async () => {
    const domain = await verifiedDomain('spf');
    const other = 'include:_spf.other-provider.test';
    dns.setTxt(domain.name, ['google-site-verification=abc123', `v=spf1 ${other} -all`]);
    let view = await apiA.okVerify(domain.id);
    const merged = `v=spf1 include:${GATEWAY_SPF_INCLUDE} ${other} -all`;
    expect(view.checks.spf).toMatchObject({ status: 'invalid', recommendedValue: merged });
    expect((await recordOf(apiA, domain.id, 'spf')).value).toBe(merged);

    // Publishing the merged record (other TXT records untouched) makes it valid.
    dns.setTxt(domain.name, ['google-site-verification=abc123', merged]);
    view = await apiA.okVerify(domain.id);
    expect(view.checks.spf).toMatchObject({ status: 'valid', recommendedValue: merged });
    expect(view.checks.spf.lookupCount).toBe(2);

    // Two SPF records: receivers return permerror.
    dns.setTxt(domain.name, [merged, `v=spf1 include:${GATEWAY_SPF_INCLUDE} ~all`]);
    view = await apiA.okVerify(domain.id);
    expect(view.checks.spf.status).toBe('invalid');
    expect(view.checks.spf.warnings).toContain('spf_multiple_records');

    // Nested includes beyond 10 DNS lookups.
    const big = `big.${domain.name}`;
    const nested = `nested.${domain.name}`;
    dns.setTxt(nested, [
      `v=spf1 ${Array.from({ length: 6 }, (_, i) => `a:h${i}.${domain.name}`).join(' ')} -all`,
    ]);
    dns.setTxt(big, [`v=spf1 include:${nested} a mx -all`]);
    dns.setTxt(domain.name, [`v=spf1 include:${GATEWAY_SPF_INCLUDE} include:${big} -all`]);
    view = await apiA.okVerify(domain.id);
    expect(view.checks.spf.status).toBe('invalid');
    expect(view.checks.spf.warnings).toContain('spf_lookup_limit_exceeded');
    expect(view.checks.spf.lookupCount).toBe(11);
  });

  it('activates a DKIM key once its record is published on an owned domain', async () => {
    const pending = await newDomain('dkim-pending');
    await publishFromApi(apiA, dns, pending.id, ['dkim']);
    let view = await apiA.okVerify(pending.id);
    // The record is valid, but keys activate only after ownership is verified.
    expect(view.checks.dkim.selectors).toEqual([
      expect.objectContaining({ keyStatus: 'pending', recordStatus: 'valid' }),
    ]);

    await publishFromApi(apiA, dns, pending.id, ['verification']);
    view = await apiA.okVerify(pending.id);
    expect(view.status).toBe('verified');
    expect(view.checks.dkim).toMatchObject({ status: 'valid' });
    expect(view.checks.dkim.selectors).toEqual([
      expect.objectContaining({ keyStatus: 'active', recordStatus: 'valid' }),
    ]);
    const key = (await apiA.okGet(pending.id)).dkimKeys[0]!;
    expect(key.activatedAt).not.toBeNull();
    const audit = await domainAudit(ctx, pending.id, 'domain.dkim_key_activated');
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toMatchObject({ selector: key.selector, previousSelector: null });

    // A different public key in DNS is invalid (the key stays active: DNS never revokes keys).
    dns.setTxt(key.host, ['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwrong']);
    view = await apiA.okVerify(pending.id);
    expect(view.checks.dkim.status).toBe('invalid');
    expect(view.checks.dkim.warnings).toContain('dkim_public_key_mismatch');
    expect(view.checks.dkim.selectors[0]).toMatchObject({ keyStatus: 'active' });
  });

  it('guides DMARC from none through quarantine to reject', async () => {
    const domain = await verifiedDomain('dmarc');
    let view = await apiA.okVerify(domain.id);
    expect(view.checks.dmarc).toMatchObject({ status: 'missing', stage: 'missing' });
    expect(view.checks.dmarc.recommendedValue).toMatch(/^v=DMARC1; p=none;/);

    const own = `mailto:dmarc@${domain.name}`;
    const host = `_dmarc.${domain.name}`;
    dns.setTxt(host, [`v=DMARC1; p=none; rua=${own}`]);
    view = await apiA.okVerify(domain.id);
    expect(view.checks.dmarc).toMatchObject({ status: 'valid', stage: 'none' });
    expect(view.checks.dmarc.warnings).toEqual(
      expect.arrayContaining(['dmarc_policy_none', 'dmarc_external_rua_needs_authorization']),
    );
    expect(view.checks.dmarc.recommendedValue).toMatch(/p=quarantine/);
    expect(view.checks.dmarc.recommendedValue).toContain(`rua=${own},${GATEWAY_DMARC_RUA}`);
    expect(view.checks.dmarc.nextStep).toMatch(/quarantine/);

    dns.setTxt(host, [`v=DMARC1; p=quarantine; pct=50; rua=${own}`]);
    view = await apiA.okVerify(domain.id);
    expect(view.checks.dmarc).toMatchObject({ stage: 'quarantine' });
    expect(view.checks.dmarc.warnings).toContain('dmarc_pct_partial');
    expect(view.checks.dmarc.recommendedValue).toMatch(/p=quarantine; pct=100/);

    dns.setTxt(host, [`v=DMARC1; p=quarantine; rua=${own}`]);
    view = await apiA.okVerify(domain.id);
    expect(view.checks.dmarc.recommendedValue).toMatch(/p=reject/);
    expect(view.checks.dmarc.nextStep).toMatch(/reject/);

    dns.setTxt(host, [`v=DMARC1; p=reject; rua=${own},${GATEWAY_DMARC_RUA}`]);
    view = await apiA.okVerify(domain.id);
    expect(view.checks.dmarc).toMatchObject({ status: 'valid', stage: 'reject' });
    expect(view.checks.dmarc.recommendedValue).toMatch(/p=reject/);
    expect(view.checks.dmarc.nextStep).toMatch(/No change needed/);

    dns.setTxt(host, ['v=DMARC1; p=none', 'v=DMARC1; p=reject']);
    view = await apiA.okVerify(domain.id);
    expect(view.checks.dmarc.status).toBe('invalid');
    expect(view.checks.dmarc.warnings).toContain('dmarc_multiple_records');
    // DMARC never gates anything: the domain stays verified.
    expect(view.status).toBe('verified');
  });

  it('reports a fully configured, active domain as ready for mail flow', async () => {
    const domain = await newDomain('complete');
    await publishFromApi(apiA, dns, domain.id);
    let view = await apiA.okVerify(domain.id);
    expect(view.status).toBe('verified');
    await apiA.setStatus(domain.id, { status: 'active' }).expect(200);
    const started = new Date();
    view = await apiA.okVerify(domain.id);
    expect(view).toMatchObject({ status: 'active', mailFlowReady: true, checkFailures: 0 });
    for (const check of Object.values(view.checks)) expect(check.status).toBe('valid');
    const [low, high] = jittered(SCHEDULE.recheckInterval);
    expect(secondsAfter(view.nextCheckAt, started)).toBeGreaterThanOrEqual(low);
    expect(secondsAfter(view.nextCheckAt, started)).toBeLessThanOrEqual(high);
  });
});

describe('MX propagation (second upstream)', () => {
  let upstream: TestDnsServer;
  let app: IntegrationApp;
  let api: DomainApi;

  beforeAll(async () => {
    upstream = await TestDnsServer.start({ defaultTtl: 60 });
    app = await createDomainApp(dns, { DNS_PROPAGATION_UPSTREAMS: upstream.address });
    api = new DomainApi(app, apiA.headers);
  });

  afterAll(async () => {
    await app?.close();
    await upstream?.close();
  });

  it('is valid only when every upstream agrees; unknown upstreams only warn', async () => {
    const domain = await api.okCreate(uniqueDomainName('prop'));
    await publishFromApi(api, dns, domain.id, ['verification', 'mx']);
    const gatewayMx = GATEWAY_MX.map((mx) => ({ priority: mx.priority, exchange: mx.exchange }));
    const id = `system:${upstream.address}`;

    upstream.setMx(domain.name, gatewayMx);
    let view = await api.okVerify(domain.id);
    expect(view.status).toBe('verified');
    expect(view.checks.mx.status).toBe('valid');
    expect(view.checks.mx.propagation).toEqual([{ upstream: id, outcome: 'valid' }]);

    upstream.setMx(domain.name, [{ priority: 10, exchange: 'mx.old-provider.test' }]);
    view = await api.okVerify(domain.id);
    expect(view.checks.mx.status).toBe('invalid');
    expect(view.checks.mx.warnings).toContain('mx_not_propagated');
    expect(view.checks.mx.propagation).toEqual([{ upstream: id, outcome: 'invalid' }]);

    upstream.fail(domain.name, 'servfail');
    view = await api.okVerify(domain.id);
    expect(view.checks.mx.status).toBe('valid');
    expect(view.checks.mx.warnings).toContain(`mx_propagation_unknown:${id}`);
    expect(view.checks.mx.propagation).toEqual([{ upstream: id, outcome: 'indeterminate' }]);
    expect(view.checkFailures).toBe(0);
  });
});

describe('lifecycle: activate, suspend, resume, delete, re-add', () => {
  it('follows the D3 state machine with audit rows, outbox events and the mail-path resolver', async () => {
    const pending = await newDomain('pending');
    const notYet = await apiA.setStatus(pending.id, { status: 'active' }).expect(409);
    expect(notYet.body.message).toBe('Domain is pending_verification');
    await apiA.setStatus(pending.id, { status: 'suspended', reason: 'x' }).expect(409);

    const domain = await verifiedDomain('life');
    expect(await resolveActiveDomain(ctx.prisma, domain.name)).toBeNull(); // verified only

    const active = await apiA.setStatus(domain.id, { status: 'active' }).expect(200);
    expect(active.body).toMatchObject({ status: 'active', statusReason: null });
    const activatedAt = active.body.activatedAt as string;
    expect(activatedAt).not.toBeNull();
    const resolved = await resolveActiveDomain(ctx.prisma, `${domain.name.toUpperCase()}.`);
    expect(resolved).toMatchObject({
      domainPublicId: domain.id,
      organizationId: orgA.id,
      name: domain.name,
      inboundEnabled: true,
      outboundEnabled: false,
    });
    await apiA.setStatus(domain.id, { status: 'active' }).expect(409);

    // A suspension needs a reason.
    await apiA.setStatus(domain.id, { status: 'suspended' }).expect(400);
    const deleteActive = await apiA.remove(domain.id).expect(409);
    expect(deleteActive.body.message).toBe('Suspend the domain before deleting it');

    const suspended = await apiA
      .setStatus(domain.id, { status: 'suspended', reason: 'Migrating to another provider' })
      .expect(200);
    expect(suspended.body).toMatchObject({
      status: 'suspended',
      statusReason: 'Migrating to another provider',
    });
    expect(await resolveActiveDomain(ctx.prisma, domain.name)).toBeNull();

    const resumed = await apiA.setStatus(domain.id, { status: 'active' }).expect(200);
    expect(resumed.body).toMatchObject({ status: 'active', statusReason: null, activatedAt });

    await apiA.setStatus(domain.id, { status: 'suspended', reason: 'Offboarding' }).expect(200);
    await apiA.remove(domain.id).expect(204);
    for (const call of [
      () => apiA.get(domain.id),
      () => apiA.dnsRecords(domain.id),
      () => apiA.status(domain.id),
      () => apiA.verify(domain.id),
      () => apiA.rotate(domain.id),
      () => apiA.setStatus(domain.id, { status: 'active' }),
      () => apiA.remove(domain.id),
    ]) {
      await call().expect(404);
    }
    const row = await domainRow(ctx, domain.id);
    expect(row).toMatchObject({
      status: 'deleted',
      verifiedName: null,
      liveName: null,
      nextCheckAt: null,
    });
    expect(row.deletedAt).not.toBeNull();
    expect(row.dkimKeys.length).toBeGreaterThan(0);
    for (const key of row.dkimKeys) {
      expect(key).toMatchObject({ status: 'revoked', privateKeyCiphertext: null });
    }
    expect(await resolveActiveDomain(ctx.prisma, domain.name)).toBeNull();
    await expect
      .poll(async () => {
        const list = await apiA.list(`?q=${domain.name}`).expect(200);
        return list.body.data.length as number;
      }, POLL)
      .toBe(0);

    // Audit trail and events, in order.
    const audit = await domainAudit(ctx, domain.id);
    expect(audit.map((a) => a.action)).toEqual([
      'domain.created',
      'domain.verified',
      'domain.status_changed',
      'domain.status_changed',
      'domain.status_changed',
      'domain.status_changed',
      'domain.deleted',
    ]);
    expect(audit.map((a) => a.metadata)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ from: 'verified', to: 'active' }),
        expect.objectContaining({
          from: 'active',
          to: 'suspended',
          reason: 'Migrating to another provider',
        }),
        expect.objectContaining({ from: 'suspended', to: 'deleted' }),
      ]),
    );
    expect(audit.at(-1)!.metadata).toMatchObject({
      revokedSelectors: domain.dkimKeys.map((k) => k.selector),
    });
    const events = await domainEvents(ctx, domain.id);
    const payloads = events.map((e) => domainStatusChangedV1.parse(e.payload));
    expect(payloads.map((p) => `${p.previousStatus}->${p.status}`)).toEqual([
      'pending_verification->verified',
      'verified->active',
      'active->suspended',
      'suspended->active',
      'active->suspended',
      'suspended->deleted',
    ]);
    for (const [i, event] of events.entries()) {
      expect(event).toMatchObject({
        eventType: EventTypes.DomainStatusChanged,
        aggregateType: 'domain',
        organizationId: orgA.id,
      });
      expect(event.correlationId.length).toBeGreaterThan(0);
      expect(payloads[i]).toMatchObject({ domainPublicId: domain.id, name: domain.name });
    }
    expect(payloads[2]!.reason).toBe('Migrating to another provider');

    // The name is free again: the organization can add it anew (a new row).
    const again = await apiA.okCreate(domain.name);
    expect(again.id).not.toBe(domain.id);
    expect(again.status).toBe('pending_verification');
    // ... and since nobody owns it, it can be verified again.
    await publishFromApi(apiA, dns, again.id, ['verification']);
    expect((await apiA.okVerify(again.id)).status).toBe('verified');
  });

  it('deletes pending and failed domains directly', async () => {
    const domain = await newDomain('del');
    await apiA.remove(domain.id).expect(204);
    const row = await domainRow(ctx, domain.id);
    expect(row.status).toBe('deleted');
    expect(row.verifications.map((v) => v.status)).toEqual(['expired']);
  });
});

describe('DKIM rotation', () => {
  it('rotates through activation, overlap and retirement', async () => {
    const domain = await newDomain('rotate');
    await publishFromApi(apiA, dns, domain.id, ['verification', 'dkim']);
    await apiA.okVerify(domain.id);
    const first = (await apiA.okGet(domain.id)).dkimKeys[0]!;
    expect(first.status).toBe('active');

    const rotated = await apiA.rotate(domain.id).expect(201);
    expect(rotated.body).toMatchObject({
      domainId: domain.id,
      key: { algorithm: 'rsa_2048', status: 'pending' },
      previous: { selector: first.selector, status: 'active' },
      overlapDays: SCHEDULE.overlapDays,
    });
    const second = rotated.body.key.selector as string;
    expect(second).not.toBe(first.selector);
    expect(rotated.body.dnsRecord).toMatchObject({
      key: `dkim:${second}`,
      host: `${second}._domainkey.${domain.name}`,
      status: 'pending',
    });
    expect(rotated.body.dnsRecord.value).toMatch(/^v=DKIM1; k=rsa; p=/);
    const started = await domainAudit(ctx, domain.id, 'domain.dkim_rotation_started');
    expect(started).toHaveLength(1);
    expect(started[0]!.metadata).toMatchObject({
      algorithm: 'rsa_2048',
      selector: second,
      previousSelector: first.selector,
    });

    // A rotation is already in progress.
    const again = await apiA.rotate(domain.id, { algorithm: 'rsa_2048' }).expect(409);
    expect(again.body.message).toBe('A DKIM rotation is already in progress');

    // Publish the new selector (the old one stays published): new active, old rotating.
    await publishFromApi(apiA, dns, domain.id, ['dkim']);
    const now = new Date();
    await apiA.okVerify(domain.id);
    let keys = (await apiA.okGet(domain.id)).dkimKeys;
    const byselector = (s: string) => keys.find((k) => k.selector === s)!;
    expect(byselector(second).status).toBe('active');
    expect(byselector(first.selector).status).toBe('rotating');
    const overlapDays = secondsAfter(byselector(first.selector).retireAfter, now) / (DAY_MS / 1000);
    expect(overlapDays).toBeGreaterThan(SCHEDULE.overlapDays - 0.01);
    expect(overlapDays).toBeLessThan(SCHEDULE.overlapDays + 0.01);
    const activated = await domainAudit(ctx, domain.id, 'domain.dkim_key_activated');
    expect(activated.at(-1)!.metadata).toMatchObject({
      selector: second,
      previousSelector: first.selector,
    });
    // Both selectors are still listed to publish during the overlap.
    let records = await apiA.okRecords(domain.id);
    expect(records.records.filter((r) => r.purpose === 'dkim').map((r) => r.key)).toEqual(
      expect.arrayContaining([`dkim:${first.selector}`, `dkim:${second}`]),
    );

    // The overlap ends: the scheduler retires the old key.
    await ctx.prisma.domain.updateMany({
      where: { organizationId: orgA.id, nextCheckAt: { not: null } },
      data: { nextCheckAt: new Date(Date.now() + DAY_MS) },
    });
    const row = await domainRow(ctx, domain.id);
    const old = row.dkimKeys.find((k) => k.selector === first.selector)!;
    await ctx.prisma.domainDkimKey.update({
      where: { id: old.id },
      data: { retireAfter: new Date(Date.now() - 60_000) },
    });
    await ctx.kv.del(domainKvKeys.tickLock);
    const summary = await ctx.get(DomainCheckScheduler).runOnce(new Date());
    await ctx.kv.del(domainKvKeys.tickLock);
    expect(summary).not.toBeNull();
    expect(summary!.retired).toBeGreaterThanOrEqual(1);

    const retired = await ctx.prisma.domainDkimKey.findUniqueOrThrow({ where: { id: old.id } });
    expect(retired).toMatchObject({ status: 'retired', privateKeyCiphertext: null });
    expect(retired.retiredAt).not.toBeNull();
    keys = (await apiA.okGet(domain.id)).dkimKeys;
    expect(byselector(first.selector).status).toBe('retired');
    records = await apiA.okRecords(domain.id);
    expect(records.records.map((r) => r.key)).not.toContain(`dkim:${first.selector}`);
    expect(records.cleanup).toEqual([
      expect.objectContaining({
        type: 'TXT',
        host: `${first.selector}._domainkey.${domain.name}`,
        reason: 'retired_dkim_selector',
      }),
    ]);
    const retiredAudit = await domainAudit(ctx, domain.id, 'domain.dkim_key_retired');
    expect(retiredAudit).toHaveLength(1);
    expect(retiredAudit[0]).toMatchObject({ actorType: 'system' });
    expect(retiredAudit[0]!.metadata).toMatchObject({ selector: first.selector });
  });

  it('replaces a key that was never published and rotates Ed25519 independently', async () => {
    const domain = await newDomain('replace');
    const original = domain.dkimKeys[0]!;
    const res = await apiA.rotate(domain.id, {}).expect(201);
    expect(res.body.previous).toMatchObject({ selector: original.selector, status: 'revoked' });
    const row = await domainRow(ctx, domain.id);
    const revoked = row.dkimKeys.find((k) => k.selector === original.selector)!;
    expect(revoked).toMatchObject({ status: 'revoked', privateKeyCiphertext: null });
    expect(row.dnsRecords.map((r) => r.recordKey)).not.toContain(`dkim:${original.selector}`);

    const ed = await apiA.rotate(domain.id, { algorithm: 'ed25519' }).expect(201);
    expect(ed.body).toMatchObject({ key: { algorithm: 'ed25519', status: 'pending' } });
    expect(ed.body.dnsRecord.value).toMatch(/^v=DKIM1; k=ed25519; p=/);
    await apiA.rotate(domain.id, { algorithm: 'rsa-4096' }).expect(400);
  });
});

describe('DoH resolver mode', () => {
  let doh: TestDohServer;
  let app: IntegrationApp;

  beforeAll(async () => {
    doh = await TestDohServer.start(dns);
    app = await createDomainApp(dns, {
      DNS_RESOLVER_MODE: 'doh',
      DNS_DOH_URL: doh.url,
      DNS_SERVERS: '',
    });
  });

  afterAll(async () => {
    await app?.close();
    await doh?.close();
  });

  it('verifies a domain through RFC 8484', async () => {
    const api = new DomainApi(app, apiA.headers);
    const domain = await api.okCreate(uniqueDomainName('doh'));
    await publishFromApi(api, dns, domain.id, ['verification']);
    const view = await api.okVerify(domain.id);
    expect(view.status).toBe('verified');
    expect(dns.queries).toContainEqual({
      name: domain.verification!.host,
      type: 'TXT',
      transport: 'doh',
    });
    const row = await domainRow(ctx, domain.id);
    expect(row.verifications[0]!.evidence).toMatchObject({
      query: { upstream: `doh:${doh.url}`, outcome: 'answer' },
    });
  });
});

describe('secrets hygiene', () => {
  it('never logged a private key or a verification token value as a log field', () => {
    const logs = ctx.logs.join('\n');
    expect(logs).not.toContain('PRIVATE KEY');
    expect(logs).not.toMatch(/"privateKey(Pem|Ciphertext)?":"[^[]/);
  });
});

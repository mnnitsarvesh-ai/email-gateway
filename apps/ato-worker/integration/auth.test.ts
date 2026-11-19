import { createHash, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { canonicalIp } from '@email-gateway/ato-detection';
import { CAPABILITIES_KEY } from '../src/maintenance/jobs';
import { Fixtures, ips } from './support/fixtures';
import { Clock, harness, testConfig, type Harness } from './support/harness';
import { accountOf, codes, configure, deliver, matureAccount } from './support/scenario';

/**
 * Step 8.4 §10.3 authentication scenarios against the real writer, Redis, the synthetic GeoIP
 * databases (documentation ranges) and the dns-sink DNSBL test zone: (1) brute force on portal
 * logins and SMTP AUTH, (2) credential stuffing / spraying across accounts and organizations,
 * (3) new country and (5) impossible travel incl. the anonymizer downgrade, the accuracy guard and
 * the unavailable path, (4) new device, (6) IP reputation (platform feed and DNSBL), account
 * changes (K1, X2), (16) tenant isolation, (17) duplicates, unknown accounts, feature off.
 */
const fx = new Fixtures();
const MIN = 60_000;
const T0 = new Date('2021-03-01T09:00:00.000Z');
const clock = new Clock(T0);
let h: Harness;
let platform: { id: bigint; domain: string; domainId: bigint };

const UA_CHROME =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
const UA_FIREFOX = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0';

beforeAll(async () => {
  platform = await fx.organization('platform', { kind: 'platform' });
  h = await harness(fx, { clock, platformOrganizationId: platform.id });
  await configure(h, platform.id);
});

afterAll(async () => {
  await h?.close();
  await fx.cleanup();
});

describe('portal and SMTP brute force (scenario 1)', () => {
  it('A1 after 10 failures in 15 minutes, A2 on the success after them (portal)', async () => {
    const org = await fx.organization('bf');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'alice', org.domain);
    const ip = ips.mumbai();
    for (let i = 0; i < 10; i++) {
      clock.advance(30_000);
      const e = await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'failure',
        ip,
        at: clock.now(),
      });
      await expect(deliver(h, e)).resolves.toBe('handled');
    }
    const account = await accountOf(fx, org.id, 'gateway_user', user.id);
    expect(account).not.toBeNull();
    expect(await codes(fx, org.id, account!.id)).toContain('ato.auth.bruteforce');
    clock.advance(30_000);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip,
        userAgent: UA_CHROME,
        at: clock.now(),
      }),
    );
    expect(await codes(fx, org.id, account!.id)).toContain('ato.auth.success_after_failures');
    const events = await fx.prisma.atoAuthEvent.findMany({
      where: { organizationId: org.id, accountId: account!.id },
    });
    expect(events).toHaveLength(11);
    const success = events.find((e) => e.outcome === 'success')!;
    expect(success).toMatchObject({
      source: 'portal_login',
      channel: 'portal',
      countryCode: 'IN',
      city: 'Mumbai',
      geoStatus: 'located',
      asn: 64500,
      ipAddress: canonicalIp(ip),
    });
    expect(success.deviceLabel).toMatch(/Chrome 130/);
    expect(success.deviceHash).toMatch(/^[0-9a-f]{16}$/);
    // Raw user agents and the attempted e-mail are never stored in ATO rows (D20).
    const text = JSON.stringify(events, (_k, v: unknown) =>
      typeof v === 'bigint' ? v.toString() : v,
    );
    expect(text).not.toContain(user.email);
    expect(text).not.toContain('Mozilla');
  });

  it('SMTP AUTH: A1 and A2 for the connector; successes aggregated per connector/IP/hour', async () => {
    const org = await fx.organization('smtpbf');
    await configure(h, org.id);
    const connector = await fx.connector(org.id, 'relay');
    const ip = ips.london();
    const entries = [
      ...Array.from({ length: 10 }, (_, i) => ({
        at: new Date(clock.now().getTime() + i * 10_000),
        result: 'fail' as const,
        connectorId: connector.id,
        clientIp: ip,
      })),
      ...Array.from({ length: 3 }, (_, i) => ({
        at: new Date(clock.now().getTime() + 120_000 + i * 1000),
        result: 'ok' as const,
        connectorId: connector.id,
        clientIp: ip,
      })),
    ];
    clock.advance(3 * MIN);
    await deliver(h, fx.smtpAuth(org.id, entries));
    const account = await accountOf(fx, org.id, 'smtp_connector', connector.id);
    const c = await codes(fx, org.id, account!.id);
    expect(c).toContain('ato.auth.bruteforce');
    expect(c).toContain('ato.auth.success_after_failures');
    const rows = await fx.prisma.atoAuthEvent.findMany({
      where: { organizationId: org.id, accountId: account!.id },
    });
    expect(rows.filter((r) => r.outcome === 'failure')).toHaveLength(10);
    const ok = rows.filter((r) => r.outcome === 'success');
    expect(ok).toHaveLength(1);
    expect(ok[0]).toMatchObject({
      attemptCount: 3,
      source: 'smtp_auth',
      channel: 'smtp',
      mechanism: 'plain',
    });
    expect(ok[0]!.occurredAt.getTime() % 3_600_000).toBe(0);
  });
});

describe('credential stuffing and spraying across organizations (scenario 2)', () => {
  it('flags the IP on 5 distinct accounts, then T5 on targets and T3 (strong) on a success → incident', async () => {
    const a = await fx.organization('spray-a');
    const b = await fx.organization('spray-b');
    await configure(h, a.id);
    await configure(h, b.id);
    const ip = ips.saoPaulo();
    const users = [
      await fx.user(a.id, 'u1', a.domain),
      await fx.user(a.id, 'u2', a.domain),
      await fx.user(b.id, 'u3', b.domain),
      await fx.user(b.id, 'u4', b.domain),
    ];
    const before = await h.metric('ato_ip_campaigns_flagged_total');
    for (const u of users) {
      clock.advance(10_000);
      const org = u === users[0] || u === users[1] ? a.id : b.id;
      await deliver(
        h,
        await fx.login({
          organizationId: org,
          userId: u.id,
          email: u.email,
          outcome: 'failure',
          ip,
          at: clock.now(),
        }),
      );
    }
    // An unknown account (platform organization) is the fifth distinct target.
    clock.advance(10_000);
    await deliver(
      h,
      await fx.login({
        organizationId: platform.id,
        envelopeOrganizationId: platform.id,
        userId: null,
        email: `nobody-${fx.suffix}@spray.example`,
        outcome: 'failure',
        ip,
        at: clock.now(),
      }),
    );
    expect(await h.metric('ato_ip_campaigns_flagged_total')).toBe(before + 1);
    // A further failure of a target account: T5 (targeted by a flagged IP).
    clock.advance(10_000);
    await deliver(
      h,
      await fx.login({
        organizationId: a.id,
        userId: users[0]!.id,
        email: users[0]!.email,
        outcome: 'failure',
        ip,
        at: clock.now(),
      }),
    );
    const u1 = await accountOf(fx, a.id, 'gateway_user', users[0]!.id);
    expect(await codes(fx, a.id, u1!.id)).toContain('ato.ti.targeted_by_campaign');
    // A success from the flagged IP on another account: T3 strong → strong floor 60 → incident.
    clock.advance(10_000);
    await deliver(
      h,
      await fx.login({
        organizationId: b.id,
        userId: users[2]!.id,
        email: users[2]!.email,
        outcome: 'success',
        ip,
        at: clock.now(),
      }),
    );
    const u3 = await accountOf(fx, b.id, 'gateway_user', users[2]!.id);
    expect(await codes(fx, b.id, u3!.id)).toContain('ato.ti.attack_source_success');
    const fresh = await fx.prisma.atoAccount.findUniqueOrThrow({ where: { id: u3!.id } });
    expect(fresh.riskScore).toBeGreaterThanOrEqual(60);
    expect(fresh.activeIncidentId).not.toBeNull();
    const incident = await fx.prisma.securityIncident.findUniqueOrThrow({
      where: { id: fresh.activeIncidentId! },
    });
    expect(incident).toMatchObject({
      category: 'account_takeover',
      subjectType: 'ato_account',
      subjectRefId: u3!.id,
      origin: 'detection',
      status: 'open',
    });
    const detail = await fx.prisma.atoIncidentDetail.findUniqueOrThrow({
      where: { incidentId: incident.id },
    });
    expect(detail.riskScoreAtOpen).toBeGreaterThanOrEqual(60);
    // The platform IP windows hold no tenant identity (D8): only HMAC members, no org id.
    const keys = await h.redis.keys(`ato:ip:${canonicalIp(ip)}:*`);
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys.filter((k) => k.includes(':a:'))) {
      const members = await h.redis.smembers(key);
      expect(members.every((m) => /^[0-9a-f]{32}$/.test(m))).toBe(true);
      expect(members.join(',')).not.toContain(fx.suffix);
    }
    expect(keys.join(',')).not.toContain(`:${a.id}:`);
  });
});

describe('geography and devices (scenarios 3, 4, 5)', () => {
  it('impossible travel Mumbai → London (G2 moderate) with new country G1, new prefix C1, new ASN C2', async () => {
    const org = await fx.organization('travel');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'traveller', org.domain);
    const home = ips.mumbai();
    await matureAccount(
      h,
      fx,
      org.id,
      { kind: 'gateway_user', userId: user.id, address: user.email },
      {
        prefix: `${home.split('.').slice(0, 3).join('.')}.0/24`,
        country: 'IN',
        asn: 64500,
        deviceUserAgent: UA_CHROME,
      },
    );
    clock.advance(MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: home,
        userAgent: UA_CHROME,
        at: clock.now(),
      }),
    );
    clock.advance(30 * MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: ips.london(),
        userAgent: UA_CHROME,
        at: clock.now(),
      }),
    );
    const account = await accountOf(fx, org.id, 'gateway_user', user.id);
    const signals = await fx.prisma.atoRiskSignal.findMany({
      where: { organizationId: org.id, accountId: account!.id },
    });
    const byCode = new Map(signals.map((s) => [s.ruleCode, s]));
    expect(byCode.get('ato.geo.impossible_travel')).toMatchObject({
      strength: 'moderate',
      weight: 30,
    });
    expect(byCode.get('ato.geo.impossible_travel')!.evidence).toMatchObject({
      fromCountry: 'IN',
      toCountry: 'GB',
    });
    expect(byCode.has('ato.geo.new_country')).toBe(true);
    expect(byCode.has('ato.access.new_ip_prefix')).toBe(true);
    expect(byCode.has('ato.access.new_asn')).toBe(true);
    expect(byCode.has('ato.access.new_device')).toBe(false); // same browser as the baseline
    // Same-day novelty: a second London success adds no second G1/C1 signal.
    clock.advance(5 * MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: ips.london(),
        userAgent: UA_CHROME,
        at: clock.now(),
      }),
    );
    const again = await codes(fx, org.id, account!.id);
    expect(again.filter((c) => c === 'ato.geo.new_country')).toHaveLength(1);
  });

  it('a new device (C3) on a mature account; an anonymizer downgrades travel (G2 weak, G4)', async () => {
    const org = await fx.organization('device');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'dev', org.domain);
    await matureAccount(
      h,
      fx,
      org.id,
      { kind: 'gateway_user', userId: user.id, address: user.email },
      {
        country: 'IN',
        asn: 64500,
        deviceUserAgent: UA_CHROME,
      },
    );
    clock.advance(MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: ips.pune(),
        userAgent: UA_CHROME,
        at: clock.now(),
      }),
    );
    clock.advance(20 * MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: ips.newYorkVpn(),
        userAgent: UA_FIREFOX,
        at: clock.now(),
      }),
    );
    const account = await accountOf(fx, org.id, 'gateway_user', user.id);
    const signals = await fx.prisma.atoRiskSignal.findMany({
      where: { organizationId: org.id, accountId: account!.id },
    });
    const byCode = new Map(signals.map((s) => [s.ruleCode, s]));
    expect(byCode.has('ato.access.new_device')).toBe(true);
    expect(byCode.get('ato.geo.impossible_travel')).toMatchObject({ strength: 'weak', weight: 10 });
    expect(byCode.has('ato.geo.anonymizer')).toBe(true);
    const vpn = await fx.prisma.atoAuthEvent.findFirst({
      where: { organizationId: org.id, accountId: account!.id, countryCode: 'US' },
    });
    expect(vpn!.anonymizerFlags).toBeGreaterThan(0);
  });

  it('a country-only location never feeds impossible travel (accuracy guard)', async () => {
    const org = await fx.organization('accuracy');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'acc', org.domain);
    clock.advance(MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: ips.mumbai(),
        at: clock.now(),
      }),
    );
    clock.advance(10 * MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: ips.germanyCountryOnly(),
        at: clock.now(),
      }),
    );
    const account = await accountOf(fx, org.id, 'gateway_user', user.id);
    expect(await codes(fx, org.id, account!.id)).not.toContain('ato.geo.impossible_travel');
    const de = await fx.prisma.atoAuthEvent.findFirst({
      where: { organizationId: org.id, accountId: account!.id, countryCode: 'DE' },
    });
    expect(de!.accuracyKm).toBe(1000);
  });

  it('without GeoIP databases every location is unavailable and no geographic rule fires', async () => {
    const org = await fx.organization('nogeo');
    const bare = await harness(fx, {
      clock,
      config: testConfig({
        ATO_GEOIP_CITY_DB_PATH: '',
        ATO_GEOIP_ASN_DB_PATH: '',
        ATO_GEOIP_ANONYMOUS_DB_PATH: '',
      }),
    });
    try {
      await configure(bare, org.id);
      const user = await fx.user(org.id, 'ng', org.domain);
      for (const ip of [ips.mumbai(), ips.london()]) {
        clock.advance(10 * MIN);
        await deliver(
          bare,
          await fx.login({
            organizationId: org.id,
            userId: user.id,
            email: user.email,
            outcome: 'success',
            ip,
            at: clock.now(),
          }),
        );
      }
      const account = await accountOf(fx, org.id, 'gateway_user', user.id);
      const rows = await fx.prisma.atoAuthEvent.findMany({
        where: { organizationId: org.id, accountId: account!.id },
      });
      expect(rows.every((r) => r.geoStatus === 'unavailable' && r.countryCode === null)).toBe(true);
      expect(
        (await codes(fx, org.id, account!.id)).filter((c) => c.startsWith('ato.geo.')),
      ).toEqual([]);
      const caps = await bare.comps.maintenance.writeCapabilities(clock.now());
      expect(caps).toMatchObject({
        geoipCity: { loaded: false },
        geoipAsn: { loaded: false },
        geoipAnonymous: { loaded: false },
      });
      // The capabilities of the configured harness are written back.
      await h.comps.maintenance.writeCapabilities(clock.now());
    } finally {
      await bare.close();
    }
    const row = await fx.prisma.systemSetting.findUnique({ where: { key: CAPABILITIES_KEY } });
    expect(row?.value).toMatchObject({ geoipCity: { loaded: true }, dnsblZones: 1 });
  });
});

describe('IP reputation through ReputationService (scenario 6)', () => {
  it('T1 strong on a success from a platform-feed IP, T6 on a failure from it', async () => {
    const org = await fx.organization('rep');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'rep', org.domain);
    const bad = ips.london();
    await fx.indicator('ip', canonicalIp(bad)!, 'high');
    clock.advance(MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'failure',
        ip: bad,
        at: clock.now(),
      }),
    );
    clock.advance(MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: bad,
        at: clock.now(),
      }),
    );
    const account = await accountOf(fx, org.id, 'gateway_user', user.id);
    const signals = await fx.prisma.atoRiskSignal.findMany({
      where: { organizationId: org.id, accountId: account!.id },
    });
    expect(signals.find((s) => s.ruleCode === 'ato.ti.malicious_ip_attempt')).toBeDefined();
    expect(signals.find((s) => s.ruleCode === 'ato.ti.malicious_ip_success')).toMatchObject({
      strength: 'strong',
      weight: 45,
    });
    const success = await fx.prisma.atoAuthEvent.findFirst({
      where: { organizationId: org.id, accountId: account!.id, outcome: 'success' },
    });
    expect(success!.reputation).toEqual({
      status: 'listed',
      severity: 'high',
      category: 'other',
      confidence: null,
      providers: ['local_feed'],
    });
  });

  it('T2 on a success from an IP listed by the DNSBL test zone; answers cached under eg:ato:rep:v1', async () => {
    const org = await fx.organization('dnsbl');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'dn', org.domain);
    clock.advance(MIN);
    // 192.0.2.66 is listed in rbl.scan.test by the dns-sink test zone (127.0.0.2).
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: '192.0.2.66',
        at: clock.now(),
      }),
    );
    const account = await accountOf(fx, org.id, 'gateway_user', user.id);
    expect(await codes(fx, org.id, account!.id)).toContain('ato.ti.dnsbl_listed_success');
    const cached = await h.redis.keys('eg:ato:rep:v1:dnsbl:*');
    expect(cached.length).toBeGreaterThan(0);
    expect(await h.redis.keys('eg:url:rep:v1:dnsbl:*:ip:*')).toEqual(
      expect.not.arrayContaining(cached),
    );
  });
});

describe('account changes, tenant isolation, duplicates, unknown accounts, feature off', () => {
  it('K1 refresh-token reuse (strong 50 → 60 high, incident); X2 attack → success → change', async () => {
    const org = await fx.organization('k1');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'k1', org.domain);
    const ip = ips.pune();
    for (let i = 0; i < 10; i++) {
      clock.advance(20_000);
      await deliver(
        h,
        await fx.login({
          organizationId: org.id,
          userId: user.id,
          email: user.email,
          outcome: 'failure',
          ip,
          at: clock.now(),
        }),
      );
    }
    clock.advance(20_000);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip,
        at: clock.now(),
      }),
    );
    clock.advance(MIN);
    // The shape the api writes (SessionService.rotate): actor `system`, the session family as
    // the resource. The worker attributes it to the family's user (step 8.4 WP6 fix).
    const familyId = randomUUID();
    await fx.prisma.userSession.create({
      data: {
        organizationId: org.id,
        userId: user.id,
        refreshTokenHash: createHash('sha256').update(`k1-${familyId}`).digest('hex'),
        familyId,
        authenticatedAt: clock.now(),
        expiresAt: new Date(clock.now().getTime() + 3_600_000),
        absoluteExpiresAt: new Date(clock.now().getTime() + 86_400_000),
        revokedAt: clock.now(),
        revokedReason: 'reuse_detected',
      },
    });
    await deliver(
      h,
      await fx.accountChange({
        organizationId: org.id,
        action: 'auth.refresh_token_reused',
        actorType: 'system',
        actorPublicId: null,
        resourceType: 'session',
        resourcePublicId: familyId,
        at: clock.now(),
      }),
    );
    const account = await accountOf(fx, org.id, 'gateway_user', user.id);
    const c = await codes(fx, org.id, account!.id);
    expect(c).toContain('ato.account.refresh_token_reuse');
    expect(c).toContain('ato.correlation.attack_then_change');
    const fresh = await fx.prisma.atoAccount.findUniqueOrThrow({ where: { id: account!.id } });
    expect(fresh.riskLevel).toBe('critical');
    expect(fresh.activeIncidentId).not.toBeNull();
    const scores = await fx.prisma.atoRiskScore.findMany({
      where: { organizationId: org.id, accountId: account!.id },
      orderBy: { id: 'asc' },
    });
    expect(scores.length).toBeGreaterThan(1);
    const risk = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org.id, eventType: 'ato.account.risk.updated.v1' },
    });
    expect(risk.length).toBeGreaterThan(0);
    const created = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org.id, eventType: 'security.incident.created.v1' },
    });
    expect(created).toHaveLength(1);
  });

  it('tenant isolation (scenario 16): same IP and addresses in two organizations never cross', async () => {
    const a = await fx.organization('iso-a');
    const b = await fx.organization('iso-b');
    await configure(h, a.id);
    await configure(h, b.id);
    const shared = `same-${fx.suffix}@shared.example`;
    const ua = await fx.prisma.user.create({
      data: { organizationId: a.id, email: shared, displayName: 'A', status: 'active' },
    });
    const ub = await fx.prisma.user.create({
      data: { organizationId: b.id, email: shared, displayName: 'B', status: 'active' },
    });
    const ip = ips.pune();
    for (let i = 0; i < 10; i++) {
      clock.advance(20_000);
      await deliver(
        h,
        await fx.login({
          organizationId: a.id,
          userId: ua.id,
          email: shared,
          outcome: 'failure',
          ip,
          at: clock.now(),
        }),
      );
    }
    clock.advance(20_000);
    await deliver(
      h,
      await fx.login({
        organizationId: b.id,
        userId: ub.id,
        email: shared,
        outcome: 'success',
        ip,
        at: clock.now(),
      }),
    );
    const accA = await accountOf(fx, a.id, 'gateway_user', ua.id);
    const accB = await accountOf(fx, b.id, 'gateway_user', ub.id);
    expect(await codes(fx, a.id, accA!.id)).toContain('ato.auth.bruteforce');
    const bCodes = await codes(fx, b.id, accB!.id);
    expect(bCodes).not.toContain('ato.auth.success_after_failures');
    expect(bCodes).not.toContain('ato.auth.bruteforce');
    expect(await fx.prisma.atoAuthEvent.count({ where: { organizationId: b.id } })).toBe(1);
  });

  it('duplicates (scenario 17): a redelivered login and a redelivered SMTP batch have one effect', async () => {
    const org = await fx.organization('dup');
    await configure(h, org.id);
    const user = await fx.user(org.id, 'dup', org.domain);
    const connector = await fx.connector(org.id, 'dup');
    clock.advance(MIN);
    const login = await fx.login({
      organizationId: org.id,
      userId: user.id,
      email: user.email,
      outcome: 'failure',
      ip: ips.mumbai(),
      at: clock.now(),
    });
    await expect(deliver(h, login)).resolves.toBe('handled');
    await expect(deliver(h, login)).resolves.toBe('duplicate');
    const batch = fx.smtpAuth(org.id, [
      { at: clock.now(), result: 'fail', connectorId: connector.id, clientIp: ips.london() },
      { at: clock.now(), result: 'ok', connectorId: connector.id, clientIp: ips.london() },
    ]);
    await deliver(h, batch);
    await deliver(h, batch);
    const rows = await fx.prisma.atoAuthEvent.findMany({ where: { organizationId: org.id } });
    expect(rows).toHaveLength(3);
    expect(rows.find((r) => r.outcome === 'success')!.attemptCount).toBe(1);
  });

  it('unknown accounts: platform IP window always; an account-less row only with platform ATO on', async () => {
    const ip = ips.saoPaulo();
    const before = await fx.prisma.atoAuthEvent.count({ where: { organizationId: platform.id } });
    clock.advance(MIN);
    const e = await fx.login({
      organizationId: platform.id,
      userId: null,
      email: `ghost-${fx.suffix}@unknown.example`,
      outcome: 'failure',
      ip,
      at: clock.now(),
    });
    await deliver(h, e);
    const rows = await fx.prisma.atoAuthEvent.findMany({
      where: {
        organizationId: platform.id,
        sourceRef: { endsWith: `:${(e.payload as { loginAuditId: string }).loginAuditId}` },
      },
    });
    expect(rows).toHaveLength(1);
    expect(await fx.prisma.atoAuthEvent.count({ where: { organizationId: platform.id } })).toBe(
      before + 1,
    );
    expect(rows[0]).toMatchObject({ accountId: null, outcome: 'failure', source: 'portal_login' });
    await fx.enableAto(platform.id, false);
    h.comps.orgs.invalidate();
    clock.advance(MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: platform.id,
        userId: null,
        email: `ghost2-${fx.suffix}@unknown.example`,
        outcome: 'failure',
        ip,
        at: clock.now(),
      }),
    );
    expect(await fx.prisma.atoAuthEvent.count({ where: { organizationId: platform.id } })).toBe(
      before + 1,
    );
    await fx.enableAto(platform.id, true);
    h.comps.orgs.invalidate();
  });

  it('feature off: nothing is persisted for the organization', async () => {
    const org = await fx.organization('off', { ato: false });
    const user = await fx.user(org.id, 'off', org.domain);
    clock.advance(MIN);
    await deliver(
      h,
      await fx.login({
        organizationId: org.id,
        userId: user.id,
        email: user.email,
        outcome: 'success',
        ip: ips.mumbai(),
        at: clock.now(),
      }),
    );
    expect(await fx.prisma.atoAccount.count({ where: { organizationId: org.id } })).toBe(0);
    expect(await fx.prisma.atoSetting.count({ where: { organizationId: org.id } })).toBe(0);
    expect(
      await h.metric('ato_events_total', { source: 'portal_login', result: 'skipped_feature' }),
    ).toBeGreaterThan(0);
  });
});

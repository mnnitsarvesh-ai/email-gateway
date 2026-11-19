/* eslint-disable @typescript-eslint/no-unsafe-return -- predicates over the api's loose JSON */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, idempotencyKey, type ApiSession } from './support/api-client';
import { purgeDormantQueues } from './support/broker';
import { compose, waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import { clearSinkDomain, sinkFiles, sinkMessage, waitForSinkMessage } from './support/mail-sink';
import { escapeRegExp, maillogOffset, waitForMaillog } from './support/maillog';
import { deleteQueued, involving, listQueue } from './support/postfix';
import {
  GOOGLE_SCOPES,
  GOOGLE_SENDER,
  M365_PERMISSIONS,
  M365_SENDER,
  RELAY_PROOF_ZONE,
  dkimSignAs,
  expectStatus,
  fake,
  guid,
  previewAndApply,
  providerDkimKey,
  providerMessage,
  providerRowCounts,
  providerStackGate,
  purgeProviderRows,
  runtimeSecret,
  serviceAccount,
  serviceEnv,
  waitForConnection,
  waitForRun,
  type Json,
  type ProviderDkimKey,
} from './support/providers';
import { lf, organizationRef, sendInbound, sleep } from './support/routing';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply, swaks, type SwaksResult } from './support/smtp-tools';
import { createWebhook, receivedRequests, type CreatedWebhook } from './support/webhooks';

/**
 * Step 8.2 Microsoft 365 and Google Workspace connectors end to end
 * (docs/plan/steps/25-m365-google-connectors.md §10.5, ADR-0076–0081), on the live containers:
 * the api's provider routes, the integration-worker against the Compose `provider-fake`, the
 * provider relay on `postfix-outbound:25` from the test clients `provider-sender-m365`
 * (172.31.250.70) and `provider-sender-google` (.71) that `PROVIDER_EGRESS_EXTRA_RANGES` counts as
 * provider egress, tenant proof at LMTP ingestion with DKIM keys generated here and published as
 * `relay-proof.test` TXT records by the fake's DNS (through dns-sink), and delivery to the sinks.
 *
 * Organizations: A (Microsoft 365, customer app secret; two linked domains, inbound, outbound,
 * internal routing, health → critical, disconnect), B (Microsoft 365 through admin consent and
 * the fake's consent redirect), C (Google Workspace, customer service account key; inbound,
 * outbound with DKIM replay, failover). Every key and secret is generated at run time; nothing
 * reaches Microsoft or Google.
 */
const gate = await providerStackGate();
const fx = new SmtpFixtures();
const suiteStart = new Date();

const domainName = (label: string) => `it-${fx.suffix}-${label}.${RELAY_PROOF_ZONE}`;
const mxHostOf = (name: string) => `${name.replace(/\./g, '-')}.mail.protection.outlook.com`;
const extAddress = (local: string) => `${local}@${fx.sinkDomain('prov-ext')}`;

let orgA = 0n;
let orgB = 0n;
let orgC = 0n;
let adminA: ApiSession | undefined;
let adminB: ApiSession | undefined;
let adminC: ApiSession | undefined;
let a1: FixtureDomain;
let a2: FixtureDomain;
let b1: FixtureDomain;
let c1: FixtureDomain;
let keyA1: ProviderDkimKey;
let keyC1: ProviderDkimKey;
let hook: CreatedWebhook | undefined;

const tenantA = guid();
const tenantB = guid();
const appA = { clientId: guid(), secret: runtimeSecret() };
const customerC = `C${fx.suffix}x9`;
const saC = serviceAccount(`it-${fx.suffix}-reader`);

const conn: { a?: string; b?: string; c?: string } = {};
const probes: { a?: string; c?: string } = {};

/** Gateway-side DNS observations the worker reads (step 2.1 rows; the stack DNS is static). */
async function dnsObservations(domain: FixtureDomain): Promise<void> {
  const now = new Date();
  for (const [recordKey, purpose, recordType] of [
    ['mx:mx1.gateway.example.test', 'mx', 'MX'],
    ['spf', 'spf', 'TXT'],
  ] as const) {
    await fx.prisma.domainDnsRecord.create({
      data: {
        organizationId: domain.organizationId,
        domainId: domain.id,
        recordKey,
        purpose,
        recordType,
        host: domain.name,
        expectedValue: purpose === 'mx' ? '10 mx1.gateway.example.test' : 'v=spf1 include:gw ~all',
        observedValue: purpose === 'mx' ? '10 mx1.gateway.example.test' : 'v=spf1 include:gw ~all',
        status: 'valid',
        statusChangedAt: now,
        lastOutcome: 'valid',
        lastCheckedAt: now,
      },
    });
  }
}

/** One message on the provider relay (postfix-outbound:25, STARTTLS) from a provider client. */
function relay(
  service: typeof M365_SENDER | typeof GOOGLE_SENDER | 'smtp-tools',
  options: { from: string; to: readonly string[]; data?: string; quitAfter?: 'RCPT' },
): Promise<SwaksResult> {
  return swaks({
    service,
    server: 'postfix-outbound',
    port: 25,
    tls: true,
    helo:
      service === GOOGLE_SENDER
        ? 'mail-gateway.google.example.test'
        : 'outbound.protection.example.test',
    from: options.from,
    to: options.to,
    ...(options.data !== undefined ? { data: options.data } : {}),
    ...(options.quitAfter ? { quitAfter: options.quitAfter } : {}),
  });
}

/** A Microsoft 365 message of tenant A: tenant header + aligned DKIM of the sender's domain. */
async function m365Message(options: {
  from: string;
  to: readonly string[];
  subject: string;
  tenant?: string | null;
  key?: ProviderDkimKey | null;
}): Promise<string> {
  const tenant = options.tenant === undefined ? tenantA : options.tenant;
  const message = providerMessage({
    from: options.from,
    to: options.to,
    subject: options.subject,
    headers: tenant ? [`X-MS-Exchange-CrossTenant-Id: ${tenant}`] : [],
  });
  const key = options.key === undefined ? keyA1 : options.key;
  return key ? dkimSignAs(message, key) : message;
}

/**
 * Waits until the relay's RCPT answer for `from` → `to` has `code` (the adapter caches the
 * provider-relay resolution and connectors for up to 30 s each, D7.3: mode changes take effect
 * within about a minute).
 */
function waitForRcpt(
  service: typeof M365_SENDER | typeof GOOGLE_SENDER,
  from: string,
  to: string,
  code: number,
): Promise<SwaksResult> {
  return waitFor(
    `RCPT ${code} for ${from} → ${to}`,
    async () => {
      const r = await relay(service, { from, to: [to], quitAfter: 'RCPT' });
      return reply(r, 'RCPT#0').code === code ? r : undefined;
    },
    { timeoutMs: 240_000, intervalMs: 5_000 },
  );
}

function accepted(result: SwaksResult, what: string): string {
  expect(reply(result, 'DATA-END').code, `${what}\n${result.transcript}`).toBe(250);
  expect(result.queueId, what).toBeDefined();
  return result.queueId!;
}

/** Waits for the LMTP ingestion outcome of a relayed queue file in postfix-outbound's log. */
function waitForBounce(offset: number, queueId: string, code: string) {
  return waitForMaillog(
    offset,
    new RegExp(`${escapeRegExp(queueId)}: .*status=bounced.*${escapeRegExp(code)}`),
    120_000,
  );
}

beforeAll(async () => {
  assertStackReady(gate);
  orgA = await fx.organization('prov-a');
  orgB = await fx.organization('prov-b');
  orgC = await fx.organization('prov-c');
  const outbound = { outboundEnabled: true } as const;
  a1 = await fx.domainNamed(orgA, domainName('m365a'), outbound);
  a2 = await fx.domainNamed(orgA, domainName('m365b'), outbound);
  b1 = await fx.domainNamed(orgB, domainName('m365p'), outbound);
  c1 = await fx.domainNamed(orgC, domainName('goog'), outbound);
  for (const d of [a1, a2, b1, c1]) {
    await fx.dkimKey(d); // the gateway's own outbound signing key (SMTP_OUTBOUND_REQUIRE_DKIM)
    await dnsObservations(d);
  }
  await fx.dkimSync();
  await fx.feature(orgA, 'webhooks', true);
  adminA = await apiSession(fx.prisma, await organizationRef(fx, orgA), 'organization_admin');
  adminB = await apiSession(fx.prisma, await organizationRef(fx, orgB), 'organization_admin');
  adminC = await apiSession(fx.prisma, await organizationRef(fx, orgC), 'organization_admin');

  // The provider side, all generated now: tenants, apps, consents, the Google customer.
  await fake.addMicrosoftTenant({
    tenantId: tenantA,
    displayName: `Tenant A ${fx.suffix}`,
    domains: [a1, a2].map((d, i) => ({
      name: d.name,
      isVerified: true,
      isDefault: i === 0,
      mxHost: mxHostOf(d.name),
    })),
  });
  await fake.addMicrosoftApp({
    clientId: appA.clientId,
    secret: appA.secret,
    homeTenantId: tenantA,
    requiredRoles: M365_PERMISSIONS,
  });
  await fake.consent(tenantA, appA.clientId, M365_PERMISSIONS);
  await fake.addMicrosoftTenant({
    tenantId: tenantB,
    displayName: `Tenant B ${fx.suffix}`,
    domains: [{ name: b1.name, isVerified: true, isDefault: true, mxHost: mxHostOf(b1.name) }],
  });
  await fake.addGoogleCustomer({
    customerId: customerC,
    primaryDomain: c1.name,
    organizationName: `Customer C ${fx.suffix}`,
    domains: [{ domainName: c1.name, verified: true, isPrimary: true }],
    admins: [`admin@${c1.name}`],
  });
  await fake.addGoogleServiceAccount({
    clientEmail: saC.clientEmail,
    clientId: saC.clientId,
    keyId: saC.keyId,
    publicKeyPem: saC.publicKeyPem,
  });
  await fake.delegate(customerC, saC.clientId, GOOGLE_SCOPES);
  keyA1 = await providerDkimKey(a1.name);
  keyC1 = await providerDkimKey(c1.name, 'google');
}, 600_000);

afterAll(async () => {
  if (gate.skip) return;
  if (hook && adminA) await adminA.delete(`/webhooks/${hook.id}`, idempotencyKey());
  await compose(['start', 'sink-google'], { timeoutMs: 60_000 }).catch(() => undefined);
  for (const session of [adminA, adminB, adminC]) await session?.remove();
  const names = [a1, a2, b1, c1].filter(Boolean).map((d) => d.name);
  for (const service of ['postfix-outbound', 'postfix'] as const) {
    const queued = involving(await listQueue(service), [...names, fx.sinkDomain('prov-ext')]);
    await deleteQueued(
      service,
      queued.map((m) => m.queue_id),
    );
  }
  for (const d of [...names, fx.sinkDomain('prov-ext')]) {
    await clearSinkDomain(d, 'all').catch(() => undefined);
    await fake.deleteTxt(`prov1._domainkey.${d}`).catch(() => undefined);
    await fake.deleteTxt(`google._domainkey.${d}`).catch(() => undefined);
  }
  const ids = [orgA, orgB, orgC].filter((id) => id !== 0n);
  await purgeProviderRows(fx.prisma, ids);
  await fx.cleanup();
  await purgeDormantQueues();
  if (ids.length === 0) return;
  const { PrismaClient } = await import('@email-gateway/database');
  const prisma = new PrismaClient({ datasourceUrl: process.env.DATABASE_URL });
  try {
    expect(await providerRowCounts(prisma, ids)).toEqual({
      connections: 0,
      grants: 0,
      domains: 0,
      runs: 0,
      observations: 0,
      healthChecks: 0,
      healthEvents: 0,
      counters: 0,
    });
    expect(await prisma.organization.count({ where: { id: { in: ids } } })).toBe(0);
  } finally {
    await prisma.$disconnect();
  }
}, 600_000);

describe.skipIf(gate.skip)(
  'provider integrations stack: connections, wizard, relay proof, health',
  { timeout: 900_000 },
  () => {
    it('(1)+(2a) Microsoft 365 with a customer app secret: tenant binding and provider domain verification (I10)', async () => {
      const created = await adminA!.post(
        '/provider-connections',
        { provider: 'microsoft_365', displayName: `Contoso ${fx.suffix}` },
        idempotencyKey(),
      );
      expectStatus(created, 201, 'POST /provider-connections');
      conn.a = (created.body as Json).id as string;
      const grant = await adminA!.post(
        `/provider-connections/${conn.a}/grants`,
        { profile: 'm365.mail_flow', authMethod: 'customer_app_secret' },
        idempotencyKey(),
      );
      expectStatus(grant, 201, 'POST …/grants');
      expect((grant.body as Json).next).toBe('credentials');
      const creds = await adminA!.put(
        `/provider-connections/${conn.a}/grants/m365.mail_flow/credentials`,
        { tenantId: tenantA, clientId: appA.clientId, clientSecret: appA.secret },
        idempotencyKey(),
      );
      expectStatus(creds, 200, 'PUT …/credentials');
      // The secret is never echoed: only a 12-hex fingerprint.
      expect(JSON.stringify(creds.body)).not.toContain(appA.secret);
      expect((creds.body as Json).credentialFingerprint).toMatch(/^[0-9a-f]{12}$/);
      const verified = await waitForConnection(adminA!, conn.a, 'grant active', (c) =>
        c.grants.some((g: Json) => g.status === 'active'),
      );
      // The tenant is only claimed until a linked domain proves control of it (D4).
      expect(verified.tenantId).toBeNull();
      expect(verified.tenantName).toBeNull();
      expect(verified.grants[0].missingPermissions ?? []).toEqual([]);
      expect(verified.grants[0].observedPermissions).toEqual(
        expect.arrayContaining(M365_PERMISSIONS),
      );
      const linked = await adminA!.put(
        `/provider-connections/${conn.a}/domains`,
        { domainIds: [a1.publicId, a2.publicId] },
        idempotencyKey(),
      );
      expectStatus(linked, 200, 'PUT …/domains');
      const bound = await waitForConnection(
        adminA!,
        conn.a,
        'status active',
        (c) => c.status === 'active',
      );
      expect(bound.tenantId).toBe(tenantA);
      expect(bound.domains.map((d: Json) => d.providerVerification).sort()).toEqual([
        'verified',
        'verified',
      ]);
      const domains = await adminA!.get(`/provider-connections/${conn.a}/domains`);
      expect((domains.body as Json).data.map((d: Json) => d.providerMxHost).sort()).toEqual(
        [mxHostOf(a1.name), mxHostOf(a2.name)].sort(),
      );
      // Another organization never sees the connection.
      expect((await adminB!.get(`/provider-connections/${conn.a}`)).status).toBe(404);
    });

    it('(2b) Microsoft 365 through admin consent: the fake redirects to the callback, the state is single use', async () => {
      const created = await adminB!.post(
        '/provider-connections',
        { provider: 'microsoft_365', displayName: `Fabrikam ${fx.suffix}` },
        idempotencyKey(),
      );
      expectStatus(created, 201, 'POST /provider-connections');
      conn.b = (created.body as Json).id as string;
      const grant = await adminB!.post(
        `/provider-connections/${conn.b}/grants`,
        { profile: 'm365.mail_flow', authMethod: 'platform_app' },
        idempotencyKey(),
      );
      expectStatus(grant, 201, 'POST …/grants (platform_app)');
      const consentUrl = (grant.body as Json).consent.consentUrl as string;
      expect(consentUrl).toMatch(/\/organizations\/v2\.0\/adminconsent\?/);
      await fake.setConsentTenant(tenantB);
      const redirect = await fetch(consentUrl, { redirect: 'manual' });
      expect(redirect.status).toBe(302);
      const callback = new URL(redirect.headers.get('location') ?? '');
      expect(callback.pathname).toBe('/integrations/providers/consent-callback');
      expect(callback.searchParams.get('admin_consent')).toBe('True');
      const body = {
        state: callback.searchParams.get('state'),
        tenant: callback.searchParams.get('tenant'),
        adminConsent: true,
      };
      const done = await adminB!.post(
        '/provider-connections/consent/complete',
        body,
        idempotencyKey(),
      );
      expectStatus(done, 200, 'POST consent/complete');
      expect(done.body).toMatchObject({ connectionId: conn.b, status: 'verifying' });
      const again = await adminB!.post(
        '/provider-connections/consent/complete',
        body,
        idempotencyKey(),
      );
      expect(again.status).toBe(404);
      expect((again.body as Json).code).toBe('consent_state_invalid');
      await fake.setConsentTenant(null);
      await waitForConnection(adminB!, conn.b, 'grant active', (c) =>
        c.grants.some((g: Json) => g.status === 'active' && g.authMethod === 'platform_app'),
      );
      expectStatus(
        await adminB!.put(
          `/provider-connections/${conn.b}/domains`,
          { domainIds: [b1.publicId] },
          idempotencyKey(),
        ),
        200,
        'PUT …/domains (B)',
      );
      const bound = await waitForConnection(
        adminB!,
        conn.b,
        'status active',
        (c) => c.status === 'active',
      );
      expect(bound.tenantId).toBe(tenantB);
    });

    it('(3) Google Workspace with a customer service account key generated at run time', async () => {
      const created = await adminC!.post(
        '/provider-connections',
        { provider: 'google_workspace', displayName: `Northwind ${fx.suffix}` },
        idempotencyKey(),
      );
      expectStatus(created, 201, 'POST /provider-connections (Google)');
      conn.c = (created.body as Json).id as string;
      expectStatus(
        await adminC!.post(
          `/provider-connections/${conn.c}/grants`,
          { profile: 'google.mail_flow', authMethod: 'customer_service_account' },
          idempotencyKey(),
        ),
        201,
        'POST …/grants (Google)',
      );
      const tokenUri = await serviceEnv('api', 'PROVIDER_GOOGLE_TOKEN_URL');
      const key = saC.key(tokenUri);
      const creds = await adminC!.put(
        `/provider-connections/${conn.c}/grants/google.mail_flow/credentials`,
        { serviceAccountKey: key, subjectEmail: `admin@${c1.name}` },
        idempotencyKey(),
      );
      expectStatus(creds, 200, 'PUT …/credentials (Google)');
      expect(JSON.stringify(creds.body)).not.toContain(key.private_key!.slice(40, 100));
      await waitForConnection(adminC!, conn.c, 'grant active', (c) =>
        c.grants.some((g: Json) => g.status === 'active'),
      );
      expectStatus(
        await adminC!.put(
          `/provider-connections/${conn.c}/domains`,
          { domainIds: [c1.publicId] },
          idempotencyKey(),
        ),
        200,
        'PUT …/domains (Google)',
      );
      const bound = await waitForConnection(
        adminC!,
        conn.c,
        'status active',
        (c) => c.status === 'active',
      );
      expect(bound.tenantId).toBe(customerC);
    });

    it('(4) inbound apply through preview → impact token → apply; mail is delivered to the provider sinks', async () => {
      const a = await previewAndApply(adminA!, conn.a!, {
        kind: 'inbound',
        domainIds: [a1.publicId, a2.publicId],
      });
      expect(a.preview.changeSet.domains.every((d: Json) => d.changed)).toBe(true);
      expect(a.preview.changeSet.domains[0].proposed.servers[0].host).toMatch(
        /\.mail\.protection\.outlook\.com$/,
      );
      expectStatus(a.apply, 200, 'apply inbound (A)');
      // A replayed apply (same token) after the row moved is impact_changed, never a second apply.
      const stale = await adminA!.post(
        `/provider-connections/${conn.a}/mail-flow/apply`,
        {
          change: { kind: 'inbound', domainIds: [a1.publicId, a2.publicId] },
          impactToken: a.preview.impactToken,
          confirm: true,
        },
        idempotencyKey(),
      );
      expect(stale.status).toBe(409);
      expect((stale.body as Json).code).toBe('impact_changed');
      const c = await previewAndApply(adminC!, conn.c!, {
        kind: 'inbound',
        domainIds: [c1.publicId],
      });
      expectStatus(c.apply, 200, 'apply inbound (C)');
      for (const code of ['m365.inbound_connector_created', 'm365.enhanced_filtering_enabled']) {
        expectStatus(
          await adminA!.post(
            `/provider-connections/${conn.a}/attestations`,
            { code, attested: true },
            idempotencyKey(),
          ),
          200,
          `attestation ${code}`,
        );
      }
      expectStatus(
        await adminC!.post(
          `/provider-connections/${conn.c}/attestations`,
          { code: 'google.inbound_gateway_configured', attested: true },
          idempotencyKey(),
        ),
        200,
        'attestation google.inbound_gateway_configured',
      );
      const sentA = await sendInbound({
        from: extAddress('partner'),
        to: [`alice@${a1.name}`],
        subject: `P8 inbound m365 ${fx.suffix}`,
      });
      const atM365 = await waitForSinkMessage(`alice@${a1.name}`, 240_000, 'sink-m365');
      expect(lf(atM365)).toContain(sentA.messageId);
      const sentC = await sendInbound({
        from: extAddress('partner'),
        to: [`carol@${c1.name}`],
        subject: `P8 inbound google ${fx.suffix}`,
      });
      const atGoogle = await waitForSinkMessage(`carol@${c1.name}`, 240_000, 'sink-google');
      expect(lf(atGoogle)).toContain(sentC.messageId);
    });

    it('(5) outbound probe_only: a probe with tenant header and aligned DKIM passes validation; other mail is deferred (451)', async () => {
      const apply = await previewAndApply(adminA!, conn.a!, {
        kind: 'outbound',
        mode: 'probe_only',
      });
      expectStatus(apply.apply, 200, 'apply outbound probe_only (A)');
      expect(apply.preview.changeSet.connector.action).toBe('create');
      const run = await adminA!.post(
        `/provider-connections/${conn.a}/validations`,
        { kind: 'full' },
        idempotencyKey(),
      );
      expectStatus(run, 201, 'POST …/validations (A)');
      probes.a = (run.body as Json).probeAddress as string;
      expect(probes.a).toMatch(/^eg-probe-[a-z2-7]{26}@/);

      // A normal recipient while the relay is probe-only: 451 at RCPT, nothing bounces.
      const deferred = await relay(M365_SENDER, {
        from: `alice@${a1.name}`,
        to: [extAddress('bob')],
        quitAfter: 'RCPT',
      });
      expect(reply(deferred, 'RCPT#0').code, deferred.transcript).toBe(451);
      expect(reply(deferred, 'RCPT#0').text).toMatch(/not active yet/);

      const probe = await relay(M365_SENDER, {
        from: `alice@${a1.name}`,
        to: [probes.a],
        data: await m365Message({ from: `alice@${a1.name}`, to: [probes.a], subject: 'probe' }),
      });
      expect(reply(probe, 'DATA-END').code, probe.transcript).toBe(250);
      const finished = await waitForRun(adminA!, conn.a!, (run.body as Json).id as string);
      const outboundProbe = finished.results.find((r: Json) => r.code === 'outbound.probe');
      expect(outboundProbe?.status, JSON.stringify(finished.results)).toBe('pass');
      expect(['passed', 'warning'], JSON.stringify(finished.results)).toContain(finished.status);
      expect(finished.probeObservations[0]).toMatchObject({
        tenantHeader: 'match',
        dkim: 'aligned_pass',
        proofResult: 'pass',
      });
      // No message row and no S3 object for a probe (I8).
      expect(
        await fx.prisma.emailMessage.count({
          where: { organizationId: orgA, createdAt: { gte: suiteStart }, direction: 'outbound' },
        }),
      ).toBe(0);
    });

    it('(6) activation; relayed outbound mail is delivered; forged, unsigned, null-sender and non-provider mail is refused', async () => {
      expectStatus(
        await adminA!.post(
          `/provider-connections/${conn.a}/attestations`,
          { code: 'm365.internal_routing_rules_created', attested: true },
          idempotencyKey(),
        ),
        200,
        'attestation internal rules',
      );
      const activated = await previewAndApply(adminA!, conn.a!, {
        kind: 'activate',
        outboundMode: 'active',
        internalRouting: true,
      });
      expectStatus(activated.apply, 200, 'apply activate (A)');
      expect((activated.apply.body as Json).connection.outboundMode).toBe('active');
      await waitForRcpt(M365_SENDER, `alice@${a1.name}`, extAddress('bob'), 250);

      const ok = await relay(M365_SENDER, {
        from: `alice@${a1.name}`,
        to: [extAddress('bob')],
        data: await m365Message({
          from: `alice@${a1.name}`,
          to: [extAddress('bob')],
          subject: `P8 out ${fx.suffix}`,
        }),
      });
      const okQueue = accepted(ok, 'relayed outbound');
      await waitForMessage(fx.prisma, orgA, { mtaQueueId: okQueue }, 120_000);
      expect(lf(await waitForSinkMessage(extAddress('bob'), 240_000))).toContain(
        `P8 out ${fx.suffix}`,
      );
      const events = await fx.prisma.emailEvent.findMany({
        where: { organizationId: orgA, createdAt: { gte: suiteStart } },
        select: { eventType: true, details: true },
      });
      // The received event records the provider relay and its passed proof (D8).
      expect(
        events.some((e) => JSON.stringify(e.details ?? {}).includes('"providerRelay"')),
        JSON.stringify(events.map((e) => e.eventType)),
      ).toBe(true);

      const offset = await maillogOffset();
      const forged = await relay(M365_SENDER, {
        from: `alice@${a1.name}`,
        to: [extAddress('forged')],
        data: await m365Message({
          from: `alice@${a1.name}`,
          to: [extAddress('forged')],
          subject: 'forged tenant',
          tenant: guid(),
        }),
      });
      await waitForBounce(
        offset,
        accepted(forged, 'forged (queued, refused at ingestion)'),
        '5.7.26',
      );
      const unsigned = await relay(M365_SENDER, {
        from: `alice@${a1.name}`,
        to: [extAddress('unsigned')],
        data: await m365Message({
          from: `alice@${a1.name}`,
          to: [extAddress('unsigned')],
          subject: 'unsigned',
          key: null,
        }),
      });
      await waitForBounce(offset, accepted(unsigned, 'unsigned'), '5.7.26');
      const nullSender = await relay(M365_SENDER, {
        from: '',
        to: [extAddress('ndr')],
        quitAfter: 'RCPT',
      });
      expect(reply(nullSender, 'RCPT#0').code, nullSender.transcript).toBe(550);
      expect(reply(nullSender, 'RCPT#0').text).toMatch(/Null-sender/);
      const outsider = await relay('smtp-tools', {
        from: `alice@${a1.name}`,
        to: [extAddress('outsider')],
        quitAfter: 'RCPT',
      });
      expect(reply(outsider, 'RCPT#0').code, outsider.transcript).toBeGreaterThanOrEqual(550);
      // Refused by Postfix's relay restrictions before the policy (not a provider address).
      expect(reply(outsider, 'RCPT#0').text).toMatch(/Access denied/);
    });

    it('(6b) Google: probe, activation and the DKIM replay limit (the sixth copy is refused)', async () => {
      expectStatus(
        (await previewAndApply(adminC!, conn.c!, { kind: 'outbound', mode: 'probe_only' })).apply,
        200,
        'apply outbound probe_only (C)',
      );
      const run = await adminC!.post(
        `/provider-connections/${conn.c}/validations`,
        { kind: 'full' },
        idempotencyKey(),
      );
      expectStatus(run, 201, 'POST …/validations (C)');
      probes.c = (run.body as Json).probeAddress as string;
      await waitForRcpt(GOOGLE_SENDER, `carol@${c1.name}`, probes.c, 250);
      const probeMessage = await dkimSignAs(
        providerMessage({ from: `carol@${c1.name}`, to: [probes.c], subject: 'probe' }),
        keyC1,
      );
      expect(
        reply(
          await relay(GOOGLE_SENDER, {
            from: `carol@${c1.name}`,
            to: [probes.c],
            data: probeMessage,
          }),
          'DATA-END',
        ).code,
      ).toBe(250);
      const finished = await waitForRun(adminC!, conn.c!, (run.body as Json).id as string);
      expect(['passed', 'warning'], JSON.stringify(finished.results)).toContain(finished.status);
      expectStatus(
        (
          await previewAndApply(adminC!, conn.c!, {
            kind: 'activate',
            outboundMode: 'active',
            internalRouting: false,
          })
        ).apply,
        200,
        'apply activate (C)',
      );
      await waitForRcpt(GOOGLE_SENDER, `carol@${c1.name}`, extAddress('dave'), 250);
      const signed = await dkimSignAs(
        providerMessage({
          from: `carol@${c1.name}`,
          to: [extAddress('dave')],
          subject: `P8 replay ${fx.suffix}`,
        }),
        keyC1,
      );
      const offset = await maillogOffset();
      const queues: string[] = [];
      for (let i = 0; i < 6; i += 1) {
        const sent = await relay(GOOGLE_SENDER, {
          from: `carol@${c1.name}`,
          to: [extAddress('dave')],
          data: signed,
        });
        queues.push(accepted(sent, `replay copy ${i + 1}`));
        // Distinct queue files, processed in order (the replay counter counts queue ids).
        await waitForMaillog(
          offset,
          new RegExp(`${escapeRegExp(queues[i]!)}: .*(status=sent|status=bounced)`),
          120_000,
        );
      }
      await waitForBounce(offset, queues[5]!, '5.7.26');
      for (const queue of queues.slice(0, 5)) {
        await waitForMessage(fx.prisma, orgC, { mtaQueueId: queue }, 60_000);
      }
    });

    it('(7) Microsoft 365 internal routing: the route token reaches the provider; a re-routed copy is stopped; critical health → webhook and alert', async () => {
      hook = await createWebhook(adminA!, {
        name: `P8 health ${fx.suffix}`,
        path: `it-p8-${fx.suffix}/health`,
        eventTypes: ['integration.health_changed'],
      });
      const to = `erin@${a2.name}`;
      const internal = await relay(M365_SENDER, {
        from: `alice@${a1.name}`,
        to: [to],
        data: await m365Message({
          from: `alice@${a1.name}`,
          to: [to],
          subject: `P8 internal ${fx.suffix}`,
        }),
      });
      accepted(internal, 'internal');
      const delivered = lf(await waitForSinkMessage(to, 240_000, 'sink-m365'));
      const token = /^X-EG-Route-Token: ([a-z2-7]{32})$/m.exec(delivered)?.[1];
      expect(token, 'route token header on the internal delivery').toBeDefined();
      const flow = await adminA!.get(`/provider-connections/${conn.a}/mail-flow`);
      expect((flow.body as Json).routeToken.value).toBe(token);
      expect(delivered.indexOf('X-Gateway-Trace:')).toBeLessThan(
        delivered.indexOf('X-EG-Route-Token:'),
      );

      // Exchange re-routes the copy when the transport-rule exception is missing: the header is
      // gone, every gateway pass adds a trace, and the hop limit (ROUTING_MAX_GATEWAY_PASSES)
      // ends the loop with a `loop_detected` delivery (ADR-0081); routing.loops turns critical.
      let loopDelivery: { id: bigint } | undefined;
      const internalDeliveries = () =>
        fx.prisma.emailDelivery.count({
          where: { organizationId: orgA, direction: 'internal', status: 'delivered' },
        });
      const seen: string[] = [];
      for (let pass = 1; pass <= 8 && !loopDelivery; pass += 1) {
        // The copy that went through the gateway most often (most trace headers), without the
        // sink's own Delivered-To / Return-Path (the sink would refuse it as its own loop).
        const copies = await Promise.all(
          (await sinkFiles(to, 'sink-m365')).map(async (f) =>
            lf(await sinkMessage(f, 'sink-m365')),
          ),
        );
        const traces = (m: string) => m.split('\nX-Gateway-Trace:').length;
        const newest = copies.sort((x, y) => traces(y) - traces(x))[0]!;
        seen.push(
          `pass ${pass}: ${copies.length} copies, ${traces(newest) - 1} traces, ${newest.split('\nReceived:').length - 1} received`,
        );
        const loopCopy = newest
          .split('\n')
          .filter((line) => !/^(X-EG-Route-Token|Delivered-To|Return-Path):/.test(line))
          .join('\r\n');
        const before = await internalDeliveries();
        accepted(
          await relay(M365_SENDER, { from: `alice@${a1.name}`, to: [to], data: loopCopy }),
          `re-routed copy ${pass}`,
        );
        loopDelivery = await waitFor(
          `pass ${pass}: another delivery to the provider or a loop_detected delivery`,
          async () => {
            const loop = await fx.prisma.emailDelivery.findFirst({
              where: { organizationId: orgA, failureReason: 'loop_detected' },
              select: { id: true },
            });
            if (loop) return { found: loop };
            if ((await internalDeliveries()) <= before) return undefined;
            // Wait until the new copy is stored at the sink before reading it next pass.
            await sleep(3_000);
            return { found: undefined };
          },
          { timeoutMs: 180_000, intervalMs: 2_000 },
        ).then((r) => r.found);
      }
      expect(loopDelivery, `the hop limit stopped the loop (${seen.join('; ')})`).toBeDefined();

      expectStatus(
        await adminA!.post(
          `/provider-connections/${conn.a}/health/check`,
          undefined,
          idempotencyKey(),
        ),
        202,
        'POST …/health/check',
      );
      const critical = await waitForConnection(
        adminA!,
        conn.a!,
        'health critical',
        (c) => c.health === 'critical',
        240_000,
      );
      expect(critical.status).toBe('active');
      const requests = await waitFor(
        'integration.health_changed webhook',
        async () => {
          const got = await receivedRequests(hook!.path);
          return got.some((r) => r.eventType === 'integration.health_changed') ? got : undefined;
        },
        { timeoutMs: 180_000, intervalMs: 2_000 },
      );
      const event = requests.find((r) => r.eventType === 'integration.health_changed')!;
      expect(event.envelope.data).toMatchObject({
        connection: { id: conn.a, provider: 'microsoft_365' },
        status: 'critical',
      });
      expect((event.envelope.data as { failingChecks: string[] }).failingChecks).toContain(
        'routing.loops',
      );
      expect(JSON.stringify(event.envelope)).not.toContain(appA.secret);
      const window = await waitFor(
        'integration_unhealthy alert window',
        () =>
          fx.prisma.notificationAlertWindow
            .findFirst({ where: { organizationId: orgA, kind: 'integration_unhealthy' } })
            .then((row) => row ?? undefined),
        { timeoutMs: 120_000, intervalMs: 2_000 },
      );
      expect(window.scopeKey).toBe(conn.a);
    });

    it('(8) disconnect: the relay connector is disabled, destinations are kept, outbound is refused afterwards', async () => {
      const preview = await adminA!.post(`/provider-connections/${conn.a}/mail-flow/preview`, {
        change: { kind: 'disable' },
      });
      expectStatus(preview, 200, 'preview disable');
      const done = await adminA!.delete(`/provider-connections/${conn.a}`, idempotencyKey(), {
        impactToken: (preview.body as Json).impactToken,
        confirm: true,
      });
      expectStatus(done, 200, 'DELETE /provider-connections/{id}');
      expect(done.body).toMatchObject({
        destinationsKept: true,
        connection: { status: 'disabled', outboundMode: 'off' },
      });
      expect(((done.body as Json).providerCleanupSteps as string[]).length).toBeGreaterThan(0);
      const connector = await fx.prisma.smtpConnector.findFirstOrThrow({
        where: { organizationId: orgA, authType: 'provider_relay' },
      });
      expect(connector.status).toBe('disabled');
      const destinations = await adminA!.get(`/domains/${a1.publicId}/destinations`);
      expect(JSON.stringify(destinations.body)).toContain('mail.protection.outlook.com');
      const refused = await waitForRcpt(M365_SENDER, `alice@${a1.name}`, extAddress('late'), 550);
      expect(reply(refused, 'RCPT#0').text).toMatch(/Relay access denied/);
    });

    it('(9) failover: with sink-google down, inbound mail for the wizard-applied Google destination reaches the alternate', async () => {
      await compose(['stop', 'sink-google'], { timeoutMs: 60_000 });
      try {
        const sent = await sendInbound({
          from: extAddress('partner'),
          to: [`frank@${c1.name}`],
          subject: `P8 failover ${fx.suffix}`,
        });
        expect(
          lf(await waitForSinkMessage(`frank@${c1.name}`, 300_000, 'sink-google-alt')),
        ).toContain(sent.messageId);
      } finally {
        await compose(['start', 'sink-google'], { timeoutMs: 60_000 });
        await sleep(2_000);
      }
    });
  },
);

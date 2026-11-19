import { randomBytes } from 'node:crypto';
import { parseEgressCidr } from '@email-gateway/database';
import { ProviderCredentialCipher } from '@email-gateway/provider-integrations';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RETENTION } from '../src/maintenance/maintenance';
import { Harness, signal } from './support/harness';

/**
 * Maintenance (§10.3, §3.3, D5, D7.6, D11): retention per table, consent expiry, re-encryption
 * after a key rotation (counts, idempotent), the shared-network gauge and the leader lock.
 */
const h = new Harness();
let org: bigint;
const DAY = 86_400_000;

beforeAll(async () => {
  await h.start();
  org = await h.organization('maintenance');
});

afterAll(async () => {
  await h.cleanup();
});

describe('maintenance', () => {
  it('applies the §3.3 retention per table', async () => {
    const now = h.clock.now().getTime();
    const user = await h.user(org);
    const connection = await h.connection(org, 'microsoft_365', { status: 'active' });
    const grant = await h.grant(connection, { authMethod: 'platform_app', status: 'active' });
    const consent = (expiresAt: Date) =>
      h.prisma.providerConsentState.create({
        data: {
          organizationId: org,
          connectionId: connection.id,
          grantId: grant.id,
          userId: user.id,
          stateSha256: randomBytes(32).toString('hex'),
          expiresAt,
        },
      });
    const oldConsent = await consent(new Date(now - 25 * 3_600_000));
    const freshConsent = await consent(new Date(now - 23 * 3_600_000));
    const observation = (receivedAt: Date, queueId: string) =>
      h.prisma.providerProbeObservation.create({
        data: {
          organizationId: org,
          connectionId: connection.id,
          tokenSha256: randomBytes(32).toString('hex'),
          queueId,
          provider: 'microsoft_365',
          clientIp: '172.31.250.70',
          envelopeFromDomain: 'x.test',
          tenantHeader: 'match',
          dkim: 'aligned_pass',
          dkimDomains: [],
          proofResult: 'pass',
          receivedAt,
        },
      });
    const oldObs = await observation(new Date(now - 31 * DAY), 'OLD1');
    const newObs = await observation(new Date(now - 29 * DAY), 'NEW1');
    const event = (createdAt: Date) =>
      h.prisma.providerHealthEvent.create({
        data: {
          organizationId: org,
          connectionId: connection.id,
          fromStatus: 'healthy',
          toStatus: 'warning',
          failingChecks: [],
          createdAt,
        },
      });
    const oldEvent = await event(new Date(now - 366 * DAY));
    const newEvent = await event(new Date(now - 364 * DAY));
    const counter = (hourStart: Date) =>
      h.prisma.providerRelayCounter.create({
        data: { organizationId: org, connectionId: connection.id, hourStart, accepted: 1 },
      });
    const oldCounter = await counter(
      new Date(Math.floor((now - 36 * DAY) / 3_600_000) * 3_600_000),
    );
    const newCounter = await counter(
      new Date(Math.floor((now - 34 * DAY) / 3_600_000) * 3_600_000),
    );
    // Validation runs: one older than 180 days, and 52 recent ones (50 are kept).
    const run = (createdAt: Date, status: 'passed' | 'queued' = 'passed') =>
      h.prisma.providerValidationRun.create({
        data: {
          organizationId: org,
          connectionId: connection.id,
          kind: 'credentials',
          status,
          requestedByType: 'system',
          createdAt,
        },
      });
    const ancient = await run(new Date(now - 181 * DAY));
    const recent: { id: bigint }[] = [];
    for (let i = 0; i < 52; i += 1) recent.push(await run(new Date(now - (52 - i) * 60_000)));

    const { components } = h.worker();
    const deleted = await components.maintenance.retention();
    expect(deleted).toMatchObject({
      provider_consent_states: 1,
      provider_probe_observations: 1,
      provider_health_events: 1,
      provider_relay_counters: 1,
    });
    expect(deleted.provider_validation_runs).toBe(3);
    const exists = async (model: { count(args: object): Promise<number> }, id: bigint) =>
      (await model.count({ where: { id } })) === 1;
    expect(await exists(h.prisma.providerConsentState, oldConsent.id)).toBe(false);
    expect(await exists(h.prisma.providerConsentState, freshConsent.id)).toBe(true);
    expect(await exists(h.prisma.providerProbeObservation, oldObs.id)).toBe(false);
    expect(await exists(h.prisma.providerProbeObservation, newObs.id)).toBe(true);
    expect(await exists(h.prisma.providerHealthEvent, oldEvent.id)).toBe(false);
    expect(await exists(h.prisma.providerHealthEvent, newEvent.id)).toBe(true);
    expect(await exists(h.prisma.providerRelayCounter, oldCounter.id)).toBe(false);
    expect(await exists(h.prisma.providerRelayCounter, newCounter.id)).toBe(true);
    expect(await exists(h.prisma.providerValidationRun, ancient.id)).toBe(false);
    expect(
      await h.prisma.providerValidationRun.count({ where: { connectionId: connection.id } }),
    ).toBe(RETENTION.validationRunsPerConnection);
    expect(await exists(h.prisma.providerValidationRun, recent[0]!.id)).toBe(false);
    expect(await exists(h.prisma.providerValidationRun, recent[51]!.id)).toBe(true);
    // Idempotent: nothing more to delete.
    const again = await components.maintenance.retention();
    expect(Object.values(again).every((n) => n === 0)).toBe(true);
  });

  it('re-encrypts credentials under the previous key after a rotation (counts, idempotent, audited)', async () => {
    const oldKey = randomBytes(32).toString('hex');
    const oldCipher = ProviderCredentialCipher.fromConfig({
      PROVIDER_CREDENTIAL_ENCRYPTION_KEY: oldKey,
    });
    const tenant = h.m365Tenant({ domains: [] });
    const connection = await h.connection(org, 'microsoft_365', {
      status: 'active',
      externalTenantId: tenant.tenantId,
      tenantVerifiedAt: h.clock.now(),
    });
    const grant = await h.grant(connection, {
      authMethod: 'customer_app_secret',
      status: 'active',
      clientId: tenant.clientId,
      claimedTenantId: tenant.tenantId,
      credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
      keyCipher: oldCipher,
    });
    expect(grant.credentialKeyId).toBe(oldCipher.currentKeyId);
    const { components } = h.worker({
      config: { PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS: oldKey },
    });
    const first = await components.maintenance.reencrypt();
    expect(first.reencrypted).toBeGreaterThanOrEqual(1);
    expect(first.failed).toBe(0);
    const after = await h.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: grant.id },
    });
    expect(after.credentialKeyId).toBe(h.cipher.currentKeyId);
    expect(after.credentialCiphertext).not.toBe(grant.credentialCiphertext);
    expect(after.credentialVersion).toBe(grant.credentialVersion);
    // The re-encrypted credential still works (decrypt with the current key, token from the fake).
    const token = await components.runtime.tokens.getAccessToken(
      { organizationId: org, connectionPublicId: connection.publicId, profile: 'm365.mail_flow' },
      signal(),
    );
    expect(token.observedPermissions.length).toBeGreaterThan(0);
    const second = await components.maintenance.reencrypt();
    expect(second.reencrypted).toBe(0);
    const audit = await h.prisma.auditLog.findFirst({
      where: { organizationId: null, action: 'integration.credentials_reencrypted' },
      orderBy: { id: 'desc' },
    });
    expect(audit?.metadata).toMatchObject({ reencrypted: first.reencrypted });
    expect(JSON.stringify(audit?.metadata)).not.toContain(tenant.secret);
    if (audit) await h.prisma.auditLog.deleteMany({ where: { id: audit.id } });
  });

  it('counts active source_ip networks overlapping an active provider egress range (D7.6)', async () => {
    const { components, metrics } = h.worker();
    const before = await components.maintenance.gauges();
    const range = await h.prisma.providerEgressRange.findFirst({
      where: { provider: 'microsoft_365', ipVersion: 4, set: { status: 'active' } },
      select: { cidr: true },
    });
    expect(range).not.toBeNull();
    const network = parseEgressCidr(range!.cidr);
    const connector = await h.prisma.smtpConnector.create({
      data: { organizationId: org, name: `it-shared-${h.suffix}`, authType: 'source_ip' },
    });
    await h.prisma.smtpConnectorNetwork.create({
      data: {
        organizationId: org,
        connectorId: connector.id,
        cidr: network.cidr,
        ipVersion: 4,
        rangeStart: Uint8Array.from(network.rangeStart),
        rangeEnd: Uint8Array.from(network.rangeEnd),
      },
    });
    expect(await components.maintenance.gauges()).toBe(before + 1);
    expect((await metrics.sharedNetworks.get()).values[0]?.value).toBe(before + 1);
    const ages = await metrics.egressSetAge.get();
    expect(ages.values.find((v) => v.labels.provider === 'microsoft_365')?.value).toBeGreaterThan(
      0,
    );
    await h.prisma.smtpConnector.update({
      where: { id: connector.id },
      data: { status: 'disabled' },
    });
    expect(await components.maintenance.gauges()).toBe(before);
  });

  it('runs on one leader only (GET_LOCK) and zeroes the gauges elsewhere', async () => {
    const a = h.worker({ config: { INTEGRATION_WORKER_ROLES: 'maintenance' } });
    const b = h.worker({ config: { INTEGRATION_WORKER_ROLES: 'maintenance' } });
    a.components.start();
    b.components.start();
    await new Promise((resolve) => setTimeout(resolve, 1_500));
    const leaders = await Promise.all(
      [a, b].map(
        async (w) =>
          (await w.metrics.leader.get()).values.find((v) => v.labels.job === 'maintenance')
            ?.value ?? 0,
      ),
    );
    expect(leaders.sort()).toEqual([0, 1]);
    await a.components.stop();
    await b.components.stop();
  });
});

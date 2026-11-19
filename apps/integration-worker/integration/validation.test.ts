import { generateProbeToken, probeTokenSha256 } from '@email-gateway/mail-routing';
import { lockdownAttestations } from '@email-gateway/provider-integrations';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { CheckResult } from '../src/checks/checks';
import { probeSmtp, type SmtpProbeOptions } from '../src/checks/smtp-probe';
import {
  generateTestPki,
  hasOpenssl,
  TestSmtpServer,
} from '../src/checks/smtp-server.test-support';
import { Harness, signal } from './support/harness';

/**
 * Validation runs (§10.3, D10): every check code of a `full` run, the SMTP probe against a local
 * SMTP server with runtime test-PKI certificates (never DATA — the server asserts it), the
 * outbound probe (completion and expiry), claims and leases (SKIP LOCKED), idempotent completion.
 */
const h = new Harness();
const pki = hasOpenssl()
  ? generateTestPki(['*.mail.protection.outlook.com', 'mail.protection.outlook.com'])
  : null;
const smtp = pki ? new TestSmtpServer({ pki }) : null;
let smtpPort = 0;
let org: bigint;

const probe = (o: SmtpProbeOptions) =>
  smtp
    ? probeSmtp({ ...o, address: '127.0.0.1', port: smtpPort, ca: [pki!.caPem] })
    : Promise.resolve({
        status: 'pass' as const,
        code: 'ok' as const,
        evidence: {
          banner: 'stub',
          tlsVersion: 'TLSv1.3',
          certificateSubject: null,
          certificateNames: [],
          namesMatch: true,
          rcptReplyClass: '2xx' as const,
        },
      });

beforeAll(async () => {
  await h.start();
  if (smtp) smtpPort = await smtp.start();
  org = await h.organization('validation');
});

afterAll(async () => {
  if (smtp) {
    expect(smtp.dataSeen).toBe(false);
    await smtp.stop();
  }
  await h.cleanup();
});

/** An active, bound Microsoft 365 connection with one linked, verified, routed domain. */
async function boundConnection(
  label: string,
  options: {
    outboundMode?: 'off' | 'probe_only' | 'active';
    destination?: boolean;
    attested?: boolean;
  } = {},
) {
  const domainName = h.name(label);
  const mxHost = `${domainName.replace(/\./g, '-')}.mail.protection.outlook.com`;
  const tenant = h.m365Tenant({ domains: [{ name: domainName, mxHost }] });
  const domain = await h.domain(org, domainName);
  const connection = await h.connection(org, 'microsoft_365', {
    status: 'active',
    externalTenantId: tenant.tenantId,
    tenantVerifiedAt: h.clock.now(),
    outboundMode: options.outboundMode ?? 'off',
    attestations:
      options.attested === false
        ? []
        : lockdownAttestations('microsoft_365').map((code) => ({
            code,
            userId: 'u',
            at: h.clock.now().toISOString(),
          })),
  });
  await h.grant(connection, {
    authMethod: 'customer_app_secret',
    status: 'active',
    clientId: tenant.clientId,
    claimedTenantId: tenant.tenantId,
    credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
  });
  await h.prisma.providerConnectionDomain.create({
    data: {
      organizationId: org,
      connectionId: connection.id,
      domainId: domain.id,
      providerVerification: 'verified',
      providerMxHost: mxHost,
    },
  });
  await h.dnsRecords(org, domain.id);
  if (options.destination !== false) {
    await h.destination(org, domain.id, 'microsoft_365', mxHost);
  }
  h.resolver.a.set(mxHost, ['203.0.113.25']);
  h.resolver.cnames.set(`selector1._domainkey.${domainName}`, [
    `selector1-x._domainkey.contoso.onmicrosoft.com`,
  ]);
  return { connection, domain, tenant, mxHost };
}

async function queueRun(
  connection: { id: bigint; organizationId: bigint },
  kind: 'full' | 'credentials' | 'inbound' | 'outbound',
  probeToken?: string,
) {
  return h.prisma.providerValidationRun.create({
    data: {
      organizationId: connection.organizationId,
      connectionId: connection.id,
      kind,
      requestedByType: 'user',
      requestedById: 'it-user',
      createdAt: h.clock.now(),
      ...(probeToken ? { probeTokenSha256: probeTokenSha256(probeToken) } : {}),
    },
  });
}

const resultsOf = async (runId: bigint) => {
  const run = await h.prisma.providerValidationRun.findUniqueOrThrow({ where: { id: runId } });
  return { run, results: (run.results ?? []) as unknown as CheckResult[] };
};

describe('validation runs', () => {
  it('full run with outbound off: every check of D10, SMTP probe without DATA, passed', async () => {
    const { connection, mxHost } = await boundConnection('full-off');
    const queued = await queueRun(connection, 'full');
    const { components, metrics } = h.worker({ probeSmtp: probe });
    expect(await components.validations.runOnce(4, signal())).toBeGreaterThanOrEqual(1);
    const { run, results } = await resultsOf(queued.id);
    expect(run.status).toBe('passed');
    expect(run.completedAt).not.toBeNull();
    expect(run.claimedUntil).toBeNull();
    const codes = new Set(results.map((r) => r.code));
    for (const code of [
      'credentials.token',
      'permissions.granted',
      'tenant.identity',
      'domains.gateway_verified',
      'domains.provider_verified',
      'dns.mx_gateway',
      'inbound.destination',
      'inbound.destination_matches_provider',
      'inbound.smtp',
      'inbound.recent_deliveries',
      'dns.spf_gateway',
      'dns.dkim_provider',
      'outbound.probe',
      'routing.no_loops',
      'lockdown.attested',
    ]) {
      expect(codes.has(code)).toBe(true);
    }
    const smtpResult = results.find((r) => r.code === 'inbound.smtp')!;
    expect(smtpResult).toMatchObject({ status: 'pass', subject: mxHost });
    expect(results.find((r) => r.code === 'outbound.probe')?.status).toBe('skipped');
    expect(results.find((r) => r.code === 'dns.spf_gateway')?.status).toBe('skipped');
    expect(run.summary).toMatchObject({ fail: 0, error: 0 });
    if (smtp) expect(smtp.dataSeen).toBe(false);
    const audit = await h.prisma.auditLog.findFirstOrThrow({
      where: {
        organizationId: org,
        action: 'integration.validation_completed',
        resourceId: connection.publicId,
      },
    });
    expect(audit.metadata).toMatchObject({ kind: 'full', status: 'passed' });
    const counted = await metrics.validationRuns.get();
    expect(counted.values.some((v) => v.labels.result === 'passed')).toBe(true);
  });

  it('a required check failing fails the run (no destinations, unverified DNS)', async () => {
    const { connection, domain } = await boundConnection('full-fail', { destination: false });
    await h.prisma.domainDnsRecord.updateMany({
      where: { domainId: domain.id, purpose: 'mx' },
      data: { status: 'invalid' },
    });
    const queued = await queueRun(connection, 'inbound');
    await h.worker({ probeSmtp: probe }).components.validations.runOnce(4, signal());
    const { run, results } = await resultsOf(queued.id);
    expect(run.status).toBe('failed');
    expect(results.find((r) => r.code === 'inbound.destination')).toMatchObject({ status: 'fail' });
    expect(results.find((r) => r.code === 'dns.mx_gateway')).toMatchObject({
      status: 'fail',
      severity: 'critical',
    });
    expect(results.find((r) => r.code === 'inbound.smtp')).toMatchObject({ status: 'fail' });
  });

  it('stale DNS observations warn; missing lockdown attestations warn', async () => {
    const { connection, domain } = await boundConnection('stale', { attested: false });
    await h.prisma.domainDnsRecord.updateMany({
      where: { domainId: domain.id },
      data: { lastCheckedAt: new Date(h.clock.now().getTime() - 2 * 86_400_000) },
    });
    const queued = await queueRun(connection, 'full');
    await h.worker({ probeSmtp: probe }).components.validations.runOnce(4, signal());
    const { run, results } = await resultsOf(queued.id);
    expect(run.status).toBe('warning');
    expect(results.find((r) => r.code === 'dns.mx_gateway')?.status).toBe('warn');
    expect(results.find((r) => r.code === 'lockdown.attested')?.status).toBe('warn');
  });

  it('outbound probe: awaiting_probe, then completed by an observation (linked), idempotently', async () => {
    const { connection, domain } = await boundConnection('probe', { outboundMode: 'probe_only' });
    const token = generateProbeToken();
    const queued = await queueRun(connection, 'outbound', token);
    const { components } = h.worker({ probeSmtp: probe });
    await components.validations.runOnce(4, signal());
    let { run } = await resultsOf(queued.id);
    expect(run.status).toBe('awaiting_probe');
    expect(run.probeExpiresAt!.getTime()).toBe(queued.createdAt.getTime() + 86_400_000);
    expect(await components.validations.completeProbes(10)).toBe(0);

    const observation = await h.prisma.providerProbeObservation.create({
      data: {
        organizationId: org,
        connectionId: connection.id,
        tokenSha256: probeTokenSha256(token),
        queueId: 'ITQ1',
        provider: 'microsoft_365',
        clientIp: '172.31.250.70',
        tlsProtocol: 'TLSv1.3',
        envelopeFromDomain: (await h.prisma.domain.findUniqueOrThrow({ where: { id: domain.id } }))
          .name,
        tenantHeader: 'match',
        dkim: 'aligned_pass',
        dkimDomains: [],
        proofResult: 'pass',
        receivedAt: h.clock.now(),
      },
    });
    expect(await components.validations.completeProbes(10)).toBe(1);
    const done = await resultsOf(queued.id);
    run = done.run;
    expect(['passed', 'warning']).toContain(run.status);
    expect(done.results.find((r) => r.code === 'outbound.probe')).toMatchObject({
      status: 'pass',
      evidence: { proofResult: 'pass', tenantHeader: 'match', dkim: 'aligned_pass' },
    });
    // The worker never stores the probe token, only its hash.
    expect(JSON.stringify(done.results)).not.toContain(token);
    const linked = await h.prisma.providerProbeObservation.findUniqueOrThrow({
      where: { id: observation.id },
    });
    expect(linked.validationRunId).toBe(queued.id);
    expect(await components.validations.completeProbes(10)).toBe(0);
  });

  it('outbound probe expiry: the maintenance role ends the run expired', async () => {
    const { connection } = await boundConnection('probe-expiry', { outboundMode: 'probe_only' });
    const queued = await queueRun(connection, 'outbound', generateProbeToken());
    const { components } = h.worker({ probeSmtp: probe });
    await components.validations.runOnce(4, signal());
    expect((await resultsOf(queued.id)).run.status).toBe('awaiting_probe');
    h.clock.advance(86_400_000 + 1_000);
    expect(await components.validations.expireProbes(100)).toBeGreaterThanOrEqual(1);
    const { run, results } = await resultsOf(queued.id);
    expect(run.status).toBe('expired');
    expect(results.find((r) => r.code === 'outbound.probe')).toMatchObject({
      status: 'fail',
      evidence: { reason: 'probe_expired' },
    });
    h.clock.set(new Date());
  });

  it('claims are disjoint (SKIP LOCKED); an expired lease is taken over; completion happens once', async () => {
    const { connection } = await boundConnection('claims');
    const runs: { id: bigint }[] = [];
    for (let i = 0; i < 4; i += 1) runs.push(await queueRun(connection, 'credentials'));
    const a = h.worker({ probeSmtp: probe }).components;
    const b = h.worker({ probeSmtp: probe }).components;
    const [ca, cb] = await Promise.all([a.validations.claim(2), b.validations.claim(2)]);
    const ids = [...ca, ...cb].map((r) => r.id.toString());
    expect(new Set(ids).size).toBe(ids.length);
    const mine = runs.map((r) => r.id.toString());
    expect(ids.filter((id) => mine.includes(id)).length).toBeGreaterThan(0);
    // Lease expiry: another worker takes the run over (attempts + 1) and completes it once.
    h.clock.advance(121_000);
    const taken = (await b.validations.claim(10)).filter((r) => mine.includes(r.id.toString()));
    expect(taken.length).toBe(4);
    for (const claimed of taken) await b.validations.execute(claimed, signal());
    for (const run of runs) {
      const row = await h.prisma.providerValidationRun.findUniqueOrThrow({ where: { id: run.id } });
      expect(['passed', 'warning']).toContain(row.status);
      expect(row.attempts).toBeGreaterThanOrEqual(1);
    }
    // A second completion of the same run writes nothing (status guard).
    expect(await a.validations.execute(taken[0]!, signal())).toBeNull();
    const audits = await h.prisma.auditLog.count({
      where: {
        organizationId: org,
        action: 'integration.validation_completed',
        resourceId: connection.publicId,
      },
    });
    expect(audits).toBe(4);
    h.clock.set(new Date());
  });
});

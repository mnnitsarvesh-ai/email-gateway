/**
 * Step 4.6 api routes against the real MySQL writer and replica (docs/plan/steps/14-sandbox.md
 * X17, X18, §9.4): the `sandbox` scan settings through the existing settings routes (the plan
 * feature `attachment_sandbox` read on the writer: `409 feature_not_enabled` without it, audit
 * with it), and the sandbox detail of the scans read API on the replica: the attachment's
 * submission outcome and the `sandbox` engine entry with the report and artifact metadata of
 * the analysis that completed it — read only by the ids of the caller's own submissions; another
 * organization's message is 404; no analysis id, reuse flag or analysis timing is returned. Rows
 * are inserted as the email-worker writes them (fixtures). No new permission.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { PrismaReadService } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, uniqueIp } from './support/http';
import {
  deleteLifecycleFixtures,
  insertLifecycleMessage,
  type LifecycleMessage,
} from './support/lifecycle';

const POLL = { timeout: 15_000, interval: 200 };
const run = randomBytes(6).toString('hex');
const SHA = `${run}${'c'.repeat(64)}`.slice(0, 64);

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let readerA: Record<string, string>;
let readerB: Record<string, string>;
const analysisIds: bigint[] = [];

const headers = (auth: Record<string, string>) => ({ ...auth, 'X-Forwarded-For': uniqueIp() });

async function deleteSandboxFixtures(organizationIds: bigint[]): Promise<void> {
  const where = { organizationId: { in: organizationIds } };
  await ctx.prisma.sandboxSubmission.deleteMany({ where });
  await ctx.prisma.sandboxArtifact.deleteMany({ where: { analysisId: { in: analysisIds } } });
  await ctx.prisma.sandboxAnalysis.deleteMany({ where: { id: { in: analysisIds } } });
  await ctx.prisma.attachmentScanResult.deleteMany({ where });
  await ctx.prisma.emailAttachment.deleteMany({ where });
  await ctx.prisma.scanEngineResult.deleteMany({ where });
  await ctx.prisma.emailScan.deleteMany({ where });
  await ctx.prisma.scanEngineSetting.deleteMany({ where });
  await ctx.prisma.auditLog.deleteMany({
    where: { ...where, resourceType: 'scan_engine_settings' },
  });
}

/** A terminal, static analysis with its bounded report and one sealed artifact's metadata. */
async function insertAnalysis(organizationId: bigint) {
  const completedAt = new Date();
  const analysis = await ctx.prisma.sandboxAnalysis.create({
    data: {
      sha256: SHA,
      sizeBytes: 120,
      detectedType: 'script_js',
      profile: 'execute',
      analysisKey: '0123456789abcdef',
      dedupeKey: null,
      status: 'completed',
      organizationId,
      deadlineAt: new Date(completedAt.getTime() + 900_000),
      dispatchedAt: new Date(completedAt.getTime() - 4_000),
      completedAt,
      verdict: 'malicious',
      reasonCodes: ['sandbox.static_only', 'sandbox.static.script_encoded_powershell'],
      report: {
        v: 1,
        findings: [{ code: 'static.script_encoded_powershell', severity: 'high', count: 1 }],
        indicators: { dns: ['dl.example'], httpHosts: [], tlsSni: [], ips: [] },
        networkTotals: { dns: 1, http: 0, tls: 0, connections: 0 },
        processes: { count: 0, images: [] },
        droppedFiles: [],
        deniedWrites: 0,
        limitsHit: [],
        browser: null,
      },
      backend: 'static',
      backendVersion: 'sandbox-static/1',
      isolation: 'process',
      executed: false,
      controllerVersion: '0.1.0',
      analyzerVersion: 'sandbox-static/1',
      mapVersion: 'sandbox-map/1',
      durationMs: 3_210,
      reuseUntil: new Date(completedAt.getTime() + 86_400_000),
      expiresAt: new Date(completedAt.getTime() + 180 * 86_400_000),
    },
  });
  analysisIds.push(analysis.id);
  await ctx.prisma.sandboxArtifact.create({
    data: {
      analysisId: analysis.id,
      seq: 0,
      kind: 'static_report',
      contentType: 'application/json',
      objectKey: `artifacts/2026/11/${analysis.publicId}/0123456789abcdef/0-static_report.bin`,
      objectSha256: 'a'.repeat(64),
      plainSha256: 'b'.repeat(64),
      sizeBytes: 812,
      wrappedKey: 'x1.deadbeef.AAAA.BBBB.CCCC.DDDD',
      keyId: 'deadbeef',
      algorithm: 'sandbox-artifact/1',
      expiresAt: new Date(Date.UTC(2026, 11, 8, 13, 47, 11)),
    },
  });
  return analysis;
}

/** A completed round with an attachment final, a sandbox final and the completed submission. */
async function insertSandboxRound(
  message: LifecycleMessage,
  analysis: { id: bigint; publicId: string },
) {
  const startedAt = new Date(message.receivedAt.getTime() + 1_000);
  const attachment = await ctx.prisma.emailAttachment.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: message.organizationId,
      partIndex: 1,
      filename: 'fixture.js',
      declaredContentType: 'application/javascript',
      detectedContentType: 'text/plain',
      sizeBytes: 120,
      sha256: SHA,
      objectKey: `org/${message.organizationId.toString()}/part/2026/11/08/${message.id.toString()}/1.att`,
    },
    select: { id: true },
  });
  const scan = await ctx.prisma.emailScan.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: message.organizationId,
      scanKind: 'initial',
      status: 'completed',
      lifecycleRound: 0,
      scanVerdict: 'suspicious',
      requiredEngines: ['rspamd', 'attachment'],
      reasonCodes: ['type.denied'],
      startedAt,
      completedAt: new Date(startedAt.getTime() + 2_000),
      deadlineAt: new Date(startedAt.getTime() + 1_800_000),
    },
    select: { id: true },
  });
  const final = (engine: string, outcome: 'suspicious' | 'malicious', at: number) => ({
    receivedAt: message.receivedAt,
    scanId: scan.id,
    messageId: message.id,
    organizationId: message.organizationId,
    engine,
    engineVersion: engine === 'sandbox' ? '0.1.0+static/sandbox-static/1' : 'clamav/1.4.6',
    outcome,
    durationMs: engine === 'sandbox' ? 0 : 40,
    attempt: 1,
    isFinal: true,
    reasonCodes:
      engine === 'sandbox'
        ? ['sandbox.static_only', 'sandbox.static.script_encoded_powershell']
        : ['type.denied'],
    settingsVersion: null,
    evidence:
      engine === 'sandbox'
        ? { submissions: 1, executed: 0, isolation: ['process'] }
        : { signals: [] },
    completedAt: new Date(startedAt.getTime() + at),
  });
  await ctx.prisma.scanEngineResult.create({ data: final('attachment', 'suspicious', 2_000) });
  await ctx.prisma.scanEngineResult.create({ data: final('sandbox', 'malicious', 9_876) });
  await ctx.prisma.attachmentScanResult.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: message.organizationId,
      scanId: scan.id,
      attachmentId: attachment.id,
      partIndex: 1,
      sha256: SHA,
      sizeBytes: 120,
      detectedType: 'script_js',
      typeFamily: 'script',
      typeMismatch: false,
      verdict: 'suspicious',
      reasonCodes: ['type.denied'],
      cacheResult: 'miss',
      durationMs: 3,
    },
  });
  await ctx.prisma.sandboxSubmission.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: message.organizationId,
      scanId: scan.id,
      attachmentId: attachment.id,
      partIndex: 1,
      sha256: SHA,
      sizeBytes: 120,
      detectedType: 'script_js',
      objectKey: `org/${message.organizationId.toString()}/part/x/1.att`,
      attachmentVerdict: 'suspicious',
      reasonCodes: ['type.denied'],
      requestedEventId: randomUUID(),
      status: 'completed',
      sandboxVerdict: 'malicious',
      sandboxReasonCodes: ['sandbox.static_only', 'sandbox.static.script_encoded_powershell'],
      completedAt: new Date(startedAt.getTime() + 9_876),
      analysisId: analysis.id,
      externalRef: analysis.publicId,
      settingsVersion: 'sandbox-map/1;p=0123456789ab;t=1',
    },
  });
  return scan.id;
}

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization({ features: { attachment_sandbox: true } });
  orgB = await fx.createOrganization({ features: { attachment_sandbox: false } });
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgA.id, orgB.id]));
  fx.registerCleanup(() => deleteSandboxFixtures([orgA.id, orgB.id]));
  readerA = apiKeyHeader(await fx.createApiKey(orgA, ['message:read', 'policy:read']));
  readerB = apiKeyHeader(await fx.createApiKey(orgB, ['message:read', 'policy:read']));
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('sandbox settings through /scan-settings/sandbox (X17)', () => {
  const url = '/api/v1/scan-settings/sandbox';

  it('refuses the opt-in without the plan feature (409, nothing written) and audits it with the feature', async () => {
    const managerB = apiKeyHeader(
      await fx.createApiKey(orgB, ['policy:read', 'scan:settings_manage']),
    );
    const refused = await ctx.http
      .put(url)
      .set(headers(managerB))
      .send({ expectedVersion: 0, settings: { enabled: true } })
      .expect(409);
    expect(refused.body).toMatchObject({
      code: 'feature_not_enabled',
      feature: 'attachment_sandbox',
    });
    expect(
      await ctx.prisma.scanEngineSetting.count({
        where: { organizationId: orgB.id, engine: 'sandbox' },
      }),
    ).toBe(0);
    // Narrowing without opting in needs no plan feature.
    await ctx.http
      .put(url)
      .set(headers(managerB))
      .send({ expectedVersion: 0, settings: { fileTypes: ['pdf'] } })
      .expect(200);

    const managerA = apiKeyHeader(
      await fx.createApiKey(orgA, ['policy:read', 'scan:settings_manage']),
    );
    const accepted = await ctx.http
      .put(url)
      .set(headers(managerA))
      .send({ expectedVersion: 0, settings: { enabled: true, maxSampleBytes: 1_048_576 } })
      .expect(200);
    expect(accepted.body).toMatchObject({
      engine: 'sandbox',
      mode: 'asynchronous',
      version: 1,
      effective: { enabled: true, maxSampleBytes: 1_048_576 },
      feature: { attachmentSandbox: true },
      execution: 'disabled',
    });
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: { organizationId: orgA.id, action: 'scan_settings.updated', resourceId: 'sandbox' },
    });
    expect(audit.metadata).toMatchObject({ after: { enabled: true, maxSampleBytes: 1_048_576 } });
    await ctx.http
      .put(url)
      .set(headers(managerA))
      .send({ expectedVersion: 0, settings: { fileTypes: ['zip'] } })
      .expect(422);

    // The list (override rows from the replica, the plan feature from the writer).
    await expect
      .poll(async () => {
        const res = await ctx.http.get('/api/v1/scan-settings').set(headers(readerA));
        const view = (res.body.data as { engine: string; version: number }[] | undefined)?.find(
          (v) => v.engine === 'sandbox',
        );
        return view?.version;
      }, POLL)
      .toBe(1);
    const listB = await ctx.http.get('/api/v1/scan-settings').set(headers(readerB)).expect(200);
    expect(
      (listB.body.data as { engine: string }[]).find((v) => v.engine === 'sandbox'),
    ).toMatchObject({ feature: { attachmentSandbox: false }, effective: { enabled: false } });
  });
});

describe('GET /messages/{messageId}/scans: sandbox detail (X18)', () => {
  it('shows the submission outcome and the analysis report through the replica; never another organization’s', async () => {
    expect(ctx.get(PrismaReadService).status().mode).toBe('reader');
    const message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned' });
    const analysis = await insertAnalysis(orgA.id);
    await insertSandboxRound(message, analysis);
    const url = `/api/v1/messages/${message.publicId}/scans`;
    await expect
      .poll(async () => {
        const body = (await ctx.http.get(url).set(headers(readerA))).body as {
          data?: { engines: { engine: string; submissions?: unknown[] }[] }[];
        };
        return body.data?.[0]?.engines.find((e) => e.engine === 'sandbox')?.submissions?.length;
      }, POLL)
      .toBe(1);
    const res = await ctx.http.get(url).set(headers(readerA)).expect(200);
    const round = res.body.data[0];
    expect(round.verdict).toBe('suspicious');
    const attachment = round.engines.find((e: { engine: string }) => e.engine === 'attachment');
    expect(attachment.attachments[0].sandbox).toMatchObject({
      status: 'completed',
      verdict: 'malicious',
      executed: false,
      isolation: 'process',
      reasonCodes: ['sandbox.static_only', 'sandbox.static.script_encoded_powershell'],
    });
    const sandbox = round.engines.find((e: { engine: string }) => e.engine === 'sandbox');
    expect(sandbox).toMatchObject({ outcome: 'malicious', durationMs: null, symbols: [] });
    expect(sandbox.completedAt).toMatch(/\.000Z$/);
    expect(sandbox.submissions[0]).toMatchObject({
      partIndex: 1,
      sha256: SHA,
      backend: 'static',
      versions: { controller: '0.1.0', backend: 'sandbox-static/1', map: 'sandbox-map/1' },
      findings: [{ code: 'static.script_encoded_powershell', severity: 'high', count: 1 }],
      indicators: { dns: ['dl.example'] },
      artifacts: [
        {
          seq: 0,
          kind: 'static_report',
          contentType: 'application/json',
          sizeBytes: 812,
          sha256: 'b'.repeat(64),
          expiresAt: '2026-12-08T00:00:00.000Z',
          purged: false,
        },
      ],
    });
    // No analysis id, timing, reuse window, object key or wrapped key reaches the tenant.
    const json = JSON.stringify(res.body);
    expect(json).not.toContain(analysis.publicId);
    expect(json).not.toMatch(/reuse|wrappedKey|objectKey|3210|"analysisId"/);

    const foreign = await ctx.http.get(url).set(headers(readerB)).expect(404);
    expect(foreign.body).toMatchObject({ code: 'message_not_found' });
  });
});

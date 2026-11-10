import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { compose, waitFor } from './support/compose';
import { clearSinkDomain } from './support/mail-sink';
import { organizationRef, MAIL_SINK_HOST } from './support/routing';
import {
  controllerHealth,
  controllerMetric,
  controllerScratch,
  EXEC_COMPOSE_FILES,
  ensureController,
  optIn,
  restoreDefaultController,
  runnerContainers,
  SANDBOX_FEATURE,
  sendAttachmentMessage,
  waitForSandboxFinal,
  waitForSubmission,
} from './support/sandbox-stack';
import { scanStackGate } from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * FOCUSED, LOCAL ONLY (step 4.6 §9.5 `sandbox-exec`): the whole chain with the
 * `hardened-container` backend — a LOCAL/CI TEST HARNESS, NOT A VM BOUNDARY (shared kernel;
 * docs/security/sandbox-threat-model.md R3/R4). Runs only with `SANDBOX_EXEC_TESTS=1`; the suite
 * then recreates the sandbox-controller with infrastructure/sandbox/compose.exec.yml (Docker
 * socket, recording sinkhole, detonation network) and restores the default controller
 * (backend `disabled`, no socket) and removes the sinkhole afterwards. Needs the runner images
 * (`email-gateway/sandbox-runner:local`, `email-gateway/url-browser-worker:local`). Never
 * together with the analytics/observability profiles (memory).
 *
 * 1. A synthetic benign script (`.js`, the tenant's deny list makes it `suspicious`) → executed
 *    in a disposable runner: `executed: true`, isolation `container`, the static findings plus
 *    process/DNS observations, a `process_log` artifact; the verdict is never `clean`
 *    (`sandbox.not_vm_isolated`).
 * 2. A synthetic HTML page (the tenant's attachment override denies `html`) → the browser
 *    profile: rendered by headless Chromium in a runner, a screenshot artifact; never `clean`.
 * 3. The controller container killed (SIGKILL) while a runner executes a slow script →
 *    started again → the startup reaper removes the orphan runner → the redelivered task
 *    completes.
 *
 * After every case: zero containers labelled `eg.sandbox.runner=1` and an empty controller
 * scratch. Only synthetic benign samples written here are executed.
 */
const ENABLED = process.env.SANDBOX_EXEC_TESTS === '1';
const gate = ENABLED ? await scanStackGate() : null;
const SKIP = gate === null || gate.skip;
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;
let analyst: ApiSession | undefined;

const nonce = () => randomBytes(8).toString('hex');
const codes = (value: unknown): string[] => (Array.isArray(value) ? (value as string[]) : []);

/** A benign script: prints, writes one file into its scratch, resolves a sinkhole name. */
function execScript(label: string, sleepMs = 0): Buffer {
  return Buffer.from(
    [
      `// synthetic benign sandbox exec fixture ${label} ${nonce()} (step 4.6, LOCAL ONLY)`,
      "const fs = require('fs');",
      "try { fs.writeFileSync('/scratch/fixture-note.txt', 'benign fixture note'); } catch (e) {}",
      "require('dns').lookup('beacon.sandbox-fixture.test', () => {});",
      `setTimeout(() => console.log('fixture done'), ${sleepMs + 500});`,
      '',
    ].join('\n'),
    'utf8',
  );
}

function htmlPage(): Buffer {
  return Buffer.from(
    [
      '<!doctype html><html><head><title>Synthetic fixture</title></head><body>',
      `<p>Synthetic benign sandbox HTML fixture ${nonce()} (step 4.6, LOCAL ONLY)</p>`,
      '<form action="https://forms.sandbox-fixture.test/submit" method="post">',
      '<input type="password" name="p"></form>',
      '</body></html>',
      '',
    ].join('\n'),
    'utf8',
  );
}

async function expectClean(): Promise<void> {
  await waitFor('no runner container left', async () => (await runnerContainers()).length === 0, {
    timeoutMs: 60_000,
    intervalMs: 1_000,
  });
  expect(await controllerScratch()).toEqual([]);
}

beforeAll(async () => {
  if (gate === null) return;
  assertStackReady(gate);
  await ensureController('hardened-container', { exec: true });
  org = await fx.organization('sbx-exec');
  domain = await fx.domain(org, 'sbx-exec');
  await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.feature(org, SANDBOX_FEATURE, true);
  analyst = await apiSession(fx.prisma, await organizationRef(fx, org), 'security_analyst');
  const opted = await optIn(analyst);
  expect(opted.status, JSON.stringify(opted.body)).toBe(200);
  // html is not on the platform deny list: deny it for this tenant so the page is `suspicious`.
  const denied = await analyst.put('/scan-settings/attachment', {
    expectedVersion: 0,
    settings: { deniedTypes: ['html'] },
  });
  expect(denied.status, JSON.stringify(denied.body)).toBe(200);
}, 600_000);

afterAll(async () => {
  if (SKIP) return;
  await restoreDefaultController().catch(() => undefined);
  await compose(
    [...EXEC_COMPOSE_FILES, '--profile', 'sandbox', 'rm', '-s', '-f', 'sandbox-sinkhole'],
    {
      timeoutMs: 120_000,
    },
  ).catch(() => undefined);
  await analyst?.remove();
  if (domain) await clearSinkDomain(domain.name, 'all').catch(() => undefined);
  await fx.cleanup();
}, 600_000);

describe.skipIf(SKIP)(
  'sandbox exec (LOCAL ONLY): hardened-container runner through the whole chain — NOT a VM boundary',
  { timeout: 900_000 },
  () => {
    it('a benign script is executed in a disposable runner; never clean', async () => {
      const health = await controllerHealth();
      expect(health).toMatchObject({ ok: true, backend: 'hardened-container' });
      const sent = await sendAttachmentMessage(
        fx.prisma,
        org,
        `exec-js@${domain.name}`,
        'Sandbox exec: script',
        [
          {
            filename: 'fixture.js',
            contentType: 'application/javascript',
            bytes: execScript('script'),
          },
        ],
      );
      const submission = await waitForSubmission(fx.prisma, sent.message, ['completed'], 300_000);
      const analysis = await fx.prisma.sandboxAnalysis.findUniqueOrThrow({
        where: { id: submission.analysisId! },
      });
      expect(analysis).toMatchObject({
        status: 'completed',
        backend: 'hardened-container',
        isolation: 'container',
        executed: true,
        profile: 'execute',
      });
      expect(analysis.verdict).not.toBe('clean');
      expect(codes(analysis.reasonCodes)).toContain('sandbox.not_vm_isolated');
      const report = analysis.report as { processes?: { count: number } } | null;
      expect(report?.processes?.count ?? 0).toBeGreaterThan(0);
      const kinds = (
        await fx.prisma.sandboxArtifact.findMany({ where: { analysisId: analysis.id } })
      ).map((a) => a.kind);
      expect(kinds).toContain('process_log');
      const final = await waitForSandboxFinal(fx.prisma, sent.message);
      expect(final.outcome).toBe(analysis.verdict);
      await expectClean();
    });

    it('a benign HTML page is rendered in a browser runner; screenshot artifact; never clean', async () => {
      const sent = await sendAttachmentMessage(
        fx.prisma,
        org,
        `exec-html@${domain.name}`,
        'Sandbox exec: html',
        [{ filename: 'page.html', contentType: 'text/html', bytes: htmlPage() }],
      );
      const submission = await waitForSubmission(fx.prisma, sent.message, ['completed'], 300_000);
      const analysis = await fx.prisma.sandboxAnalysis.findUniqueOrThrow({
        where: { id: submission.analysisId! },
      });
      expect(analysis).toMatchObject({
        status: 'completed',
        profile: 'browser',
        isolation: 'container',
        executed: true,
      });
      expect(analysis.verdict).not.toBe('clean');
      const kinds = (
        await fx.prisma.sandboxArtifact.findMany({ where: { analysisId: analysis.id } })
      ).map((a) => a.kind);
      expect(kinds).toContain('screenshot');
      await waitForSandboxFinal(fx.prisma, sent.message);
      await expectClean();
    });

    it('controller killed mid-run → restarted → the startup reaper removes the orphan runner → the redelivered task completes', async () => {
      const sent = await sendAttachmentMessage(
        fx.prisma,
        org,
        `exec-kill@${domain.name}`,
        'Sandbox exec: kill',
        [
          {
            filename: 'slow.js',
            contentType: 'application/javascript',
            bytes: execScript('slow', 25_000),
          },
        ],
      );
      const submission = await waitForSubmission(fx.prisma, sent.message, ['submitted'], 120_000);
      await waitFor(
        'a runner executing the slow script',
        async () => (await runnerContainers()).length >= 1,
        {
          timeoutMs: 120_000,
          intervalMs: 500,
        },
      );
      const killed = await compose(['kill', '-s', 'SIGKILL', 'sandbox-controller'], {
        timeoutMs: 60_000,
      });
      expect(killed.exitCode, killed.stderr).toBe(0);
      // The runner outlives the killed controller (an orphan, labelled with the controller name).
      expect((await runnerContainers()).length).toBeGreaterThanOrEqual(1);
      await ensureController('hardened-container', { exec: true });
      // Startup reap (X8) before consuming; then the broker redelivers the unacked task.
      expect(
        await controllerMetric('sandbox_reaped_total', { kind: 'runner', mode: 'startup' }),
      ).toBeGreaterThanOrEqual(1);
      const done = await waitForSubmission(fx.prisma, sent.message, ['completed'], 300_000);
      expect(done.analysisId).toBe(submission.analysisId);
      const analysis = await fx.prisma.sandboxAnalysis.findUniqueOrThrow({
        where: { id: done.analysisId! },
      });
      expect(analysis).toMatchObject({
        status: 'completed',
        executed: true,
        isolation: 'container',
      });
      await waitForSandboxFinal(fx.prisma, sent.message);
      await expectClean();
    });
  },
);

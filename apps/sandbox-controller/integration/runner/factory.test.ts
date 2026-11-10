import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sandboxObservationsSchema } from '@email-gateway/security-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { SandboxBackend } from '../../src/backends/backend';
import { createBackend, type FactoryConfig } from '../../src/backends/factory';
import { eicarTestString } from '../../src/backends/static/analyzers/generic';
import { compiledAnalyzerChild } from '../../src/backends/static/child.test-support';
import { ScratchArea } from '../../src/scratch/scratch';
import { describeBackendConformance } from '../support/backend-conformance';
import {
  BROWSER_IMAGE,
  CONTROLLER_NAME,
  context,
  dockerSocket,
  ensureSinkhole,
  findingCodes,
  logger,
  NETWORK,
  probe,
  relayTransport,
  RUNNER_IMAGE,
  runnerContainers,
  SINKHOLE_IP,
  sinkholeContainer,
  sinkholeToken,
  stopSinkhole,
  task,
} from './support';

// The factory-built `hardened-container` backend (step 4.6 WP5): `withStaticAnalysis(static,
// runner)` exactly as `main.ts` builds it, against the real Docker daemon and the exec override's
// sinkhole. LOCAL/CI ONLY, NOT A VM BOUNDARY. Only synthetic benign probes and the EICAR test
// string assembled at run time are executed.

const scratchRoots: string[] = [];

function scratchRoot(): string {
  const dir = mkdtempSync(join(tmpdir(), 'eg-wp5-factory-'));
  scratchRoots.push(dir);
  return dir;
}

function factoryConfig(): FactoryConfig {
  return {
    SANDBOX_BACKEND: 'hardened-container',
    SANDBOX_STATIC_HEAP_MB: 256,
    SANDBOX_STATIC_MAX_RSS_MB: 512,
    SANDBOX_STATIC_CPU_SECONDS: 20,
    SANDBOX_STATIC_TIMEOUT_MS: 30_000,
    SANDBOX_VM_RUNTIME_CLASS: 'gvisor',
    SANDBOX_VM_ALLOWED_HANDLERS: ['runsc'],
    SANDBOX_VM_NAMESPACE: 'email-gateway-sandbox-runners',
    KUBERNETES_SERVICE_HOST: undefined,
    KUBERNETES_SERVICE_PORT: undefined,
    APP_ENV: 'local',
    SANDBOX_ALLOW_NON_VM_EXECUTION: true,
    SANDBOX_CONTROLLER_NAME: CONTROLLER_NAME,
    SANDBOX_DOCKER_SOCKET: dockerSocket(),
    SANDBOX_RUNNER_IMAGE: RUNNER_IMAGE,
    SANDBOX_BROWSER_IMAGE: BROWSER_IMAGE,
    SANDBOX_RUNNER_NETWORK: NETWORK,
    SANDBOX_SINKHOLE_DNS: SINKHOLE_IP,
    SANDBOX_SINKHOLE_ADMIN_URL: 'http://172.31.252.53:3094',
    SANDBOX_SINKHOLE_ADMIN_TOKEN: sinkholeToken(),
  };
}

async function factoryBackend(root: string): Promise<SandboxBackend> {
  const scratch = new ScratchArea(root);
  await scratch.init();
  return createBackend(factoryConfig(), {
    scratch,
    logger,
    analyzerChildEntry: compiledAnalyzerChild(),
    sinkholeTransport: relayTransport(await sinkholeContainer()),
  });
}

beforeAll(async () => {
  await ensureSinkhole();
}, 180_000);

afterAll(async () => {
  for (const dir of scratchRoots) rmSync(dir, { recursive: true, force: true });
  const left = await runnerContainers();
  await stopSinkhole();
  if (left.length > 0) throw new Error(`${left.length} runner container(s) were left behind`);
}, 180_000);

describeBackendConformance({
  label: 'hardened-container via the factory (static first + real runner)',
  create: async () => {
    const root = scratchRoot();
    return { backend: await factoryBackend(root), scratchRoot: root };
  },
  sample: { bytes: probe('benign-marker.sh'), detectedType: 'script_shell', profile: 'execute' },
  expect: { name: 'hardened-container', executes: true, selfTestOk: true },
  timeoutMs: 120_000,
});

describe('factory-built hardened-container composite', () => {
  it('resolves its runner version through the self-test', async () => {
    const backend = await factoryBackend(scratchRoot());
    try {
      expect(backend.version).toBe('hardened-container/1+runner:unresolved');
      const result = await backend.selfTest(AbortSignal.timeout(120_000));
      expect(result.ok).toBe(true);
      expect(result.details).toMatchObject({ staticOk: true });
      expect(backend.version).toMatch(/^hardened-container\/1\+runner:[0-9a-f]{12}$/);
    } finally {
      await backend.close();
    }
  }, 180_000);

  it('detects the runtime-built EICAR string statically and still executes the script in the runner', async () => {
    const backend = await factoryBackend(scratchRoot());
    const ctx = context();
    try {
      expect((await backend.selfTest(AbortSignal.timeout(120_000))).ok).toBe(true);
      const script = Buffer.from(
        `#!/bin/sh\n# synthetic benign sample: prints the EICAR test string\necho '${eicarTestString()}'\n`,
        'utf8',
      );
      const obs = await backend.run(task(script, 'script_shell', 'execute'), ctx);
      expect(obs.status).toBe('completed');
      expect(obs.executed).toBe(true);
      expect(sandboxObservationsSchema.safeParse(obs.observations).success).toBe(true);
      expect(findingCodes(obs)).toContain('static.eicar_test');
      expect(obs.observations.processCount).toBeGreaterThan(0);
      const kinds = obs.artifacts.map((a) => a.kind);
      expect(kinds).toContain('static_report');
      expect(kinds).toContain('process_log');
      expect(obs.cleanup.runnerRemoved).toBe(true);
      expect(await runnerContainers()).toEqual([]);
    } finally {
      ctx.cleanup();
      await backend.close();
    }
  }, 180_000);

  it('answers a type the runner does not execute with the static result only (executed: false)', async () => {
    const backend = await factoryBackend(scratchRoot());
    const ctx = context();
    try {
      const pdf = Buffer.from(
        '%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n%%EOF\n',
        'latin1',
      );
      const obs = await backend.run({ ...task(pdf, 'pdf', 'execute'), profile: 'static' }, ctx);
      expect(obs.status).toBe('completed');
      expect(obs.executed).toBe(false);
      expect(findingCodes(obs).some((c) => c.startsWith('static.pdf_'))).toBe(true);
      expect(await runnerContainers()).toEqual([]);
    } finally {
      ctx.cleanup();
      await backend.close();
    }
  }, 120_000);
});

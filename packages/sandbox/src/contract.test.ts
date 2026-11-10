import {
  ATTACHMENT_FILE_TYPE_VALUES,
  EVENT_REGISTRY,
  SANDBOX_ARTIFACT_CONTENT_TYPE_VALUES,
  SANDBOX_ARTIFACT_KIND_VALUES,
  SANDBOX_BACKEND_VALUES,
  SANDBOX_FINDING_SEVERITY_VALUES,
  SANDBOX_ISOLATION_VALUES,
  SANDBOX_PROFILE_VALUES,
  SANDBOX_TASK_STATUS_VALUES,
  SANDBOX_VERDICT_VALUES,
} from '@email-gateway/event-contracts';
import {
  ARTIFACT_CONTENT_TYPES,
  ARTIFACT_KINDS,
  emptySandboxObservations,
  FILE_TYPE_IDS,
  SANDBOX_BACKENDS,
  SANDBOX_ERROR_CODES,
  SANDBOX_FINDING_CODES,
  SANDBOX_FINDING_SEVERITIES,
  SANDBOX_FINDING_SEVERITY,
  SANDBOX_ISOLATION_CLASSES,
  SANDBOX_LIMITS,
  SANDBOX_NOT_EXECUTED_REASONS,
  SANDBOX_PROFILES,
  SANDBOX_REASON_CODES,
  SANDBOX_SKIP_REASONS,
  SANDBOX_TASK_STATUSES,
  SANDBOX_VERDICTS,
  sandboxObservationsSchema,
  type SandboxFindingCode,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { aggregateSubmissions, mapAnalysis, submissionSkipCodes } from './verdict/map';

/**
 * Contract tests (step 4.6 §4): every code `sandbox-map/1` can emit is in `SANDBOX_REASON_CODES`,
 * every reason code is reachable, and the event-contracts mirrors equal the security-contracts
 * lists (event-contracts has no dependency on security-contracts).
 */
describe('sandbox-map/1 code set', () => {
  it('emits only SANDBOX_REASON_CODES and can emit every one of them', () => {
    const emitted = new Set<string>();
    const add = (codes: string[]) => codes.forEach((c) => emitted.add(c));
    add(mapAnalysis({ kind: 'expired' }).reasonCodes);
    for (const errorCode of SANDBOX_ERROR_CODES) {
      add(
        mapAnalysis({
          kind: 'result',
          status: 'failed',
          executed: false,
          isolation: 'process',
          notExecutedReason: null,
          errorCode,
          durationMs: 0,
          findings: [],
          limitsHit: [],
        }).reasonCodes,
      );
    }
    for (const notExecutedReason of SANDBOX_NOT_EXECUTED_REASONS) {
      add(
        mapAnalysis({
          kind: 'result',
          status: 'not_executed',
          executed: false,
          isolation: 'none',
          notExecutedReason,
          errorCode: null,
          durationMs: 0,
          findings: [],
          limitsHit: [],
        }).reasonCodes,
      );
    }
    const completed = (
      executed: boolean,
      isolation: (typeof SANDBOX_ISOLATION_CLASSES)[number],
      findings: SandboxFindingCode[],
      limitsHit: (typeof SANDBOX_LIMITS)[number][] = [],
      durationMs = 60_000,
    ) =>
      mapAnalysis({
        kind: 'result',
        status: 'completed',
        executed,
        isolation,
        notExecutedReason: null,
        errorCode: null,
        durationMs,
        findings: findings.map((code) => ({ code })),
        limitsHit,
      }).reasonCodes;
    for (const code of SANDBOX_FINDING_CODES) add(completed(false, 'process', [code]));
    for (const limit of SANDBOX_LIMITS) add(completed(false, 'process', [], [limit]));
    add(completed(false, 'process', []));
    add(completed(true, 'container', []));
    add(completed(true, 'vm', [], [], 1));
    add(completed(true, 'vm', ['evasion.long_sleep']));
    add(completed(true, 'vm', []));
    for (const reason of SANDBOX_SKIP_REASONS) {
      add(submissionSkipCodes(reason));
      add(aggregateSubmissions([{ status: 'skipped', skipReason: reason }]).reasonCodes);
    }
    for (const code of emitted) expect(SANDBOX_REASON_CODES, code).toContain(code);
    expect([...emitted].sort()).toEqual([...SANDBOX_REASON_CODES].sort());
  });
});

describe('event-contracts mirrors equal the security-contracts lists', () => {
  it('verdicts, backends, isolation classes, profiles, task statuses, severities', () => {
    expect([...SANDBOX_VERDICT_VALUES]).toEqual([...SANDBOX_VERDICTS]);
    expect([...SANDBOX_BACKEND_VALUES]).toEqual([...SANDBOX_BACKENDS]);
    expect([...SANDBOX_ISOLATION_VALUES]).toEqual([...SANDBOX_ISOLATION_CLASSES]);
    expect([...SANDBOX_PROFILE_VALUES]).toEqual([...SANDBOX_PROFILES]);
    expect([...SANDBOX_TASK_STATUS_VALUES]).toEqual([...SANDBOX_TASK_STATUSES]);
    expect([...SANDBOX_FINDING_SEVERITY_VALUES]).toEqual([...SANDBOX_FINDING_SEVERITIES]);
    expect([...SANDBOX_ARTIFACT_KIND_VALUES]).toEqual([...ARTIFACT_KINDS]);
    expect([...SANDBOX_ARTIFACT_CONTENT_TYPE_VALUES]).toEqual([...ARTIFACT_CONTENT_TYPES]);
    expect([...ATTACHMENT_FILE_TYPE_VALUES]).toEqual([...FILE_TYPE_IDS]);
  });

  it('every security-contracts observation (with enum codes) is a valid task_completed.v1 observation', () => {
    const schema = EVENT_REGISTRY['mail.sandbox.task_completed.v1'].schema;
    const example = {
      taskId: '01890a5d-ac96-774b-bcce-b302099a8070',
      analysisId: '1',
      sampleSha256: 'a'.repeat(64),
      resultMac: 'b'.repeat(64),
      status: 'completed',
      notExecutedReason: null,
      errorCode: null,
      backend: 'static',
      backendVersion: 'sandbox-static/1',
      isolation: 'process',
      executed: false,
      profile: 'static',
      controllerVersion: 'c/1',
      analyzerVersion: null,
      startedAt: '2026-11-01T00:00:00.000Z',
      completedAt: '2026-11-01T00:00:01.000Z',
      durationMs: 1000,
      artifacts: [],
      cleanup: { runnerRemoved: null, scratchRemoved: true },
    };
    const observations = {
      ...emptySandboxObservations(),
      findings: SANDBOX_FINDING_CODES.slice(0, 32).map((code) => ({
        code,
        severity: SANDBOX_FINDING_SEVERITY[code],
        count: 1,
      })),
      limitsHit: [...SANDBOX_LIMITS],
    };
    expect(sandboxObservationsSchema.safeParse(observations).success).toBe(true);
    expect(schema.safeParse({ ...example, observations }).error).toBeUndefined();
    // Every not-executed reason and error code fits the event's token shape.
    for (const reason of SANDBOX_NOT_EXECUTED_REASONS) {
      expect(
        schema.safeParse({
          ...example,
          observations: emptySandboxObservations(),
          status: 'not_executed',
          notExecutedReason: reason,
        }).success,
        reason,
      ).toBe(true);
    }
    for (const code of SANDBOX_ERROR_CODES) {
      expect(
        schema.safeParse({
          ...example,
          observations: emptySandboxObservations(),
          status: 'failed',
          errorCode: code,
        }).success,
        code,
      ).toBe(true);
    }
  });
});

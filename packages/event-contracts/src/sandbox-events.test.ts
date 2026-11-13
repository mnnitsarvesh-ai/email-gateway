import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { ZodType } from 'zod';
import { parseEvent } from './envelope';
import {
  attachmentSandboxCompletedV1,
  EventTypes,
  SANDBOX_COMPLETION_STATUS_VALUES,
  SANDBOX_VERDICT_VALUES,
  sandboxTaskCompletedV1,
  sandboxTaskRequestedV1,
} from './events';
import { EXAMPLE_EVENT_PAYLOADS } from './examples';
import { EVENT_REGISTRY } from './registry';
import { eventRoutingKey, routeMessage } from './topology';

/** Step 4.6 §4, X11: the three sandbox events. */
type Payload = Record<string, unknown>;
const clone = <T>(value: T): T => structuredClone(value);
const requested = EXAMPLE_EVENT_PAYLOADS['mail.sandbox.task_requested.v1'] as Payload;
const completed = EXAMPLE_EVENT_PAYLOADS['mail.sandbox.task_completed.v1'] as Payload;
const submission = EXAMPLE_EVENT_PAYLOADS['mail.attachment.sandbox_completed.v1'] as Payload;
const TASK_ID = requested.taskId as string;
const RUN = '0f1e2d3c4b5a6978';

const okRequested = (p: unknown) => sandboxTaskRequestedV1.safeParse(p).success;
const okCompleted = (p: unknown) => sandboxTaskCompletedV1.safeParse(p).success;
const okSubmission = (p: unknown) => attachmentSandboxCompletedV1.safeParse(p).success;

/** Deep patch: sets `path` (dotted) of a clone of `base`. */
function patch(base: Payload, path: string, value: unknown): Payload {
  const copy = clone(base);
  const keys = path.split('.');
  let node: Record<string, unknown> = copy;
  for (const key of keys.slice(0, -1)) node = node[key] as Record<string, unknown>;
  const last = keys.at(-1)!;
  if (value === undefined) delete node[last];
  else node[last] = value;
  return copy;
}

/** A maximal task_completed.v1 (every list at its bound, longest strings). */
function maximalTaskCompleted(): Payload {
  const hex = (c: string) => c.repeat(64);
  const host = (i: number) => `${'a'.repeat(50)}-${i}.${'b'.repeat(60)}.${'c'.repeat(60)}.test`;
  return {
    ...clone(completed),
    status: 'completed',
    backend: 'hardened-container',
    backendVersion: `hardened-container/1+runner:${'d'.repeat(36)}`,
    isolation: 'container',
    executed: true,
    controllerVersion: 'v'.repeat(64),
    analyzerVersion: 'w'.repeat(64),
    observations: {
      processes: Array.from({ length: 32 }, (_, i) => ({
        seq: i,
        parentSeq: i === 0 ? null : i - 1,
        image: 'i'.repeat(64),
        argvSha256: hex('a'),
        exitCode: -2_147_483_648,
        killedBy: 'pids',
      })),
      processCount: 1_000_000,
      network: {
        dns: Array.from({ length: 50 }, (_, i) => ({
          name: host(i),
          type: 'AAAA',
          source: 'sinkhole',
        })),
        http: Array.from({ length: 50 }, (_, i) => ({
          host: host(i),
          port: 65_535,
          method: 'OTHER',
          pathSha256: hex('b'),
          userAgentSha256: hex('c'),
        })),
        tls: Array.from({ length: 50 }, (_, i) => ({ sni: host(i), port: 443 })),
        connections: Array.from({ length: 50 }, (_, i) => ({
          ip: `2001:db8:ffff:ffff:ffff:ffff:ffff:${(0xff00 + i).toString(16)}`,
          port: 65_535,
          protocol: 'udp',
          outcome: 'sinkhole',
        })),
        totals: { dns: 1_000_000, http: 1_000_000, tls: 1_000_000, connections: 1_000_000 },
      },
      files: {
        dropped: Array.from({ length: 32 }, (_, i) => ({
          seq: i,
          sha256: hex('e'),
          sizeBytes: 2 ** 40,
          typeHint: 'pe_executable',
        })),
        deniedWrites: 1_000_000,
      },
      findings: Array.from({ length: 32 }, (_, i) => ({
        code: `behaviour.${'x'.repeat(50)}_${String(i).padStart(2, '0')}`,
        severity: 'critical',
        count: 1_000_000,
      })),
      limitsHit: [
        'memory',
        'pids',
        'cpu',
        'scratch_full',
        'wall_timeout',
        'analyzer_resources',
        'output_truncated',
        'artifact_cap',
      ],
      browser: {
        navigations: 1_000_000,
        requests: 1_000_000,
        downloadsAttempted: 1_000_000,
        dialogs: 1_000_000,
        passwordFields: 1_000_000,
        forms: 1_000_000,
      },
    },
    artifacts: Array.from({ length: 16 }, (_, i) => ({
      seq: i,
      kind: 'dropped_file',
      contentType: 'application/octet-stream',
      key: `artifacts/2026/11/${TASK_ID}/${RUN}/${i}-dropped_file.bin`,
      objectSha256: hex('a'),
      plainSha256: hex('b'),
      sizeBytes: 8_388_608,
      wrappedKey: `x1.k1234567.${'A'.repeat(43)}.${'B'.repeat(16)}.${'C'.repeat(22)}.${'D'.repeat(43)}`,
      keyId: 'k1234567',
      algorithm: 'sandbox-artifact/1',
    })),
    cleanup: { runnerRemoved: true, scratchRemoved: true },
  };
}

describe('sandbox event types (step 4.6 X11)', () => {
  it('are registered on email.security with their aggregates, version 1', () => {
    expect(EventTypes.SandboxTaskRequested).toBe('mail.sandbox.task_requested.v1');
    expect(EventTypes.SandboxTaskCompleted).toBe('mail.sandbox.task_completed.v1');
    expect(EventTypes.AttachmentSandboxCompleted).toBe('mail.attachment.sandbox_completed.v1');
    expect(EVENT_REGISTRY['mail.sandbox.task_requested.v1']).toMatchObject({
      version: 1,
      exchange: 'email.security',
      aggregateType: 'sandbox_analysis',
    });
    expect(EVENT_REGISTRY['mail.sandbox.task_completed.v1']).toMatchObject({
      version: 1,
      exchange: 'email.security',
      aggregateType: 'sandbox_analysis',
    });
    expect(EVENT_REGISTRY['mail.attachment.sandbox_completed.v1']).toMatchObject({
      version: 1,
      exchange: 'email.security',
      aggregateType: 'attachment',
    });
  });

  it('parse their examples inside an envelope', () => {
    const cases: [keyof typeof EXAMPLE_EVENT_PAYLOADS, ZodType][] = [
      ['mail.sandbox.task_requested.v1', sandboxTaskRequestedV1],
      ['mail.sandbox.task_completed.v1', sandboxTaskCompletedV1],
      ['mail.attachment.sandbox_completed.v1', attachmentSandboxCompletedV1],
    ];
    for (const [type, schema] of cases) {
      const payload = EXAMPLE_EVENT_PAYLOADS[type];
      const event = parseEvent(
        {
          eventId: randomUUID(),
          eventType: type,
          occurredAt: '2026-11-01T10:15:31.900Z',
          correlationId: 'corr-12345678',
          organizationId: '42',
          payload,
        },
        schema,
      );
      expect(event.payload).toEqual(payload);
    }
  });

  it('route the task to scan.sandbox, the result to scan.sandbox.results and the completion to the firehose (topology v8) and the webhook fanout (v11)', () => {
    expect(
      routeMessage('email.security', eventRoutingKey('42', 'mail.sandbox.task_requested.v1')),
    ).toEqual(['email.analytics', 'scan.sandbox']);
    expect(
      routeMessage('email.security', eventRoutingKey('42', 'mail.sandbox.task_completed.v1')),
    ).toEqual(['email.analytics', 'scan.sandbox.results']);
    expect(
      routeMessage('email.security', eventRoutingKey('42', 'mail.attachment.sandbox_completed.v1')),
      // Topology v11 (step 6.2 §4.3): the webhook fanout projects malicious late verdicts.
    ).toEqual(['email.analytics', 'email.webhooks']);
    expect(
      routeMessage('email.security', eventRoutingKey('42', 'mail.attachment.sandbox_requested.v1')),
    ).toEqual(['email.analytics', 'scan.sandbox.submissions']);
  });
});

describe('mail.sandbox.task_requested.v1', () => {
  it('accepts the example and every profile', () => {
    expect(okRequested(requested)).toBe(true);
    for (const profile of ['static', 'execute', 'browser']) {
      expect(okRequested(patch(requested, 'profile', profile)), profile).toBe(true);
    }
  });

  it('validates ids, the sample and the deadline', () => {
    expect(okRequested(patch(requested, 'taskId', 'not-a-uuid'))).toBe(false);
    expect(okRequested(patch(requested, 'analysisId', '0'))).toBe(false);
    expect(okRequested(patch(requested, 'analysisId', 501))).toBe(false);
    // The key must embed the task id and live under samples/<yyyy>/<mm>/.
    expect(okRequested(patch(requested, 'sample.key', `samples/2026/11/${randomUUID()}.bin`))).toBe(
      false,
    );
    expect(okRequested(patch(requested, 'sample.key', `org/42/part/${TASK_ID}.bin`))).toBe(false);
    expect(okRequested(patch(requested, 'sample.key', `samples/2026/11/${TASK_ID}.exe`))).toBe(
      false,
    );
    expect(okRequested(patch(requested, 'sample.key', `samples/26/11/${TASK_ID}.bin`))).toBe(false);
    expect(okRequested(patch(requested, 'sample.sha256', 'C'.repeat(64)))).toBe(false);
    expect(okRequested(patch(requested, 'sample.sizeBytes', 0))).toBe(false);
    expect(okRequested(patch(requested, 'sample.sizeBytes', 67_108_864))).toBe(true);
    expect(okRequested(patch(requested, 'sample.sizeBytes', 67_108_865))).toBe(false);
    expect(okRequested(patch(requested, 'sample.detectedType', 'docx'))).toBe(false);
    expect(okRequested(patch(requested, 'profile', 'detonate'))).toBe(false);
    expect(okRequested(patch(requested, 'deadlineAt', requested.requestedAt))).toBe(false);
    expect(okRequested(patch(requested, 'requestedAt', 'yesterday'))).toBe(false);
    // The sealed one-time result token (X11) is required and has its exact shape.
    expect(okRequested(patch(requested, 'resultToken', undefined))).toBe(false);
    expect(okRequested(patch(requested, 'resultToken', 'f'.repeat(64)))).toBe(false);
    expect(
      okRequested(
        patch(requested, 'resultToken', (requested.resultToken as string).replace('t1', 't2')),
      ),
    ).toBe(false);
    expect(
      okRequested(patch(requested, 'resultToken', `${requested.resultToken as string}A`)),
    ).toBe(false);
  });

  it('bounds every limit', () => {
    const bounds: Record<string, [number, number]> = {
      wallTimeoutMs: [5_000, 600_000],
      memoryMb: [64, 4_096],
      cpuMillis: [100, 4_000],
      pids: [16, 1_024],
      scratchMb: [8, 1_024],
      maxArtifacts: [0, 16],
      maxArtifactBytes: [1, 8_388_608],
      maxTotalArtifactBytes: [1, 33_554_432],
    };
    for (const [key, [min, max]] of Object.entries(bounds)) {
      expect(okRequested(patch(requested, `limits.${key}`, min)), key).toBe(true);
      expect(okRequested(patch(requested, `limits.${key}`, max)), key).toBe(true);
      expect(okRequested(patch(requested, `limits.${key}`, min - 1)), key).toBe(false);
      expect(okRequested(patch(requested, `limits.${key}`, max + 1)), key).toBe(false);
      expect(okRequested(patch(requested, `limits.${key}`, undefined)), key).toBe(false);
    }
  });

  it('is strict: no file name, no organization, no secret', () => {
    expect(okRequested({ ...requested, fileName: 'invoice.js' })).toBe(false);
    expect(okRequested({ ...requested, resultKey: 'f'.repeat(64) })).toBe(false);
    expect(okRequested(patch(requested, 'sample.objectKey', 'org/42/part/x'))).toBe(false);
    expect(okRequested(patch(requested, 'limits.network', true))).toBe(false);
  });
});

describe('mail.sandbox.task_completed.v1', () => {
  const notExecuted = {
    ...clone(completed),
    status: 'not_executed',
    notExecutedReason: 'backend_disabled',
    backend: 'disabled',
    backendVersion: 'disabled/1',
    isolation: 'none',
    analyzerVersion: null,
    artifacts: [],
    observations: {
      processes: [],
      processCount: 0,
      network: {
        dns: [],
        http: [],
        tls: [],
        connections: [],
        totals: { dns: 0, http: 0, tls: 0, connections: 0 },
      },
      files: { dropped: [], deniedWrites: 0 },
      findings: [],
      limitsHit: [],
      browser: null,
    },
  };
  const failed = {
    ...clone(notExecuted),
    status: 'failed',
    notExecutedReason: null,
    errorCode: 'sample_integrity',
    backend: 'static',
    backendVersion: 'sandbox-static/1',
    isolation: 'process',
  };

  it('accepts the example, a not_executed, a failed and a maximal result', () => {
    expect(okCompleted(completed)).toBe(true);
    expect(okCompleted(notExecuted)).toBe(true);
    expect(okCompleted(failed)).toBe(true);
    expect(sandboxTaskCompletedV1.safeParse(maximalTaskCompleted()).error).toBeUndefined();
  });

  it('pairs the status with its reason / error code', () => {
    expect(okCompleted(patch(completed, 'errorCode', 'internal'))).toBe(false);
    expect(okCompleted(patch(completed, 'notExecutedReason', 'backend_disabled'))).toBe(false);
    expect(okCompleted({ ...notExecuted, notExecutedReason: null })).toBe(false);
    expect(okCompleted({ ...notExecuted, errorCode: 'internal' })).toBe(false);
    expect(okCompleted({ ...failed, errorCode: null })).toBe(false);
    expect(okCompleted({ ...failed, errorCode: 'Not A Token' })).toBe(false);
  });

  it('binds isolation and execution to the backend', () => {
    // Isolation is the backend's: disabled none, static process, hardened-container container, vm vm.
    expect(okCompleted(patch(completed, 'isolation', 'vm'))).toBe(false);
    expect(okCompleted({ ...notExecuted, isolation: 'process' })).toBe(false);
    // Only an executing backend reports executed: true; never with not_executed.
    expect(okCompleted(patch(completed, 'executed', true))).toBe(false);
    expect(
      okCompleted({
        ...clone(completed),
        backend: 'hardened-container',
        isolation: 'container',
        executed: true,
      }),
    ).toBe(true);
    expect(
      okCompleted({
        ...notExecuted,
        backend: 'hardened-container',
        isolation: 'container',
        executed: true,
      }),
    ).toBe(false);
    expect(okCompleted(patch(completed, 'backend', 'docker'))).toBe(false);
  });

  it('validates the MAC, versions and times', () => {
    expect(okCompleted(patch(completed, 'resultMac', 'f'.repeat(63)))).toBe(false);
    expect(okCompleted(patch(completed, 'resultMac', 'F'.repeat(64)))).toBe(false);
    expect(okCompleted(patch(completed, 'backendVersion', 'x'.repeat(65)))).toBe(false);
    expect(okCompleted(patch(completed, 'controllerVersion', 'bad\nversion'))).toBe(false);
    expect(okCompleted(patch(completed, 'completedAt', '2026-11-01T10:15:32.000Z'))).toBe(false);
    expect(okCompleted(patch(completed, 'durationMs', -1))).toBe(false);
    expect(okCompleted(patch(completed, 'sampleSha256', 'c'.repeat(65)))).toBe(false);
  });

  it('bounds and validates the observations', () => {
    const max = maximalTaskCompleted();
    const over = (path: string, extra: unknown) => {
      const copy = clone(max);
      const keys = path.split('.');
      let node: Record<string, unknown> = copy;
      for (const key of keys) node = node[key] as Record<string, unknown>;
      (node as unknown as unknown[]).push(extra);
      return okCompleted(copy);
    };
    const firstOf = (path: string) => {
      let node: unknown = max;
      for (const key of path.split('.')) node = (node as Record<string, unknown>)[key];
      return clone((node as unknown[])[0]);
    };
    for (const path of [
      'observations.processes',
      'observations.network.dns',
      'observations.network.http',
      'observations.network.tls',
      'observations.network.connections',
      'observations.files.dropped',
      'observations.findings',
      'observations.limitsHit',
      'artifacts',
    ]) {
      expect(over(path, firstOf(path)), path).toBe(false);
    }
    const obs = 'observations';
    expect(
      okCompleted(
        patch(completed, `${obs}.network.dns`, [
          { name: 'http://x.test/', type: 'A', source: 'static' },
        ]),
      ),
    ).toBe(false);
    expect(
      okCompleted(
        patch(completed, `${obs}.network.dns`, [{ name: 'X.TEST', type: 'A', source: 'static' }]),
      ),
    ).toBe(false);
    expect(
      okCompleted(
        patch(completed, `${obs}.network.connections`, [
          { ip: '010.0.0.1', port: 80, protocol: 'tcp', outcome: 'refused' },
        ]),
      ),
    ).toBe(false);
    expect(
      okCompleted(
        patch(completed, `${obs}.network.connections`, [
          { ip: '10.0.0.1', port: 0, protocol: 'tcp', outcome: 'refused' },
        ]),
      ),
    ).toBe(false);
    expect(
      okCompleted(
        patch(completed, `${obs}.network.connections`, [
          { ip: '::1', port: 80, protocol: 'tcp', outcome: 'refused' },
        ]),
      ),
    ).toBe(true);
    expect(
      okCompleted(
        patch(completed, `${obs}.findings`, [{ code: 'NotDotted', severity: 'high', count: 1 }]),
      ),
    ).toBe(false);
    expect(
      okCompleted(
        patch(completed, `${obs}.findings`, [{ code: 'static.x', severity: 'severe', count: 1 }]),
      ),
    ).toBe(false);
    expect(
      okCompleted(
        patch(completed, `${obs}.findings`, [{ code: 'static.x', severity: 'low', count: 0 }]),
      ),
    ).toBe(false);
    expect(
      okCompleted(
        patch(completed, `${obs}.findings`, [
          { code: 'static.x', severity: 'low', count: 1 },
          { code: 'static.x', severity: 'low', count: 2 },
        ]),
      ),
    ).toBe(false);
    expect(okCompleted(patch(completed, `${obs}.limitsHit`, ['memory', 'memory']))).toBe(false);
    expect(
      okCompleted(
        patch(completed, `${obs}.processes`, [
          {
            seq: 0,
            parentSeq: null,
            image: '/usr/bin/sh',
            argvSha256: null,
            exitCode: 0,
            killedBy: null,
          },
        ]),
      ),
    ).toBe(false);
    expect(okCompleted(patch(completed, `${obs}.filename`, 'x.js'))).toBe(false);
    expect(
      okCompleted(
        patch(completed, `${obs}.files.dropped`, [
          { seq: 0, sha256: 'a'.repeat(64), sizeBytes: 1, typeHint: 'text', path: '/tmp/x' },
        ]),
      ),
    ).toBe(false);
  });

  it('binds every artifact key to the task id, seq and kind, the content type to the kind and the key id to the wrapped key', () => {
    const artifact = (completed.artifacts as Payload[])[0]!;
    const withArtifact = (a: Payload) => patch(completed, 'artifacts', [a]);
    expect(
      okCompleted(
        withArtifact({
          ...artifact,
          key: `artifacts/2026/11/${randomUUID()}/${RUN}/0-static_report.bin`,
        }),
      ),
    ).toBe(false);
    expect(
      okCompleted(
        withArtifact({
          ...artifact,
          key: `artifacts/2026/11/${TASK_ID}/${RUN}/1-static_report.bin`,
        }),
      ),
    ).toBe(false);
    expect(
      okCompleted(
        withArtifact({ ...artifact, key: `artifacts/2026/11/${TASK_ID}/${RUN}/0-screenshot.bin` }),
      ),
    ).toBe(false);
    expect(okCompleted(withArtifact({ ...artifact, key: `samples/2026/11/${TASK_ID}.bin` }))).toBe(
      false,
    );
    expect(okCompleted(withArtifact({ ...artifact, contentType: 'image/png' }))).toBe(false);
    expect(okCompleted(withArtifact({ ...artifact, keyId: 'k2' }))).toBe(false);
    expect(okCompleted(withArtifact({ ...artifact, wrappedKey: 'v1.k1.a.b.c' }))).toBe(false);
    expect(
      okCompleted(withArtifact({ ...artifact, wrappedKey: `x1.k1.${'A'.repeat(250)}.b.c.d` })),
    ).toBe(false);
    expect(okCompleted(withArtifact({ ...artifact, algorithm: 'dlp-evidence/1' }))).toBe(false);
    expect(okCompleted(withArtifact({ ...artifact, seq: 16 }))).toBe(false);
    // Without a run id, or with an upper-case one: refused.
    expect(
      okCompleted(
        withArtifact({ ...artifact, key: `artifacts/2026/11/${TASK_ID}/0-static_report.bin` }),
      ),
    ).toBe(false);
    expect(
      okCompleted(
        withArtifact({
          ...artifact,
          key: `artifacts/2026/11/${TASK_ID}/0F1E2D3C4B5A6978/0-static_report.bin`,
        }),
      ),
    ).toBe(false);
    // The artifacts of one result come from one run.
    const second = {
      ...artifact,
      seq: 1,
      key: `artifacts/2026/11/${TASK_ID}/aaaaaaaaaaaaaaaa/1-static_report.bin`,
    };
    expect(okCompleted(patch(completed, 'artifacts', [artifact, second]))).toBe(false);
    expect(
      okCompleted(
        patch(completed, 'artifacts', [
          artifact,
          {
            ...second,
            key: (artifact.key as string).replace('/0-static_report', '/1-static_report'),
          },
        ]),
      ),
    ).toBe(true);
    expect(okCompleted(withArtifact({ ...artifact, kind: 'memory_dump' }))).toBe(false);
    expect(okCompleted(patch(completed, 'artifacts', [artifact, artifact]))).toBe(false);
  });

  it('requires the cleanup report and is strict', () => {
    expect(okCompleted(patch(completed, 'cleanup', undefined))).toBe(false);
    expect(okCompleted(patch(completed, 'cleanup.scratchRemoved', null))).toBe(false);
    expect(okCompleted(patch(completed, 'cleanup.runnerRemoved', false))).toBe(true);
    expect(okCompleted({ ...completed, verdict: 'clean' })).toBe(false);
    expect(okCompleted({ ...completed, organizationId: '42' })).toBe(false);
  });
});

describe('mail.attachment.sandbox_completed.v1', () => {
  it('accepts the example and each terminal status with a consistent verdict', () => {
    expect(okSubmission(submission)).toBe(true);
    expect([...SANDBOX_COMPLETION_STATUS_VALUES]).toEqual([
      'completed',
      'skipped',
      'failed',
      'expired',
    ]);
    expect(
      okSubmission({
        ...submission,
        status: 'skipped',
        verdict: null,
        isolation: null,
        executed: false,
        reasonCodes: ['sandbox.tenant_disabled'],
      }),
    ).toBe(true);
    expect(
      okSubmission({
        ...submission,
        status: 'expired',
        verdict: 'timeout',
        reasonCodes: ['sandbox.timeout'],
      }),
    ).toBe(true);
    expect(okSubmission({ ...submission, status: 'expired', verdict: null })).toBe(true);
    expect(okSubmission({ ...submission, status: 'failed', verdict: 'error' })).toBe(true);
    for (const verdict of SANDBOX_VERDICT_VALUES.filter((v) => v !== 'clean')) {
      expect(okSubmission({ ...submission, verdict }), verdict).toBe(true);
    }
  });

  it('refuses inconsistent status / verdict / isolation combinations', () => {
    expect(okSubmission({ ...submission, status: 'skipped' })).toBe(false);
    expect(
      okSubmission({
        ...submission,
        status: 'skipped',
        verdict: null,
        isolation: null,
        executed: true,
      }),
    ).toBe(false);
    expect(
      okSubmission({
        ...submission,
        status: 'skipped',
        verdict: null,
        isolation: 'none',
        executed: false,
      }),
    ).toBe(false);
    expect(okSubmission({ ...submission, verdict: null })).toBe(false);
    expect(okSubmission({ ...submission, status: 'expired', verdict: 'unknown' })).toBe(false);
    expect(okSubmission({ ...submission, status: 'failed', verdict: 'malicious' })).toBe(false);
    // clean only from a VM-isolated run (sandbox-map/1 C1).
    expect(okSubmission({ ...submission, verdict: 'clean' })).toBe(false);
    expect(okSubmission({ ...submission, verdict: 'clean', isolation: 'vm', executed: true })).toBe(
      true,
    );
  });

  it('validates ids, codes and is strict', () => {
    for (const key of ['submissionId', 'messageId', 'scanId']) {
      expect(okSubmission({ ...submission, [key]: '01' }), key).toBe(false);
    }
    expect(okSubmission({ ...submission, partIndex: 65_536 })).toBe(false);
    expect(okSubmission({ ...submission, lifecycleRound: -1 })).toBe(false);
    expect(okSubmission({ ...submission, reasonCodes: ['attachment.none'] })).toBe(false);
    expect(
      okSubmission({ ...submission, reasonCodes: ['sandbox.timeout', 'sandbox.timeout'] }),
    ).toBe(false);
    expect(
      okSubmission({
        ...submission,
        reasonCodes: Array.from({ length: 17 }, (_, i) => `sandbox.c${i}`),
      }),
    ).toBe(false);
    expect(okSubmission({ ...submission, status: 'pending' })).toBe(false);
    expect(okSubmission({ ...submission, analysisId: '501' })).toBe(false);
    expect(okSubmission({ ...submission, fileName: 'x.js' })).toBe(false);
  });
});

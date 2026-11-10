import { describe, expect, it } from 'vitest';
import { MessageScansPageSchema } from '../dto/message-scans.schemas';
import type {
  EngineResultRow,
  SandboxAnalysisRow,
  SandboxArtifactRow,
  SandboxSubmissionRow,
  ScanRoundRow,
} from '../repositories/message-scans-read.repository';
import {
  type AttachmentInputs,
  engineOf,
  roundOf,
  sandboxOutcomeOf,
  sandboxSubmissionsOf,
} from './message-scans';

/** Step 4.6 X18: sandbox submissions on the attachment entries and the `sandbox` engine entry. */

const SHA = 'c'.repeat(64);
const TASK = '0193a7c0-0000-7000-8000-00000000abcd';
const at = (ms: number) => new Date(Date.UTC(2026, 10, 8, 8, 0, 0) + ms);

const submission = (overrides: Partial<SandboxSubmissionRow> = {}): SandboxSubmissionRow => ({
  id: 501n,
  scanId: 7n,
  attachmentId: 900n,
  partIndex: 1,
  sha256: SHA,
  status: 'completed',
  skipReason: null,
  sandboxVerdict: 'unknown',
  sandboxReasonCodes: ['sandbox.not_executed', 'sandbox.not_executed.backend_disabled', 'bogus'],
  completedAt: at(1_234),
  analysisId: 40n,
  externalRef: TASK,
  ...overrides,
});

const report = {
  v: 1,
  findings: [{ code: 'static.script_download_cradle', severity: 'high', count: 2 }],
  indicators: { dns: ['sinkhole.example'], httpHosts: [], tlsSni: [], ips: ['198.51.100.7'] },
  networkTotals: { dns: 1, http: 0, tls: 0, connections: 1 },
  processes: { count: 2, images: ['sh', 'curl'] },
  droppedFiles: [{ sha256: SHA, sizeBytes: 12, typeHint: 'text' }],
  deniedWrites: 0,
  limitsHit: ['wall_timeout'],
  browser: null,
};

const analysis = (overrides: Partial<SandboxAnalysisRow> = {}): SandboxAnalysisRow => ({
  id: 40n,
  publicId: TASK,
  report,
  backend: 'static',
  backendVersion: 'sandbox-static/1',
  isolation: 'process',
  executed: false,
  controllerVersion: '0.1.0',
  analyzerVersion: 'sandbox-static/1',
  mapVersion: 'sandbox-map/1',
  ...overrides,
});

const artifact = (overrides: Partial<SandboxArtifactRow> = {}): SandboxArtifactRow => ({
  analysisId: 40n,
  seq: 0,
  kind: 'static_report',
  contentType: 'application/json',
  sizeBytes: 321,
  plainSha256: 'd'.repeat(64),
  expiresAt: new Date('2026-12-08T13:47:11.123Z'),
  purgedAt: null,
  ...overrides,
});

const inputs = (over: Partial<AttachmentInputs> = {}): AttachmentInputs => ({
  results: [],
  parts: [],
  submissions: [submission()],
  analyses: [analysis()],
  artifacts: [artifact()],
  ...over,
});

describe('sandbox outcome of an attachment (step 4.6 X18)', () => {
  it('shows status, verdict, known codes, executed/isolation and a time rounded to the second', () => {
    expect(sandboxOutcomeOf(submission(), analysis())).toEqual({
      submissionId: '501',
      status: 'completed',
      skipReason: null,
      verdict: 'unknown',
      reasonCodes: ['sandbox.not_executed', 'sandbox.not_executed.backend_disabled'],
      executed: false,
      isolation: 'process',
      completedAt: '2026-11-08T08:00:01.000Z',
    });
  });

  it('shows a skipped submission with its reason and no analysis', () => {
    expect(
      sandboxOutcomeOf(
        submission({
          status: 'skipped',
          skipReason: 'tenant_disabled',
          sandboxVerdict: null,
          sandboxReasonCodes: ['sandbox.tenant_disabled'],
          analysisId: null,
          externalRef: null,
        }),
        undefined,
      ),
    ).toMatchObject({
      status: 'skipped',
      skipReason: 'tenant_disabled',
      verdict: null,
      reasonCodes: ['sandbox.tenant_disabled'],
      executed: null,
      isolation: null,
    });
  });

  it('drops an unknown stored verdict / skip reason instead of passing it through', () => {
    expect(
      sandboxOutcomeOf(submission({ sandboxVerdict: 'benign', skipReason: 'x' }), undefined),
    ).toMatchObject({ verdict: null, skipReason: null });
  });
});

describe('sandbox engine entry (step 4.6 X18)', () => {
  it('lists the round’s submissions by part index with the analysis report and artifact metadata', () => {
    const views = sandboxSubmissionsOf(
      7n,
      inputs({
        submissions: [
          submission({ id: 502n, partIndex: 3, attachmentId: 901n }),
          submission(),
          submission({ id: 600n, scanId: 8n }),
        ],
      }),
    );
    expect(views.map((v) => v.submissionId)).toEqual(['501', '502']);
    expect(views[0]).toEqual({
      submissionId: '501',
      status: 'completed',
      skipReason: null,
      verdict: 'unknown',
      reasonCodes: ['sandbox.not_executed', 'sandbox.not_executed.backend_disabled'],
      executed: false,
      isolation: 'process',
      completedAt: '2026-11-08T08:00:01.000Z',
      partIndex: 1,
      sha256: SHA,
      backend: 'static',
      versions: {
        controller: '0.1.0',
        backend: 'sandbox-static/1',
        analyzer: 'sandbox-static/1',
        map: 'sandbox-map/1',
      },
      findings: report.findings,
      indicators: report.indicators,
      processes: report.processes,
      droppedFiles: report.droppedFiles,
      limitsHit: ['wall_timeout'],
      artifacts: [
        {
          seq: 0,
          kind: 'static_report',
          contentType: 'application/json',
          sizeBytes: 321,
          sha256: 'd'.repeat(64),
          expiresAt: '2026-12-08T00:00:00.000Z',
          purged: false,
        },
      ],
    });
  });

  it('never exposes analysis ids, reuse, timings or the dispatching organization', () => {
    const json = JSON.stringify(sandboxSubmissionsOf(7n, inputs()));
    expect(json).not.toContain(TASK);
    for (const key of [
      'analysisId',
      'publicId',
      'reuse',
      'reused',
      'durationMs',
      'dispatchedAt',
      'deadlineAt',
      'organizationId',
      'objectKey',
      'wrappedKey',
    ]) {
      expect(json).not.toContain(`"${key}"`);
    }
  });

  it('ignores an analysis that did not complete the submission (pending, or external_ref mismatch)', () => {
    const pending = sandboxSubmissionsOf(
      7n,
      inputs({
        submissions: [submission({ status: 'submitted', sandboxVerdict: null, completedAt: null })],
      }),
    )[0]!;
    expect(pending).toMatchObject({
      status: 'submitted',
      executed: null,
      backend: null,
      findings: [],
      artifacts: [],
    });
    const mismatch = sandboxSubmissionsOf(
      7n,
      inputs({
        submissions: [submission({ externalRef: '0193a7c0-0000-7000-8000-000000000000' })],
      }),
    )[0]!;
    expect(mismatch).toMatchObject({
      executed: null,
      isolation: null,
      findings: [],
      artifacts: [],
    });
  });

  it('shows a malformed stored report as empty and purged artifacts as purged', () => {
    const view = sandboxSubmissionsOf(
      7n,
      inputs({
        analyses: [analysis({ report: { v: 1, findings: [{ code: 'x' }], secret: 'payload' } })],
        artifacts: [
          artifact({ purgedAt: new Date() }),
          artifact({ seq: 1, kind: 'bogus' as never }),
        ],
      }),
    )[0]!;
    expect(view.findings).toEqual([]);
    expect(view.indicators).toEqual({ dns: [], httpHosts: [], tlsSni: [], ips: [] });
    expect(view.artifacts).toEqual([expect.objectContaining({ seq: 0, purged: true })]);
    expect(JSON.stringify(view)).not.toContain('payload');
  });

  it('withholds the sandbox final’s duration, rounds its time and attaches the submissions', () => {
    const final: EngineResultRow = {
      scanId: 7n,
      engine: 'sandbox',
      engineVersion: '0.1.0+disabled/disabled/1',
      outcome: 'unknown',
      score: null,
      requiredScore: null,
      action: null,
      reasonCodes: ['sandbox.not_executed', 'sandbox.not_executed.backend_disabled'],
      errorCode: null,
      settingsVersion: 'sandbox-map/1;p=abc;t=1',
      durationMs: 0,
      evidence: { submissions: 1, executed: 0, isolation: ['none'] },
      attempt: 1,
      isFinal: true,
      completedAt: at(2_750),
    };
    expect(engineOf('sandbox', [final])).toMatchObject({
      durationMs: null,
      completedAt: '2026-11-08T08:00:02.000Z',
      attempts: [{ durationMs: null, at: '2026-11-08T08:00:02.000Z' }],
    });
    const scan: ScanRoundRow = {
      id: 7n,
      lifecycleRound: 0,
      scanKind: 'initial',
      status: 'completed',
      scanVerdict: 'suspicious',
      reasonCodes: ['attachment.script'],
      requiredEngines: ['rspamd', 'attachment'],
      startedAt: at(0),
      completedAt: at(900),
      deadlineAt: at(60_000),
    };
    const round = roundOf(scan, [final], [], inputs());
    const entry = round.engines.find((e) => e.engine === 'sandbox')!;
    expect(entry.symbols).toEqual([]);
    expect(entry.submissions).toHaveLength(1);
    expect(round.verdict).toBe('suspicious');
    // The page validates against the published response schema.
    expect(
      MessageScansPageSchema.safeParse({
        messageId: '0193a7c0-0000-7000-8000-000000000001',
        data: [round],
        nextCursor: null,
      }).success,
    ).toBe(true);
  });
});

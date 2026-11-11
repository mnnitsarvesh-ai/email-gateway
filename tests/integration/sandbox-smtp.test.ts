import { GetObjectCommand } from '@aws-sdk/client-s3';
import { openArtifact, parseArtifactPrivateKey } from '@email-gateway/sandbox';
import {
  attachmentSandboxCompletedV1,
  messageScannedV1,
  sandboxTaskRequestedV1,
} from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { waitFor } from './support/compose';
import { metricValue } from './support/metrics';
import { clearSinkDomain, sinkFiles } from './support/mail-sink';
import { envelopeOfRow, LiveBroker, record } from './support/messaging-stack';
import { expectPolicyFollowsRisk } from './support/policy';
import { riskRowsOf } from './support/risk';
import { MAIL_SINK_HOST, organizationRef } from './support/routing';
import {
  benignScript,
  type ControllerBackend,
  controllerHealth,
  controllerMetric,
  controllerService,
  ensureController,
  optIn,
  restoreDefaultController,
  SANDBOX_FEATURE,
  sandboxRowsOf,
  scansView,
  sendAttachmentMessage,
  taskRowsOf,
  waitForSandboxFinal,
  waitForSubmission,
} from './support/sandbox-stack';
import {
  messagePublicId,
  sandboxSubmissionsOf,
  scannedEventsOf,
  scanStackGate,
} from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * The step 4.6 sandbox engine end to end through the inbound Postfix (docs/plan/steps/
 * 14-sandbox.md §9.5, X10–X18): smtp-tools → postfix:25 → smtp-adapter → email-worker MIME role
 * → stage 1 (the attachment engine finds a `suspicious` script attachment and writes its
 * `sandbox_submissions` row + `mail.attachment.sandbox_requested.v1`) → event-relay →
 * `scan.sandbox.submissions` → the email-worker's sandbox dispatcher (plan feature, tenant
 * opt-in, dedup by content hash, sealed sample in the restricted bucket, `task_requested.v1`) →
 * event-relay → `scan.sandbox` → the sandbox-controller CONTAINER (apps profile) → its
 * `task_completed.v1` (direct publish with confirms) → `scan.sandbox.results` → the results
 * consumer (MAC, state, organization, hash, keys) → the round's asynchronous `sandbox` final.
 *
 * Backend (env `SANDBOX_STACK_BACKEND`, default `disabled`; the suite recreates the controller
 * with it and restores `disabled` afterwards):
 * - `disabled` (the default everywhere; EXECUTION OF UNKNOWN FILES IS DISABLED): the analysis
 *   is `not_executed` → the final is `unknown` with `sandbox.not_executed.backend_disabled`;
 * - `static` (no execution, production-eligible): static findings for the synthetic script,
 *   `executed: false`, isolation `process`, and a sealed `static_report` artifact in the
 *   sandbox bucket, opened here with the test-only SANDBOX_ARTIFACT_PRIVATE_KEY.
 *
 * In both: the delivery decision is made on the ROUND (verdict `suspicious`, never `clean`) and,
 * since step 5.1, on the round's revision-0 risk score, which never includes the sandbox (R13);
 * since step 5.2 the policy-engine decides it (P9; the 5.1 dev pass-through was removed): the
 * synthetic script is a denied type with YARA findings, so with Rspamd's spam score it is held
 * (5.1 observed 890, critical, quarantine → `quarantined`), and a `deliver`/`tag` score would be
 * delivered. The sandbox final never changes the round or that decision (the late final adds risk
 * revision 1 only and never re-evaluates policy, P13); an identical second attachment reuses the analysis
 * (no second task) after a static run, and is dispatched again after `backend_disabled` (an
 * operational reason, never reused); a tenant with the feature but not opted in → `skipped` / `tenant_disabled`;
 * the controller stopped while a task is queued, then started → the result arrives; the task
 * republished as an exact copy (admin confirm publisher, like the relay) → one final. Only
 * synthetic benign scripts are sent; nothing is executed by either backend.
 */
const gate = await scanStackGate();
/** Score/level/action of the first script message's revision-0 risk row (record). */
let riskDecision = '';
const fx = new SmtpFixtures();
const BACKEND = (process.env.SANDBOX_STACK_BACKEND ?? 'disabled') as ControllerBackend;
if (BACKEND !== 'disabled' && BACKEND !== 'static') {
  throw new Error('SANDBOX_STACK_BACKEND must be disabled or static (exec: sandbox-exec.test.ts)');
}

let orgA = 0n;
let orgB = 0n;
let domainA: FixtureDomain;
let domainB: FixtureDomain;
let analystA: ApiSession | undefined;
let analystB: ApiSession | undefined;
let broker: LiveBroker | undefined;
/** The first analysed message (reused by the second; its task republished later). */
let first:
  { message: { id: bigint; receivedAt: Date }; analysisId: bigint; script: Buffer } | undefined;

interface ScansBody {
  data: {
    round: number;
    status: string;
    verdict: string | null;
    engines: {
      engine: string;
      outcome: string | null;
      durationMs: number | null;
      attachments?: { sandbox: Record<string, unknown> | null }[];
      submissions?: Record<string, unknown>[];
    }[];
  }[];
}

const codes = (value: unknown): string[] => (Array.isArray(value) ? (value as string[]) : []);
const script = (label: string) => ({
  filename: `${label}.js`,
  contentType: 'application/javascript',
  bytes: benignScript(label),
});

beforeAll(async () => {
  assertStackReady(gate);
  await ensureController(BACKEND);
  orgA = await fx.organization('sbx-a');
  orgB = await fx.organization('sbx-b');
  domainA = await fx.domain(orgA, 'sbx-a');
  domainB = await fx.domain(orgB, 'sbx-b');
  await fx.destinations(domainA, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  await fx.destinations(domainB, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  // security_analyst holds policy:read, scan:settings_manage and message:read.
  analystA = await apiSession(fx.prisma, await organizationRef(fx, orgA), 'security_analyst');
  analystB = await apiSession(fx.prisma, await organizationRef(fx, orgB), 'security_analyst');
  broker = await LiveBroker.connect();
}, 300_000);

afterAll(async () => {
  if (gate.skip) return;
  // Leave the default controller running (it also drains any task of this run).
  if ((await controllerHealth()).backend !== 'disabled' || !(await controllerHealth()).ok) {
    await restoreDefaultController().catch(() => undefined);
  }
  await broker?.close().catch(() => undefined);
  await analystA?.remove();
  await analystB?.remove();
  for (const d of [domainA, domainB]) {
    if (d) await clearSinkDomain(d.name, 'all').catch(() => undefined);
  }
  await fx.cleanup();
  // Nothing of this run is left: no analysis, artifact row or sandbox object of its tasks.
}, 300_000);

describe.skipIf(gate.skip)(
  `sandbox stack: engine through Postfix (controller backend ${BACKEND})`,
  { timeout: 600_000 },
  () => {
    it('opt-in through the api: 409 without the plan feature, 200 with it; the view states the execution mode', async () => {
      const refused = await optIn(analystA!);
      expect(refused.status).toBe(409);
      expect(refused.body).toMatchObject({ code: 'feature_not_enabled', feature: SANDBOX_FEATURE });
      await fx.feature(orgA, SANDBOX_FEATURE, true);
      await fx.feature(orgB, SANDBOX_FEATURE, true);
      const accepted = await optIn(analystA!);
      expect(accepted.status, JSON.stringify(accepted.body)).toBe(200);
      expect(accepted.body).toMatchObject({
        engine: 'sandbox',
        mode: 'asynchronous',
        effective: { enabled: true },
        feature: { attachmentSandbox: true },
      });
      const list = await analystB!.get('/scan-settings');
      const view = (list.body as { data: Record<string, unknown>[] }).data.find(
        (v) => v.engine === 'sandbox',
      );
      expect(view).toMatchObject({
        override: null,
        effective: { enabled: false },
        feature: { attachmentSandbox: true },
      });
      expect(['disabled', 'static_only', 'local_test_runner']).toContain(view!.execution);
    });

    it('a suspicious script: submission → task on scan.sandbox → controller result → asynchronous sandbox final; policy follows the revision-0 risk score, never clean', async () => {
      const tasksBefore = await controllerMetric('sandbox_tasks_total', { backend: BACKEND });
      const sample = script('first');
      const sent = await sendAttachmentMessage(
        fx.prisma,
        orgA,
        `sbx-first@${domainA.name}`,
        'Sandbox stack: first script',
        [sample],
      );
      expect(sent.round.status).toBe('completed');
      const roundVerdict = sent.round.scanVerdict;
      expect(['suspicious', 'spam']).toContain(roundVerdict);

      const submission = await waitForSubmission(fx.prisma, sent.message, ['completed']);
      expect(submission.analysisId).not.toBeNull();
      const analysis = await fx.prisma.sandboxAnalysis.findUniqueOrThrow({
        where: { id: submission.analysisId! },
      });
      expect(analysis).toMatchObject({
        organizationId: orgA,
        sha256: submission.sha256,
        detectedType: 'script_js',
        profile: 'execute',
        backend: BACKEND,
        executed: false,
        mapVersion: 'sandbox-map/1',
      });
      expect(submission.externalRef).toBe(analysis.publicId);
      expect(analysis.resultEventId).not.toBeNull();
      // One task, through the outbox and the relay, consumed by the controller container.
      const [taskRow, ...moreTasks] = await taskRowsOf(fx.prisma, orgA, analysis.id);
      expect(moreTasks).toEqual([]);
      const task = sandboxTaskRequestedV1.parse(taskRow!.payload);
      expect(task).toMatchObject({ taskId: analysis.publicId, profile: 'execute' });
      expect(task.sample.key).toMatch(
        new RegExp(`^samples/\\d{4}/\\d{2}/${analysis.publicId}\\.bin$`),
      );
      expect(JSON.stringify(taskRow!.payload)).not.toContain('first.js');
      await waitFor(
        'the controller counted the task',
        async () =>
          (await controllerMetric('sandbox_tasks_total', { backend: BACKEND })) >= tasksBefore + 1,
        { timeoutMs: 30_000, intervalMs: 1_000 },
      );

      const final = await waitForSandboxFinal(fx.prisma, sent.message);
      if (BACKEND === 'disabled') {
        expect(analysis).toMatchObject({
          status: 'not_executed',
          verdict: 'unknown',
          isolation: 'none',
          notExecutedReason: 'backend_disabled',
        });
        expect(final).toMatchObject({ outcome: 'unknown', durationMs: 0 });
        expect(codes(final.reasonCodes)).toEqual([
          'sandbox.not_executed',
          'sandbox.not_executed.backend_disabled',
        ]);
        expect(await fx.prisma.sandboxArtifact.count({ where: { analysisId: analysis.id } })).toBe(
          0,
        );
      } else {
        expect(analysis).toMatchObject({ status: 'completed', isolation: 'process' });
        expect(['malicious', 'suspicious', 'unknown']).toContain(analysis.verdict);
        expect(codes(analysis.reasonCodes)).toContain('sandbox.static.script_encoded_powershell');
        expect(codes(final.reasonCodes)).toContain('sandbox.static.script_encoded_powershell');
        expect(final.outcome).toBe(analysis.verdict);
        // The sealed static report, opened with the test-only private key (no service holds it).
        const [artifact, ...moreArtifacts] = await fx.prisma.sandboxArtifact.findMany({
          where: { analysisId: analysis.id },
        });
        expect(moreArtifacts).toEqual([]);
        expect(artifact).toMatchObject({
          seq: 0,
          kind: 'static_report',
          contentType: 'application/json',
          algorithm: 'sandbox-artifact/1',
        });
        expect(artifact!.objectKey).toMatch(
          new RegExp(
            `^artifacts/\\d{4}/\\d{2}/${analysis.publicId}/[0-9a-f]{16}/0-static_report\\.bin$`,
          ),
        );
        const object = await fx.s3.send(
          new GetObjectCommand({ Bucket: fx.sandboxBucket, Key: artifact!.objectKey }),
        );
        const sealed = Buffer.from(await object.Body!.transformToByteArray());
        const privateKey = process.env.SANDBOX_ARTIFACT_PRIVATE_KEY;
        if (!privateKey) throw new Error('SANDBOX_ARTIFACT_PRIVATE_KEY is not set (.env)');
        const plain = openArtifact(
          parseArtifactPrivateKey(privateKey),
          sealed,
          artifact!.wrappedKey!,
          {
            taskId: analysis.publicId,
            seq: 0,
            kind: 'static_report',
          },
        );
        const report = JSON.parse(plain.toString('utf8')) as Record<string, unknown>;
        expect(JSON.stringify(report)).toContain('script_encoded_powershell');
        // Never the sample text itself.
        expect(plain.toString('utf8')).not.toContain('synthetic benign sandbox fixture');
      }
      // The sample object is deleted once the result is applied (best effort, then the sweeper).
      await waitFor(
        'the sample object deleted',
        async () =>
          (await fx.prisma.sandboxAnalysis.findUniqueOrThrow({ where: { id: analysis.id } }))
            .sampleDeletedAt !== null,
        { timeoutMs: 120_000, intervalMs: 1_000 },
      );

      // Asynchronous (X10): the round is unchanged; policy decided on the round (step 5.2).
      const [scanned] = await scannedEventsOf(fx.prisma, orgA, sent.message);
      expect(messageScannedV1.parse(scanned!.payload)).toMatchObject({ verdict: roundVerdict });
      expect(roundVerdict).not.toBe('clean');
      const roundAfter = await fx.prisma.emailScan.findUniqueOrThrow({
        where: { id_receivedAt: { id: sent.round.id, receivedAt: sent.round.receivedAt } },
      });
      expect(roundAfter.scanVerdict).toBe(roundVerdict);
      expect(codes(roundAfter.reasonCodes).some((c) => c.startsWith('sandbox.'))).toBe(false);
      // Step 5.2: policy follows the revision-0 risk row (never the sandbox).
      const decision = await expectPolicyFollowsRisk(fx.prisma, sent.message, 0);
      expect(await sinkFiles(sent.rcpt)).toHaveLength(decision.held ? 0 : 1);
      // The late sandbox final adds revision 1 (ADR-0042); revision 0 is unchanged by it.
      const revisions = await waitFor(
        'risk revision 1 with the sandbox result',
        async () => {
          const rows = await riskRowsOf(fx.prisma, sent.message);
          return rows.some((r) => r.revision === 1) ? rows : undefined;
        },
        { timeoutMs: 60_000, intervalMs: 1_000 },
      );
      expect(revisions.map((r) => r.revision)).toEqual([0, 1]);
      expect(revisions[0]).toEqual(decision.risk);
      // P13: the late revision 1 does not re-evaluate; the message keeps one evaluation.
      expect(
        await fx.prisma.policyExecutionLog.count({
          where: { messageId: sent.message.id, receivedAt: sent.message.receivedAt },
        }),
      ).toBe(1);
      expect((revisions[0]!.evidence as { sandbox: unknown }).sandbox).toBeNull();
      expect((revisions[1]!.evidence as { sandbox: { outcome: string } | null }).sandbox).toEqual({
        outcome: final.outcome,
      });
      riskDecision = `${decision.risk.score}/${decision.risk.level}/${decision.risk.recommendedAction}/${decision.evaluation.disposition}`;

      // The submission's sandbox_completed.v1 (firehose only in 4.6).
      const completed = await fx.prisma.messageOutbox.findMany({
        where: { organizationId: orgA, eventType: 'mail.attachment.sandbox_completed.v1' },
      });
      const mine = completed
        .map((r) => attachmentSandboxCompletedV1.parse(r.payload))
        .filter((p) => p.submissionId === submission.id.toString());
      expect(mine).toHaveLength(1);
      expect(mine[0]).toMatchObject({ status: 'completed', executed: false });

      // The scans read API (replica): the outcome on the attachment, the report on the entry.
      const body = await scansView<ScansBody>(
        analystA!,
        await messagePublicId(fx.prisma, sent.message),
        (b) => b.data[0]?.engines.some((e) => e.engine === 'sandbox') ?? false,
      );
      const round = body.data[0]!;
      expect(round.verdict).toBe(roundVerdict);
      const attachmentEntry = round.engines.find((e) => e.engine === 'attachment')!;
      expect(attachmentEntry.attachments![0]!.sandbox).toMatchObject({
        submissionId: submission.id.toString(),
        status: 'completed',
        verdict: analysis.verdict,
        executed: false,
        isolation: analysis.isolation,
      });
      const sandboxEntry = round.engines.find((e) => e.engine === 'sandbox')!;
      expect(sandboxEntry).toMatchObject({ outcome: final.outcome, durationMs: null });
      expect(sandboxEntry.submissions).toEqual([
        expect.objectContaining({
          submissionId: submission.id.toString(),
          backend: BACKEND,
          executed: false,
          artifacts:
            BACKEND === 'static' ? [expect.objectContaining({ kind: 'static_report' })] : [],
        }),
      ]);
      expect(JSON.stringify(sandboxEntry)).not.toContain(analysis.publicId);
      // Another organization never sees this message's scans.
      expect(
        (await analystB!.get(`/messages/${await messagePublicId(fx.prisma, sent.message)}/scans`))
          .status,
      ).toBe(404);

      first = { message: sent.message, analysisId: analysis.id, script: sample.bytes };
      record('sandbox-smtp', {
        backend: BACKEND,
        round_verdict: roundVerdict ?? '',
        sandbox_final: final.outcome,
        analysis_status: analysis.status,
        sandbox_codes: codes(final.reasonCodes).join(','),
        risk_revision0: riskDecision,
      });
    });

    it(`an identical second attachment ${BACKEND === 'static' ? 'reuses the analysis: no second task' : 'gets a new analysis (backend_disabled is never reused)'}, its own final`, async () => {
      expect(first).toBeDefined();
      const sent = await sendAttachmentMessage(
        fx.prisma,
        orgA,
        `sbx-second@${domainA.name}`,
        'Sandbox stack: identical script',
        [{ filename: 'again.js', contentType: 'application/javascript', bytes: first!.script }],
      );
      const submission = await waitForSubmission(fx.prisma, sent.message, ['completed']);
      const final = await waitForSandboxFinal(fx.prisma, sent.message);
      const firstFinal = await waitForSandboxFinal(fx.prisma, first!.message);
      expect(final.outcome).toBe(firstFinal.outcome);
      expect(await taskRowsOf(fx.prisma, orgA, first!.analysisId)).toHaveLength(1);
      if (BACKEND === 'static') {
        // A completed static run (unknown) has a reuse window: linked, no second task.
        expect(submission.analysisId).toBe(first!.analysisId);
      } else {
        // not_executed/backend_disabled describes the platform, not the sample: no reuse window,
        // so the identical attachment is dispatched again under a new analysis.
        expect(submission.analysisId).not.toBeNull();
        expect(submission.analysisId).not.toBe(first!.analysisId);
        expect(await taskRowsOf(fx.prisma, orgA, submission.analysisId!)).toHaveLength(1);
      }
      // The read API never says that an analysis was reused.
      const body = await scansView<ScansBody>(
        analystA!,
        await messagePublicId(fx.prisma, sent.message),
        (b) => b.data[0]?.engines.some((e) => e.engine === 'sandbox') ?? false,
      );
      expect(JSON.stringify(body)).not.toMatch(/reuse/i);
    });

    it('a tenant with the plan feature but not opted in: skipped / tenant_disabled, no analysis', async () => {
      const sent = await sendAttachmentMessage(
        fx.prisma,
        orgB,
        `sbx-b@${domainB.name}`,
        'Sandbox stack: not opted in',
        [script('not-opted-in')],
      );
      const submission = await waitForSubmission(fx.prisma, sent.message, ['skipped']);
      expect(submission).toMatchObject({ skipReason: 'tenant_disabled', analysisId: null });
      const final = await waitForSandboxFinal(fx.prisma, sent.message);
      expect(final).toMatchObject({ outcome: 'skipped', engineVersion: 'sandbox-engine/1' });
      expect(codes(final.reasonCodes)).toEqual(['sandbox.tenant_disabled']);
      expect(await fx.prisma.sandboxAnalysis.count({ where: { organizationId: orgB } })).toBe(0);
    });

    it('controller stopped while a task is queued, then started: the result arrives; an exact copy of the task gives one final', async () => {
      await controllerService('stop');
      let restarted = false;
      try {
        const sent = await sendAttachmentMessage(
          fx.prisma,
          orgA,
          `sbx-restart@${domainA.name}`,
          'Sandbox stack: controller restart',
          [script('restart')],
        );
        const submission = await waitForSubmission(fx.prisma, sent.message, ['submitted']);
        const analysisId = submission.analysisId!;
        await waitFor(
          'the analysis dispatched and its task waiting in scan.sandbox',
          async () => {
            const a = await fx.prisma.sandboxAnalysis.findUniqueOrThrow({
              where: { id: analysisId },
            });
            return a.status === 'dispatched' && (await broker!.depth('scan.sandbox')) >= 1;
          },
          { timeoutMs: 60_000, intervalMs: 1_000 },
        );
        // Nothing completes while the controller is down; the mail flow is unaffected: the
        // policy-engine decides on the revision-0 risk row (steps 5.1, 5.2), not on the sandbox.
        await expectPolicyFollowsRisk(fx.prisma, sent.message, 0);
        expect((await sandboxSubmissionsOf(fx.prisma, sent.message))[0]!.status).toBe('submitted');

        await controllerService('start');
        restarted = true;
        await ensureController(BACKEND);
        const done = await waitForSubmission(fx.prisma, sent.message, ['completed']);
        expect(done.analysisId).toBe(analysisId);
        const final = await waitForSandboxFinal(fx.prisma, sent.message);
        const analysis = await fx.prisma.sandboxAnalysis.findUniqueOrThrow({
          where: { id: analysisId },
        });
        expect(final.outcome).toBe(analysis.verdict);

        // Republish an exact copy of the task (as a relay retry would): the controller runs it
        // again (stateless) and publishes a second result, which the results consumer absorbs.
        const [taskRow] = await taskRowsOf(fx.prisma, orgA, analysisId);
        const tasksBefore = await controllerMetric('sandbox_tasks_total', { backend: BACKEND });
        const resultsBefore = await metricValue('email-worker', 'amqp_consumer_messages_total', {
          queue: 'scan.sandbox.results',
        });
        await broker!.publish([envelopeOfRow(taskRow!)]);
        await waitFor(
          'the duplicate task run by the controller and its result consumed',
          async () =>
            (await controllerMetric('sandbox_tasks_total', { backend: BACKEND })) >=
              tasksBefore + 1 &&
            (await metricValue('email-worker', 'amqp_consumer_messages_total', {
              queue: 'scan.sandbox.results',
            })) >=
              resultsBefore + 1,
          { timeoutMs: 120_000, intervalMs: 1_000 },
        );
        const after = await fx.prisma.sandboxAnalysis.findUniqueOrThrow({
          where: { id: analysisId },
        });
        expect(after.resultEventId).toBe(analysis.resultEventId);
        expect(after.completedAt?.getTime()).toBe(analysis.completedAt?.getTime());
        const rows = await sandboxRowsOf(fx.prisma, sent.message);
        expect(rows.filter((r) => r.isFinal)).toHaveLength(1);
        const completedEvents = (
          await fx.prisma.messageOutbox.findMany({
            where: { organizationId: orgA, eventType: 'mail.attachment.sandbox_completed.v1' },
          })
        ).filter(
          (r) => (r.payload as { submissionId?: string }).submissionId === done.id.toString(),
        );
        expect(completedEvents).toHaveLength(1);
        record('sandbox-smtp', { restart_final: final.outcome, duplicate_task_finals: 1 });
      } finally {
        if (!restarted) await controllerService('start').catch(() => undefined);
      }
    });

    it('leaves nothing of the sandbox in the message row or MySQL text columns (metadata only)', async () => {
      const analyses = await fx.prisma.sandboxAnalysis.findMany({
        where: { organizationId: orgA },
      });
      expect(analyses.length).toBeGreaterThan(0);
      const text = JSON.stringify(analyses, (_k, v: unknown) =>
        typeof v === 'bigint' ? v.toString() : v,
      );
      expect(text).not.toContain('synthetic benign sandbox fixture');
      expect(text).not.toContain('.js');
    });
  },
);

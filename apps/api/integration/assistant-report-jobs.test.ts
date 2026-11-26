/**
 * Step AI-6 asynchronous security reports end to end (docs/plan/steps/34-ai-chat-hardening-
 * operations.md D5, I26, R1, R9, §9 item 5; ADR-0096; contracts §35.6): real MySQL, Redis, MinIO
 * (the mail bucket) and RabbitMQ from the local `.env`; the api listens on its ephemeral loopback
 * port and runs the report-job consumer in-process (`ASSISTANT_REPORT_JOBS_CONSUMER=true`,
 * `RABBITMQ_ASSISTANT_URL` of the `eg-assistant` role user). The turn writes the queued report,
 * the job and the outbox row `assistant.report.generate_requested.v1`; the live event-relay
 * publishes it to `email.policy` → queue `assistant.reports` (without a live relay the suite's
 * helper publishes its own row with the relay's envelope rules); the consumer mints a job token
 * of the user's live session and composes the report through the loopback with it. The provider
 * is the deterministic fake (never a real LLM; nothing reaches the internet).
 *
 * Covered: a 30-day report is queued (card `queued`, envelope 202 with the background note, no
 * figures, the outbox row with ids only, `assistant.report_job_queued`) and becomes available
 * (object in MinIO with the stored SHA-256, `assistant.report_generated` with `async: true` and the
 * job id, the report view's `job`, the loopback reads made with the job's correlation); the next
 * turn's action update tells the model the report is ready (`reported_at` set); a job token is
 * accepted only for GET on the report source routes (`GET /api/v1/policies` and a POST → 401,
 * proving the guard matches the route template at request time); a session revoked before the
 * job runs → `assistant_report_session_ended`; the expiry sweep → `assistant_report_job_expired`;
 * deleting the conversation cancels a queued job (report purged); a redelivered message (the
 * processor and a re-published envelope) changes nothing; `report_send_email` on a queued report
 * → `409 assistant_report_not_ready`. Synthetic `it-*` organizations only; every row, message
 * and object of the suite is removed.
 */
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers get /api/v1/assistant/reports/:reportId
// @covers delete /api/v1/assistant/conversations/:conversationId
// @covers get /api/v1/reports/traffic
// @covers get /api/v1/policies
// Native tools covered (no route): report_generate (queued), report_send_email (not ready).
import { createHash, randomUUID } from 'node:crypto';
import { REPORT_QUEUED_NOTE } from '@email-gateway/assistant';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { REPORT_JOB_LEASE_MS } from '../src/modules/assistant/assistant.constants';
import { ReportJobsRepository } from '../src/modules/assistant/repositories/report-jobs.repository';
import { AssistantRetentionService } from '../src/modules/assistant/services/assistant-retention.service';
import {
  ReportJobBusyError,
  ReportJobProcessor,
} from '../src/modules/assistant/services/reports/report-job.processor';
import { AccessTokenPrincipalResolver } from '../src/modules/auth/services/access-token-principal-resolver.service';
import type { IntegrationApp } from './support/app';
import {
  A,
  ALL_TENANT_PERMISSIONS,
  allFeatures,
  call,
  clearAssistantCounters,
  createAssistantApp,
  directive,
  enableAssistant,
  envelopesOf,
  type Member,
  memberWith,
  newConversation,
  platformMember,
  recordLoopback,
  reportObjectBytes,
  reportObjectKeys,
  REPORTS,
  secondSession,
  trackReports,
  turn,
  waitFor,
} from './support/assistant';
import {
  awaitJobPublished,
  envelopeOfOutboxRow,
  jobOutboxRow,
  mintJobToken,
  publishEnvelope,
  reportJobConsumer,
  startReportJobConsumer,
  stopReportJobConsumer,
} from './support/assistant-hardening';
import { deleteAtoRows } from './support/ato';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { bearer } from './support/http';

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let analyst: Member;
const orgIds: bigint[] = [];

interface Queued {
  conversation: string;
  turnId: string;
  executionId: string;
  reportId: string;
  jobId: string;
}

/** A turn that queues a 30-day report (the window is longer than 168 h). */
async function queueReport(who: Member, conversation?: string): Promise<Queued> {
  const id = conversation ?? (await newConversation(ctx, who));
  const res = await turn(ctx, who.headers, id, directive('report_generate', { range: '30d' }));
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  const execution = (res.body.executions as Array<Record<string, unknown>>).find(
    (e) => e.tool === 'report_generate',
  )!;
  expect(execution).toMatchObject({ decision: 'allowed', status: 'succeeded', httpStatus: 202 });
  const card = execution.card as { kind: string; report: { reportId: string; status: string } };
  expect(card.kind).toBe('report');
  expect(card.report.status).toBe('queued');
  const job = await ctx.prisma.aiChatReportJob.findFirstOrThrow({
    where: { report: { publicId: card.report.reportId } },
    select: { publicId: true },
  });
  return {
    conversation: id,
    turnId: res.body.turn.id as string,
    executionId: execution.id as string,
    reportId: card.report.reportId,
    jobId: job.publicId,
  };
}

const jobRow = (jobId: string) =>
  ctx.prisma.aiChatReportJob.findUniqueOrThrow({ where: { publicId: jobId } });
const reportOf = (reportId: string) =>
  ctx.prisma.aiChatReport.findUniqueOrThrow({ where: { publicId: reportId } });

async function settled(jobId: string) {
  return waitFor(
    () => jobRow(jobId),
    (job) => ['succeeded', 'failed', 'cancelled'].includes(job.status),
    30_000,
  );
}

beforeAll(async () => {
  ({ ctx } = await createAssistantApp({
    env: {
      ASSISTANT_REPORT_JOBS_CONSUMER: 'true',
      ASSISTANT_REPORTS_PER_USER_PER_DAY: '50',
    },
  }));
  expect(reportJobConsumer(ctx).running).toBe(true);
  fx = createFixtures(ctx);
  trackReports(ctx, fx, orgIds);
  fx.registerCleanup(() => deleteAtoRows(ctx.prisma, orgIds), { rerunOnConflict: true });
  const operator = await platformMember(ctx, fx);
  org = await fx.createOrganization({ features: allFeatures(), planCode: 'enterprise' });
  orgIds.push(org.id);
  analyst = await memberWith(ctx, fx, org, { permissions: [...ALL_TENANT_PERMISSIONS] });
  await enableAssistant(ctx, operator, org, analyst);
}, 120_000);

afterAll(async () => {
  if (ctx) {
    startReportJobConsumer(ctx);
    await clearAssistantCounters(ctx, orgIds);
  }
  await fx?.cleanup();
  if (ctx) for (const id of orgIds) expect(await reportObjectKeys(ctx, id)).toEqual([]);
  await ctx?.close();
});

describe('a background report end to end (D5)', () => {
  let queued: Queued;

  it('queues a 30-day report and the consumer makes it available through the outbox and RabbitMQ', async () => {
    const recorder = recordLoopback(ctx);
    try {
      queued = await queueReport(analyst);
      // The queued rows: report (no object), job (the session, auth methods), outbox (ids only).
      const report = await reportOf(queued.reportId);
      expect(report.objectKey === null || report.status !== 'queued').toBe(true);
      const job = await jobRow(queued.jobId);
      expect(job).toMatchObject({ attempts: job.attempts, errorCode: null });
      expect(job.authMethods).toBe('pwd,otp');
      const outbox = (await jobOutboxRow(ctx.prisma, queued.jobId))!;
      expect(outbox).toMatchObject({
        aggregateType: 'assistant_report_job',
        aggregateId: queued.jobId,
        organizationId: org.id,
      });
      expect(Object.keys(outbox.payload as object).sort()).toEqual([
        'jobId',
        'reportId',
        'requestedAt',
      ]);
      expect(
        await ctx.prisma.auditLog.count({
          where: { organizationId: org.id, action: 'assistant.report_job_queued' },
        }),
      ).toBeGreaterThanOrEqual(1);
      // The envelope the model received: 202, queued, the background note, no figures.
      const [envelope] = await envelopesOf(ctx, queued.turnId);
      expect(envelope!.parsed).toMatchObject({
        status: 'ok',
        httpStatus: 202,
        note: REPORT_QUEUED_NOTE,
        data: { reportId: queued.reportId, status: 'queued' },
      });
      expect(Object.keys(envelope!.parsed.data as object)).not.toContain('figures');

      await awaitJobPublished(ctx, queued.jobId);
      const done = await settled(queued.jobId);
      expect(done).toMatchObject({ status: 'succeeded', attempts: 1, errorCode: null });

      const available = await reportOf(queued.reportId);
      expect(available.status).toBe('available');
      expect(available.objectKey).not.toBeNull();
      const bytes = await reportObjectBytes(ctx, available.objectKey!);
      expect(createHash('sha256').update(bytes).digest('hex')).toBe(available.sha256);
      const generated = await ctx.prisma.auditLog.findMany({
        where: {
          organizationId: org.id,
          action: 'assistant.report_generated',
          resourceId: queued.reportId,
        },
      });
      expect(generated).toHaveLength(1);
      expect(generated[0]!.metadata).toMatchObject({ async: true, jobId: queued.jobId });
      // The actor is the requesting user (the job acts as the user's session, I26).
      expect(generated[0]).toMatchObject({ actorType: 'user' });
      expect([analyst.user.publicId, analyst.user.id.toString()]).toContain(generated[0]!.actorId);
      // The source reads went through the loopback under the job's correlation.
      const jobReads = recorder.calls.filter(
        (c) => c.method === 'GET' && c.correlationId.startsWith(done.correlationId),
      );
      expect(jobReads.length).toBeGreaterThan(0);
      expect(jobReads.every((c) => c.path.startsWith('/api/v1/'))).toBe(true);
    } finally {
      recorder.restore();
    }

    const view = await call(ctx, analyst.headers, 'get', `${REPORTS}/${queued.reportId}`);
    expect(view.status).toBe(200);
    expect(view.body.report).toMatchObject({
      status: 'available',
      job: { status: 'succeeded', attempts: 1, errorCode: null },
    });
    expect(view.body.html).toContain('<!doctype html>');
  });

  it('the next turn’s action update tells the model the report is ready (once)', async () => {
    const res = await turn(ctx, analyst.headers, queued.conversation, '/text Thanks.');
    expect(res.status).toBe(200);
    const row = await ctx.prisma.aiChatTurn.findUniqueOrThrow({
      where: { publicId: res.body.turn.id as string },
      select: { providerTranscript: true },
    });
    expect(row.providerTranscript).toMatch(
      /report_generate \(call r\d+\): the background report is ready\./,
    );
    expect((await jobRow(queued.jobId)).reportedAt).not.toBeNull();
    const after = await turn(ctx, analyst.headers, queued.conversation, '/text Again.');
    const later = await ctx.prisma.aiChatTurn.findUniqueOrThrow({
      where: { publicId: after.body.turn.id as string },
      select: { providerTranscript: true },
    });
    expect(later.providerTranscript).not.toContain('the background report is ready');
  });

  it('a redelivered message changes nothing (the processor and a re-published envelope)', async () => {
    const outbox = (await jobOutboxRow(ctx.prisma, queued.jobId))!;
    const envelope = envelopeOfOutboxRow(outbox);
    const before = await reportOf(queued.reportId);
    expect(await ctx.get(ReportJobProcessor).handle(envelope)).toBe('duplicate');
    await publishEnvelope(envelope);
    await new Promise((r) => setTimeout(r, 1_500));
    const after = await reportOf(queued.reportId);
    expect(after).toMatchObject({ status: 'available', objectKey: before.objectKey });
    expect(after.sha256).toBe(before.sha256);
    expect(
      await ctx.prisma.auditLog.count({
        where: {
          organizationId: org.id,
          action: 'assistant.report_generated',
          resourceId: queued.reportId,
        },
      }),
    ).toBe(1);
    expect((await jobRow(queued.jobId)).attempts).toBe(1);
  });
});

describe('the job token (D5, I26)', () => {
  it('is accepted only for GET on the report source routes', async () => {
    const token = await mintJobToken(ctx, analyst, randomUUID());
    const headers = bearer(token);
    const to = new Date();
    const from = new Date(to.getTime() - 86_400_000);
    const window = `from=${encodeURIComponent(from.toISOString())}&to=${encodeURIComponent(to.toISOString())}`;
    const allowed = await call(ctx, headers, 'get', `/api/v1/reports/traffic?${window}`);
    expect(allowed.status, allowed.text).toBe(200);
    const summary = await call(ctx, headers, 'get', `/api/v1/quarantine/summary?${window}`);
    expect(summary.status, summary.text).toBe(200);
    // Not allow-listed: another GET, a POST, the assistant's own routes.
    for (const [method, path, body] of [
      ['get', '/api/v1/policies', undefined],
      ['get', '/api/v1/auth/me', undefined],
      ['get', `${A}/conversations`, undefined],
      ['post', `${A}/conversations`, {}],
      ['post', '/api/v1/auth/logout', undefined],
    ] as const) {
      const res = await call(ctx, headers, method, path, body);
      expect(res.status, `${method} ${path}`).toBe(401);
    }
    // The same session's ordinary access token reads the policies (the session is live).
    expect((await call(ctx, analyst.headers, 'get', '/api/v1/policies')).status).toBe(200);
  });
});

describe('jobs that never run (D5 retention, I26)', () => {
  beforeAll(async () => {
    await stopReportJobConsumer(ctx);
    expect(reportJobConsumer(ctx).running).toBe(false);
  });

  afterAll(() => {
    startReportJobConsumer(ctx);
  });

  it('report_send_email on a queued report → 409 assistant_report_not_ready (no confirmation)', async () => {
    const queued = await queueReport(analyst);
    const res = await turn(
      ctx,
      analyst.headers,
      queued.conversation,
      directive('report_send_email', {}),
    );
    expect(res.status).toBe(200);
    const execution = (res.body.executions as Array<Record<string, unknown>>).find(
      (e) => e.tool === 'report_send_email',
    );
    expect(execution).toMatchObject({ httpStatus: 409, errorCode: 'assistant_report_not_ready' });
    expect(res.body.confirmations ?? []).toEqual([]);
    expect(
      await ctx.prisma.aiChatActionConfirmation.count({
        where: { conversation: { publicId: queued.conversation } },
      }),
    ).toBe(0);
  });

  it('a session revoked before the job runs → assistant_report_session_ended', async () => {
    const session = await secondSession(ctx, fx, analyst);
    const queued = await queueReport(session);
    await awaitJobPublished(ctx, queued.jobId);
    expect((await call(ctx, session.headers, 'post', '/api/v1/auth/logout')).status).toBe(204);
    startReportJobConsumer(ctx);
    try {
      const failed = await settled(queued.jobId);
      expect(failed).toMatchObject({
        status: 'failed',
        errorCode: 'assistant_report_session_ended',
      });
      expect((await reportOf(queued.reportId)).status).toBe('failed');
      expect(await reportObjectKeys(ctx, org.id)).not.toContain(
        expect.stringContaining(queued.reportId),
      );
      const view = await call(ctx, analyst.headers, 'get', `${REPORTS}/${queued.reportId}`);
      expect(view.body.report).toMatchObject({
        status: 'failed',
        job: { status: 'failed', errorCode: 'assistant_report_session_ended' },
      });
      // The next turn of that conversation tells the model it failed, with the code.
      const next = await turn(ctx, analyst.headers, queued.conversation, '/text And?');
      const row = await ctx.prisma.aiChatTurn.findUniqueOrThrow({
        where: { publicId: next.body.turn.id as string },
        select: { providerTranscript: true },
      });
      expect(row.providerTranscript).toMatch(
        /the background report failed \(assistant_report_session_ended\)/,
      );
    } finally {
      await stopReportJobConsumer(ctx);
    }
  });

  it('the expiry sweep fails a job past its expiry; the late message changes nothing', async () => {
    const queued = await queueReport(analyst);
    await awaitJobPublished(ctx, queued.jobId);
    await ctx.prisma.aiChatReportJob.update({
      where: { publicId: queued.jobId },
      data: { expiresAt: new Date(Date.now() - 1_000) },
    });
    expect(
      await ctx.get(AssistantRetentionService).expireReportJobs(new Date()),
    ).toBeGreaterThanOrEqual(1);
    expect(await jobRow(queued.jobId)).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_report_job_expired',
    });
    expect((await reportOf(queued.reportId)).status).toBe('failed');
    startReportJobConsumer(ctx);
    try {
      await new Promise((r) => setTimeout(r, 1_500));
      expect(await jobRow(queued.jobId)).toMatchObject({
        status: 'failed',
        errorCode: 'assistant_report_job_expired',
        attempts: 0,
      });
    } finally {
      await stopReportJobConsumer(ctx);
    }
  });

  it('deleting the conversation cancels its queued job (report purged); the late message changes nothing', async () => {
    const queued = await queueReport(analyst);
    await awaitJobPublished(ctx, queued.jobId);
    expect(
      (await call(ctx, analyst.headers, 'delete', `${A}/conversations/${queued.conversation}`))
        .status,
    ).toBe(204);
    expect(await jobRow(queued.jobId)).toMatchObject({ status: 'cancelled' });
    expect((await reportOf(queued.reportId)).status).toBe('purged');
    startReportJobConsumer(ctx);
    try {
      await new Promise((r) => setTimeout(r, 1_500));
      expect(await jobRow(queued.jobId)).toMatchObject({ status: 'cancelled', attempts: 0 });
      expect((await reportOf(queued.reportId)).status).toBe('purged');
    } finally {
      await stopReportJobConsumer(ctx);
    }
  });
});

describe('claim release and the renewed lease (D5, review fix)', () => {
  // The processor is driven directly; the in-process consumer stays off meanwhile.
  beforeAll(async () => {
    await stopReportJobConsumer(ctx);
    expect(reportJobConsumer(ctx).running).toBe(false);
  });

  afterAll(() => {
    startReportJobConsumer(ctx);
  });

  it('an unexpected error releases the claim; a live lease waits; the retry runs the job', async () => {
    const queued = await queueReport(analyst);
    await awaitJobPublished(ctx, queued.jobId);
    const envelope = envelopeOfOutboxRow((await jobOutboxRow(ctx.prisma, queued.jobId))!);
    const processor = ctx.get(ReportJobProcessor);
    const resolve = vi
      .spyOn(ctx.get(AccessTokenPrincipalResolver), 'resolve')
      .mockRejectedValueOnce(new Error('resolver exploded'));
    try {
      // 1. The unexpected error is rethrown (a retry hop) and the row is claimable again.
      await expect(processor.handle(envelope)).rejects.toThrow('resolver exploded');
    } finally {
      resolve.mockRestore();
    }
    expect(await jobRow(queued.jobId)).toMatchObject({
      status: 'queued',
      attempts: 1,
      leaseUntil: null,
      errorCode: 'assistant_report_job_failed',
    });
    // 2. Another consumer's live lease: a transient retry, never an ack; renewals are its own.
    const claimedAt = new Date(Date.now() - 1_000);
    await ctx.prisma.aiChatReportJob.update({
      where: { publicId: queued.jobId },
      data: {
        status: 'running',
        startedAt: claimedAt,
        leaseUntil: new Date(Date.now() + REPORT_JOB_LEASE_MS),
      },
    });
    await expect(processor.handle(envelope)).rejects.toThrow(ReportJobBusyError);
    const row = await jobRow(queued.jobId);
    const repo = ctx.get(ReportJobsRepository);
    expect(await repo.renewLease(org.id, row.id, claimedAt, new Date(), REPORT_JOB_LEASE_MS)).toBe(
      true,
    );
    expect(
      await repo.renewLease(org.id, row.id, new Date(0), new Date(), REPORT_JOB_LEASE_MS),
    ).toBe(false);
    // 3. Its holder died: once the lease lapsed, the retry claims and runs the job.
    await ctx.prisma.aiChatReportJob.update({
      where: { publicId: queued.jobId },
      data: { leaseUntil: new Date(Date.now() - 1_000) },
    });
    expect(await processor.handle(envelope)).toBe('handled');
    expect(await jobRow(queued.jobId)).toMatchObject({
      status: 'succeeded',
      attempts: 2,
      leaseUntil: null,
    });
    expect((await reportOf(queued.reportId)).status).toBe('available');
  });
});

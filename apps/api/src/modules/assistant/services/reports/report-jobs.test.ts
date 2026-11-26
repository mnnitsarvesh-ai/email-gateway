import { randomBytes } from 'node:crypto';
import { Logger } from '@nestjs/common';
import {
  findTool,
  REPORT_QUEUED_NOTE,
  REPORT_SOURCE_DEFS,
  type ReportSourceKey,
} from '@email-gateway/assistant';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { immediateAssistantRunner, testUser } from '../../../../../test/support/assistant-fixtures';
import { reportSourceBodies } from '../../../../../test/support/assistant-report-fixtures';
import { createAssistantHarness } from '../../../../../test/support/assistant-harness';
import type { UserPrincipal } from '../../../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../../../auth-contracts/tenant-scope';
import type { AccessTokenPrincipalResolver } from '../../../auth/services/access-token-principal-resolver.service';
import { TokenService } from '../../../auth/services/token.service';
import type { AssistantConfig } from '../../assistant.constants';
import type {
  ReportJobCreate,
  ReportJobRow,
  ReportJobsRepository,
  ReportJobWithRefs,
} from '../../repositories/report-jobs.repository';
import type {
  QueuedReportCreate,
  ReportAvailable,
  ReportsRepository,
} from '../../repositories/reports.repository';
import { ownerOf } from '../conversation.service';
import { NativeToolsService } from '../native-tools.service';
import { ToolExecutorService, type ExecutionContext } from '../tool-executor.service';
import { ReportGeneratorService } from './report-generator.service';
import { classifyReportJobFailure } from './report-job.consumer';
import {
  ReportJobBusyError,
  ReportJobProcessor,
  ReportJobRetryError,
} from './report-job.processor';

/**
 * Step AI-6 D5 (ADR-0096, I26): the report job producer (`report_generate` with a window longer
 * than ASSISTANT_REPORT_SYNC_MAX_HOURS) and the consumer's steps 1–5 (`ReportJobProcessor`), over
 * the in-memory report world, an in-memory job store and a real `TokenService`.
 */

const PERMISSIONS = ['assistant:use', 'report:read', 'quarantine:read', 'ato:read'];
const NOW = new Date('2026-11-23T09:00:30.000Z');
const WINDOW = { from: '2026-10-24T09:00:00.000Z', to: '2026-11-23T09:00:00.000Z' };
const ORG = 7001n;

afterEach(() => vi.restoreAllMocks());

const pathOf = (key: ReportSourceKey): string =>
  findTool(REPORT_SOURCE_DEFS[key].tool)!.pathTemplate;

/** In-memory `ai_chat_report_jobs` + the outbox + the ledger (what the repository writes). */
class JobStore {
  readonly jobs: Array<ReportJobRow & { conversationPublicId: string; reportPublicId: string }> =
    [];
  readonly outbox: unknown[] = [];
  readonly ledger = new Set<string>();
  renewals = 0;
  private next = 9000n;

  repository(
    reports: { statusOf(id: bigint): string; publicIdOf(id: bigint): string },
    userPublicId: string,
  ): ReportJobsRepository {
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- the double's closures share the store
    const store = this;
    const find = (id: bigint) => store.jobs.find((j) => j.id === id)!;
    return {
      insert: (
        owner: { scope: { organizationId: bigint }; userId: bigint },
        data: ReportJobCreate,
      ) => {
        store.next += 1n;
        store.jobs.push({
          ...data,
          id: store.next,
          organizationId: owner.scope.organizationId,
          userId: owner.userId,
          arguments: structuredClone(data.arguments) as ReportJobRow['arguments'],
          status: 'queued',
          attempts: 0,
          leaseUntil: null,
          errorCode: null,
          reportedAt: null,
          startedAt: null,
          finishedAt: null,
          conversationPublicId: 'unused',
          reportPublicId: 'unused',
        });
        return Promise.resolve(store.next);
      },
      insertGenerateRequested: (_tx: unknown, event: unknown) => {
        store.outbox.push(structuredClone(event));
        return Promise.resolve();
      },
      findForConsumer: (organizationId: bigint, publicId: string) => {
        const job = store.jobs.find(
          (j) => j.organizationId === organizationId && j.publicId === publicId,
        );
        return Promise.resolve(
          job
            ? ({
                ...job,
                reportPublicId: reports.publicIdOf(job.reportId),
                reportStatus: reports.statusOf(job.reportId),
                userPublicId,
                executionPublicId: '0193d000-0000-7000-8000-0000000e0001',
              } satisfies ReportJobWithRefs)
            : null,
        );
      },
      claim: (_o: bigint, id: bigint, now: Date, leaseMs: number) => {
        const job = find(id);
        const free =
          job.status === 'queued' ||
          (job.status === 'running' && job.leaseUntil !== null && job.leaseUntil < now);
        if (!free || job.expiresAt <= now) return Promise.resolve(false);
        Object.assign(job, {
          status: 'running',
          attempts: job.attempts + 1,
          leaseUntil: new Date(now.getTime() + leaseMs),
          startedAt: now,
        });
        return Promise.resolve(true);
      },
      leaseHeld: (_o: bigint, id: bigint, now: Date) => {
        const job = find(id);
        return Promise.resolve(
          job.status === 'running' && job.leaseUntil !== null && job.leaseUntil >= now,
        );
      },
      renewLease: (_o: bigint, id: bigint, claimedAt: Date, now: Date, leaseMs: number) => {
        const job = find(id);
        if (job.status !== 'running' || job.startedAt?.getTime() !== claimedAt.getTime()) {
          return Promise.resolve(false);
        }
        store.renewals += 1;
        job.leaseUntil = new Date(now.getTime() + leaseMs);
        return Promise.resolve(true);
      },
      requeue: (_o: bigint, id: bigint, code: string, claimedAt?: Date) => {
        const job = find(id);
        if (job.status !== 'running') return Promise.resolve(false);
        if (claimedAt && job.startedAt?.getTime() !== claimedAt.getTime()) {
          return Promise.resolve(false);
        }
        Object.assign(job, { status: 'queued', leaseUntil: null, errorCode: code });
        return Promise.resolve(true);
      },
      succeed: (_o: bigint, id: bigint, now: Date) => {
        const job = find(id);
        if (job.status !== 'running') return Promise.resolve(false);
        Object.assign(job, { status: 'succeeded', finishedAt: now, leaseUntil: null });
        return Promise.resolve(true);
      },
      fail: (_o: bigint, ref: { id: bigint; reportId: bigint }, code: string, now: Date) => {
        const job = find(ref.id);
        if (job.status !== 'queued' && job.status !== 'running') return Promise.resolve(false);
        Object.assign(job, { status: 'failed', errorCode: code, finishedAt: now });
        (reports as unknown as { fail(id: bigint, code: string): void }).fail(ref.reportId, code);
        return Promise.resolve(true);
      },
      recordLedger: (_tx: unknown, consumer: string, eventId: string) => {
        const key = `${consumer}:${eventId}`;
        if (store.ledger.has(key)) return Promise.resolve(false);
        store.ledger.add(key);
        return Promise.resolve(true);
      },
    } as unknown as ReportJobsRepository;
  }
}

function setup(options: { principal?: UserPrincipal; env?: Record<string, string> } = {}) {
  const principal = options.principal ?? testUser({ permissions: new Set(PERMISSIONS) });
  const h = createAssistantHarness(
    { AUTH_JWT_SECRET: randomBytes(32).toString('hex'), ...options.env },
    undefined,
    principal,
  );
  const c = h.config as AssistantConfig;
  h.world.enable(ORG);
  h.world.features.set(ORG, true);
  const owner = ownerOf(principal, scopeFromPrincipal(principal));
  const conversation = h.world.addConversation(owner);
  for (const key of Object.keys(REPORT_SOURCE_DEFS) as ReportSourceKey[]) {
    h.loopback.on(`GET ${pathOf(key)}`, () => ({
      kind: 'response',
      status: 200,
      body: reportSourceBodies(WINDOW)[key],
    }));
  }
  const rw = h.world.reportWorld;
  const reports = rw.reportsDouble() as ReportsRepository & {
    statusOf(id: bigint): string;
    publicIdOf(id: bigint): string;
    fail(id: bigint, code: string): void;
  };
  reports.insertQueued = (o, data: QueuedReportCreate) =>
    rw
      .reportsDouble()
      .insertPending(o, {
        ...data,
        figures: [],
        objectKey: '',
        sizeBytes: 0,
        sha256: '',
      })
      .then((id) => {
        Object.assign(
          rw.reports.find((r) => r.id === id)!,
          {
            status: 'queued',
            objectKey: null,
            sizeBytes: null,
            sha256: null,
          },
        );
        return id;
      });
  reports.markJobReportAvailable = (_o: bigint, id: bigint, data: ReportAvailable) => {
    const row = rw.reports.find((r) => r.id === id)!;
    if (row.status !== 'queued') return Promise.resolve(false);
    Object.assign(row, { ...data, status: 'available' });
    return Promise.resolve(true);
  };
  reports.statusOf = (id) => rw.reports.find((r) => r.id === id)!.status;
  reports.publicIdOf = (id) => rw.reports.find((r) => r.id === id)!.publicId;
  reports.fail = (id, code) => {
    const row = rw.reports.find((r) => r.id === id)!;
    if (row.status === 'queued') Object.assign(row, { status: 'failed', errorCode: code });
  };
  const store = new JobStore();
  const jobs = store.repository(reports, principal.userPublicId);
  const objects = rw.storeDouble();
  const generator = new ReportGeneratorService(
    c,
    reports,
    objects,
    h.loopback,
    h.audit,
    h.metrics,
    jobs,
  );
  generator.now = () => NOW;
  const native = new NativeToolsService(generator, h.delivery);
  const executor = new ToolExecutorService(
    c,
    h.world.executionsDouble(),
    h.loopback,
    immediateAssistantRunner,
    h.audit,
    h.metrics,
    h.proposer,
    native,
  );
  let seq = 1;
  const ctx: ExecutionContext = {
    principal,
    owner,
    conversationId: conversation.id,
    conversationPublicId: conversation.publicId,
    turnId: null,
    turnPublicId: null,
    parentExecutionId: null,
    parentExecutionPublicId: null,
    authorization: 'Bearer it-access-token',
    clientIp: '198.51.100.7',
    correlationBase: 'it-corr-0001',
    signal: new AbortController().signal,
    allocateSeq: () => seq++,
    organizationName: 'IT Org',
  };
  const generate = (args: Record<string, unknown>) =>
    executor.execute(ctx, { name: 'report_generate', arguments: args }, 0);

  // The consumer: a real token service; the resolver returns the session's principal.
  const tokens = new TokenService(c as never);
  let resolved: UserPrincipal | null = principal;
  const resolver = {
    resolve: vi.fn(async (token: string) => {
      const claims = await tokens.verify(token);
      return claims && resolved ? { ...resolved, assistantJobId: claims.ajb } : null;
    }),
  } as unknown as AccessTokenPrincipalResolver;
  const processor = new ReportJobProcessor(
    c,
    jobs,
    reports,
    generator,
    objects,
    tokens,
    resolver,
    h.availability,
    immediateAssistantRunner,
    h.audit,
    h.metrics,
  );
  processor.now = () => NOW;
  const event = (job: { publicId: string }, report: string): EventEnvelope<never> =>
    ({
      eventId: job.publicId,
      eventType: 'assistant.report.generate_requested.v1',
      organizationId: String(ORG),
      payload: { jobId: job.publicId, reportId: report, requestedAt: NOW.toISOString() },
    }) as unknown as EventEnvelope<never>;
  return {
    h,
    c,
    rw,
    store,
    resolver,
    objects,
    tokens,
    generate,
    processor,
    event,
    principal,
    setResolved: (p: UserPrincipal | null) => (resolved = p),
  };
}

/** Queues a 30-day report and returns the job and its report public id. */
async function queued(t: ReturnType<typeof setup>) {
  const out = await t.generate({ range: '30d' });
  const job = t.store.jobs.at(-1)!;
  const reportId = (out.envelope as unknown as { data: { reportId: string } }).data.reportId;
  return { out, job, reportId };
}

describe('report job producer (step AI-6 D5)', () => {
  it('queues a window longer than ASSISTANT_REPORT_SYNC_MAX_HOURS: 202, queued card, rows, outbox, audits', async () => {
    const t = setup();
    const { out, job, reportId } = await queued(t);
    expect(out).toMatchObject({ decision: 'allowed', status: 'succeeded', httpStatus: 202 });
    expect(out.card).toMatchObject({ kind: 'report', report: { status: 'queued', figures: [] } });
    expect(out.envelope).toMatchObject({
      status: 'ok',
      httpStatus: 202,
      note: REPORT_QUEUED_NOTE,
      data: { status: 'queued', reportId, title: 'Security report: Last 30 days' },
    });
    // Nothing was read or stored synchronously.
    expect(t.h.loopback.toolCalls).toHaveLength(0);
    const report = t.rw.reports.find((r) => r.publicId === reportId)!;
    expect(report).toMatchObject({ status: 'queued', objectKey: null });
    const execution = t.h.world.executions.find((e) => e.publicId === out.executionId)!;
    expect(job).toMatchObject({
      reportId: report.id,
      executionId: execution.id,
      sessionId: t.principal.sessionId,
      authMethods: 'pwd,otp',
      homeOrganizationPublicId: t.principal.organizationPublicId,
      platformOverrideId: null,
      arguments: { range: '30d' },
      organizationLabel: 'IT Org',
      correlationId: 'it-corr-0001.1',
      status: 'queued',
    });
    expect(job.expiresAt.getTime() - NOW.getTime()).toBe(1800 * 1000);
    expect(t.store.outbox).toEqual([
      {
        organizationId: ORG,
        correlationId: 'it-corr-0001.1',
        payload: { jobId: job.publicId, reportId, requestedAt: NOW.toISOString() },
      },
    ]);
    expect(t.h.audit.entries.map((e) => e.action)).toEqual([
      'assistant.tool_executed',
      'assistant.report_job_queued',
    ]);
    expect(t.h.audit.entries[1]).toMatchObject({
      resourceType: 'assistant_report_job',
      resourceId: job.publicId,
      metadata: { reportId, jobId: job.publicId, executionId: out.executionId },
    });
  });

  it('keeps 7 days synchronous, and every window when jobs are disabled', async () => {
    const t = setup();
    const week = await t.generate({ range: '7d' });
    expect(week).toMatchObject({ status: 'succeeded', httpStatus: 201 });
    expect(t.store.jobs).toHaveLength(0);
    const off = setup({ env: { ASSISTANT_REPORT_JOBS_ENABLED: 'false' } });
    expect(await off.generate({ range: '30d' })).toMatchObject({ httpStatus: 201 });
    expect(off.store.jobs).toHaveLength(0);
  });
});

describe('ReportJobProcessor (step AI-6 D5 consumer steps 1-5)', () => {
  it('composes with a GET-only job token of the session and makes the report available once', async () => {
    const t = setup();
    const { job, reportId } = await queued(t);
    expect(await t.processor.handle(t.event(job, reportId))).toBe('handled');
    expect(job).toMatchObject({ status: 'succeeded', attempts: 1 });
    const report = t.rw.reports.find((r) => r.publicId === reportId)!;
    expect(report.status).toBe('available');
    expect(report.objectKey).toMatch(/^org\/7001\/assistant\/report\//);
    expect(t.rw.objects.get(report.objectKey!)!.toString('utf8')).toContain('<!doctype html>');
    // The loopback reads: the job token (ajb = job id, ≤ 300 s), no client IP, the job's
    // correlation `<job correlation>.<n>` and the original execution id.
    const calls = t.h.loopback.toolCalls;
    expect(calls.length).toBeGreaterThan(0);
    const token = calls[0]!.authorization.replace(/^Bearer /, '');
    const claims = await t.tokens.verify(token, NOW);
    expect(claims).toMatchObject({
      ajb: job.publicId,
      sid: t.principal.sessionId,
      amr: ['pwd', 'otp'],
    });
    expect(claims!.exp - claims!.iat).toBe(300);
    for (const call of calls) {
      expect(call).toMatchObject({ method: 'GET', clientIp: null });
      expect(call.correlationId).toMatch(/^it-corr-0001\.1\.\d+$/);
      expect(call.executionId).toBe('0193d000-0000-7000-8000-0000000e0001');
    }
    const generated = t.h.audit.entries.at(-1)!;
    expect(generated).toMatchObject({
      action: 'assistant.report_generated',
      resourceId: reportId,
      metadata: { async: true, jobId: job.publicId },
    });
    // The token never reaches a log or an audit row.
    expect(
      JSON.stringify(t.h.audit.entries, (_k, v: unknown) => (typeof v === 'bigint' ? `${v}` : v)),
    ).not.toContain(token);
    // A redelivery is a duplicate (terminal job).
    expect(await t.processor.handle(t.event(job, reportId))).toBe('duplicate');
  });

  it('acks a missing job, another report and a terminal job; waits (transient) for a live lease', async () => {
    const t = setup();
    const { job, reportId } = await queued(t);
    expect(
      await t.processor.handle(
        t.event({ publicId: '0193d000-0000-7000-8000-00000000dead' }, reportId),
      ),
    ).toBe('duplicate');
    expect(await t.processor.handle(t.event(job, '0193d000-0000-7000-8000-00000000beef'))).toBe(
      'duplicate',
    );
    Object.assign(job, { status: 'running', leaseUntil: new Date(NOW.getTime() + 60_000) });
    // Another consumer's live lease: a transient retry (never an ack that would lose the job).
    const busy = t.processor.handle(t.event(job, reportId));
    await expect(busy).rejects.toThrow(ReportJobBusyError);
    expect(classifyReportJobFailure(new ReportJobBusyError())).toBe('transient');
    expect(classifyReportJobFailure(new Error('boom'))).toBe('retryable');
    expect(job.attempts).toBe(0);
    // An expired lease is taken over.
    Object.assign(job, { leaseUntil: new Date(NOW.getTime() - 1) });
    expect(await t.processor.handle(t.event(job, reportId))).toBe('handled');
    expect(job.status).toBe('succeeded');
  });

  it('fails an expired job and its report (assistant_report_job_expired)', async () => {
    const t = setup();
    const { job, reportId } = await queued(t);
    job.expiresAt = new Date(NOW.getTime() - 1);
    expect(await t.processor.handle(t.event(job, reportId))).toBe('handled');
    expect(job).toMatchObject({ status: 'failed', errorCode: 'assistant_report_job_expired' });
    expect(t.rw.reports.find((r) => r.publicId === reportId)).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_report_job_expired',
    });
    expect(t.h.loopback.toolCalls).toHaveLength(0);
  });

  it('ends with the session (revoked or expired) and refuses a lost permission or a disabled assistant', async () => {
    const ended = setup();
    const a = await queued(ended);
    ended.setResolved(null);
    await ended.processor.handle(ended.event(a.job, a.reportId));
    expect(a.job).toMatchObject({ status: 'failed', errorCode: 'assistant_report_session_ended' });

    const lost = setup();
    const b = await queued(lost);
    lost.setResolved(testUser({ permissions: new Set(['assistant:use']) }));
    await lost.processor.handle(lost.event(b.job, b.reportId));
    expect(b.job).toMatchObject({ status: 'failed', errorCode: 'assistant_report_not_allowed' });

    const off = setup();
    const c = await queued(off);
    off.h.world.enable(ORG, { enabled: false });
    await off.processor.handle(off.event(c.job, c.reportId));
    expect(c.job).toMatchObject({ status: 'failed', errorCode: 'assistant_report_not_allowed' });
    for (const t of [ended, lost, off]) expect(t.h.loopback.toolCalls).toHaveLength(0);
  });

  it('retries "no data" while attempts remain, then fails with the code', async () => {
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const t = setup();
    const { job, reportId } = await queued(t);
    for (const key of Object.keys(REPORT_SOURCE_DEFS) as ReportSourceKey[]) {
      t.h.loopback.on(`GET ${pathOf(key)}`, () => ({
        kind: 'response',
        status: 503,
        body: { code: 'service_unavailable' },
      }));
    }
    await expect(t.processor.handle(t.event(job, reportId))).rejects.toThrow(ReportJobRetryError);
    expect(job).toMatchObject({ status: 'queued', attempts: 1 });
    job.attempts = 4;
    expect(await t.processor.handle(t.event(job, reportId))).toBe('handled');
    expect(job).toMatchObject({
      status: 'failed',
      attempts: 5,
      errorCode: 'assistant_report_sources_unavailable',
    });
    expect(t.rw.reports.find((r) => r.publicId === reportId)!.status).toBe('failed');
  });
});

describe('ReportJobProcessor claim release and lease (step AI-6 D5, review fix)', () => {
  const quiet = () => {
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  };

  it('releases the claim on an unexpected error so the retry hop runs the job', async () => {
    quiet();
    const t = setup();
    const { job, reportId } = await queued(t);
    const resolve = t.resolver.resolve as unknown as ReturnType<typeof vi.fn>;
    const real = resolve.getMockImplementation()!;
    resolve.mockImplementationOnce(() => Promise.reject(new Error('resolver exploded')));
    // First delivery: the error is rethrown (a retry hop), the job is claimable again.
    await expect(t.processor.handle(t.event(job, reportId))).rejects.toThrow('resolver exploded');
    expect(job).toMatchObject({
      status: 'queued',
      attempts: 1,
      leaseUntil: null,
      errorCode: 'assistant_report_job_failed',
    });
    // The retry hop arrives within the old lease window and still runs the job.
    resolve.mockImplementation(real);
    expect(await t.processor.handle(t.event(job, reportId))).toBe('handled');
    expect(job).toMatchObject({ status: 'succeeded', attempts: 2 });
    expect(t.rw.reports.find((r) => r.publicId === reportId)!.status).toBe('available');
  });

  it('a finalize failure releases the claim and deletes the orphaned object', async () => {
    quiet();
    const t = setup();
    const { job, reportId } = await queued(t);
    const reports = (t.processor as unknown as { reports: ReportsRepository }).reports;
    const mark = reports.markJobReportAvailable;
    reports.markJobReportAvailable = () => Promise.reject(new Error('deadlock'));
    await expect(t.processor.handle(t.event(job, reportId))).rejects.toThrow('deadlock');
    expect(job).toMatchObject({ status: 'queued', attempts: 1 });
    expect(t.rw.objects.size).toBe(0);
    expect(t.rw.log.filter((l) => l.startsWith('delete:'))).toHaveLength(1);
    reports.markJobReportAvailable = mark;
    // The transaction rolled back its ledger row (the in-memory runner does not roll back).
    t.store.ledger.clear();
    expect(await t.processor.handle(t.event(job, reportId))).toBe('handled');
    expect(job.status).toBe('succeeded');
  });

  it('fails the job (assistant_report_job_failed) on an unexpected error at the last attempt', async () => {
    quiet();
    const t = setup();
    const { job, reportId } = await queued(t);
    job.attempts = 4;
    const resolve = t.resolver.resolve as unknown as ReturnType<typeof vi.fn>;
    resolve.mockImplementationOnce(() => Promise.reject(new Error('resolver exploded')));
    expect(await t.processor.handle(t.event(job, reportId))).toBe('handled');
    expect(job).toMatchObject({
      status: 'failed',
      attempts: 5,
      errorCode: 'assistant_report_job_failed',
    });
    expect(t.rw.reports.find((r) => r.publicId === reportId)).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_report_job_failed',
    });
  });

  it('a crash loop (claim past the attempt limit) fails the job instead of running again', async () => {
    quiet();
    const t = setup();
    const { job, reportId } = await queued(t);
    // The fifth attempt's pod died: running, its lease lapsed.
    Object.assign(job, {
      status: 'running',
      attempts: 5,
      leaseUntil: new Date(NOW.getTime() - 1),
    });
    expect(await t.processor.handle(t.event(job, reportId))).toBe('handled');
    expect(job).toMatchObject({ status: 'failed', errorCode: 'assistant_report_job_failed' });
    expect(t.h.loopback.toolCalls).toHaveLength(0);
  });

  it('renews the lease while composing; a lease taken over aborts the attempt without changes', async () => {
    quiet();
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    try {
      const renewed = setup();
      const a = await queued(renewed);
      const path = pathOf(Object.keys(REPORT_SOURCE_DEFS)[0] as ReportSourceKey);
      const handler = renewed.h.loopback.handlers.get(`GET ${path}`)!;
      renewed.h.loopback.on(`GET ${path}`, async (call) => {
        await vi.advanceTimersByTimeAsync(20_000);
        return handler(call);
      });
      expect(await renewed.processor.handle(renewed.event(a.job, a.reportId))).toBe('handled');
      expect(renewed.store.renewals).toBe(1);
      expect(a.job.status).toBe('succeeded');

      const taken = setup();
      const b = await queued(taken);
      const handlerB = taken.h.loopback.handlers.get(`GET ${path}`)!;
      const takeover = new Date(NOW.getTime() + 61_000);
      taken.h.loopback.on(`GET ${path}`, async (call) => {
        // Another consumer took the job over (its own claim time), then the renewal ticks.
        Object.assign(b.job, {
          startedAt: takeover,
          leaseUntil: new Date(takeover.getTime() + 60_000),
        });
        await vi.advanceTimersByTimeAsync(20_000);
        return handlerB(call);
      });
      expect(await taken.processor.handle(taken.event(b.job, b.reportId))).toBe('duplicate');
      // The new holder's claim is untouched; nothing was finalized or kept in the bucket.
      expect(b.job).toMatchObject({ status: 'running', startedAt: takeover });
      expect(taken.rw.reports.find((r) => r.publicId === b.reportId)!.status).toBe('queued');
      expect(taken.rw.objects.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

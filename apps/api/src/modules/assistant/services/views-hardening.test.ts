import { describe, expect, it, vi } from 'vitest';
import { testUser } from '../../../../test/support/assistant-fixtures';
import { createAssistantHarness } from '../../../../test/support/assistant-harness';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import type { AssistantConfig } from '../assistant.constants';
import type { MessageFeedbackRepository } from '../repositories/message-feedback.repository';
import type { ReportJobRow, ReportJobsRepository } from '../repositories/report-jobs.repository';
import type { ReportWithRefs } from '../repositories/reports.repository';
import { AssistantRetentionService } from './assistant-retention.service';
import { ConfirmationViewsService } from './confirmation-views.service';
import { ConversationService, ownerOf } from './conversation.service';
import { reportView } from './reports/reports.service';
import { immediateAssistantRunner } from '../../../../test/support/assistant-fixtures';

/**
 * Step AI-6 view and sweep additions: the status view (D6), the report view's job (D5), the
 * messages view's feedback (D2) and the report job expiry sweep (D5).
 */

const ORG = 7001n;
const NOW = new Date('2026-11-26T10:00:00.000Z');

describe('status view (step AI-6 D6)', () => {
  it('names the key source, whether the secondary is in use and the data-sharing level', async () => {
    const h = createAssistantHarness({
      ASSISTANT_FALLBACK_PROVIDER: 'fake',
      ASSISTANT_FALLBACK_MODEL: 'fake-secondary',
    });
    h.world.features.set(ORG, true);
    h.world.enable(ORG, { dataSharing: 'pseudonymized' });
    await expect(h.availability.status(h.scope, NOW, h.user)).resolves.toMatchObject({
      available: true,
      keySource: 'platform',
      fallbackActive: false,
      dataSharing: 'pseudonymized',
    });
    await h.kv.set('as:brk:fake', '5', 60);
    await expect(h.availability.status(h.scope, NOW, h.user)).resolves.toMatchObject({
      available: true,
      fallbackActive: true,
    });
    await h.kv.set('as:brk:fake:fb', '5', 60);
    await expect(h.availability.status(h.scope, NOW, h.user)).resolves.toMatchObject({
      available: false,
      reason: 'provider_unavailable',
      keySource: 'platform',
      fallbackActive: false,
    });
  });
});

describe('report view job (step AI-6 D5)', () => {
  it('adds the job of an asynchronous report and null otherwise', () => {
    const row = {
      publicId: '0193d000-0000-7000-8000-000000000001',
      conversationPublicId: '0193d000-0000-7000-8000-000000000002',
      executionPublicId: null,
      status: 'queued',
      title: 'Security report: Last 30 days',
      periodFrom: new Date('2026-10-27T10:00:00.000Z'),
      periodTo: NOW,
      granularity: 'day',
      sections: { included: ['summary'], omitted: [], atoRange: '30d' },
      figures: [],
      sizeBytes: null,
      sha256: null,
      templateVersion: 'assistant-report/1',
      createdAt: NOW,
    } as unknown as ReportWithRefs;
    expect(reportView(row, []).job).toBeNull();
    const job = {
      status: 'running',
      attempts: 2,
      errorCode: 'assistant_report_sources_unavailable',
      expiresAt: new Date(NOW.getTime() + 1_800_000),
    } as Pick<ReportJobRow, 'status' | 'attempts' | 'errorCode' | 'expiresAt'>;
    expect(reportView(row, [], job)).toMatchObject({
      status: 'queued',
      job: {
        status: 'running',
        attempts: 2,
        errorCode: 'assistant_report_sources_unavailable',
        expiresAt: '2026-11-26T10:30:00.000Z',
      },
    });
  });
});

describe('report job expiry sweep (step AI-6 D5)', () => {
  it('fails unfinished jobs past expires_at with their reports, counted once', async () => {
    const h = createAssistantHarness();
    const failed: Array<[bigint, string]> = [];
    const jobs = {
      dueToExpire: vi.fn(() =>
        Promise.resolve([
          { id: 1n, publicId: 'j-1', organizationId: ORG, reportId: 11n, createdAt: NOW },
          { id: 2n, publicId: 'j-2', organizationId: ORG, reportId: 12n, createdAt: NOW },
        ]),
      ),
      fail: vi.fn((_o: bigint, job: { id: bigint }, code: string) => {
        failed.push([job.id, code]);
        // The second moved meanwhile (finished): not counted.
        return Promise.resolve(job.id === 1n);
      }),
    } as unknown as ReportJobsRepository;
    const c = h.config as AssistantConfig;
    const retention = new AssistantRetentionService(
      c,
      h.kv,
      h.conversationsRepo,
      h.world.executionsDouble(),
      h.world.usageDouble(),
      immediateAssistantRunner,
      h.metrics,
      h.world.confirmationsDouble(),
      h.audit,
      h.world.reportWorld.reportsDouble(),
      h.world.reportWorld.deliveriesDouble(),
      h.world.reportWorld.storeDouble(),
      h.reports,
      jobs,
    );
    expect(await retention.expireReportJobs(NOW)).toBe(1);
    expect(failed).toEqual([
      [1n, 'assistant_report_job_expired'],
      [2n, 'assistant_report_job_expired'],
    ]);
    const result = await retention.runOnce(NOW);
    expect(result).toMatchObject({ reportJobsExpired: 1 });
    // The harness (no job store) skips the sweep.
    expect(await h.retention.expireReportJobs(NOW)).toBe(0);
  });
});

describe('messages view feedback (step AI-6 D2)', () => {
  it('shows the owner’s rating on assistant messages only', async () => {
    const h = createAssistantHarness();
    h.world.features.set(ORG, true);
    h.world.enable(ORG);
    const conversation = h.world.addConversation(ownerOf(h.user, h.scope));
    await h.ask(conversation.publicId, '/text hello');
    const answer = h.world.messages.find((m) => m.role === 'assistant')!;
    const forMessages = vi.fn(() =>
      Promise.resolve(
        new Map([[answer.id, { rating: 'down', reason: 'incorrect', comment: null }]]),
      ),
    );
    const c = h.config as AssistantConfig;
    const confirmations = h.world.confirmationsDouble();
    const service = new ConversationService(
      c,
      h.conversationsRepo,
      h.world.executionsDouble(),
      h.world.settingsDouble(),
      h.availability,
      new CursorCodec(h.config),
      immediateAssistantRunner,
      h.audit,
      confirmations,
      new ConfirmationViewsService(confirmations, h.limits),
      h.metrics,
      h.reports,
      { forMessages } as unknown as MessageFeedbackRepository,
    );
    const page = await service.messages(h.user, h.scope, conversation.publicId, {
      sort: 'seq',
      limit: 25,
    } as never);
    expect(page.data.map((m) => [m.role, m.feedback])).toEqual([
      ['user', null],
      ['assistant', { rating: 'down', reason: 'incorrect', comment: null }],
    ]);
    expect(forMessages).toHaveBeenCalledWith(expect.anything(), conversation.id, [answer.id]);
    // Without the feedback store (the harness) every item carries null.
    const plain = await h.conversations.messages(h.user, h.scope, conversation.publicId, {
      sort: 'seq',
      limit: 25,
    } as never);
    expect(plain.data.every((m) => m.feedback === null)).toBe(true);
    expect(testUser().userId).toBe(h.user.userId);
  });
});

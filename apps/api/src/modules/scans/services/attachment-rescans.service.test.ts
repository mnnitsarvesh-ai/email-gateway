import { BadRequestException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TransactionRunner } from '../../../database/transaction-runner';
import type { CodedHttpException } from '../../../http/coded-exception';
import type {
  AttachmentRescansRepository,
  RescanJobRow,
} from '../repositories/attachment-rescans.repository';
import { AttachmentRescansService, RESCAN_AUDIT } from './attachment-rescans.service';

const NOW = new Date('2026-11-05T12:00:00.000Z');
const ORG_PUBLIC = '0190f0f0-0000-7000-8000-000000000009';
const JOB_PUBLIC = '0190f0f0-0000-7000-8000-0000000000aa';

const platformUser: UserPrincipal = {
  kind: 'user',
  userId: 3n,
  userPublicId: '0190f0f0-0000-7000-8000-000000000003',
  organizationId: 1n,
  organizationPublicId: '0190f0f0-0000-7000-8000-000000000001',
  organizationKind: 'platform',
  sessionId: 's',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['platform:scan_rescan']),
};
const client = { ip: '198.51.100.7', userAgent: null } as never;

const job = (overrides: Partial<RescanJobRow> = {}): RescanJobRow => ({
  id: 5n,
  publicId: JOB_PUBLIC,
  trigger: 'admin',
  status: 'pending',
  organizationId: 9n,
  windowStart: new Date(NOW.getTime() - 24 * 3_600_000),
  windowEnd: NOW,
  states: ['scanned', 'scan_failed', 'quarantined', 'held_for_review'],
  component: null,
  fromVersion: null,
  toVersion: null,
  maxMessages: 5000,
  selectedCount: 0,
  requestedCount: 0,
  skippedCount: 0,
  reason: 'new signatures',
  lastError: null,
  startedAt: null,
  completedAt: null,
  createdAt: NOW,
  updatedAt: NOW,
  organization: { publicId: ORG_PUBLIC },
  requestedBy: { publicId: platformUser.userPublicId },
  ...overrides,
});

function setup(options: { organization?: boolean; candidates?: number; cancel?: boolean } = {}) {
  const tx = { marker: 'tx' };
  const repository = {
    findOrganization: vi.fn(() =>
      Promise.resolve(options.organization === false ? null : { id: 9n, publicId: ORG_PUBLIC }),
    ),
    countCandidates: vi.fn(() => Promise.resolve(options.candidates ?? 12)),
    create: vi.fn(() => Promise.resolve(job())),
    list: vi.fn(() => Promise.resolve([job()])),
    find: vi.fn(() => Promise.resolve(job())),
    findOnWriter: vi.fn(() => Promise.resolve(job())),
    cancel: vi.fn(() => Promise.resolve(options.cancel ?? true)),
  };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'user', id: platformUser.userPublicId })),
  };
  const transactions = { run: vi.fn((fn: (t: unknown) => Promise<unknown>) => fn(tx)) };
  const service = new AttachmentRescansService(
    { ATTACHMENT_RESCAN_MAX_MESSAGES: 5000 },
    repository as unknown as AttachmentRescansRepository,
    transactions as unknown as TransactionRunner,
    audit as unknown as AuditService,
  );
  return { service, repository, audit, tx };
}

const failure = (promise: Promise<unknown>) =>
  promise.then(
    () => null,
    (error: unknown) => error,
  );

describe('AttachmentRescansService (step 4.2 A13)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  it('a dry run counts the candidates with the job filter and writes nothing', async () => {
    const { service, repository, audit } = setup({ candidates: 12 });
    const result = await service.request(
      platformUser,
      { windowHours: 24, reason: 'check', dryRun: true, organizationId: ORG_PUBLIC },
      client,
    );
    expect(result).toEqual({
      kind: 'estimate',
      body: {
        dryRun: true,
        estimatedMessages: 12,
        windowStart: new Date(NOW.getTime() - 24 * 3_600_000).toISOString(),
        windowEnd: NOW.toISOString(),
        states: ['scanned', 'scan_failed', 'quarantined', 'held_for_review'],
        maxMessages: 5000,
      },
    });
    expect(repository.countCandidates).toHaveBeenCalledWith({
      windowStart: new Date(NOW.getTime() - 24 * 3_600_000),
      windowEnd: NOW,
      states: ['scanned', 'scan_failed', 'quarantined', 'held_for_review'],
      organizationId: 9n,
    });
    expect(repository.create).not.toHaveBeenCalled();
    expect(audit.record).not.toHaveBeenCalled();
  });

  it('creates a pending admin job and its audit row in one transaction; estimate capped', async () => {
    const { service, repository, audit, tx } = setup({ candidates: 900 });
    const result = await service.request(
      platformUser,
      {
        windowHours: 2,
        states: ['scan_failed'],
        maxMessages: 100,
        reason: 'clamd db',
        dryRun: false,
      },
      client,
    );
    expect(result).toEqual({
      kind: 'created',
      body: { jobId: JOB_PUBLIC, status: 'pending', estimatedMessages: 100 },
    });
    expect(repository.create).toHaveBeenCalledWith(tx, {
      windowStart: new Date(NOW.getTime() - 2 * 3_600_000),
      windowEnd: NOW,
      states: ['scan_failed'],
      organizationId: null,
      maxMessages: 100,
      reason: 'clamd db',
      requestedByUserId: 3n,
    });
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: null,
        action: RESCAN_AUDIT.requested,
        resourceType: 'attachment_rescan_job',
        resourceId: JOB_PUBLIC,
        metadata: expect.objectContaining({
          windowHours: 2,
          states: ['scan_failed'],
          maxMessages: 100,
          estimatedMessages: 100,
          reason: 'clamd db',
        }),
      }),
      tx,
    );
  });

  it('refuses an unknown organization (404) and maxMessages above the configured cap (400)', async () => {
    const unknown = setup({ organization: false });
    const notFound = await failure(
      unknown.service.request(
        platformUser,
        { windowHours: 1, reason: 'x', organizationId: ORG_PUBLIC, dryRun: false },
        client,
      ),
    );
    expect((notFound as CodedHttpException).getResponse()).toMatchObject({
      code: 'organization_not_found',
    });
    expect(unknown.repository.create).not.toHaveBeenCalled();
    const capped = setup();
    expect(
      await failure(
        capped.service.request(
          platformUser,
          { windowHours: 1, reason: 'x', maxMessages: 5001, dryRun: false },
          client,
        ),
      ),
    ).toBeInstanceOf(BadRequestException);
  });

  it('cancels a pending job with its audit row', async () => {
    const { service, repository, audit, tx } = setup();
    repository.findOnWriter
      .mockResolvedValueOnce(job())
      .mockResolvedValueOnce(job({ status: 'cancelled', completedAt: NOW }));
    const view = await service.cancel(platformUser, JOB_PUBLIC, { reason: 'too broad' }, client);
    expect(view).toMatchObject({ jobId: JOB_PUBLIC, status: 'cancelled' });
    expect(repository.cancel).toHaveBeenCalledWith(tx, 5n, NOW);
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: 9n,
        action: RESCAN_AUDIT.cancelled,
        resourceId: JOB_PUBLIC,
        metadata: expect.objectContaining({ fromStatus: 'pending', reason: 'too broad' }),
      }),
      tx,
    );
  });

  it('refuses to cancel a finished job (409) or an unknown one (404)', async () => {
    const finished = setup({ cancel: false });
    finished.repository.findOnWriter.mockResolvedValue(job({ status: 'completed' }));
    const conflict = await failure(finished.service.cancel(platformUser, JOB_PUBLIC, {}, client));
    expect((conflict as CodedHttpException).getStatus()).toBe(409);
    expect(conflict).toMatchObject({
      code: 'rescan_job_not_cancellable',
      details: { status: 'completed' },
    });
    expect(finished.audit.record).not.toHaveBeenCalled();
    const missing = setup();
    missing.repository.findOnWriter.mockResolvedValue(null as never);
    const notFound = await failure(missing.service.cancel(platformUser, JOB_PUBLIC, {}, client));
    expect((notFound as CodedHttpException).getResponse()).toMatchObject({
      code: 'rescan_job_not_found',
    });
  });

  it('lists newest first and reads one job', async () => {
    const { service, repository } = setup();
    const page = await service.list(platformUser, { limit: 10, status: 'pending' });
    expect(repository.list).toHaveBeenCalledWith({ take: 11, status: 'pending' });
    expect(page.data[0]).toMatchObject({
      jobId: JOB_PUBLIC,
      organizationId: ORG_PUBLIC,
      requestedByUserId: platformUser.userPublicId,
    });
    expect(await service.get(platformUser, JOB_PUBLIC)).toMatchObject({ jobId: JOB_PUBLIC });
    repository.find.mockResolvedValueOnce(null as never);
    expect(
      ((await failure(service.get(platformUser, JOB_PUBLIC))) as CodedHttpException).getStatus(),
    ).toBe(404);
  });
});

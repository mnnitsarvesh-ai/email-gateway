import { BadRequestException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedHttpException } from '../../../http/coded-exception';
import { ARCHIVE_EXAMPLES, CaptureIssueSchema } from '../dto/archive.schemas';
import type {
  ArchiveRecordsRepository,
  CaptureIssueRow,
} from '../repositories/archive-records.repository';
import { ArchiveOperationsService } from './archive-operations.service';

const SCOPE = { organizationId: 9001n } as TenantScope;
const MESSAGE = '3f0c1a52-7c1e-4d55-9a0e-1b2c3d4e5f60';

const row = (overrides: Partial<CaptureIssueRow> = {}): CaptureIssueRow => ({
  id: 11n,
  receivedAt: new Date('2026-11-16T10:15:00.000Z'),
  messageId: 42n,
  messagePublicId: MESSAGE,
  status: 'failed',
  skipReason: null,
  lastErrorCode: 'storage_error',
  attempts: 3,
  sourceJournal: true,
  sourcePolicy: false,
  nextCheckAt: new Date('2026-11-16T11:00:00.000Z'),
  createdAt: new Date('2026-11-16T10:15:02.000Z'),
  ...overrides,
});

function service(found: CaptureIssueRow | null) {
  const captureIssue = vi.fn(() => Promise.resolve(found));
  const records = { captureIssue } as unknown as ArchiveRecordsRepository;
  const svc = new ArchiveOperationsService(
    records,
    undefined as never,
    undefined as never,
    undefined as never,
    undefined as never,
  );
  return { svc, captureIssue };
}

async function codeOf(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
  } catch (e) {
    if (e instanceof CodedHttpException) return e.code;
    throw e;
  }
  return undefined;
}

describe('ArchiveOperationsService.captureIssue (step AI-5 D8)', () => {
  it('returns the list item view of a failed intent, scoped by the caller and the lower-cased id', async () => {
    const { svc, captureIssue } = service(row());
    const view = await svc.captureIssue(SCOPE, MESSAGE.toUpperCase());
    expect(captureIssue).toHaveBeenCalledWith(SCOPE, MESSAGE);
    expect(view).toEqual({
      messageId: MESSAGE,
      receivedAt: '2026-11-16T10:15:00.000Z',
      status: 'failed',
      code: 'storage_error',
      attempts: 3,
      sources: { journal: true, policy: false },
      nextCheckAt: '2026-11-16T11:00:00.000Z',
      createdAt: '2026-11-16T10:15:02.000Z',
    });
    expect(CaptureIssueSchema.parse(view)).toEqual(view);
  });

  it.each(['pending', 'captured_open', 'closed', 'lost'] as const)(
    'answers an intent in status %s too',
    async (status) => {
      const { svc } = service(row({ status, lastErrorCode: null }));
      const view = await svc.captureIssue(SCOPE, MESSAGE);
      expect(view).toMatchObject({ status, code: null });
    },
  );

  it('uses the skip reason as the code of a skipped intent', async () => {
    const { svc } = service(row({ status: 'skipped', lastErrorCode: null, skipReason: 'max_age' }));
    expect(await svc.captureIssue(SCOPE, MESSAGE)).toMatchObject({
      status: 'skipped',
      code: 'max_age',
    });
  });

  it('answers 404 archive_capture_issue_not_found when nothing is found', async () => {
    const { svc } = service(null);
    expect(await codeOf(svc.captureIssue(SCOPE, MESSAGE))).toBe('archive_capture_issue_not_found');
  });

  it('refuses a non-uuid id with 400 before reading', async () => {
    const { svc, captureIssue } = service(row());
    await expect(svc.captureIssue(SCOPE, 'nope')).rejects.toBeInstanceOf(BadRequestException);
    expect(captureIssue).not.toHaveBeenCalled();
  });

  it('the OpenAPI example is a valid view', () => {
    expect(CaptureIssueSchema.parse(ARCHIVE_EXAMPLES.captureIssue)).toEqual(
      ARCHIVE_EXAMPLES.captureIssue,
    );
  });
});

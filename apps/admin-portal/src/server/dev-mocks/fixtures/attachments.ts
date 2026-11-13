import 'server-only';
import { createHash } from 'node:crypto';
import type { ListItem } from '@/lib/api/types';
import { SeededRandom, fixtureAnchor, paginate, stableUuid } from '../generator';
import { apiError, ok, type FixtureHandlers } from '../types';
import { bodyOf, withPrincipal, str } from './reports';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Attachment hash search and platform rescans (WP3). Searchable synthetic hashes (any range
 * covering the last 7 days): SHA-256 of `synthetic-sample-0` (malicious, 30 messages: two
 * pages) and of `synthetic-invoice` (clean, 3 messages). Any other hash finds nothing.
 */

type Attachment = ListItem<'AttachmentsController_search_v1'>;
type Job = ListItem<'AttachmentRescansController_list_v1'>;

const sha = (value: string) => createHash('sha256').update(value).digest('hex');
export const SEARCHABLE: Record<
  string,
  { count: number; filename: string; type: string; verdict: Attachment['verdict'] }
> = {
  [sha('synthetic-sample-0')]: {
    count: 30,
    filename: 'Invoice_2026-11.pdf.exe',
    type: 'application/x-dosexec',
    verdict: 'malicious',
  },
  [sha('synthetic-invoice')]: {
    count: 3,
    filename: 'invoice-1042.pdf',
    type: 'application/pdf',
    verdict: 'clean',
  },
};

const store = globalThis as typeof globalThis & { __egDevFixtureRescans?: Map<string, Job> };
function jobs(): Map<string, Job> {
  if (store.__egDevFixtureRescans) return store.__egDevFixtureRescans;
  const anchor = fixtureAnchor();
  const at = (h: number) => new Date(anchor - h * 3_600_000).toISOString();
  const base = (i: number, status: Job['status'], trigger: Job['trigger']): Job => ({
    jobId: stableUuid(`rescan:${i}`),
    trigger,
    status,
    organizationId: null,
    windowStart: at(48 + i * 24),
    windowEnd: at(i * 24),
    states: ['scanned', 'quarantined'],
    component: trigger === 'signature_update' ? 'clamav' : null,
    fromVersion: trigger === 'signature_update' ? `2702${i}` : null,
    toVersion: trigger === 'signature_update' ? `2702${i + 1}` : null,
    maxMessages: 50_000,
    selectedCount: status === 'pending' ? 0 : 1_200 + i * 37,
    requestedCount: status === 'completed' ? 1_200 + i * 37 : status === 'running' ? 600 : 0,
    skippedCount: status === 'skipped' ? 1 : 0,
    requestedByUserId: trigger === 'admin' ? stableUuid('user:platform_admin@example.com') : null,
    reason: trigger === 'admin' ? 'Synthetic: rescan after a campaign report' : null,
    lastError: status === 'failed' ? 'scan queue unavailable (synthetic)' : null,
    startedAt: status === 'pending' ? null : at(i * 24),
    completedAt: ['completed', 'failed', 'cancelled', 'skipped'].includes(status)
      ? at(i * 24 - 1)
      : null,
    createdAt: at(i * 24 + 1),
    updatedAt: at(i * 24),
  });
  const statuses: Job['status'][] = [
    'running',
    'pending',
    'completed',
    'completed',
    'failed',
    'cancelled',
    'skipped',
  ];
  store.__egDevFixtureRescans = new Map(
    statuses.map((s, i) => {
      const job = base(i, s, i % 2 ? 'admin' : 'signature_update');
      return [job.jobId, job];
    }),
  );
  return store.__egDevFixtureRescans;
}

export const fixtures: FixtureHandlers = {
  AttachmentsController_search_v1: (request) =>
    withPrincipal(request, (p) => {
      const q = request.query;
      const hash = q.get('sha256') ?? '';
      if (!/^[0-9a-f]{64}$/.test(hash))
        return apiError(400, 'validation_failed', ['sha256: 64 lower-case hexadecimal characters']);
      const to = q.get('to') ? Date.parse(q.get('to') ?? '') : Date.now();
      const from = q.get('from') ? Date.parse(q.get('from') ?? '') : to - 86_400_000;
      if (to - from > 31 * 86_400_000 + 3_600_000)
        return apiError(400, 'validation_failed', ['from: the range is longer than 31 days']);
      const known = SEARCHABLE[hash];
      const r = new SeededRandom(`attachments:${p.organizationId}:${hash}`);
      const anchor = fixtureAnchor();
      const rows: Attachment[] = known
        ? Array.from({ length: known.count }, (_, i) => ({
            messageId: stableUuid(`message:${p.organizationId}:${hash}:${i}`),
            receivedAt: new Date(anchor - i * 5 * 3_600_000 - r.int(0, 3_000_000)).toISOString(),
            partIndex: r.int(1, 3),
            filename: known.filename,
            sizeBytes: r.int(20_000, 400_000),
            detectedContentType: known.type,
            verdict: known.verdict,
          })).filter((a) => {
            const t = Date.parse(a.receivedAt);
            return t >= from && t < to;
          })
        : [];
      return { status: 200, body: paginate(rows, q) };
    }),

  AttachmentRescansController_list_v1: (request) =>
    withPrincipal(request, () => {
      const status = request.query.get('status');
      return {
        status: 200,
        body: paginate(
          [...jobs().values()].filter((j) => !status || j.status === status),
          request.query,
        ),
      };
    }),

  AttachmentRescansController_get_v1: (request) =>
    withPrincipal(request, () => {
      const job = jobs().get(request.params.jobId ?? '');
      return job
        ? ok('AttachmentRescansController_get_v1', job)
        : apiError(404, 'rescan_job_not_found', 'Rescan job not found');
    }),

  AttachmentRescansController_request_v1: (request) =>
    withPrincipal(request, () => {
      const b = bodyOf(request);
      const hours = Number(b.windowHours);
      if (!Number.isInteger(hours) || hours < 1 || hours > 168)
        return apiError(400, 'validation_failed', ['windowHours: 1 to 168']);
      const states = (Array.isArray(b.states) ? b.states : ['scanned']) as Job['states'];
      const maxMessages = typeof b.maxMessages === 'number' ? b.maxMessages : 50_000;
      const estimate = Math.min(maxMessages, hours * 42);
      const windowEnd = new Date().toISOString();
      const windowStart = new Date(Date.now() - hours * 3_600_000).toISOString();
      if (b.dryRun === true) {
        return ok('AttachmentRescansController_request_v1', {
          dryRun: true,
          estimatedMessages: estimate,
          windowStart,
          windowEnd,
          states: states as ('scanned' | 'scan_failed' | 'quarantined' | 'held_for_review')[],
          maxMessages,
        });
      }
      const jobId = crypto.randomUUID();
      const now = new Date().toISOString();
      jobs().set(jobId, {
        jobId,
        trigger: 'admin',
        status: 'pending',
        organizationId: typeof b.organizationId === 'string' ? b.organizationId : null,
        windowStart,
        windowEnd,
        states,
        component: null,
        fromVersion: null,
        toVersion: null,
        maxMessages,
        selectedCount: 0,
        requestedCount: 0,
        skippedCount: 0,
        requestedByUserId: null,
        reason: str(b, 'reason', ''),
        lastError: null,
        startedAt: null,
        completedAt: null,
        createdAt: now,
        updatedAt: now,
      });
      return ok(
        'AttachmentRescansController_request_v1',
        { jobId, status: 'pending', estimatedMessages: estimate },
        202,
      );
    }),

  AttachmentRescansController_cancel_v1: (request) =>
    withPrincipal(request, () => {
      const job = jobs().get(request.params.jobId ?? '');
      if (!job) return apiError(404, 'rescan_job_not_found', 'Rescan job not found');
      if (job.status !== 'pending' && job.status !== 'running')
        return apiError(409, 'rescan_job_not_cancellable', 'The job cannot be cancelled', {
          status: job.status,
        });
      Object.assign(job, {
        status: 'cancelled',
        completedAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
      return ok('AttachmentRescansController_cancel_v1', job);
    }),
};

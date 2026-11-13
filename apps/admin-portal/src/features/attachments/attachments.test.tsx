import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { ListItem } from '@/lib/api/types';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { SCAN_SETTINGS } from '@/features/settings/test-data';
import { AttachmentsPage } from './attachments-page';
import { rescanBody, rescanSchema } from './schemas';

const SHA = 'b'.repeat(64);
const MESSAGE = '01930000-0000-7000-8000-0000000e0002';
const JOB = '01930000-0000-7000-8000-0000000f0001';
const job = (
  over: Partial<ListItem<'AttachmentRescansController_list_v1'>> = {},
): ListItem<'AttachmentRescansController_list_v1'> => ({
  jobId: JOB,
  trigger: 'admin',
  status: 'running',
  organizationId: null,
  windowStart: '2026-11-12T00:00:00.000Z',
  windowEnd: '2026-11-13T00:00:00.000Z',
  states: ['scanned'],
  component: null,
  fromVersion: null,
  toVersion: null,
  maxMessages: 5000,
  selectedCount: 120,
  requestedCount: 80,
  skippedCount: 0,
  requestedByUserId: null,
  reason: 'New signatures',
  lastError: null,
  startedAt: '2026-11-13T09:00:00.000Z',
  completedAt: null,
  createdAt: '2026-11-13T09:00:00.000Z',
  updatedAt: '2026-11-13T09:05:00.000Z',
  ...over,
});

describe('Attachment analysis: hash search', () => {
  it('validates the hash, searches, shows filenames as text and links to the scan details', async () => {
    let params: URLSearchParams | null = null;
    mockApi({
      AttachmentsController_search_v1: ({ url }) => (
        (params = url.searchParams),
        okJson({
          data: [
            {
              messageId: MESSAGE,
              receivedAt: '2026-11-12T08:00:00.000Z',
              partIndex: 2,
              filename: 'invoice<img src=x>.pdf.exe',
              sizeBytes: 20480,
              detectedContentType: 'application/x-dosexec',
              verdict: 'malicious',
            },
          ],
          nextCursor: null,
        })
      ),
    });
    const { container, user } = renderWithProviders(<AttachmentsPage />, { route: '/attachments' });
    expect(screen.getByText('Search by SHA-256')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'malware messages with attachments' })).toHaveAttribute(
      'href',
      '/messages?verdict=malware&hasAttachments=true',
    );
    await user.type(screen.getByLabelText(/^SHA-256/), 'abc');
    await user.click(screen.getByRole('button', { name: 'Search' }));
    expect(screen.getByText(/Enter the 64 hexadecimal characters/)).toBeInTheDocument();
    await user.clear(screen.getByLabelText(/^SHA-256/));
    await user.type(screen.getByLabelText(/^SHA-256/), SHA.toUpperCase());
    await user.click(screen.getByRole('button', { name: 'Search' }));
    await waitFor(() => expect(currentTestUrl()).toBe(`/attachments?sha256=${SHA}`));
    expect(await screen.findByText('invoice<img src=x>.pdf.exe')).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
    expect(params!.get('sha256')).toBe(SHA);
    expect(params!.get('sort')).toBe('-receivedAt');
    expect(screen.getByText('Malicious')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Scan details of the message/ })).toHaveAttribute(
      'href',
      `/messages/${MESSAGE}/scans`,
    );
    await expectNoAxeViolations(container);
  });

  it('empty result and error with code and request id', async () => {
    mockApi({ AttachmentsController_search_v1: () => okJson({ data: [], nextCursor: null }) });
    const { unmount } = renderWithProviders(<AttachmentsPage />, {
      route: `/attachments?sha256=${SHA}`,
    });
    expect(
      await screen.findByText('No attachment with this hash in the range'),
    ).toBeInTheDocument();
    unmount();
    mockApi({
      AttachmentsController_search_v1: () =>
        apiErrorJson(400, 'validation_failed', ['to: range exceeds 31 days'], {
          requestId: 'req-att-1',
        }),
    });
    renderWithProviders(<AttachmentsPage />, { route: `/attachments?sha256=${SHA}` });
    expect(await screen.findByText('req-att-1')).toBeInTheDocument();
  });

  it('read-only attachment engine settings', async () => {
    mockApi({ ScanSettingsController_list_v1: () => okJson(SCAN_SETTINGS) });
    renderWithProviders(<AttachmentsPage />, {
      route: '/attachments?tab=settings',
      role: 'read_only_user',
    });
    expect(await screen.findByText('Largest attachment scanned (bytes)')).toBeInTheDocument();
    expect(screen.getByText('25.0 MB')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'View all scan settings' })).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Platform rescans' })).not.toBeInTheDocument();
  });
});

describe('Attachment analysis: platform rescans', () => {
  it('lists jobs, shows a detail sheet and cancels with confirmation', async () => {
    let cancelBody: unknown = 'none';
    mockApi({
      AttachmentRescansController_list_v1: () => okJson({ data: [job()], nextCursor: null }),
      AttachmentRescansController_get_v1: () => okJson(job()),
      AttachmentRescansController_cancel_v1: ({ body }) => (
        (cancelBody = body),
        okJson(job({ status: 'cancelled' }))
      ),
    });
    const { container, user } = renderWithProviders(<AttachmentsPage />, {
      route: '/attachments?tab=rescans',
      role: 'platform_admin',
    });
    expect(await screen.findByText('Running')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: /Details of rescan job/ }));
    expect(
      await within(await screen.findByRole('dialog')).findByText('New signatures'),
    ).toBeInTheDocument();
    await user.keyboard('{Escape}');
    await user.click(screen.getByRole('button', { name: /Actions for rescan job/ }));
    await user.click(await screen.findByRole('menuitem', { name: 'Cancel job' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Cancel job' }),
    );
    await waitFor(() => expect(cancelBody).toEqual({}));
    expectRequestMatchesContract('AttachmentRescansController_cancel_v1', cancelBody);
  });

  it('requests a rescan: estimate (dry run) first, then the job', async () => {
    const bodies: unknown[] = [];
    mockApi({
      AttachmentRescansController_list_v1: () => okJson({ data: [], nextCursor: null }),
      AttachmentRescansController_request_v1: ({ body }) => {
        bodies.push(body);
        return (body as { dryRun?: boolean }).dryRun
          ? okJson({
              dryRun: true,
              estimatedMessages: 340,
              windowStart: '2026-11-12T10:00:00.000Z',
              windowEnd: '2026-11-13T10:00:00.000Z',
              states: ['scanned'],
              maxMessages: 5000,
            })
          : okJson({ jobId: JOB, status: 'pending', estimatedMessages: 340 }, 202);
      },
    });
    const { user } = renderWithProviders(<AttachmentsPage />, {
      route: '/attachments?tab=rescans',
      role: 'platform_admin',
    });
    await user.click(await screen.findByRole('button', { name: 'Request rescan' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText(/^Reason/), 'Signature update 2026-11-13');
    await user.click(within(dialog).getByRole('button', { name: 'Estimate' }));
    expect(await within(dialog).findByText(/about 340 messages/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Start rescan' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[0]).toEqual({
      windowHours: 24,
      states: ['scanned'],
      reason: 'Signature update 2026-11-13',
      dryRun: true,
    });
    expect(bodies[1]).toEqual({
      windowHours: 24,
      states: ['scanned'],
      reason: 'Signature update 2026-11-13',
    });
    for (const body of bodies)
      expectRequestMatchesContract('AttachmentRescansController_request_v1', body);
    expect(await screen.findByText(/Rescan job queued/)).toBeInTheDocument();
  });

  it('rescan schema bounds', () => {
    expect(
      rescanSchema.safeParse({
        windowHours: 200,
        states: ['scanned'],
        organizationId: '',
        maxMessages: '',
        reason: 'x',
      }).success,
    ).toBe(false);
    expectRequestMatchesContract(
      'AttachmentRescansController_request_v1',
      rescanBody(
        rescanSchema.parse({
          windowHours: '6',
          states: ['quarantined'],
          organizationId: MESSAGE,
          maxMessages: '100',
          reason: 'x',
        }),
        false,
      ),
    );
  });
});

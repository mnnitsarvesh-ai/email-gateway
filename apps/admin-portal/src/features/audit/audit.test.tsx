import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { ListItem } from '@/lib/api/types';
import {
  TEST_ORG,
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { AuditLogsPage, normalizePrefix } from './audit-logs-page';

type AuditRow = ListItem<'AuditLogsController_search_v1'>;

const row = (i: number, over: Partial<AuditRow> = {}): AuditRow => ({
  id: `90${String(i).padStart(4, '0')}`,
  createdAt: new Date(Date.UTC(2026, 10, 12, 10, i)).toISOString(),
  actor: { type: 'user', id: '01930000-0000-7000-8000-000000000101' },
  action: i % 2 ? 'domain.created' : 'quarantine.released',
  resourceType: i % 2 ? 'domain' : 'quarantine_entry',
  resourceId: `01930000-0000-7000-8000-0000000d${String(i).padStart(4, '0')}`,
  correlationId: 'corr-1',
  sourceIp: '198.51.100.7',
  metadata: { reason: 'ticket 42', html: '<b>not bold</b>' },
  ...over,
});

describe('Audit logs: activity', () => {
  it('lists entries (loading → rows), opens a detail drawer that shows metadata as text', async () => {
    let params: URLSearchParams | null = null;
    mockApi({
      AuditLogsController_search_v1: ({ url }) => (
        (params = url.searchParams),
        okJson({ data: [row(1), row(2)], nextCursor: null })
      ),
    });
    const { container, user } = renderWithProviders(<AuditLogsPage />, { route: '/audit-logs' });
    expect(await screen.findByText('domain.created')).toBeInTheDocument();
    expect(params!.get('from')).toBeTruthy();
    expect(params!.get('limit')).toBe('25');
    await expectNoAxeViolations(container);
    await user.click(screen.getAllByRole('button', { name: /^Details of domain.created/ })[0]!);
    const metadata = await screen.findByTestId('audit-metadata');
    expect(metadata.textContent).toContain('"html": "<b>not bold</b>"');
    expect(metadata.querySelector('b')).toBeNull();
    expect(within(screen.getByRole('dialog')).getByText('198.51.100.7')).toBeInTheDocument();
  });

  it('filters write the URL and the request; prefixes are normalized and validated', async () => {
    const seen: URLSearchParams[] = [];
    mockApi({
      AuditLogsController_search_v1: ({ url }) => (
        seen.push(url.searchParams),
        okJson({ data: [row(1)], nextCursor: null })
      ),
    });
    const { user } = renderWithProviders(<AuditLogsPage />, { route: '/audit-logs' });
    await screen.findByText('domain.created');
    await user.type(screen.getByLabelText('Action prefix'), 'quarantine');
    await waitFor(() => expect(currentTestUrl()).toContain('actionPrefix=quarantine.'));
    await waitFor(() => expect(seen.at(-1)?.get('actionPrefix')).toBe('quarantine.'));
    await user.clear(screen.getByLabelText('Action prefix'));
    await user.type(screen.getByLabelText('Action prefix'), 'Bad-Prefix');
    expect(await screen.findByText(/Use lower-case letters and underscores/)).toBeInTheDocument();
    expect(normalizePrefix('domain')).toBe('domain.');
    await user.click(screen.getByRole('combobox', { name: 'Actor type' }));
    await user.click(await screen.findByRole('option', { name: 'API key' }));
    await waitFor(() => expect(seen.at(-1)?.get('actorType')).toBe('api_key'));
  });

  it('sorts by time through the allowed values only', async () => {
    const seen: URLSearchParams[] = [];
    mockApi({
      AuditLogsController_search_v1: ({ url }) => (
        seen.push(url.searchParams),
        okJson({ data: [row(1)], nextCursor: null })
      ),
    });
    const { user } = renderWithProviders(<AuditLogsPage />, { route: '/audit-logs' });
    await screen.findByText('domain.created');
    await user.click(screen.getByRole('button', { name: /Time.*change sort order/ }));
    await waitFor(() => expect(currentTestUrl()).toContain('sort=createdAt'));
    await waitFor(() => expect(seen.at(-1)?.get('sort')).toBe('createdAt'));
  });

  it('pages forward and back with cursors', async () => {
    const cursors: (string | null)[] = [];
    mockApi({
      AuditLogsController_search_v1: ({ url }) => {
        const cursor = url.searchParams.get('cursor');
        cursors.push(cursor);
        return cursor === 'c2'
          ? okJson({ data: [row(30, { action: 'user.invited' })], nextCursor: null })
          : okJson({ data: Array.from({ length: 25 }, (_, i) => row(i + 1)), nextCursor: 'c2' });
      },
    });
    const { user } = renderWithProviders(<AuditLogsPage />, { route: '/audit-logs' });
    await screen.findAllByText('domain.created');
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('user.invited')).toBeInTheDocument();
    expect(screen.getByText(/Page 2/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Previous' }));
    await waitFor(() => expect(screen.queryByText('user.invited')).not.toBeInTheDocument());
    expect(cursors).toEqual([null, 'c2']);
  });

  it('empty and error states', async () => {
    mockApi({ AuditLogsController_search_v1: () => okJson({ data: [], nextCursor: null }) });
    const { unmount } = renderWithProviders(<AuditLogsPage />, { route: '/audit-logs' });
    expect(await screen.findByText('No audit entries in this range')).toBeInTheDocument();
    unmount();
    mockApi({
      AuditLogsController_search_v1: () =>
        apiErrorJson(400, 'validation_failed', ['from: range exceeds 90 days'], {
          requestId: 'req-aud-4',
        }),
    });
    renderWithProviders(<AuditLogsPage />, { route: '/audit-logs' });
    expect(await screen.findByText('validation_failed')).toBeInTheDocument();
    expect(screen.getByText('req-aud-4')).toBeInTheDocument();
  });
});

describe('Audit logs: sign-in events and platform trail', () => {
  it('sign-in events filter by outcome and validate the user id', async () => {
    const seen: URLSearchParams[] = [];
    mockApi({
      LoginEventsController_list_v1: ({ url }) => (
        seen.push(url.searchParams),
        okJson({
          data: [
            {
              id: '77',
              occurredAt: '2026-11-12T09:00:00.000Z',
              email: 'priya.patel7@example.com',
              outcome: 'failure',
              failureReason: 'invalid_credentials',
              ipAddress: '203.0.113.9',
              userAgent: 'Mozilla/5.0 (test)',
              userId: null,
            },
          ],
          nextCursor: null,
        })
      ),
    });
    const { container, user } = renderWithProviders(<AuditLogsPage />, {
      route: '/audit-logs?tab=sign-in',
    });
    expect(await screen.findByText('priya.patel7@example.com')).toBeInTheDocument();
    expect(screen.getByText('invalid_credentials')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('combobox', { name: 'Outcome' }));
    await user.click(await screen.findByRole('option', { name: 'Rate limited' }));
    await waitFor(() => expect(seen.at(-1)?.get('outcome')).toBe('rate_limited'));
    await user.type(screen.getByLabelText('User ID'), 'not-a-uuid');
    expect(await screen.findByText('Enter a UUID.')).toBeInTheDocument();
    expect(seen.at(-1)?.has('userId')).toBe(false);
  });

  it('organization users have no platform tab', async () => {
    mockApi({ AuditLogsController_search_v1: () => okJson({ data: [], nextCursor: null }) });
    renderWithProviders(<AuditLogsPage />, { route: '/audit-logs', role: 'security_analyst' });
    await screen.findByText('No audit entries in this range');
    expect(screen.queryByRole('tab', { name: 'Platform' })).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Sign-in events' })).toBeInTheDocument();
  });

  it('platform trail needs a target and explains mfa_required', async () => {
    const seen: URLSearchParams[] = [];
    mockApi({
      OrganizationsController_list_v1: () =>
        okJson({
          data: [
            {
              id: TEST_ORG.id,
              slug: 'alpha',
              name: 'Alpha Industries (example)',
              kind: 'customer',
              status: 'active',
              statusReason: null,
              statusChangedAt: null,
              plan: { code: 'business', name: 'Business' },
              deploymentMode: 'saas',
              dataRegion: 'eu-west-1',
              deployments: [],
              deletion: null,
              createdAt: '2026-07-01T00:00:00.000Z',
              updatedAt: '2026-07-01T00:00:00.000Z',
            },
          ],
          nextCursor: null,
        }),
      PlatformAuditLogsController_search_v1: ({ url }) => (
        seen.push(url.searchParams),
        apiErrorJson(403, 'mfa_required', 'This operation requires an MFA session')
      ),
    });
    const { user, container } = renderWithProviders(<AuditLogsPage />, {
      route: '/audit-logs?tab=platform',
      role: 'platform_admin',
    });
    expect(await screen.findByText('Choose what to search')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('switch'));
    await waitFor(() => expect(seen.at(-1)?.get('scope')).toBe('platform'));
    expect(await screen.findByText(/needs a session signed in with MFA/)).toBeInTheDocument();
    expect(screen.getByText('mfa_required')).toBeInTheDocument();
    await user.click(screen.getByRole('switch'));
    await user.click(screen.getByRole('combobox', { name: 'Organization to search' }));
    await user.click(await screen.findByRole('option', { name: /Alpha Industries/ }));
    await waitFor(() => expect(seen.at(-1)?.get('organizationId')).toBe(TEST_ORG.id));
  });

  it('users without audit:read get the 403 page', () => {
    renderWithProviders(<AuditLogsPage />, { route: '/audit-logs', role: 'read_only_user' });
    expect(
      screen.getByRole('heading', { name: 'You do not have access to this page' }),
    ).toBeInTheDocument();
  });
});

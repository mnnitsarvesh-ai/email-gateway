import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoInjectedMarkup } from '@/features/messages/test-data';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { preferencesBody, settingsBody, settingsFormDefaults } from './forms';
import { QuarantinePage } from './quarantine-page';
import { SelfEntryDetail } from './self-service';
import {
  CATALOG,
  ENTRY_ID,
  HOSTILE,
  entryDetail,
  entrySummary,
  preview,
  settings,
} from './test-data';

describe('My quarantine (/quarantine/me)', () => {
  it('lists own entries with filters in the URL and saves the digest preference', async () => {
    const searches: URLSearchParams[] = [];
    let prefBody: unknown = null;
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineSelfController_search_v1: ({ url }) => {
        searches.push(url.searchParams);
        return okJson({
          items: [entrySummary({ subject: HOSTILE, reason: 'spam' })],
          nextCursor: null,
        });
      },
      QuarantineSelfController_preferences_v1: () =>
        okJson({ digestOptOut: false, allowOptOut: true }),
      QuarantineSelfController_putPreferences_v1: ({ body }) => {
        prefBody = body;
        return okJson({ digestOptOut: true, allowOptOut: true });
      },
    });
    const { user, container } = renderWithProviders(<QuarantinePage routeTab="me" />, {
      role: 'mailbox_user',
      route: '/quarantine/me',
    });
    expect(await screen.findByText(/window.__pwned/)).toBeInTheDocument();
    expectNoInjectedMarkup(container);
    expect(screen.getByRole('link', { name: /open message/ })).toHaveAttribute(
      'href',
      `/quarantine/me/${ENTRY_ID}`,
    );
    const window = searches[0];
    expect(Date.parse(window?.get('to') ?? '') - Date.parse(window?.get('from') ?? '')).toBe(
      30 * 86_400_000,
    );
    await user.click(screen.getByLabelText('Reason'));
    await user.click(await screen.findByRole('option', { name: 'Spam' }));
    await waitFor(() => expect(currentTestUrl()).toContain('reason=spam'));
    await waitFor(() => expect(searches[searches.length - 1]?.get('reason')).toBe('spam'));
    await user.click(
      await screen.findByRole('switch', { name: 'Do not send me the quarantine digest' }),
    );
    await user.click(screen.getByRole('button', { name: 'Save preference' }));
    await waitFor(() => expect(prefBody).toEqual({ digestOptOut: true }));
    expectRequestMatchesContract('QuarantineSelfController_putPreferences_v1', prefBody);
    await expectNoAxeViolations(container);
  });

  it('disables opting out when the organization does not allow it; shows the empty state', async () => {
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineSelfController_search_v1: () => okJson({ items: [], nextCursor: null }),
      QuarantineSelfController_preferences_v1: () =>
        okJson({ digestOptOut: false, allowOptOut: false }),
    });
    renderWithProviders(<QuarantinePage routeTab="me" />, {
      role: 'mailbox_user',
      route: '/quarantine/me',
    });
    expect(await screen.findByText('No quarantined messages for you')).toBeInTheDocument();
    expect(await screen.findByRole('switch')).toBeDisabled();
    expect(screen.getByText(/does not allow opting out/)).toBeInTheDocument();
  });
});

describe('My quarantined message (/quarantine/me/[entryId])', () => {
  it('shows the entry, the preview on demand and self-releases with a key', async () => {
    let body: unknown = null;
    let key: string | null = null;
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineSelfController_detail_v1: () =>
        okJson(
          entryDetail({
            reason: 'spam',
            allowedActions: ['preview', 'release', 'request_release'],
          }),
        ),
      QuarantineSelfController_preview_v1: () => okJson(preview()),
      QuarantineSelfController_release_v1: ({ body: b, request }) => {
        body = b;
        key = request.headers.get('idempotency-key');
        return okJson(
          {
            outcome: 'queued',
            entryId: ENTRY_ID,
            state: 'releasing',
            releaseId: '01933c3a-1b2c-7d4e-8f00-0000000b0001',
            rowVersion: 3,
          },
          202,
        );
      },
    });
    const { user, container } = renderWithProviders(<SelfEntryDetail entryId={ENTRY_ID} />, {
      role: 'mailbox_user',
    });
    await user.click(await screen.findByRole('button', { name: 'Show sanitized preview' }));
    expect((await screen.findByTestId('preview-text')).textContent).toContain('<script>');
    expectNoInjectedMarkup(container);
    expect(screen.queryByRole('link', { name: 'Open message details' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Release to my inbox' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(
      within(dialog).getByLabelText(/Why do you trust this message/),
      'Expected newsletter',
    );
    await user.click(within(dialog).getByRole('button', { name: 'Release' }));
    await waitFor(() =>
      expect(body).toEqual({ reason: 'Expected newsletter', expectedRowVersion: 2 }),
    );
    expectRequestMatchesContract('QuarantineSelfController_release_v1', body);
    expect(key).toBeTruthy();
    expect(await screen.findByText(/Release queued/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('offers only a release request when self-release is not allowed, and explains refusals', async () => {
    let body: unknown = null;
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineSelfController_detail_v1: () =>
        okJson(entryDetail({ allowedActions: ['request_release'] })),
      QuarantineSelfController_requestRelease_v1: ({ body: b }) => {
        body = b;
        return apiErrorJson(403, 'quarantine_self_release_not_allowed', 'No', {
          extra: { cause: 'hard_block' },
        });
      },
    });
    const { user } = renderWithProviders(<SelfEntryDetail entryId={ENTRY_ID} />, {
      role: 'mailbox_user',
    });
    await screen.findByRole('button', { name: 'Request release' });
    expect(screen.queryByRole('button', { name: 'Release to my inbox' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Show sanitized preview' }),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Request release' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(
      within(dialog).getByLabelText(/Why do you need this message/),
      'Invoice from a supplier',
    );
    await user.click(within(dialog).getByRole('button', { name: 'Request release' }));
    expect(
      await within(dialog).findByText(/cannot release this message yourself \(Hard block\)/),
    ).toBeInTheDocument();
    expectRequestMatchesContract('QuarantineSelfController_requestRelease_v1', body);
  });

  it('is not found for another address and forbidden without quarantine:self', async () => {
    mockApi({
      QuarantineSelfController_detail_v1: () =>
        apiErrorJson(404, 'quarantine_entry_not_found', 'Not found', { requestId: 'req-self' }),
    });
    const { unmount } = renderWithProviders(<SelfEntryDetail entryId={ENTRY_ID} />, {
      role: 'mailbox_user',
    });
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('req-self')).toBeInTheDocument();
    unmount();
    renderWithProviders(<SelfEntryDetail entryId={ENTRY_ID} />, { role: 'read_only_user' });
    expect(await screen.findByText(/quarantine:self/)).toBeInTheDocument();
  });
});

describe('Quarantine settings (/quarantine/settings)', () => {
  it('saves changed keys plus stored keys with the row version (contract); passes axe', async () => {
    let body: unknown = null;
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineToolsController_getSettings_v1: () => okJson(settings()),
      QuarantineToolsController_putSettings_v1: ({ body: b, request }) => {
        body = b;
        expect(request.headers.get('idempotency-key')).toBeNull();
        return okJson(settings({ rowVersion: 5 }));
      },
    });
    const { user, container } = renderWithProviders(<QuarantinePage routeTab="settings" />, {
      role: 'organization_admin',
      route: '/quarantine/settings',
    });
    const days = await screen.findByLabelText('Review hold (days)');
    await expectNoAxeViolations(container);
    await user.clear(days);
    await user.type(days, '5');
    await user.click(
      screen.getByRole('switch', { name: 'Allow downloads of clean quarantined content' }),
    );
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      settings: {
        review: { days: 5 },
        alerts: { minIntervalMinutes: 60 },
        download: { enabled: true },
      },
      expectedRowVersion: 4,
    });
    expectRequestMatchesContract('QuarantineToolsController_putSettings_v1', body);
  });

  it('validates bounds locally and maps api violations to fields', async () => {
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineToolsController_getSettings_v1: () => okJson(settings()),
      QuarantineToolsController_putSettings_v1: () =>
        apiErrorJson(400, 'quarantine_settings_invalid', 'Invalid', {
          extra: {
            violations: [
              {
                path: 'digest.maxEntries',
                code: 'out_of_bounds',
                message: 'too many for this plan',
              },
            ],
          },
        }),
    });
    const { user } = renderWithProviders(<QuarantinePage routeTab="settings" />, {
      role: 'organization_admin',
      route: '/quarantine/settings',
    });
    const days = await screen.findByLabelText('Review hold (days)');
    await user.clear(days);
    await user.type(days, '40');
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText('Review days: at most 13')).toBeInTheDocument();
    await user.clear(days);
    await user.type(days, '6');
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText('too many for this plan')).toBeInTheDocument();
  });

  it('is read-only without settings:manage', async () => {
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineToolsController_getSettings_v1: () => okJson(settings()),
    });
    renderWithProviders(<QuarantinePage routeTab="settings" />, {
      role: 'security_analyst',
      route: '/quarantine/settings',
    });
    expect(await screen.findByLabelText('Review hold (days)')).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Save settings' })).not.toBeInTheDocument();
    expect(screen.getByText(/needs the settings:manage permission/)).toBeInTheDocument();
  });

  it('shows the error state with code and request id', async () => {
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineToolsController_getSettings_v1: () =>
        apiErrorJson(500, 'internal_error', 'Boom', { requestId: 'req-set' }),
    });
    renderWithProviders(<QuarantinePage routeTab="settings" />, {
      role: 'organization_admin',
      route: '/quarantine/settings',
    });
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('req-set')).toBeInTheDocument();
  });

  it('builds bodies that match the contracts', () => {
    const current = settings();
    expectRequestMatchesContract(
      'QuarantineToolsController_putSettings_v1',
      settingsBody(settingsFormDefaults(current.effective), current),
    );
    expect(settingsBody(settingsFormDefaults(current.effective), current).settings).toEqual({
      alerts: { minIntervalMinutes: 60 },
    });
    expectRequestMatchesContract(
      'QuarantineSelfController_putPreferences_v1',
      preferencesBody(false),
    );
  });
});

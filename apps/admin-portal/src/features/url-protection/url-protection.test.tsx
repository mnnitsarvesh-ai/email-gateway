import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { ListItem } from '@/lib/api/types';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { urlClicksReport } from '@/features/reports/test-data';
import { SCAN_SETTINGS } from '@/features/settings/test-data';
import { UrlProtectionPage } from './url-protection-page';

const MESSAGE = '01930000-0000-7000-8000-0000000e0001';
const click = (
  i: number,
  over: Partial<ListItem<'UrlProtectionController_clicks_v1'>> = {},
): ListItem<'UrlProtectionController_clicks_v1'> => ({
  id: `01930000-0000-7000-8000-0000000c${String(i).padStart(4, '0')}`,
  clickedAt: '2026-11-12T10:00:00.000Z',
  decision: 'blocked',
  verdict: 'malicious',
  reasonCodes: ['U_FEED_MATCH'],
  messageId: MESSAGE,
  urlSeq: i,
  host: `login${i}.evil-example.test`,
  registrableDomain: 'evil-example.test',
  clientNetwork: '203.0.113.0/24',
  ...over,
});

describe('URL protection', () => {
  it('lists clicks with hosts as text and links to the scan details', async () => {
    let params: URLSearchParams | null = null;
    mockApi({
      UrlProtectionController_clicks_v1: ({ url }) => (
        (params = url.searchParams),
        okJson({ data: [click(1)], nextCursor: null })
      ),
    });
    const { container } = renderWithProviders(<UrlProtectionPage />, { route: '/url-protection' });
    const host = await screen.findByText('login1.evil-example.test');
    expect(host.closest('a')).toBeNull();
    expect(screen.getByRole('link', { name: /Scan details of the message/ })).toHaveAttribute(
      'href',
      `/messages/${MESSAGE}/scans`,
    );
    expect(params!.get('sort')).toBe('-clickedAt');
    expect(params!.get('from')).toBeTruthy();
    await expectNoAxeViolations(container);
  });

  it('filters write the URL and the request; pagination with cursors', async () => {
    const seen: URLSearchParams[] = [];
    mockApi({
      UrlProtectionController_clicks_v1: ({ url }) => {
        seen.push(url.searchParams);
        return url.searchParams.get('cursor') === 'k2'
          ? okJson({ data: [click(2, { host: 'second.example.test' })], nextCursor: null })
          : okJson({ data: [click(1)], nextCursor: 'k2' });
      },
    });
    const { user } = renderWithProviders(<UrlProtectionPage />, {
      route: '/url-protection?range=24h',
    });
    await screen.findByText('login1.evil-example.test');
    await user.click(screen.getByRole('button', { name: 'Load next page' }));
    expect(await screen.findByText('second.example.test')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Previous' }));
    await screen.findByText('login1.evil-example.test');
    await user.click(screen.getByRole('combobox', { name: 'Decision' }));
    await user.click(await screen.findByRole('option', { name: 'Warned' }));
    await waitFor(() => expect(currentTestUrl()).toContain('decision=warned'));
    await waitFor(() => expect(seen.at(-1)?.get('decision')).toBe('warned'));
    await user.type(screen.getByLabelText('Message ID'), MESSAGE);
    await waitFor(() => expect(seen.at(-1)?.get('messageId')).toBe(MESSAGE));
  });

  it('empty and error states', async () => {
    mockApi({ UrlProtectionController_clicks_v1: () => okJson({ data: [], nextCursor: null }) });
    const { unmount } = renderWithProviders(<UrlProtectionPage />, { route: '/url-protection' });
    expect(await screen.findByText('No clicks in this range')).toBeInTheDocument();
    unmount();
    mockApi({
      UrlProtectionController_clicks_v1: () =>
        apiErrorJson(404, 'message_not_found', 'Message not found', { requestId: 'req-url-3' }),
    });
    renderWithProviders(<UrlProtectionPage />, { route: `/url-protection?messageId=${MESSAGE}` });
    expect(await screen.findByText('message_not_found')).toBeInTheDocument();
    expect(screen.getByText('req-url-3')).toBeInTheDocument();
  });

  it('click report and read-only engine settings with a link to the editor', async () => {
    mockApi({
      ReportsController_urlClicks_v1: () => okJson(urlClicksReport()),
      ScanSettingsController_list_v1: () => okJson(SCAN_SETTINGS),
    });
    const { user, container } = renderWithProviders(<UrlProtectionPage />, {
      route: '/url-protection?tab=report',
    });
    expect(
      await screen.findByRole('img', { name: /Clicks by decision\. Total 42/ }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'URL engine settings' }));
    expect(await screen.findByText('bad.example.test')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Change in Settings' })).toHaveAttribute(
      'href',
      '/settings?tab=scanning',
    );
    await expectNoAxeViolations(container);
  });

  it('report-only users see just the click report; mailbox users get 403', () => {
    mockApi({ ReportsController_urlClicks_v1: () => okJson(urlClicksReport()) });
    const { unmount } = renderWithProviders(<UrlProtectionPage />, {
      route: '/url-protection',
      permissions: ['report:read'],
    });
    expect(screen.queryByRole('tab', { name: 'Clicks' })).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Click report' })).toBeInTheDocument();
    unmount();
    renderWithProviders(<UrlProtectionPage />, { route: '/url-protection', role: 'mailbox_user' });
    expect(
      screen.getByRole('heading', { name: 'You do not have access to this page' }),
    ).toBeInTheDocument();
  });
});

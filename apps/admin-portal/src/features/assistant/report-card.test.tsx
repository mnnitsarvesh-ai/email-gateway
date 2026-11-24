import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiErrorJson, expectNoAxeViolations, mockApi, okJson, renderWithProviders } from '@/test';
import { gateForPath } from '@/lib/navigation';
import { safePortalHref } from './portal-routes';
import { REPORT_FRAME_TITLE, reportFileName } from './report-card';
import { ReportPage } from './report-page';
import { ResultCard } from './result-card';
import { cardSchema, parseStreamEvent } from './stream';
import {
  CONVERSATION_ID,
  DELIVERY_ID,
  REPORT_CARD,
  REPORT_EXECUTION_ID,
  REPORT_HTML,
  REPORT_ID,
  reportDocument,
} from './test-data';

/** jsdom cannot run axe inside frames; the frame's own content is checked by Playwright. */
const NO_FRAMES = { iframes: false } as const;

function frame(): HTMLIFrameElement {
  return screen.getByTitle<HTMLIFrameElement>(REPORT_FRAME_TITLE);
}

/** The I16 frame contract: every sandbox restriction on, the HTML only as `srcdoc`. */
function expectInertFrame(iframe: HTMLIFrameElement, html: string) {
  expect(iframe.tagName).toBe('IFRAME');
  expect(iframe.getAttribute('sandbox')).toBe('');
  expect(iframe.getAttribute('sandbox')).not.toMatch(/allow-/);
  expect(iframe.getAttribute('srcdoc')).toBe(html);
  expect(iframe.hasAttribute('src')).toBe(false);
  expect(iframe.getAttribute('referrerpolicy')).toBe('no-referrer');
  expect(iframe.getAttribute('loading')).toBe('lazy');
  expect(iframe).toHaveAccessibleName(REPORT_FRAME_TITLE);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('report card contract (step AI-R D9)', () => {
  it('accepts a card of kind report and keeps its report object', () => {
    const parsed = cardSchema.safeParse(REPORT_CARD);
    expect(parsed.success).toBe(true);
    expect(parsed.data?.report?.reportId).toBe(REPORT_ID);
    const event = parseStreamEvent({
      event: 'tool.completed',
      data: JSON.stringify({
        executionId: REPORT_EXECUTION_ID,
        status: 'succeeded',
        decision: 'allowed',
        card: REPORT_CARD,
      }),
    });
    expect(event).toMatchObject({ type: 'tool.completed', card: { kind: 'report' } });
  });

  it('refuses a report card without its report, a non-UUID id, and unknown kinds', () => {
    const { report: _report, ...bare } = REPORT_CARD;
    expect(cardSchema.safeParse(bare).success).toBe(false);
    expect(
      cardSchema.safeParse({ ...REPORT_CARD, report: { ...REPORT_CARD.report, reportId: '../x' } })
        .success,
    ).toBe(false);
    expect(cardSchema.safeParse({ ...REPORT_CARD, kind: 'html' }).success).toBe(false);
    expect(
      parseStreamEvent({
        event: 'tool.completed',
        data: JSON.stringify({
          executionId: REPORT_EXECUTION_ID,
          status: 'succeeded',
          decision: 'allowed',
          card: { ...REPORT_CARD, kind: 'dashboard' },
        }),
      }),
    ).toBeNull();
  });

  it('links /assistant/reports/<uuid> only', () => {
    expect(safePortalHref(`/assistant/reports/${REPORT_ID}`)).toBe(
      `/assistant/reports/${REPORT_ID}`,
    );
    for (const href of [
      '/assistant/reports',
      '/assistant/reports/latest',
      '/assistant/reports/1234',
      `/assistant/reports/${REPORT_ID}/html`,
      `/assistant/reports/${REPORT_ID}x`,
      `/bff/api/v1/assistant/reports/${REPORT_ID}`,
    ])
      expect(safePortalHref(href), href).toBeNull();
    expect(gateForPath(`/assistant/reports/${REPORT_ID}`)).toEqual([
      'AssistantReportsController_get_v1',
    ]);
    expect(gateForPath('/assistant')).toEqual(['AssistantConversationsController_list_v1']);
  });

  it('never uses dangerouslySetInnerHTML in the report files', () => {
    for (const file of ['report-card.tsx', 'report-page.tsx', 'result-card.tsx']) {
      const source = readFileSync(join(__dirname, file), 'utf8');
      expect(source, file).not.toMatch(/dangerouslySetInnerHTML|innerHTML|allow-scripts/);
    }
    const route = readFileSync(
      join(__dirname, '../../app/(console)/assistant/reports/[reportId]/page.tsx'),
      'utf8',
    );
    expect(route).toContain('ReportPage');
  });

  it('names the download security-report-<UTC date>.html', () => {
    expect(reportFileName('2026-11-23T23:59:00.000Z')).toBe('security-report-2026-11-23.html');
    expect(reportFileName('not a date')).toBe('security-report-download.html');
  });
});

describe('ReportCard', () => {
  it('renders the summary, then the sandboxed frame with the fetched HTML', async () => {
    const calls: string[] = [];
    mockApi({
      AssistantReportsController_get_v1: ({ params }) => {
        calls.push(params.reportId ?? '');
        return okJson(reportDocument());
      },
    });
    const navigate = vi.fn();
    const { container } = renderWithProviders(
      <ResultCard card={REPORT_CARD} onNavigate={navigate} />,
    );
    const card = screen.getByRole('region', { name: 'Result: Security report: Last 7 days' });
    expect(
      within(card).getByRole('heading', { name: 'Security report: Last 7 days' }),
    ).toBeVisible();
    expect(card).toHaveTextContent('Last 7 days, UTC');
    expect(card).toHaveTextContent('Generated');
    const figures = within(card).getByRole('list', { name: 'Key figures' });
    expect(
      within(figures)
        .getAllByRole('listitem')
        .map((li) => li.textContent),
    ).toEqual(['Messages12,480', 'Threats312']);
    expect(card).toHaveTextContent(
      'Not included: Quarantine (needs the permission quarantine:read); Account takeover (not enabled for your organization).',
    );

    await waitFor(() => expect(frame()).toBeInTheDocument());
    expectInertFrame(frame(), REPORT_HTML);
    expect(calls).toEqual([REPORT_ID]);
    // The report's markup is never part of the portal's document.
    expect(container.querySelector('svg[aria-label="Traffic"]')).toBeNull();
    expect(screen.queryByText(/E2E <script> organization/)).toBeNull();

    const open = within(card).getByRole('link', { name: 'Open full size' });
    expect(open).toHaveAttribute('href', `/assistant/reports/${REPORT_ID}`);
    // The card's generic portal link is not repeated as "Open Open full size in the portal".
    expect(within(card).queryByText(/in the portal/)).toBeNull();
    expect(within(card).getByRole('button', { name: 'Download HTML' })).toBeEnabled();
    expect(within(card).getByText(/Not emailed yet/)).toBeInTheDocument();
    await expectNoAxeViolations(container, NO_FRAMES);
  });

  it('fetches the report only once the card becomes visible', async () => {
    let observerCallback: IntersectionObserverCallback | null = null;
    const observe = vi.fn();
    vi.stubGlobal(
      'IntersectionObserver',
      class {
        constructor(callback: IntersectionObserverCallback) {
          observerCallback = callback;
        }
        observe = observe;
        disconnect = vi.fn();
        unobserve = vi.fn();
        takeRecords = () => [];
      },
    );
    let calls = 0;
    mockApi({
      AssistantReportsController_get_v1: () => {
        calls += 1;
        return okJson(reportDocument());
      },
    });
    renderWithProviders(<ResultCard card={REPORT_CARD} />);
    expect(observe).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('status')).toHaveTextContent('Loading the report');
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(calls).toBe(0);
    expect(screen.queryByTitle(REPORT_FRAME_TITLE)).toBeNull();

    act(() => {
      observerCallback?.(
        [{ isIntersecting: true } as IntersectionObserverEntry],
        {} as IntersectionObserver,
      );
    });
    await waitFor(() => expect(frame()).toBeInTheDocument());
    expect(calls).toBe(1);
  });

  it('downloads the HTML through a Blob URL that is revoked after the click', async () => {
    const createObjectURL = vi.fn((_blob: Blob) => 'blob:security-report');
    const revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL }));
    const clicks: Array<{ href: string; download: string }> = [];
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clicks.push({ href: this.getAttribute('href') ?? '', download: this.download });
    });
    mockApi({ AssistantReportsController_get_v1: () => okJson(reportDocument()) });
    const { user } = renderWithProviders(<ResultCard card={REPORT_CARD} />);
    await waitFor(() => expect(frame()).toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: 'Download HTML' }));

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    const blob = createObjectURL.mock.calls[0]![0];
    expect(blob.type).toBe('text/html;charset=utf-8');
    expect(await blob.text()).toBe(REPORT_HTML);
    expect(clicks).toEqual([
      { href: 'blob:security-report', download: 'security-report-2026-11-23.html' },
    ]);
    await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith('blob:security-report'));
    // The temporary anchor is gone again.
    expect(document.querySelector('a[download]')).toBeNull();
    click.mockRestore();
  });

  it('shows the purged state without a frame or download', async () => {
    mockApi({
      AssistantReportsController_get_v1: () =>
        okJson(reportDocument({ status: 'purged', sizeBytes: null, sha256: null }, null)),
    });
    const { container } = renderWithProviders(<ResultCard card={REPORT_CARD} />);
    expect(
      await screen.findByText('This report was deleted with the conversation content.'),
    ).toBeVisible();
    expect(screen.queryByTitle(REPORT_FRAME_TITLE)).toBeNull();
    expect(screen.getByRole('button', { name: 'Download HTML' })).toBeDisabled();
    await expectNoAxeViolations(container, NO_FRAMES);
  });

  it('explains a report that is not found, and a failed load with Try again', async () => {
    let attempt = 0;
    mockApi({
      AssistantReportsController_get_v1: () => {
        attempt += 1;
        return apiErrorJson(404, 'assistant_report_not_found', 'Report not found');
      },
    });
    renderWithProviders(<ResultCard card={REPORT_CARD} />);
    expect(await screen.findByText(/This report was not found/)).toBeVisible();
    expect(attempt).toBe(1);
    expect(screen.queryByTitle(REPORT_FRAME_TITLE)).toBeNull();
  });

  it('lists the deliveries with their status and refreshes them', async () => {
    let calls = 0;
    const queued = {
      id: DELIVERY_ID,
      to: 'analyst@example.test',
      recipientKind: 'self' as const,
      status: 'queued' as const,
      errorCode: null,
      requestedAt: '2026-11-23T09:31:00.000Z',
      sentAt: null,
    };
    const failed = {
      id: '01930000-0000-7000-8000-00000000d002',
      to: 'team@example.test',
      recipientKind: 'domain' as const,
      status: 'failed' as const,
      errorCode: 'assistant_report_integrity',
      requestedAt: '2026-11-23T09:30:30.000Z',
      sentAt: null,
    };
    mockApi({
      AssistantReportsController_get_v1: () => {
        calls += 1;
        return okJson(
          reportDocument({
            deliveries:
              calls === 1
                ? [queued, failed]
                : [{ ...queued, status: 'sent', sentAt: '2026-11-23T09:31:05.000Z' }, failed],
          }),
        );
      },
    });
    const { user, container } = renderWithProviders(<ResultCard card={REPORT_CARD} />);
    const list = await screen.findByRole('list', { name: 'Emails of this report' });
    const items = within(list).getAllByRole('listitem');
    expect(items[0]).toHaveTextContent('analyst@example.test');
    expect(items[0]).toHaveTextContent('Queued');
    expect(items[1]).toHaveTextContent('Failed');
    expect(items[1]).toHaveTextContent(
      'Not sent: the stored report failed its integrity check (assistant_report_integrity)',
    );
    await expectNoAxeViolations(container, NO_FRAMES);

    await user.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(within(list).getAllByRole('listitem')[0]).toHaveTextContent('Sent'));
    expect(within(list).getAllByRole('listitem')[0]).toHaveTextContent(/Sent .*2026|Sent/);
    expect(calls).toBe(2);
  });
});

describe('ReportPage (/assistant/reports/<id>)', () => {
  it('shows the report at full size with a way back to its conversation', async () => {
    mockApi({ AssistantReportsController_get_v1: () => okJson(reportDocument()) });
    const { container } = renderWithProviders(<ReportPage reportId={REPORT_ID} />, {
      route: `/assistant/reports/${REPORT_ID}`,
    });
    expect(screen.getByRole('status')).toBeInTheDocument();
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Security report: Last 7 days' }),
    ).toBeVisible();
    await waitFor(() => expect(frame()).toBeInTheDocument());
    expectInertFrame(frame(), REPORT_HTML);
    expect(screen.getByText(/2026-11-16 00:00 – 2026-11-23 00:00 UTC/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to the conversation' })).toHaveAttribute(
      'href',
      `/assistant?conversation=${CONVERSATION_ID}`,
    );
    expect(screen.getByRole('button', { name: 'Download HTML' })).toBeEnabled();
    await expectNoAxeViolations(container, NO_FRAMES);
  });

  it('answers 404 for a report of someone else, and refuses a malformed id without a request', async () => {
    mockApi({
      AssistantReportsController_get_v1: () =>
        apiErrorJson(404, 'assistant_report_not_found', 'Report not found'),
    });
    const { unmount } = renderWithProviders(<ReportPage reportId={REPORT_ID} />);
    expect(await screen.findByText(/This report was not found/)).toBeVisible();
    expect(screen.getByRole('link', { name: 'Back to the AI assistant' })).toHaveAttribute(
      'href',
      '/assistant',
    );
    expect(screen.getByRole('button', { name: 'Download HTML' })).toBeDisabled();
    unmount();

    renderWithProviders(<ReportPage reportId="not-a-report" />);
    expect(await screen.findByText(/This report was not found/)).toBeVisible();
    expect(screen.queryByTitle(REPORT_FRAME_TITLE)).toBeNull();
  });

  it('shows the purged state', async () => {
    mockApi({
      AssistantReportsController_get_v1: () =>
        okJson(reportDocument({ status: 'purged', sizeBytes: null, sha256: null }, null)),
    });
    const { container } = renderWithProviders(<ReportPage reportId={REPORT_ID} />);
    expect(
      await screen.findByText('This report was deleted with the conversation content.'),
    ).toBeVisible();
    expect(screen.queryByTitle(REPORT_FRAME_TITLE)).toBeNull();
    expect(screen.getByRole('button', { name: 'Download HTML' })).toBeDisabled();
    await expectNoAxeViolations(container, NO_FRAMES);
  });

  it('is forbidden without assistant:use', async () => {
    renderWithProviders(<ReportPage reportId={REPORT_ID} />, { permissions: ['report:read'] });
    expect(await screen.findByRole('heading', { level: 1 })).toHaveTextContent(/access/i);
    expect(screen.queryByTitle(REPORT_FRAME_TITLE)).toBeNull();
  });
});

import { act, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { expectNoAxeViolations, mockApi, okJson, renderWithProviders } from '@/test';
import {
  GENERATING_TEXT,
  REPORT_FRAME_TITLE,
  REPORT_POLL_MS,
  isReportInProgress,
  reportFailureText,
  reportPollInterval,
} from './report-card';
import { ResultCard } from './result-card';
import { cardSchema } from './stream';
import { REPORT_CARD, REPORT_HTML, reportDocument } from './test-data';
import type { AssistantCard, ReportDocument } from './types';

/** Step AI-6 (design 34 D5): background reports and the polling report card. */

const NOW = Date.parse('2026-11-26T10:00:00.000Z');
const EXPIRES = '2026-11-26T10:30:00.000Z';

function queuedDoc(
  job: Partial<NonNullable<ReportDocument['report']['job']>> = {},
): ReportDocument {
  return reportDocument(
    {
      status: 'queued',
      figures: [],
      sizeBytes: null,
      sha256: null,
      job: { status: 'queued', attempts: 0, errorCode: null, expiresAt: EXPIRES, ...job },
    },
    null,
  );
}

const QUEUED_CARD: AssistantCard = {
  ...REPORT_CARD,
  title: 'Security report: Last 30 days',
  report: {
    ...REPORT_CARD.report!,
    status: 'queued',
    title: 'Security report: Last 30 days',
    generatedAt: '',
    sizeBytes: 0,
    figures: [],
    omitted: [],
    period: { ...REPORT_CARD.report!.period, label: 'Last 30 days' },
  },
};

afterEach(() => {
  vi.useRealTimers();
});

describe('report poll interval (D5 stop conditions)', () => {
  it('polls every 5 s while queued or running, stops at a terminal status or after expiresAt', () => {
    expect(reportPollInterval(queuedDoc(), NOW)).toBe(REPORT_POLL_MS);
    expect(reportPollInterval(queuedDoc({ status: 'running', attempts: 1 }), NOW)).toBe(5_000);
    // Expired job: stop (the api fails it with assistant_report_job_expired).
    expect(reportPollInterval(queuedDoc(), Date.parse(EXPIRES))).toBe(false);
    expect(reportPollInterval(queuedDoc(), Date.parse(EXPIRES) + 1)).toBe(false);
    // Terminal states and documents that never were background reports.
    expect(reportPollInterval(reportDocument(), NOW)).toBe(false);
    expect(
      reportPollInterval(
        reportDocument({
          status: 'failed',
          job: { status: 'failed', attempts: 5, errorCode: 'x', expiresAt: EXPIRES },
        }),
        NOW,
      ),
    ).toBe(false);
    expect(reportPollInterval(reportDocument({ status: 'purged' }, null), NOW)).toBe(false);
    expect(reportPollInterval(queuedDoc({ status: 'cancelled' }), NOW)).toBe(false);
    expect(reportPollInterval(undefined, NOW)).toBe(false);
    expect(isReportInProgress(queuedDoc())).toBe(true);
  });

  it('accepts the queued card (status, no figures) and old cards without a status', () => {
    expect(cardSchema.safeParse(QUEUED_CARD).success).toBe(true);
    expect(cardSchema.safeParse(REPORT_CARD).success).toBe(true);
    expect(
      cardSchema.safeParse({ ...QUEUED_CARD, report: { ...QUEUED_CARD.report, status: 'html' } })
        .success,
    ).toBe(false);
  });

  it('names the coded failure reasons', () => {
    expect(reportFailureText('assistant_report_session_ended')).toBe(
      'your session ended before it was ready',
    );
    expect(reportFailureText('assistant_report_job_expired')).toBe('it did not finish in time');
    expect(reportFailureText(null)).toBe('it could not be generated');
  });
});

describe('queued report card (D5)', () => {
  it('shows "Generating in the background…", polls until available, then renders the frame', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: NOW });
    const answers: ReportDocument[] = [
      queuedDoc(),
      queuedDoc({ status: 'running', attempts: 1 }),
      reportDocument({
        job: { status: 'succeeded', attempts: 1, errorCode: null, expiresAt: EXPIRES },
      }),
    ];
    let calls = 0;
    mockApi({
      AssistantReportsController_get_v1: () => {
        const doc = answers[Math.min(calls, answers.length - 1)]!;
        calls += 1;
        return okJson(doc);
      },
    });
    const { container } = renderWithProviders(<ResultCard card={QUEUED_CARD} />);
    expect(screen.getAllByText(GENERATING_TEXT).length).toBeGreaterThan(0);
    await waitFor(() => expect(calls).toBe(1));
    expect(screen.queryByTitle(REPORT_FRAME_TITLE)).not.toBeInTheDocument();
    await expectNoAxeViolations(container, { iframes: false });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(REPORT_POLL_MS);
    });
    await waitFor(() => expect(calls).toBe(2));
    expect(screen.getAllByText(GENERATING_TEXT).length).toBeGreaterThan(0);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(REPORT_POLL_MS);
    });
    await waitFor(() => expect(calls).toBe(3));
    const frame = await screen.findByTitle<HTMLIFrameElement>(REPORT_FRAME_TITLE);
    expect(frame.getAttribute('srcdoc')).toBe(REPORT_HTML);
    expect(frame.getAttribute('sandbox')).toBe('');
    // The figures come from the polled document once the card had none.
    expect(screen.getByRole('list', { name: 'Key figures' })).toHaveTextContent('12,480');
    expect(screen.queryByText(GENERATING_TEXT)).not.toBeInTheDocument();
    // Terminal: no further request.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(REPORT_POLL_MS * 3);
    });
    expect(calls).toBe(3);
  });

  it('shows the coded reason of a failed background report and stops polling', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: NOW });
    let calls = 0;
    mockApi({
      AssistantReportsController_get_v1: () => {
        calls += 1;
        return okJson(
          reportDocument(
            {
              status: 'failed',
              figures: [],
              job: {
                status: 'failed',
                attempts: 1,
                errorCode: 'assistant_report_session_ended',
                expiresAt: EXPIRES,
              },
            },
            null,
          ),
        );
      },
    });
    renderWithProviders(<ResultCard card={QUEUED_CARD} />);
    expect(
      await screen.findByText(
        /The background report failed: your session ended before it was ready/,
      ),
    ).toBeVisible();
    expect(screen.getByText('assistant_report_session_ended')).toBeVisible();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(REPORT_POLL_MS * 2);
    });
    expect(calls).toBe(1);
  });

  it('stops after the job expired and says so', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: Date.parse(EXPIRES) + 1_000 });
    let calls = 0;
    mockApi({
      AssistantReportsController_get_v1: () => {
        calls += 1;
        return okJson(queuedDoc());
      },
    });
    renderWithProviders(<ResultCard card={QUEUED_CARD} />);
    expect(await screen.findByText(/did not finish in time/)).toBeVisible();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(REPORT_POLL_MS * 2);
    });
    expect(calls).toBe(1);
  });
});

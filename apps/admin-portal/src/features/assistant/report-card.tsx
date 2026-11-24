'use client';

import {
  AlertTriangleIcon,
  DownloadIcon,
  FileXIcon,
  Maximize2Icon,
  RefreshCwIcon,
} from 'lucide-react';
import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import type { ApiError } from '@/lib/api/errors';
import { useApiQuery } from '@/lib/api/hooks';
import type { Tone } from '@/lib/design/tokens';
import { cn } from '@/lib/utils';
import { safePortalHref } from './portal-routes';
import type {
  AssistantCard,
  ReportCardData,
  ReportDelivery,
  ReportDocument,
  ReportOmissionReason,
} from './types';

/**
 * Report cards (step AI-R D9): the card of a `report_generate` result and the pieces the
 * full-size page shares with it. Every figure and label comes from the card or from `GET
 * /assistant/reports/{reportId}` (server-built, I15); the report itself is the server's inert HTML
 * shown only in `<iframe sandbox="" srcDoc>` (I16: no `allow-*` token, so no script, no same
 * origin, no navigation, no form and no popup), never inserted into the portal's own document.
 */

/** The iframe's accessible name. */
export const REPORT_FRAME_TITLE = 'Security report';
export const PURGED_TEXT = 'This report was deleted with the conversation content.';
export const NOT_FOUND_TEXT =
  'This report was not found. Only the person who generated it can open it, and it is removed with its conversation.';

const SECTION_LABELS: Readonly<Record<string, string>> = {
  summary: 'Summary',
  traffic: 'Traffic',
  threats: 'Threats',
  domains: 'Domains',
  delivery: 'Delivery',
  processing: 'Processing',
  url_clicks: 'URL clicks',
  quarantine: 'Quarantine',
  ato: 'Account takeover',
};

export function sectionLabel(section: string): string {
  return SECTION_LABELS[section] ?? section;
}

function omissionText(reason: ReportOmissionReason, code: string | null | undefined): string {
  switch (reason) {
    case 'permission':
      return code ? `needs the permission ${code}` : 'needs a permission you do not have';
    case 'not_enabled':
      return 'not enabled for your organization';
    case 'unexpected_response':
      return 'the data could not be read';
    case 'unavailable':
    default:
      return 'the data was not available';
  }
}

/** "Last 7 days, UTC" (the card's period label; the explicit window already names UTC). */
export function periodText(label: string): string {
  return /\bUTC\b/.test(label) ? label : `${label}, UTC`;
}

/** The period of a stored report view (no label there): `YYYY-MM-DD HH:MM – YYYY-MM-DD HH:MM UTC`. */
export function windowText(from: string, to: string): string {
  return `${utcMinute(from)} – ${utcMinute(to)} UTC`;
}

/** `YYYY-MM-DD HH:MM` in UTC (the text itself when it is not a date). */
export function utcMinute(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toISOString().slice(0, 16).replace('T', ' ');
}

/** `security-report-<YYYY-MM-DD>.html` (the UTC date the report was generated). */
export function reportFileName(generatedAt: string | null | undefined): string {
  const date = generatedAt ? new Date(generatedAt) : null;
  const day = date && !Number.isNaN(date.getTime()) ? date.toISOString().slice(0, 10) : 'download';
  return `security-report-${day}.html`;
}

/**
 * Saves the report HTML as a local file on the user's request: a Blob URL on a temporary anchor
 * with `download`, revoked right after the click (the HTML never becomes a navigable page).
 */
export function downloadReportHtml(html: string, fileName: string): void {
  const url = URL.createObjectURL(new Blob([html], { type: 'text/html;charset=utf-8' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** The report document through the BFF (`AssistantReportsController_get_v1`). */
export function useReportDocument(reportId: string, enabled: boolean) {
  return useApiQuery(
    'AssistantReportsController_get_v1',
    { path: { reportId } },
    { enabled, staleTime: 30_000, refetchOnWindowFocus: false },
  );
}

/**
 * `true` once the element was in (or near) the viewport; immediately without
 * IntersectionObserver (older browsers, tests), so the report is never left unloaded.
 */
function useFirstVisible<T extends Element>() {
  const ref = useRef<T>(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    if (visible) return;
    const element = ref.current;
    if (!element || typeof IntersectionObserver === 'undefined') {
      setVisible(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { rootMargin: '200px' },
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, [visible]);
  return [ref, visible] as const;
}

/**
 * The sandboxed frame of the report HTML. `sandbox=""` (every restriction on), the HTML only as
 * `srcdoc`, no referrer; 560 px high (420 px below `md`) in the card, the viewport on the page.
 */
export function ReportFrame({
  html,
  variant = 'card',
  className,
}: {
  html: string;
  variant?: 'card' | 'page';
  className?: string;
}) {
  return (
    <iframe
      sandbox=""
      srcDoc={html}
      title={REPORT_FRAME_TITLE}
      referrerPolicy="no-referrer"
      loading="lazy"
      className={cn(
        'block w-full rounded-md border bg-white',
        variant === 'card'
          ? 'h-[420px] md:h-[560px]'
          : 'h-[calc(100dvh-16rem)] min-h-[420px] md:h-[calc(100dvh-13rem)]',
        className,
      )}
    />
  );
}

/** A state of a report that has no HTML to show (purged, pending, failed, not found, error). */
export function ReportNotice({
  tone = 'muted',
  children,
}: {
  tone?: 'muted' | 'danger';
  children: React.ReactNode;
}) {
  const Icon = tone === 'danger' ? AlertTriangleIcon : FileXIcon;
  return (
    <div
      className={cn(
        'flex items-start gap-2 rounded-md border p-3 text-sm',
        tone === 'danger' ? 'border-destructive/40' : 'bg-muted/40',
      )}
    >
      <Icon
        className={cn(
          'mt-0.5 size-4 shrink-0',
          tone === 'danger' ? 'text-destructive' : 'text-muted-foreground',
        )}
        aria-hidden
      />
      <div className="grid gap-1">{children}</div>
    </div>
  );
}

/** What to show instead of (or before) the frame for a loaded or failed report document. */
export function ReportState({
  data,
  error,
  loading,
  onRetry,
}: {
  data: ReportDocument | undefined;
  error: ApiError | null;
  loading: boolean;
  onRetry?: () => void;
}) {
  if (loading && !data) return <LoadingState label="Loading the report" rows={4} className="p-1" />;
  if (error && !data) {
    if (error.status === 404) return <ReportNotice>{NOT_FOUND_TEXT}</ReportNotice>;
    if (error.status === 410) return <ReportNotice>{PURGED_TEXT}</ReportNotice>;
    return (
      <ReportNotice tone="danger">
        <p role="alert">
          The report could not be loaded: {error.message} ({error.code})
          {error.requestId ? `. Request ID: ${error.requestId}` : ''}
        </p>
        {onRetry ? (
          <Button variant="outline" size="sm" className="w-fit" onClick={onRetry}>
            Try again
          </Button>
        ) : null}
      </ReportNotice>
    );
  }
  if (!data) return null;
  const { report, html } = data;
  if (report.status === 'purged') return <ReportNotice>{PURGED_TEXT}</ReportNotice>;
  if (report.status === 'pending')
    return <ReportNotice>The report is still being prepared. Refresh in a moment.</ReportNotice>;
  if (report.status === 'failed')
    return (
      <ReportNotice tone="danger">
        <p>The report could not be stored. Ask the assistant to generate it again.</p>
      </ReportNotice>
    );
  if (html === null)
    return (
      <ReportNotice tone="danger">
        <p>The stored report could not be read. Ask the assistant to generate it again.</p>
      </ReportNotice>
    );
  return null;
}

const DELIVERY_STATUS: Readonly<
  Record<ReportDelivery['status'], { readonly label: string; readonly tone: Tone }>
> = {
  queued: { label: 'Queued', tone: 'info' },
  sent: { label: 'Sent', tone: 'success' },
  failed: { label: 'Failed', tone: 'danger' },
};

const DELIVERY_ERRORS: Readonly<Record<string, string>> = {
  assistant_report_purged: 'the report was deleted before it was sent',
  assistant_report_missing: 'the stored report is missing',
  assistant_report_integrity: 'the stored report failed its integrity check',
  assistant_report_email_timeout: 'it could not be sent within a day',
  assistant_report_recipient_invalid: 'the recipient address is not valid',
};

export function deliveryFailureText(code: string | null): string {
  if (!code) return 'the email could not be sent';
  return DELIVERY_ERRORS[code] ?? 'the email could not be sent';
}

/** Emails of the report, newest first (`report.deliveries`), with Refresh. */
export function ReportDeliveries({
  deliveries,
  refreshing,
  onRefresh,
}: {
  deliveries: readonly ReportDelivery[];
  refreshing: boolean;
  onRefresh: () => void;
}) {
  return (
    <section aria-label="Report emails" className="grid gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-xs font-semibold">Emails</h4>
        <Button variant="ghost" size="sm" onClick={onRefresh} disabled={refreshing}>
          <RefreshCwIcon className={cn(refreshing && 'animate-spin')} aria-hidden />
          {refreshing ? 'Refreshing …' : 'Refresh'}
        </Button>
      </div>
      {deliveries.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          Not emailed yet. Ask the assistant to send this report to your email.
        </p>
      ) : (
        <ul className="grid gap-1.5" aria-label="Emails of this report">
          {deliveries.map((delivery) => {
            const status = DELIVERY_STATUS[delivery.status];
            return (
              <li
                key={delivery.id}
                className="grid gap-1 rounded-md border px-2 py-1.5 text-xs sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center"
              >
                <div className="grid min-w-0 gap-0.5">
                  <span className="truncate font-medium">
                    {delivery.to ?? <span className="text-muted-foreground">Address removed</span>}
                  </span>
                  <span className="text-muted-foreground">
                    Requested <DateTime value={delivery.requestedAt} mode="absolute" />
                    {delivery.sentAt ? (
                      <>
                        {' · Sent '}
                        <DateTime value={delivery.sentAt} mode="absolute" />
                      </>
                    ) : null}
                  </span>
                  {delivery.status === 'failed' ? (
                    <span className="text-destructive">
                      Not sent: {deliveryFailureText(delivery.errorCode)}
                      {delivery.errorCode ? (
                        <>
                          {' '}
                          (<code className="font-mono">{delivery.errorCode}</code>)
                        </>
                      ) : null}
                    </span>
                  ) : null}
                </div>
                <ToneBadge tone={status.tone}>{status.label}</ToneBadge>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

/** Figure chips (formatted server values). */
export function ReportFigures({ figures }: { figures: ReportCardData['figures'] }) {
  if (figures.length === 0) return null;
  return (
    <ul aria-label="Key figures" className="flex flex-wrap gap-1.5">
      {figures.map((figure, index) => (
        <li
          key={`${figure.label}-${index}`}
          className="inline-flex items-baseline gap-1 rounded-full border bg-muted/40 px-2 py-0.5 text-xs"
        >
          <span className="text-muted-foreground">{figure.label}</span>
          <span className="font-semibold tabular-nums">{figure.value}</span>
        </li>
      ))}
    </ul>
  );
}

/** "Not included: Quarantine (needs the permission quarantine:read); …". */
export function ReportOmissions({ omitted }: { omitted: ReportCardData['omitted'] }) {
  if (omitted.length === 0) return null;
  return (
    <p className="text-xs text-muted-foreground">
      <span className="font-medium text-foreground">Not included: </span>
      {omitted
        .map(
          (entry) => `${sectionLabel(entry.section)} (${omissionText(entry.reason, entry.code)})`,
        )
        .join('; ')}
      .
    </p>
  );
}

/** The card of a `report_generate` result (card kind `report`). */
export function ReportCard({ card, onNavigate }: { card: AssistantCard; onNavigate?: () => void }) {
  const report = card.report;
  const [ref, visible] = useFirstVisible<HTMLElement>();
  const query = useReportDocument(report?.reportId ?? '', visible && Boolean(report));
  if (!report) return null;
  const data = query.data;
  const html = data?.report.status === 'available' ? data.html : null;
  const fullSize = safePortalHref(`/assistant/reports/${report.reportId.toLowerCase()}`);
  return (
    <section
      ref={ref}
      aria-label={`Result: ${card.title}`}
      className="grid min-w-0 gap-2 rounded-lg border bg-card p-3 text-sm shadow-xs"
    >
      <div className="grid gap-0.5">
        <h3 className="text-sm font-semibold">{report.title}</h3>
        <p className="text-xs text-muted-foreground">
          {periodText(report.period.label)} · Generated{' '}
          <DateTime value={report.generatedAt} mode="absolute" />
        </p>
      </div>
      <ReportFigures figures={report.figures} />
      <ReportOmissions omitted={report.omitted} />
      <ReportState
        data={data}
        error={query.error}
        loading={!visible || query.isLoading}
        onRetry={() => void query.refetch()}
      />
      {html !== null ? <ReportFrame html={html} /> : null}
      <div role="group" aria-label="Report actions" className="flex flex-wrap items-center gap-2">
        {fullSize ? (
          <Button asChild variant="outline" size="sm">
            <Link href={fullSize} onClick={onNavigate}>
              <Maximize2Icon aria-hidden />
              Open full size
            </Link>
          </Button>
        ) : null}
        <Button
          variant="outline"
          size="sm"
          disabled={html === null}
          onClick={() => {
            if (html !== null)
              downloadReportHtml(
                html,
                reportFileName(data?.report.createdAt ?? report.generatedAt),
              );
          }}
        >
          <DownloadIcon aria-hidden />
          Download HTML
        </Button>
      </div>
      {data ? (
        <ReportDeliveries
          deliveries={data.report.deliveries}
          refreshing={query.isFetching}
          onRefresh={() => void query.refetch()}
        />
      ) : null}
    </section>
  );
}

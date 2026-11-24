'use client';

import { ArrowLeftIcon, DownloadIcon } from 'lucide-react';
import Link from 'next/link';
import { PageHeader } from '@/components/page-header';
import { Button } from '@/components/ui/button';
import { RouteGate } from '@/lib/auth/route-gate';
import type { Gate } from '@/lib/navigation';
import {
  NOT_FOUND_TEXT,
  ReportFigures,
  ReportFrame,
  ReportNotice,
  ReportOmissions,
  ReportState,
  downloadReportHtml,
  reportFileName,
  useReportDocument,
  utcMinute,
  windowText,
} from './report-card';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The operation the page reads (design D9: the route is gated by it). */
export const REPORT_PAGE_GATE: Gate = ['AssistantReportsController_get_v1'];

/**
 * `/assistant/reports/<reportId>` (step AI-R D9): one chat report at full size, in the same
 * sandboxed frame as the card (`sandbox=""`, `srcdoc`), with a toolbar to go back to its
 * conversation and to download the HTML. Owner only: the api answers 404 for anyone else.
 */
export function ReportPage({ reportId }: { reportId: string }) {
  return (
    <RouteGate gate={REPORT_PAGE_GATE}>
      <ReportPageContent reportId={reportId} />
    </RouteGate>
  );
}

function ReportPageContent({ reportId }: { reportId: string }) {
  const valid = UUID.test(reportId);
  const query = useReportDocument(reportId, valid);
  const data = query.data;
  const report = data?.report;
  const html = report?.status === 'available' ? (data?.html ?? null) : null;
  const back = report
    ? `/assistant?conversation=${encodeURIComponent(report.conversationId)}`
    : '/assistant';
  const title = report?.title ?? 'Security report';

  const toolbar = (
    <div role="group" aria-label="Report actions" className="flex flex-wrap items-center gap-2">
      <Button asChild variant="outline" size="sm">
        <Link href={back}>
          <ArrowLeftIcon aria-hidden />
          {report ? 'Back to the conversation' : 'Back to the AI assistant'}
        </Link>
      </Button>
      <Button
        variant="outline"
        size="sm"
        disabled={html === null}
        onClick={() => {
          if (html !== null && report) downloadReportHtml(html, reportFileName(report.createdAt));
        }}
      >
        <DownloadIcon aria-hidden />
        Download HTML
      </Button>
    </div>
  );

  return (
    <div className="flex min-w-0 flex-col gap-3">
      <PageHeader
        title={title}
        breadcrumbs={[{ label: 'AI assistant', href: '/assistant' }, { label: title }]}
        description={
          report ? (
            <>
              {windowText(report.period.from, report.period.to)} · Generated{' '}
              {utcMinute(report.createdAt)} UTC
            </>
          ) : undefined
        }
        actions={toolbar}
        className="pb-0"
      />
      {!valid ? (
        <ReportNotice>{NOT_FOUND_TEXT}</ReportNotice>
      ) : (
        <>
          {report ? (
            <div className="grid gap-2">
              <ReportFigures figures={report.figures} />
              <ReportOmissions omitted={report.omitted} />
            </div>
          ) : null}
          <ReportState
            data={data}
            error={query.error}
            loading={query.isLoading}
            onRetry={() => void query.refetch()}
          />
          {html !== null ? <ReportFrame html={html} variant="page" /> : null}
        </>
      )}
    </div>
  );
}

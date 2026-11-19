'use client';

import { PrinterIcon } from 'lucide-react';
import Link from 'next/link';
import type { ReactNode } from 'react';
import { NotFoundView } from '@/components/not-found-view';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { ApiError } from '@/lib/api/errors';
import { useApiQuery } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatUtc, humanize } from '@/lib/format';
import { categoryLabel, categoryUi } from './categories';
import { ScrollRegion } from '@/features/ato/components';
import { str } from '@/features/ato/model';
import { incidentHref, type IncidentReport } from './model';

/**
 * `/incidents/[incidentId]/report`: the print view of `security-incident-report/1` (§5.2 I8, D16).
 * Fetching it is audited by the api (`security_incident.report_exported`); the browser's
 * "Print / Save as PDF" makes the file. Messages appear with masked senders only.
 */
export function IncidentReportPage({ incidentId }: { incidentId: string }) {
  return (
    <RouteGate gate={['IncidentsController_report_v1']}>
      <ReportContent incidentId={incidentId} />
    </RouteGate>
  );
}

function ReportContent({ incidentId }: { incidentId: string }) {
  const report = useApiQuery(
    'IncidentsController_report_v1',
    { path: { incidentId } },
    { retry: false, staleTime: Infinity, refetchOnWindowFocus: false },
  );
  if (report.isLoading) return <LoadingState label="Preparing the incident report" />;
  if (report.error instanceof ApiError && report.error.status === 404) return <NotFoundView />;
  if (report.error)
    return <ErrorState error={report.error} onRetry={() => void report.refetch()} />;
  if (!report.data) return null;
  return <ReportView report={report.data} incidentId={incidentId} />;
}

function text(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value)) return formatUtc(value);
  if (Array.isArray(value)) return value.map(text).join(', ');
  if (typeof value === 'object') return JSON.stringify(value);
  return str(value);
}

function KeyValues({ data }: { data: Record<string, unknown> }) {
  return (
    <dl className="grid grid-cols-1 gap-x-4 gap-y-1 text-sm sm:grid-cols-[minmax(10rem,auto)_1fr]">
      {Object.entries(data).map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-medium">
            {humanize(k.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase())}
          </dt>
          <dd className="min-w-0 break-all sm:break-words">{text(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

function Part({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="grid gap-2 break-inside-avoid">
      <h2 className="border-b pb-1 text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function ReportView({ report, incidentId }: { report: IncidentReport; incidentId: string }) {
  const incident = report.incident;
  const category = typeof incident.category === 'string' ? incident.category : '';
  const ui = categoryUi(category);
  return (
    <article className="mx-auto grid max-w-4xl min-w-0 gap-5 bg-background p-2 print:max-w-none print:p-0">
      <title>{`Incident report · Email Security Gateway`}</title>
      <div className="flex flex-wrap items-center justify-between gap-2 print:hidden">
        <Link
          href={incidentHref(incidentId)}
          className="text-sm text-primary underline-offset-2 hover:underline"
        >
          Back to the incident
        </Link>
        <Button size="sm" onClick={() => window.print()}>
          <PrinterIcon aria-hidden />
          Print or save as PDF
        </Button>
      </div>
      <header className="grid gap-1">
        <h1 className="text-2xl font-semibold">
          Security incident report: {categoryLabel(category)}
        </h1>
        <p className="text-sm text-muted-foreground">
          {report.version} · generated {formatUtc(report.generatedAt)} · confidential: for the
          organization’s security team
        </p>
        {report.truncated ? (
          <p role="note" className="text-sm font-medium">
            Lists in this report are truncated to the configured maximum number of items.
          </p>
        ) : null}
      </header>
      <Part title="Incident">
        <KeyValues data={incident} />
      </Part>
      <Part title="Resolution">
        {report.resolution ? (
          <KeyValues data={report.resolution} />
        ) : (
          <p className="text-sm">Not resolved.</p>
        )}
      </Part>
      <Part title="Evidence">
        <KeyValues data={report.evidence} />
      </Part>
      {report.sections.map((section) => {
        const custom = ui?.ReportSection ? <ui.ReportSection section={section} /> : null;
        return (
          <Part key={section.id} title={section.title}>
            {custom ??
              (section.data && typeof section.data === 'object' && !Array.isArray(section.data) ? (
                <KeyValues data={section.data as Record<string, unknown>} />
              ) : (
                <p className="text-sm break-words">{text(section.data)}</p>
              ))}
          </Part>
        );
      })}
      <Part title="Related messages">
        {report.messages.length === 0 ? (
          <p className="text-sm">None.</p>
        ) : (
          <ScrollRegion label="Related messages">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Related messages</caption>
              <thead>
                <tr>
                  {['Message', 'Received', 'Direction', 'Sender (masked)'].map((h) => (
                    <th key={h} scope="col" className="border-b px-1 py-1 font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {report.messages.map((m) => (
                  <tr key={`${m.messageId}-${m.receivedAt}`} className="border-b">
                    <td className="px-1 py-1 font-mono text-xs">{m.messageId}</td>
                    <td className="px-1 py-1">{formatUtc(m.receivedAt)}</td>
                    <td className="px-1 py-1">{humanize(m.direction)}</td>
                    <td className="px-1 py-1">{m.senderMasked ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </ScrollRegion>
        )}
      </Part>
      <Part title="Notes">
        {report.notes.length === 0 ? (
          <p className="text-sm">No notes.</p>
        ) : (
          <ol className="grid gap-2 text-sm">
            {report.notes.map((n, i) => (
              <li key={i}>
                <span className="font-medium">
                  {formatUtc(n.at)} · {humanize(n.actorType)}
                </span>
                <p className="whitespace-pre-wrap">{n.note}</p>
              </li>
            ))}
          </ol>
        )}
      </Part>
      <Part title="Timeline">
        <ol className="grid gap-1 text-sm">
          {report.timeline.map((entry, i) => (
            <li key={i}>
              {text(entry.at)} · {humanize(str(entry.type).replace(/^ato\./, ''))}
              {entry.toStatus ? ` → ${humanize(str(entry.toStatus))}` : ''}
              {entry.toSeverity ? ` (severity ${humanize(str(entry.toSeverity))})` : ''}
            </li>
          ))}
        </ol>
      </Part>
    </article>
  );
}

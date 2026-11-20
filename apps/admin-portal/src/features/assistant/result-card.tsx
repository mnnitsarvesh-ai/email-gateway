'use client';

import { AlertTriangleIcon, ExternalLinkIcon, LockIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo, useState } from 'react';
import { BarChart, TimeSeriesChart, type ChartRow, type ChartSeries } from '@/components/charts';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { Button } from '@/components/ui/button';
import { ApiError } from '@/lib/api/errors';
import { callOperation } from '@/lib/api/call';
import { cn } from '@/lib/utils';
import { decisionLabel, turnErrorText } from './model';
import { safePortalHref } from './portal-routes';
import { cardSchema } from './stream';
import type { AssistantCard, CardLink, CardValue, ExecutionDecision } from './types';

/**
 * Result cards (`assistant-card/1`, step AI-1 D8/D14): what a tool returned, rendered from the
 * card the api built from the real API response (never from the model's text). Table cards use
 * the design-system DataTable with row links to the portal page and "Load more" (`POST
 * /assistant/executions/{id}/more`, appended rows); key-value, series (time-series or bar chart),
 * message and error cards; and the denied card for a refused tool call.
 */

type Row = Readonly<Record<string, CardValue>> & { readonly __ref: string };

const ISO_DATE = /^\d{4}-\d{2}-\d{2}(?:[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)?$/;

function safeLinks(links: readonly CardLink[]): CardLink[] {
  return links.flatMap((link) => {
    const href = safePortalHref(link.href);
    return href ? [{ ...link, href }] : [];
  });
}

export function CardValueText({ value }: { value: CardValue | undefined }) {
  if (value === null || value === undefined || value === '')
    return <span className="text-muted-foreground">—</span>;
  if (typeof value === 'boolean') return <span>{value ? 'Yes' : 'No'}</span>;
  if (typeof value === 'number') return <span className="tabular-nums">{String(value)}</span>;
  // Record values may be mail-derived (subjects, senders, file names): text only, never a link.
  return <UntrustedText value={value} maxLength={80} />;
}

function PageLinks({ links, onNavigate }: { links: readonly CardLink[]; onNavigate?: () => void }) {
  if (links.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-x-3 gap-y-1">
      {links.map((link) => (
        <Link
          key={`${link.href}|${link.label}`}
          href={link.href}
          onClick={onNavigate}
          className="inline-flex items-center gap-1 text-xs text-primary underline underline-offset-2 hover:no-underline"
        >
          <ExternalLinkIcon className="size-3" aria-hidden />
          Open {link.label} in the portal
        </Link>
      ))}
    </div>
  );
}

function CardFrame({
  title,
  tone = 'default',
  children,
  footer,
}: {
  title: string;
  tone?: 'default' | 'danger' | 'muted';
  children?: React.ReactNode;
  footer?: React.ReactNode;
}) {
  return (
    <section
      aria-label={`Result: ${title}`}
      className={cn(
        'grid gap-2 rounded-lg border bg-card p-3 text-sm shadow-xs',
        tone === 'danger' && 'border-destructive/40',
        tone === 'muted' && 'bg-muted/40',
      )}
    >
      <h3 className="text-sm font-semibold">{title}</h3>
      {children}
      {footer}
    </section>
  );
}

/** Appends the next page of a list execution (no model call). */
function useMore(initial: AssistantCard, initialHasMore: boolean) {
  const [state, setState] = useState(() => ({
    rows: (initial.rows ?? []).map((row, index) => ({
      ...row,
      __ref: initial.refs[index] ?? `${initial.executionId}:${index}`,
    })),
    links: safeLinks(initial.portalLinks),
    executionId: initial.executionId,
    hasMore: initialHasMore,
    pending: false,
    error: null as ApiError | null,
  }));
  const loadMore = async () => {
    if (state.pending || !state.hasMore) return;
    setState((current) => ({ ...current, pending: true, error: null }));
    try {
      const execution = await callOperation('AssistantExecutionsController_more_v1', {
        path: { executionId: state.executionId },
      });
      const parsed = execution.card ? cardSchema.safeParse(execution.card) : null;
      const card = parsed?.success ? (parsed.data as AssistantCard) : null;
      if (!card || card.kind !== 'table') {
        const message = card?.error
          ? `${card.error.message} (${card.error.code})`
          : 'The next page could not be loaded.';
        setState((current) => ({
          ...current,
          pending: false,
          error: new ApiError({
            status: card?.error?.httpStatus ?? 500,
            code: card?.error?.code ?? 'assistant_more_failed',
            message,
          }),
        }));
        return;
      }
      setState((current) => {
        const seen = new Set(current.rows.map((row) => row.__ref));
        const rows = (card.rows ?? [])
          .map((row, index) => ({
            ...row,
            __ref: card.refs[index] ?? `${card.executionId}:${index}`,
          }))
          .filter((row) => !seen.has(row.__ref)) as Row[];
        const links = safeLinks(card.portalLinks);
        const known = new Set(current.links.map((link) => `${link.href}|${link.ref ?? ''}`));
        return {
          rows: [...current.rows, ...rows],
          links: [
            ...current.links,
            ...links.filter((link) => !known.has(`${link.href}|${link.ref ?? ''}`)),
          ],
          executionId: execution.id,
          hasMore: card.nextCursor ?? execution.hasMore,
          pending: false,
          error: null,
        };
      });
    } catch (error) {
      setState((current) => ({
        ...current,
        pending: false,
        hasMore:
          error instanceof ApiError && error.code === 'assistant_no_more_results'
            ? false
            : current.hasMore,
        error:
          error instanceof ApiError
            ? error
            : new ApiError({ status: 0, code: 'network_error', message: 'The request failed' }),
      }));
    }
  };
  return { ...state, loadMore };
}

function TableCard({
  card,
  hasMore,
  onNavigate,
}: {
  card: AssistantCard;
  hasMore: boolean;
  onNavigate?: () => void;
}) {
  const more = useMore(card, hasMore);
  const rowLinks = useMemo(() => {
    const map = new Map<string, CardLink>();
    for (const link of more.links) if (link.ref && !map.has(link.ref)) map.set(link.ref, link);
    return map;
  }, [more.links]);
  const pageLinks = more.links.filter((link) => !link.ref);
  const columns = useMemo<DataTableColumn<Row>[]>(() => {
    const out: DataTableColumn<Row>[] = (card.columns ?? []).map((column) => ({
      id: column.key,
      header: column.label,
      meta: { label: column.label },
      cell: ({ row }) => <CardValueText value={row.original[column.key]} />,
    }));
    if (rowLinks.size > 0) {
      out.push({
        id: '__open',
        header: () => <span className="sr-only">Open</span>,
        meta: { label: 'Open', hideable: false, className: 'w-px whitespace-nowrap text-right' },
        cell: ({ row }) => {
          const link = rowLinks.get(row.original.__ref);
          return link ? (
            <Link
              href={link.href}
              onClick={onNavigate}
              aria-label={`Open ${link.label}`}
              className="text-xs text-primary underline underline-offset-2 hover:no-underline"
            >
              Open
            </Link>
          ) : null;
        },
      });
    }
    return out;
  }, [card.columns, onNavigate, rowLinks]);
  const count = more.rows.length;
  return (
    <CardFrame
      title={card.title}
      footer={
        <div className="grid gap-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs text-muted-foreground" aria-live="polite">
              {count} {count === 1 ? 'row' : 'rows'}
              {typeof card.total === 'number' ? ` of ${card.total}` : ''}
              {card.truncated ? ' (some rows were left out to keep the result small)' : ''}
            </p>
            {more.hasMore ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => void more.loadMore()}
                disabled={more.pending}
              >
                {more.pending ? 'Loading …' : 'Load more'}
              </Button>
            ) : null}
          </div>
          {more.error ? (
            <p role="alert" className="text-xs text-destructive">
              {turnErrorText(more.error.code, more.error.message)}
              {more.error.requestId ? ` Request ID: ${more.error.requestId}` : ''}
            </p>
          ) : null}
          <PageLinks links={pageLinks} onNavigate={onNavigate} />
        </div>
      }
    >
      <DataTable<Row>
        tableId={`assistant-card-${card.tool}`}
        caption={card.title}
        columns={columns}
        list={{
          rows: more.rows,
          page: 1,
          hasNext: false,
          hasPrevious: false,
          isShortPage: false,
          next: () => undefined,
          previous: () => undefined,
          query: {
            isLoading: false,
            isFetching: more.pending,
            error: null,
            refetch: () => undefined,
          },
        }}
        getRowId={(row) => row.__ref}
        emptyState={<p className="p-3 text-sm text-muted-foreground">No results.</p>}
        mobileCard={(row) => (
          <div className="grid gap-1 text-xs">
            <dl className="grid gap-1">
              {(card.columns ?? []).map((column) => (
                <div key={column.key} className="flex gap-2">
                  <dt className="shrink-0 text-muted-foreground">{column.label}</dt>
                  <dd className="min-w-0">
                    <CardValueText value={row[column.key]} />
                  </dd>
                </div>
              ))}
            </dl>
            {rowLinks.get(row.__ref) ? (
              <Link
                href={rowLinks.get(row.__ref)?.href ?? '/'}
                onClick={onNavigate}
                className="text-primary underline underline-offset-2"
              >
                Open {rowLinks.get(row.__ref)?.label}
              </Link>
            ) : null}
          </div>
        )}
        toolbar={false}
        pagination={false}
        stickyFirstColumn={false}
        className="shadow-none"
      />
    </CardFrame>
  );
}

function KvCard({ card, onNavigate }: { card: AssistantCard; onNavigate?: () => void }) {
  const fields = card.fields ?? [];
  return (
    <CardFrame
      title={card.title}
      footer={<PageLinks links={safeLinks(card.portalLinks)} onNavigate={onNavigate} />}
    >
      {fields.length === 0 ? (
        <p className="text-muted-foreground">No details returned.</p>
      ) : (
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-[minmax(8rem,auto)_1fr]">
          {fields.map((field) => (
            <div key={field.key} className="contents">
              <dt className="text-muted-foreground">{field.label}</dt>
              <dd className="min-w-0 break-words">
                <CardValueText value={field.value} />
              </dd>
            </div>
          ))}
        </dl>
      )}
    </CardFrame>
  );
}

/** Chart rows of a series card (`x` buckets × named series; missing values stay null). */
export function seriesRows(series: NonNullable<AssistantCard['series']>): {
  rows: ChartRow[];
  series: ChartSeries[];
  timeAxis: boolean;
} {
  const chartSeries = series.series.map((entry, index) => ({
    key: `s${index}`,
    label: entry.name,
  }));
  const rows = series.x.map((x, rowIndex) => {
    const row: ChartRow = { x };
    series.series.forEach((entry, index) => {
      row[`s${index}`] = entry.values[rowIndex] ?? null;
    });
    return row;
  });
  return {
    rows,
    series: chartSeries,
    timeAxis: series.x.length > 0 && series.x.every((x) => ISO_DATE.test(x)),
  };
}

function formatBucket(value: string | number): string {
  const text = String(value);
  if (!ISO_DATE.test(text)) return text;
  const date = new Date(text.length === 10 ? `${text}T00:00:00Z` : text);
  if (Number.isNaN(date.getTime())) return text;
  return text.length === 10
    ? new Intl.DateTimeFormat(undefined, {
        month: 'short',
        day: 'numeric',
        timeZone: 'UTC',
      }).format(date)
    : new Intl.DateTimeFormat(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      }).format(date);
}

function SeriesCard({ card, onNavigate }: { card: AssistantCard; onNavigate?: () => void }) {
  const data = card.series ? seriesRows(card.series) : null;
  return (
    <CardFrame
      title={card.title}
      footer={<PageLinks links={safeLinks(card.portalLinks)} onNavigate={onNavigate} />}
    >
      {!data || data.rows.length === 0 ? (
        <p className="text-muted-foreground">No data points returned.</p>
      ) : data.timeAxis ? (
        <TimeSeriesChart
          title={card.title}
          rows={data.rows}
          xKey="x"
          series={data.series}
          formatX={formatBucket}
          height={200}
        />
      ) : (
        <BarChart
          title={card.title}
          rows={data.rows}
          categoryKey="x"
          series={data.series}
          layout={data.rows.length > 6 ? 'horizontal' : 'vertical'}
          height={200}
        />
      )}
    </CardFrame>
  );
}

function MessageCard({ card, onNavigate }: { card: AssistantCard; onNavigate?: () => void }) {
  return (
    <CardFrame
      title={card.title}
      tone="muted"
      footer={<PageLinks links={safeLinks(card.portalLinks)} onNavigate={onNavigate} />}
    >
      <p>{card.message ?? 'The request completed without content.'}</p>
    </CardFrame>
  );
}

export function ErrorCard({ card, onNavigate }: { card: AssistantCard; onNavigate?: () => void }) {
  const error = card.error;
  return (
    <CardFrame
      title={card.title}
      tone="danger"
      footer={<PageLinks links={safeLinks(card.portalLinks)} onNavigate={onNavigate} />}
    >
      <div className="flex items-start gap-2">
        <AlertTriangleIcon className="mt-0.5 size-4 shrink-0 text-destructive" aria-hidden />
        <div className="grid gap-1">
          <p>{error?.message ?? card.message ?? 'The request failed.'}</p>
          {error ? (
            <p className="text-xs text-muted-foreground">
              Error <code className="font-mono">{error.code}</code> (HTTP {error.httpStatus})
            </p>
          ) : null}
        </div>
      </div>
    </CardFrame>
  );
}

/** A refused tool call (`tool.denied` or a stored denied execution). */
export function DeniedCard({
  title,
  decision,
  message,
}: {
  title: string;
  decision: Exclude<ExecutionDecision, 'allowed'>;
  message: string;
}) {
  return (
    <CardFrame title={title} tone="muted">
      <div className="flex items-start gap-2">
        <LockIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
        <div className="grid gap-1">
          <p className="font-medium">{decisionLabel(decision)}</p>
          <p className="text-muted-foreground">{message}</p>
          {decision === 'denied_permission' ? (
            <p className="text-xs text-muted-foreground">
              The assistant can only do what your role allows. Ask an administrator for the
              permission if you need it.
            </p>
          ) : null}
        </div>
      </div>
    </CardFrame>
  );
}

/** One result card by kind. `hasMore` comes from the execution (`hasMore`) or the card flag. */
export function ResultCard({
  card,
  hasMore,
  onNavigate,
}: {
  card: AssistantCard;
  hasMore?: boolean;
  onNavigate?: () => void;
}) {
  switch (card.kind) {
    case 'table':
      return (
        <TableCard
          card={card}
          hasMore={hasMore ?? card.nextCursor === true}
          onNavigate={onNavigate}
        />
      );
    case 'kv':
      return <KvCard card={card} onNavigate={onNavigate} />;
    case 'series':
      return <SeriesCard card={card} onNavigate={onNavigate} />;
    case 'error':
      return <ErrorCard card={card} onNavigate={onNavigate} />;
    case 'message':
    default:
      return <MessageCard card={card} onNavigate={onNavigate} />;
  }
}

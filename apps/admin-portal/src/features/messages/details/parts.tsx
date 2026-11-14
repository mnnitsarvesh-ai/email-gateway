'use client';

import { LockIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { cn } from '@/lib/utils';
import { Section } from '../controls';
import { sectionRequirement, type SectionDefinition } from './sections';

/**
 * Small building blocks of the details sections: a captioned data table for engine results, an
 * honest "no data" note, the forbidden state of a section and a query-state wrapper.
 */

export interface GridColumn<Row> {
  readonly header: string;
  readonly cell: (row: Row, index: number) => ReactNode;
  readonly className?: string;
  /** The first column becomes the row header (`<th scope="row">`). */
  readonly rowHeader?: boolean;
}

/** A plain captioned table (engine results, contributions, symbols); scrolls horizontally. */
export function DataGrid<Row>({
  caption,
  columns,
  rows,
  rowKey,
  captionVisible = false,
}: {
  caption: string;
  columns: readonly GridColumn<Row>[];
  rows: readonly Row[];
  rowKey: (row: Row, index: number) => string;
  captionVisible?: boolean;
}) {
  return (
    // Focusable and named: on a phone the grid scrolls horizontally and keyboard users must be
    // able to scroll it (WCAG 2.1.1); positioned so that absolutely positioned descendants (copy
    // buttons' live regions) stay inside the scroller instead of widening the page.
    <div
      className="relative overflow-x-auto rounded-md border"
      role="group"
      aria-label={caption}
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable region
      tabIndex={0}
    >
      <table className="w-full text-sm">
        <caption
          className={cn(
            captionVisible
              ? 'px-3 py-2 text-left text-xs font-medium text-muted-foreground'
              : 'sr-only',
          )}
        >
          {caption}
        </caption>
        <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
          <tr>
            {columns.map((column) => (
              <th key={column.header} scope="col" className="px-3 py-2 font-semibold">
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={rowKey(row, index)} className="border-t align-top">
              {columns.map((column) =>
                column.rowHeader ? (
                  <th
                    key={column.header}
                    scope="row"
                    className={cn('px-3 py-2 text-left font-medium', column.className)}
                  >
                    {column.cell(row, index)}
                  </th>
                ) : (
                  <td key={column.header} className={cn('px-3 py-2', column.className)}>
                    {column.cell(row, index)}
                  </td>
                ),
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** An honest statement that data is absent (never an invented number). */
export function NoData({ children }: { children: ReactNode }) {
  return <p className="text-sm text-muted-foreground">{children}</p>;
}

/** A small titled block inside a section. */
export function Block({
  title,
  description,
  children,
  actions,
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="grid gap-2 rounded-md border p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="grid gap-0.5">
          <h3 className="text-sm font-semibold">{title}</h3>
          {description ? <p className="text-xs text-muted-foreground">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
      </div>
      {children}
    </div>
  );
}

/** The forbidden state of a section opened by a direct `?section=` without its permission. */
export function SectionForbidden({ section }: { section: SectionDefinition }) {
  const required = sectionRequirement(section);
  return (
    <Section title={section.label}>
      <div role="alert" className="flex flex-col gap-2 text-sm">
        <div className="flex items-center gap-2 font-semibold">
          <LockIcon className="size-4 text-destructive" aria-hidden />
          <span>You do not have access to this section</span>
        </div>
        <p className="text-muted-foreground">
          Your role does not include the permission this section needs; its data is not loaded. Ask
          an organization administrator if you need access.
        </p>
        {required.length > 0 ? (
          <p className="text-muted-foreground">
            Requires{' '}
            {required.map((permission) => (
              <code
                key={permission}
                className="mx-0.5 rounded-sm bg-muted px-1 py-0.5 font-mono text-xs text-foreground"
              >
                {permission}
              </code>
            ))}
            .
          </p>
        ) : null}
      </div>
    </Section>
  );
}

/** Loading → skeleton, error → ErrorState (code, requestId, Retry), else the content. */
export function QueryBoundary({
  query,
  label,
  rows = 4,
  children,
}: {
  query: { isLoading: boolean; error: unknown; refetch: () => unknown };
  label: string;
  rows?: number;
  children: () => ReactNode;
}) {
  if (query.isLoading) return <LoadingState label={label} rows={rows} />;
  if (query.error) {
    return <ErrorState error={query.error} onRetry={() => void query.refetch()} compact />;
  }
  return <>{children()}</>;
}

/** A label/value pair rendered inline ("Score 9.4 / 6"). */
export function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <span>{children}</span>
    </span>
  );
}

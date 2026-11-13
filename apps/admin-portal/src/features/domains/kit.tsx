'use client';

import type { UseQueryResult } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { NotFoundView } from '@/components/not-found-view';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ApiError } from '@/lib/api/errors';
import { cn } from '@/lib/utils';

/**
 * Small building blocks shared by the WP4 directory and configuration pages (domains, mail
 * servers, users, roles, integrations). Feature-local by design (§3.6): composites of the shared
 * design-system components, no new visual variants.
 */

export interface FilterOption {
  readonly value: string;
  readonly label: string;
}

const ALL = '__all__';

/** A labelled filter `Select` bound to one URL-state value (`undefined` = every value). */
export function FilterSelect({
  label,
  value,
  onChange,
  options,
  allLabel = 'All',
  className,
}: {
  label: string;
  value: string | undefined;
  onChange: (value: string | undefined) => void;
  options: readonly FilterOption[];
  allLabel?: string;
  className?: string;
}) {
  return (
    <Select
      value={value ?? ALL}
      onValueChange={(next) => onChange(next === ALL ? undefined : next)}
    >
      <SelectTrigger aria-label={label} size="sm" className={cn('min-w-36', className)}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>
          {label}: {allLabel}
        </SelectItem>
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/** A plain `Select` for forms with a visible label (`id` links them). */
export function LabelledSelect({
  id,
  label,
  value,
  onChange,
  options,
  disabled,
  description,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: readonly FilterOption[];
  disabled?: boolean;
  description?: ReactNode;
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Select value={value} onValueChange={onChange} disabled={disabled}>
        <SelectTrigger id={id} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {description ? <p className="text-xs text-muted-foreground">{description}</p> : null}
    </div>
  );
}

/** Key/value pairs of a detail view (`<dl>`). */
export function DetailList({
  items,
  className,
}: {
  items: readonly { readonly label: string; readonly value: ReactNode }[];
  className?: string;
}) {
  return (
    <dl
      className={cn(
        'grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-[minmax(8rem,auto)_1fr]',
        className,
      )}
    >
      {items.map((item) => (
        <div key={item.label} className="contents">
          <dt className="text-xs font-medium text-muted-foreground sm:pt-0.5">{item.label}</dt>
          <dd className="min-w-0 break-words">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A titled section card. */
export function Section({
  title,
  description,
  actions,
  children,
  className,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn('min-w-0', className)}>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="grid min-w-0 gap-1">
          <CardTitle>
            <h2 className="text-base font-semibold">{title}</h2>
          </CardTitle>
          {description ? <CardDescription>{description}</CardDescription> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </CardHeader>
      <CardContent className="grid min-w-0 gap-4 [&>*]:min-w-0">{children}</CardContent>
    </Card>
  );
}

/**
 * Renders one query's states: skeleton, a 404 as the not-found page (another tenant's ids look
 * exactly like missing ones), any other error with code and request id, then the content.
 */
export function QueryView<T>({
  query,
  label,
  children,
  notFound = 'page',
  rows = 4,
}: {
  query: Pick<UseQueryResult<T, ApiError>, 'data' | 'error' | 'isLoading' | 'refetch'>;
  label: string;
  children: (data: T) => ReactNode;
  /** `page` renders the full not-found view; `inline` the error state. */
  notFound?: 'page' | 'inline';
  rows?: number;
}) {
  if (query.isLoading) return <LoadingState label={`Loading ${label}`} rows={rows} />;
  if (query.error) {
    if (notFound === 'page' && query.error instanceof ApiError && query.error.status === 404) {
      return <NotFoundView />;
    }
    return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  }
  if (query.data === undefined) return <LoadingState label={`Loading ${label}`} rows={rows} />;
  return <>{children(query.data)}</>;
}

/** A modal for a focused task (create, edit). */
export function FormDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  wide = false,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={cn('max-h-[90vh] overflow-y-auto', wide && 'sm:max-w-2xl')}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description ? (
            <DialogDescription asChild>
              <div>{description}</div>
            </DialogDescription>
          ) : (
            <DialogDescription className="sr-only">{title}</DialogDescription>
          )}
        </DialogHeader>
        {children}
      </DialogContent>
    </Dialog>
  );
}

/** Error of a mutation shown inside a dialog or panel (code and request id). */
export function MutationError({ error }: { error: ApiError | null }) {
  if (!error) return null;
  return <ErrorState error={error} compact />;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Route ids of UUID resources: anything else is a missing resource (no api call). */
export function isUuid(value: string): boolean {
  return UUID.test(value);
}

/** Splits a textarea of values separated by newlines, commas or semicolons (trimmed, unique). */
export function splitList(text: string): string[] {
  return [
    ...new Set(
      text
        .split(/[\n,;]+/)
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  ];
}

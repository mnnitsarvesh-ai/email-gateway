'use client';

import { ChevronDownIcon, ChevronLeftIcon, ChevronRightIcon } from 'lucide-react';
import { useEffect, useId, useState, type ReactNode } from 'react';
import { ToneBadge } from '@/components/domain/tone-badge';
import { ErrorState } from '@/components/states/error-state';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import type { Tone } from '@/lib/design/tokens';
import { humanize } from '@/lib/format';
import { RANGE_PRESETS, resolvePreset, type RangePreset, type ResolvedRange } from '@/lib/range';
import { cn } from '@/lib/utils';

/**
 * Feature-local filter and layout controls shared by the mail and policy pages (WP5). They
 * wrap the design-system primitives; values come from and go to `useUrlState`.
 */

export interface FilterOption {
  readonly value: string;
  readonly label: string;
}

/** `['a_b', 'c']` → options labelled with `humanize`. */
export function optionsOf(values: readonly string[]): FilterOption[] {
  return values.map((value) => ({ value, label: humanize(value) }));
}

const ANY = '__any';

/** One value or "Any" (Radix Select; the empty choice is the sentinel `__any`). */
export function FilterSelect({
  label,
  value,
  options,
  onChange,
  anyLabel = 'Any',
  allowAny = true,
  className,
}: {
  label: string;
  value: string | undefined;
  options: readonly FilterOption[];
  onChange: (value: string | undefined) => void;
  anyLabel?: string;
  allowAny?: boolean;
  className?: string;
}) {
  const id = useId();
  const current = value ?? (allowAny ? ANY : options[0]?.value);
  return (
    <div className={cn('grid gap-1', className)}>
      <Label htmlFor={id} className="text-xs text-muted-foreground">
        {label}
      </Label>
      <Select value={current} onValueChange={(next) => onChange(next === ANY ? undefined : next)}>
        <SelectTrigger id={id} size="sm" className="min-w-32">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {allowAny ? <SelectItem value={ANY}>{anyLabel}</SelectItem> : null}
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

/** Several values (comma list on the wire), at most `max`. */
export function FilterMultiSelect({
  label,
  values,
  options,
  onChange,
  max,
  className,
}: {
  label: string;
  values: readonly string[];
  options: readonly FilterOption[];
  onChange: (values: string[]) => void;
  max?: number;
  className?: string;
}) {
  const id = useId();
  const summary =
    values.length === 0
      ? 'Any'
      : values.map((v) => options.find((o) => o.value === v)?.label ?? v).join(', ');
  return (
    <div className={cn('grid gap-1', className)}>
      <span id={id} className="text-xs font-medium text-muted-foreground">
        {label}
      </span>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            // Name "<label> <current value>": the visible value is part of the accessible
            // name (WCAG 2.5.3 label in name; axe label-content-name-mismatch, step 7.1 WP6).
            aria-labelledby={`${id} ${id}-value`}
            className="max-w-56 min-w-32 justify-between font-normal"
          >
            <span id={`${id}-value`} className="truncate">
              {summary}
            </span>
            <ChevronDownIcon className="opacity-60" aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start">
          <DropdownMenuLabel>
            {label}
            {max ? ` (at most ${max})` : ''}
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          {options.map((option) => {
            const checked = values.includes(option.value);
            const disabled = !checked && max !== undefined && values.length >= max;
            return (
              <DropdownMenuCheckboxItem
                key={option.value}
                checked={checked}
                disabled={disabled}
                onSelect={(event) => event.preventDefault()}
                onCheckedChange={(next) =>
                  onChange(
                    next === true
                      ? [...values, option.value]
                      : values.filter((v) => v !== option.value),
                  )
                }
              >
                {option.label}
              </DropdownMenuCheckboxItem>
            );
          })}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

/**
 * A free-text filter committed on Enter or blur (not per keystroke: exact-match searches such as
 * sender and recipient are audited by the api, so a half-typed value must not be sent).
 */
export function FilterText({
  label,
  value,
  onCommit,
  placeholder,
  type = 'text',
  inputMode,
  className,
  description,
}: {
  label: string;
  value: string | undefined;
  onCommit: (value: string | undefined) => void;
  placeholder?: string;
  type?: 'text' | 'email' | 'number';
  inputMode?: 'text' | 'email' | 'numeric';
  className?: string;
  description?: string;
}) {
  const id = useId();
  const [text, setText] = useState(value ?? '');
  useEffect(() => setText(value ?? ''), [value]);
  const commit = () => {
    const next = text.trim();
    if (next !== (value ?? '')) onCommit(next === '' ? undefined : next);
  };
  return (
    <div className={cn('grid gap-1', className)}>
      <Label htmlFor={id} className="text-xs text-muted-foreground">
        {label}
      </Label>
      <Input
        id={id}
        type={type}
        inputMode={inputMode}
        value={text}
        placeholder={placeholder}
        onChange={(event) => setText(event.target.value)}
        onBlur={commit}
        onKeyDown={(event) => {
          if (event.key === 'Enter') {
            event.preventDefault();
            commit();
          }
        }}
        className="h-8 min-w-40"
        aria-describedby={description ? `${id}-desc` : undefined}
      />
      {description ? (
        <span id={`${id}-desc`} className="sr-only">
          {description}
        </span>
      ) : null}
    </div>
  );
}

const PRESET_LABEL: Record<RangePreset, string> = {
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
};

/** Range presets for a list with a bounded window; `maxDays` hides presets beyond the bound. */
export function RangeSelect({
  value,
  onChange,
  maxDays,
  label = 'Range',
  className,
}: {
  value: RangePreset;
  onChange: (value: RangePreset) => void;
  maxDays?: number;
  label?: string;
  className?: string;
}) {
  const presets = RANGE_PRESETS.filter(
    (preset) => maxDays === undefined || presetDays(preset) <= maxDays,
  );
  return (
    <FilterSelect
      label={label}
      value={value}
      allowAny={false}
      options={presets.map((preset) => ({ value: preset, label: PRESET_LABEL[preset] }))}
      onChange={(next) => onChange((next as RangePreset | undefined) ?? value)}
      className={className}
    />
  );
}

export function presetDays(preset: RangePreset): number {
  return preset === '24h' ? 1 : preset === '7d' ? 7 : 30;
}

/** The ISO window of a preset (stable within the hour, so query keys do not churn). */
export function windowOf(preset: RangePreset): ResolvedRange {
  return resolvePreset(preset);
}

/** A `<dl>` of label/value rows (detail pages). Values are React nodes; never raw HTML. */
export function DetailList({
  items,
  className,
}: {
  items: readonly {
    readonly label: string;
    readonly value: ReactNode;
    readonly hidden?: boolean;
  }[];
  className?: string;
}) {
  return (
    <dl
      className={cn(
        'grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-[minmax(10rem,auto)_1fr]',
        className,
      )}
    >
      {items
        .filter((item) => !item.hidden)
        .map((item) => (
          <div key={item.label} className="contents">
            <dt className="text-xs font-medium text-muted-foreground sm:pt-0.5">{item.label}</dt>
            <dd className="min-w-0 break-words">{item.value}</dd>
          </div>
        ))}
    </dl>
  );
}

/** Reason codes and other machine codes as small monospace chips. */
export function CodeList({
  codes,
  emptyLabel = 'None',
  label,
}: {
  codes: readonly string[] | null | undefined;
  emptyLabel?: string;
  label?: string;
}) {
  if (!codes || codes.length === 0) {
    return <span className="text-muted-foreground">{emptyLabel}</span>;
  }
  return (
    <ul className="flex flex-wrap gap-1" aria-label={label}>
      {codes.map((code, index) => (
        <li
          key={`${code}-${index}`}
          className="rounded-sm bg-muted px-1.5 py-0.5 font-mono text-xs text-foreground"
        >
          {code}
        </li>
      ))}
    </ul>
  );
}

/** A labelled enum value as a tone badge (unknown values are neutral and printed as-is). */
export function EnumBadge({
  value,
  tones,
  emptyLabel = 'None',
}: {
  value: string | null | undefined;
  tones?: Readonly<Record<string, Tone>>;
  emptyLabel?: string;
}) {
  if (!value) return <span className="text-muted-foreground">{emptyLabel}</span>;
  return <ToneBadge tone={tones?.[value] ?? 'neutral'}>{humanize(value)}</ToneBadge>;
}

/** Yes / No text for booleans (never colour only). */
export function YesNo({ value }: { value: boolean | null | undefined }) {
  if (value === null || value === undefined)
    return <span className="text-muted-foreground">Unknown</span>;
  return <span>{value ? 'Yes' : 'No'}</span>;
}

export interface PagerState {
  readonly page: number;
  readonly hasNext: boolean;
  readonly hasPrevious: boolean;
  readonly isShortPage: boolean;
  readonly next: () => void;
  readonly previous: () => void;
  readonly rowCount: number;
  readonly isFetching: boolean;
}

/** Cursor pagination for non-table lists (Previous pops the cursor stack; no totals). */
export function CursorPager({ label, state }: { label: string; state: PagerState }) {
  return (
    <div className="grid gap-2">
      {state.isShortPage ? (
        <p className="text-xs text-muted-foreground">
          More results may exist further back.{' '}
          <Button variant="link" size="sm" className="h-auto p-0" onClick={state.next}>
            Load next page
          </Button>
        </p>
      ) : null}
      <nav aria-label={`${label} pagination`} className="flex items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground" aria-live="polite">
          Page {state.page} · {state.rowCount} {state.rowCount === 1 ? 'item' : 'items'}
        </p>
        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="sm"
            onClick={state.previous}
            disabled={!state.hasPrevious || state.isFetching}
          >
            <ChevronLeftIcon aria-hidden />
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={state.next}
            disabled={!state.hasNext || state.isFetching}
          >
            Next
            <ChevronRightIcon aria-hidden />
          </Button>
        </div>
      </nav>
    </div>
  );
}

/** A titled section of a detail page. */
export function Section({
  title,
  description,
  actions,
  children,
  className,
  headingLevel = 2,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  headingLevel?: 2 | 3;
}) {
  const id = useId();
  const Heading = headingLevel === 2 ? 'h2' : 'h3';
  return (
    <section
      aria-labelledby={id}
      className={cn('grid gap-3 rounded-lg border bg-card p-4 shadow-xs md:p-5', className)}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="grid gap-0.5">
          <Heading id={id} className="text-base font-semibold">
            {title}
          </Heading>
          {description ? <p className="text-xs text-muted-foreground">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}

/** Inline error of a secondary query inside a section. */
export function SectionError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  return <ErrorState error={error} onRetry={onRetry} compact />;
}

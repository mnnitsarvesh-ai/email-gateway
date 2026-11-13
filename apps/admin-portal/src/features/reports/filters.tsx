'use client';

import { useEffect, useId, useState } from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useDebouncedValue } from '@/hooks/use-debounced-value';
import { cn } from '@/lib/utils';

/**
 * A labelled text filter for a DataTable filter bar: typing is debounced (300 ms) before the
 * value is written to the URL; `validate` returns an error text for values the api would refuse
 * (they are not sent).
 */
export function TextFilter({
  label,
  value,
  onChange,
  placeholder,
  validate,
  normalize = (v) => v.trim(),
  className,
  mono = false,
}: {
  label: string;
  value: string | undefined;
  onChange: (value: string | undefined) => void;
  placeholder?: string;
  validate?: (value: string) => string | null;
  normalize?: (value: string) => string;
  className?: string;
  mono?: boolean;
}) {
  const id = useId();
  const errorId = useId();
  const [text, setText] = useState(value ?? '');
  const debounced = useDebouncedValue(text, 300);
  const normalized = normalize(debounced);
  const error = normalized && validate ? validate(normalized) : null;

  useEffect(() => {
    if (error) return;
    const next = normalized || undefined;
    if (next !== value) onChange(next);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the debounced text drives it
  }, [normalized, error]);

  useEffect(() => {
    // External resets ("Clear filters").
    if ((value ?? '') !== normalize(text)) setText(value ?? '');
    // eslint-disable-next-line react-hooks/exhaustive-deps -- external value only
  }, [value]);

  return (
    <div className={cn('grid gap-1', className)}>
      <Label htmlFor={id} className="text-xs">
        {label}
      </Label>
      <Input
        id={id}
        value={text}
        placeholder={placeholder}
        onChange={(event) => setText(event.target.value)}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? errorId : undefined}
        className={cn('h-8 w-44', mono && 'font-mono text-xs')}
        spellCheck={false}
        autoComplete="off"
      />
      {error ? (
        <p id={errorId} className="text-xs font-medium text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}

/** A labelled select filter; the first option ("All") clears the filter. */
export function SelectFilter<V extends string>({
  label,
  value,
  onChange,
  options,
  allLabel = 'All',
  className,
}: {
  label: string;
  value: V | undefined;
  onChange: (value: V | undefined) => void;
  options: readonly { value: V; label: string }[];
  allLabel?: string;
  className?: string;
}) {
  const id = useId();
  return (
    <div className={cn('grid gap-1', className)}>
      <Label htmlFor={id} className="text-xs">
        {label}
      </Label>
      <Select
        value={value ?? '__all'}
        onValueChange={(next) => onChange(next === '__all' ? undefined : (next as V))}
      >
        <SelectTrigger id={id} size="sm" className="min-w-36">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="__all">{allLabel}</SelectItem>
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

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function validateUuid(value: string): string | null {
  return UUID_PATTERN.test(value) ? null : 'Enter a UUID.';
}

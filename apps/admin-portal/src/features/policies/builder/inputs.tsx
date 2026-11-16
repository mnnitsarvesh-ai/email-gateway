'use client';

import { PlusIcon, XIcon } from 'lucide-react';
import { useId, useState, type ReactNode } from 'react';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { cn } from '@/lib/utils';

/**
 * Small controlled inputs of the builder. They do input hygiene only (design B2): an integer
 * input yields an integer, list items are trimmed and de-duplicated, an empty entry is no value.
 * Whether a value is valid for the DSL is decided by the server.
 */

/** `"42"` → 42; anything that is not a whole number → `null`. */
export function parseInteger(text: string): number | null {
  const trimmed = text.trim();
  if (!/^-?\d+$/.test(trimmed)) return null;
  const n = Number(trimmed);
  return Number.isSafeInteger(n) ? n : null;
}

/**
 * Local text of a controlled input: it follows the external value, except while the text
 * already means that value (so typing "1." or a trailing space is not rewritten).
 */
export function useDraft(external: string, means: (draft: string) => boolean) {
  const [draft, setDraft] = useState(external);
  const [seen, setSeen] = useState(external);
  if (external !== seen) {
    setSeen(external);
    if (!means(draft)) setDraft(external);
  }
  return [draft, setDraft] as const;
}

export function FieldMessage({
  id,
  children,
  tone = 'error',
}: {
  id: string;
  children: ReactNode;
  tone?: 'error' | 'hint';
}) {
  return (
    <p
      id={id}
      className={cn(
        'text-xs',
        tone === 'error' ? 'font-medium text-destructive' : 'text-muted-foreground',
      )}
    >
      {children}
    </p>
  );
}

/** A whole-number input; keeps the last valid number in the model while the text is invalid. */
export function IntegerInput({
  id,
  value,
  onChange,
  min,
  max,
  labelledBy,
  ariaLabel,
  describedBy,
  required = true,
  className,
  disabled,
}: {
  id?: string;
  value: number | undefined;
  onChange: (value: number | undefined) => void;
  min?: number;
  max?: number;
  labelledBy?: string;
  ariaLabel?: string;
  describedBy?: string;
  /** When false, clearing the input clears the value. */
  required?: boolean;
  className?: string;
  disabled?: boolean;
}) {
  const messageId = useId();
  const external = value === undefined ? '' : String(value);
  const [text, setText] = useDraft(external, (draft) => parseInteger(draft) === (value ?? null));
  const invalid = text.trim() === '' ? required : parseInteger(text) === null;
  return (
    <div className="grid gap-1">
      <Input
        id={id}
        type="number"
        inputMode="numeric"
        step={1}
        min={min}
        max={max}
        value={text}
        disabled={disabled}
        aria-labelledby={labelledBy}
        aria-label={ariaLabel}
        aria-invalid={invalid || undefined}
        aria-describedby={
          [describedBy, invalid ? messageId : null].filter(Boolean).join(' ') || undefined
        }
        onChange={(event) => {
          const next = event.target.value;
          setText(next);
          const parsed = parseInteger(next);
          if (parsed !== null) onChange(parsed);
          else if (next.trim() === '' && !required) onChange(undefined);
        }}
        className={cn('h-8', className)}
      />
      {invalid ? <FieldMessage id={messageId}>Enter a whole number.</FieldMessage> : null}
    </div>
  );
}

const UNSET = '__unset';

export interface SelectOption {
  readonly value: string;
  readonly label: string;
}

/** A design-system select; `unsetLabel` adds a choice that clears the value. */
export function ChoiceSelect({
  id,
  value,
  options,
  onChange,
  labelledBy,
  ariaLabel,
  describedBy,
  placeholder = 'Choose …',
  unsetLabel,
  disabled,
  invalid,
  className,
  registerRef,
}: {
  id?: string;
  value: string | undefined;
  options: readonly SelectOption[];
  onChange: (value: string | undefined) => void;
  labelledBy?: string;
  ariaLabel?: string;
  describedBy?: string;
  placeholder?: string;
  unsetLabel?: string;
  disabled?: boolean;
  invalid?: boolean;
  className?: string;
  registerRef?: (element: HTMLElement | null) => void;
}) {
  const known = value === undefined || options.some((o) => o.value === value);
  return (
    <Select
      value={value ?? (unsetLabel ? UNSET : '')}
      onValueChange={(next) => onChange(next === UNSET ? undefined : next)}
      disabled={disabled}
    >
      <SelectTrigger
        id={id}
        ref={registerRef}
        size="sm"
        aria-labelledby={labelledBy}
        aria-label={ariaLabel}
        aria-describedby={describedBy}
        aria-invalid={invalid || undefined}
        className={cn('w-full min-w-0', className)}
      >
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {unsetLabel ? <SelectItem value={UNSET}>{unsetLabel}</SelectItem> : null}
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
        {!known && value !== undefined ? (
          <SelectItem value={value}>{`${value} (not in the catalogue)`}</SelectItem>
        ) : null}
      </SelectContent>
    </Select>
  );
}

/** Several values of a closed vocabulary as checkboxes (unknown current values stay listed). */
export function CheckboxList({
  labelledBy,
  describedBy,
  values,
  options,
  onChange,
  maxItems,
}: {
  labelledBy: string;
  describedBy?: string;
  values: readonly unknown[];
  options: readonly SelectOption[];
  onChange: (values: unknown[]) => void;
  maxItems?: number | null;
}) {
  const baseId = useId();
  const extra = values.filter(
    (v): v is string => typeof v === 'string' && !options.some((o) => o.value === v),
  );
  const all = [
    ...options,
    ...extra.map((v) => ({ value: v, label: `${v} (not in the catalogue)` })),
  ];
  const atMax = maxItems !== null && maxItems !== undefined && values.length >= maxItems;
  return (
    <div
      role="group"
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      className="flex min-w-0 flex-wrap gap-x-4 gap-y-2 py-1"
    >
      {all.map((option, i) => {
        const checked = values.includes(option.value);
        const id = `${baseId}-${i}`;
        return (
          <div key={option.value} className="flex items-center gap-1.5">
            <Checkbox
              id={id}
              checked={checked}
              disabled={!checked && atMax}
              onCheckedChange={(next) =>
                onChange(
                  next === true
                    ? [...values, option.value]
                    : values.filter((v) => v !== option.value),
                )
              }
            />
            <Label htmlFor={id} className="text-sm font-normal">
              {option.label}
            </Label>
          </div>
        );
      })}
    </div>
  );
}

const display = (item: unknown): string =>
  typeof item === 'string' ? item : (JSON.stringify(item) ?? String(item));

/**
 * A list of text items as removable chips with one entry input (Enter or "Add"). Items are
 * trimmed; empty and duplicate entries are ignored; `split` accepts a pasted comma/newline list.
 */
export function ChipsInput({
  labelledBy,
  describedBy,
  items,
  onChange,
  noun = 'value',
  maxItems,
  maxItemLength,
  suggestions,
  placeholder,
  split = false,
  inputRef,
  renderItem,
}: {
  labelledBy: string;
  describedBy?: string;
  items: readonly unknown[];
  onChange: (items: unknown[]) => void;
  noun?: string;
  maxItems?: number | null;
  maxItemLength?: number | null;
  suggestions?: readonly string[] | null;
  placeholder?: string;
  split?: boolean;
  inputRef?: (element: HTMLElement | null) => void;
  renderItem?: (item: unknown) => string;
}) {
  const listId = useId();
  const limitId = useId();
  const [text, setText] = useState('');
  const atMax = maxItems !== null && maxItems !== undefined && items.length >= maxItems;
  const add = () => {
    const entries = (split ? text.split(/[\n,]+/) : [text]).map((t) => t.trim()).filter(Boolean);
    if (entries.length === 0) return;
    const next = [...items];
    for (const entry of entries) {
      if (maxItems !== null && maxItems !== undefined && next.length >= maxItems) break;
      if (!next.includes(entry)) next.push(entry);
    }
    onChange(next);
    setText('');
  };
  const show = renderItem ?? display;
  return (
    <div
      role="group"
      aria-labelledby={labelledBy}
      aria-describedby={describedBy}
      className="grid min-w-0 gap-2"
    >
      <div className="flex min-w-0 gap-2">
        <Input
          ref={inputRef}
          value={text}
          list={suggestions && suggestions.length > 0 ? listId : undefined}
          maxLength={maxItemLength ?? undefined}
          placeholder={placeholder}
          disabled={atMax}
          aria-label={`Add ${noun}`}
          aria-describedby={atMax ? limitId : undefined}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => setText(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              add();
            }
          }}
          className="h-8 min-w-0 flex-1"
        />
        <Button variant="outline" size="sm" onClick={add} disabled={atMax || text.trim() === ''}>
          <PlusIcon aria-hidden />
          Add
        </Button>
      </div>
      {suggestions && suggestions.length > 0 ? (
        <datalist id={listId}>
          {suggestions.map((s) => (
            <option key={s} value={s} />
          ))}
        </datalist>
      ) : null}
      {atMax ? (
        <FieldMessage id={limitId} tone="hint">
          {`At most ${String(maxItems)} ${noun}s.`}
        </FieldMessage>
      ) : null}
      {items.length > 0 ? (
        <ul className="flex min-w-0 flex-wrap gap-1.5" aria-label={`Selected ${noun}s`}>
          {items.map((item, i) => (
            <li
              key={`${display(item)}-${i}`}
              className="inline-flex max-w-full min-w-0 items-center gap-0.5 rounded-md border bg-muted py-0.5 pr-0.5 pl-2 text-xs"
            >
              <span className="min-w-0 font-mono break-all">{show(item)}</span>
              <Button
                variant="ghost"
                size="icon"
                className="size-6"
                aria-label={`Remove ${show(item)}`}
                onClick={() => onChange(items.filter((_, j) => j !== i))}
              >
                <XIcon className="size-3.5" aria-hidden />
              </Button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

/** Toggle buttons (aria-pressed) for a short vocabulary, e.g. weekdays or directions. */
export function ToggleList({
  label,
  options,
  values,
  onChange,
}: {
  label: string;
  options: readonly SelectOption[];
  values: readonly string[];
  onChange: (values: string[]) => void;
}) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-1">
      {options.map((option) => {
        const pressed = values.includes(option.value);
        return (
          <Button
            key={option.value}
            size="sm"
            variant={pressed ? 'default' : 'outline'}
            aria-pressed={pressed}
            className="h-7 px-2"
            onClick={() => {
              if (pressed) {
                onChange(values.filter((v) => v !== option.value));
                return;
              }
              // Catalogue order; values the options do not list are kept at the end.
              const known = options.map((o) => o.value);
              onChange([
                ...known.filter((v) => v === option.value || values.includes(v)),
                ...values.filter((v) => !known.includes(v)),
              ]);
            }}
          >
            {option.label}
          </Button>
        );
      })}
    </div>
  );
}

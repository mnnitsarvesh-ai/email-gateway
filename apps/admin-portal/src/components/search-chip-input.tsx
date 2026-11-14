'use client';

import { SearchIcon, XIcon } from 'lucide-react';
import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { cn } from '@/lib/utils';

export type SearchValidation =
  { readonly ok: true; readonly value: string } | { readonly ok: false; readonly message: string };

/** One searchable field: its label and the validator that also normalizes the value. */
export interface SearchChipField {
  readonly id: string;
  /** Option and chip label, e.g. "Sender (envelope)". */
  readonly label: string;
  readonly placeholder?: string;
  /** One sentence under the input while this field is selected. */
  readonly hint?: string;
  readonly inputMode?: 'text' | 'email';
  readonly validate: (raw: string) => SearchValidation;
}

export interface SearchChip {
  readonly fieldId: string;
  readonly value: string;
}

/** Idle time before a valid value commits (step 7.2 §2 E10). */
export const SEARCH_COMMIT_DELAY_MS = 600;

/**
 * Search bar with a field selector, one input and the committed searches as removable chips
 * (step 7.2 §2 E10). A value commits on Enter or after `debounceMs` without typing, **only when
 * the field's validator passes**, and an unchanged value never commits again, so no request is
 * made per keystroke. The input edits the selected field's search: choosing a field (or a chip)
 * loads its committed value. Chip values are attacker-controlled text and render as text.
 */
export function SearchChipInput({
  fields,
  chips,
  onCommit,
  onRemove,
  label = 'Search',
  debounceMs = SEARCH_COMMIT_DELAY_MS,
  assist,
  status,
  className,
}: {
  fields: readonly SearchChipField[];
  chips: readonly SearchChip[];
  onCommit: (fieldId: string, value: string) => void;
  onRemove: (fieldId: string) => void;
  label?: string;
  debounceMs?: number;
  /** Extra action for the current input (e.g. "Open message" for an id). */
  assist?: (fieldId: string, text: string) => ReactNode;
  /** Inline status under the search (refusals of the api, shown next to the search). */
  status?: ReactNode;
  className?: string;
}) {
  const labelId = useId();
  const inputId = useId();
  const hintId = useId();
  const messageId = useId();
  const [fieldId, setFieldId] = useState(fields[0]?.id ?? '');
  const field = fields.find((f) => f.id === fieldId) ?? fields[0];
  const committed = chips.find((chip) => chip.fieldId === field?.id)?.value ?? '';
  const [text, setText] = useState(committed);
  const [message, setMessage] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const seen = useRef({ fieldId: field?.id, committed });

  // External changes of the committed value (URL, "Clear filters", an applied view) reach the
  // input; our own commits arrive here too and leave the text as typed.
  useEffect(() => {
    if (seen.current.fieldId === field?.id && seen.current.committed === committed) return;
    const sameField = seen.current.fieldId === field?.id;
    seen.current = { fieldId: field?.id, committed };
    if (!sameField || committed !== normalized(field, text)) {
      setText(committed);
      setMessage(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only external changes drive it
  }, [committed, field?.id]);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  const cancelTimer = () => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
  };

  const attempt = (raw: string) => {
    cancelTimer();
    if (!field) return;
    const trimmed = raw.trim();
    if (trimmed === '') {
      setMessage(null);
      return;
    }
    const result = field.validate(trimmed);
    if (!result.ok) {
      setMessage(result.message);
      return;
    }
    setMessage(null);
    if (result.value === committed) return;
    seen.current = { fieldId: field.id, committed: result.value };
    onCommit(field.id, result.value);
  };

  const chooseField = (id: string) => {
    cancelTimer();
    setFieldId(id);
    setMessage(null);
    const value = chips.find((chip) => chip.fieldId === id)?.value ?? '';
    seen.current = { fieldId: id, committed: value };
    setText(value);
  };

  const describedBy = [field?.hint ? hintId : null, message ? messageId : null]
    .filter(Boolean)
    .join(' ');

  return (
    <div className={cn('grid min-w-0 gap-2', className)} role="search" aria-labelledby={labelId}>
      <span id={labelId} className="text-xs font-medium text-muted-foreground">
        {label}
      </span>
      <div className="flex min-w-0 flex-wrap items-start gap-2">
        <Select value={field?.id} onValueChange={chooseField}>
          <SelectTrigger size="sm" aria-label="Search field" className="min-w-44">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {fields.map((f) => (
              <SelectItem key={f.id} value={f.id}>
                {f.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="relative min-w-48 flex-1 sm:max-w-md">
          <SearchIcon
            className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            id={inputId}
            type="search"
            inputMode={field?.inputMode}
            autoComplete="off"
            spellCheck={false}
            aria-label={`Search by ${field?.label ?? 'value'}`}
            aria-describedby={describedBy || undefined}
            aria-invalid={message ? true : undefined}
            placeholder={field?.placeholder}
            value={text}
            onChange={(event) => {
              const next = event.target.value;
              setText(next);
              setMessage(null);
              cancelTimer();
              timer.current = setTimeout(() => attempt(next), debounceMs);
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault();
                attempt(text);
              }
            }}
            className="h-8 pl-8"
          />
        </div>
        {field && assist ? assist(field.id, text.trim()) : null}
      </div>
      {field?.hint ? (
        <p id={hintId} className="text-xs text-muted-foreground">
          {field.hint}
        </p>
      ) : null}
      <p
        id={messageId}
        aria-live="polite"
        className={cn('text-xs font-medium text-destructive', !message && 'sr-only')}
      >
        {message ?? ''}
      </p>
      {status}
      {chips.length > 0 ? (
        <ul className="flex min-w-0 flex-wrap gap-1.5" aria-label="Active searches">
          {chips.map((chip) => {
            const chipField = fields.find((f) => f.id === chip.fieldId);
            const name = chipField?.label ?? chip.fieldId;
            return (
              <li
                key={chip.fieldId}
                className="inline-flex max-w-full min-w-0 items-center gap-0.5 rounded-md border bg-muted py-0.5 pr-0.5 pl-2 text-xs"
              >
                <button
                  type="button"
                  className="inline-flex min-w-0 items-center gap-1 rounded-sm text-left hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                  onClick={() => chooseField(chip.fieldId)}
                >
                  <span className="sr-only">Edit search</span>{' '}
                  <span className="font-medium whitespace-nowrap">{name}:</span>{' '}
                  <UntrustedText value={chip.value} maxLength={60} />
                </button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-6"
                  aria-label={`Remove search ${name}`}
                  onClick={() => {
                    if (chip.fieldId === field?.id) {
                      cancelTimer();
                      setText('');
                      setMessage(null);
                      seen.current = { fieldId: field.id, committed: '' };
                    }
                    onRemove(chip.fieldId);
                  }}
                >
                  <XIcon className="size-3.5" aria-hidden />
                </Button>
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}

function normalized(field: SearchChipField | undefined, text: string): string {
  if (!field) return text;
  const result = field.validate(text.trim());
  return result.ok ? result.value : text.trim();
}

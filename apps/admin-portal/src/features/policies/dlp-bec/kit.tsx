'use client';

import { AlertCircleIcon, ShieldAlertIcon } from 'lucide-react';
import { useCallback, useId, useState, type ReactNode } from 'react';
import type { Control, FieldPath, FieldValues } from 'react-hook-form';
import { toast } from 'sonner';
import { CopyButton } from '@/components/copy-button';
import type { DataTableList } from '@/components/data-table';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { emitSessionEvent } from '@/lib/session/events';
import { cn } from '@/lib/utils';
import type { Problem } from './errors';
import { linesOf } from './model';

/**
 * Feature-local building blocks of the DLP and BEC editors (step 7.3 WP5): composites of the
 * design-system components, no new visual variants (design §2 B14: labelled native controls,
 * sheets full width below 640 px, errors linked to their inputs).
 */

/** A side sheet for one editing task: full width on phones, a panel from 640 px. */
export function EditorSheet({
  open,
  onOpenChange,
  title,
  description,
  wide = false,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  wide?: boolean;
  children: ReactNode;
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className={cn('w-full gap-0 overflow-y-auto', wide ? 'sm:max-w-3xl' : 'sm:max-w-xl')}
      >
        <SheetHeader className="pr-12">
          <SheetTitle>{title}</SheetTitle>
          {description ? (
            <SheetDescription asChild>
              <div>{description}</div>
            </SheetDescription>
          ) : (
            <SheetDescription className="sr-only">{title}</SheetDescription>
          )}
        </SheetHeader>
        <div className="grid min-w-0 gap-4 px-4 pb-6 [&>*]:min-w-0">{children}</div>
      </SheetContent>
    </Sheet>
  );
}

/** Code and request ID of an API error (with copy). */
export function ErrorCodes({ code, requestId }: { code: string; requestId: string | null }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] items-center gap-x-3 gap-y-1 text-xs">
      <dt>Code</dt>
      <dd className="font-mono">{code}</dd>
      {requestId ? (
        <>
          <dt>Request ID</dt>
          <dd className="flex min-w-0 items-center gap-1 font-mono">
            <span className="truncate">{requestId}</span>
            <CopyButton value={requestId} label="Copy request ID" />
          </dd>
        </>
      ) : null}
    </dl>
  );
}

/**
 * The problem of a failed write at the top of a form or inside a confirmation: the sentences, the
 * API code and request ID, "Load the current version" after a version conflict and the MFA state.
 */
export function FormAlert({
  problem,
  onReload,
}: {
  problem: Problem | null;
  onReload?: () => void;
}) {
  if (!problem) return null;
  if (problem.mfa) return <MfaRequiredNotice requestId={problem.error.requestId} />;
  return (
    <div
      role="alert"
      className="flex gap-2 rounded-md border border-destructive/40 bg-tone-danger px-3 py-2 text-sm text-tone-danger-foreground"
    >
      <AlertCircleIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="grid min-w-0 gap-2">
        {problem.messages.map((message, index) => (
          <p key={index}>{message}</p>
        ))}
        <ErrorCodes code={problem.error.code} requestId={problem.error.requestId} />
        {problem.conflict && onReload ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="justify-self-start"
            onClick={onReload}
          >
            Load the current version
          </Button>
        ) : null}
      </div>
    </div>
  );
}

/**
 * "Requires a session with multi-factor authentication" (`403 mfa_required`, `@RequireMfa()`
 * routes): shown before the action when the session has no MFA, and after a refusal.
 */
export function MfaRequiredNotice({
  action = 'This action',
  requestId = null,
}: {
  action?: string;
  requestId?: string | null;
}) {
  return (
    <div
      role="note"
      aria-label="Multi-factor authentication required"
      className="flex gap-2 rounded-md border border-border bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground"
    >
      <ShieldAlertIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="grid min-w-0 gap-2">
        <p className="font-medium">Requires a session with multi-factor authentication</p>
        <p>
          {action} is allowed only in a session signed in with multi-factor authentication (MFA).
          Your current session was not. Sign in again with your authenticator code.
        </p>
        <ErrorCodes code="mfa_required" requestId={requestId} />
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="justify-self-start"
          onClick={() => emitSessionEvent({ type: 'mfa-required' })}
        >
          Sign in again with MFA
        </Button>
      </div>
    </div>
  );
}

/** The submit row of an editor: disabled while pending and during a `429` countdown. */
export function SubmitRow({
  label,
  pending,
  retryAfterSeconds = 0,
  onCancel,
}: {
  label: string;
  pending: boolean;
  retryAfterSeconds?: number;
  onCancel: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button type="submit" disabled={pending || retryAfterSeconds > 0}>
        {pending ? 'Saving …' : label}
      </Button>
      <Button type="button" variant="outline" onClick={onCancel}>
        Cancel
      </Button>
      {retryAfterSeconds > 0 ? (
        <p className="text-xs text-muted-foreground" aria-live="polite">
          Try again in {retryAfterSeconds} s.
        </p>
      ) : null}
    </div>
  );
}

/** A section's intro line and its actions (wraps on phones). */
export function SectionToolbar({
  children,
  actions,
}: {
  children?: ReactNode;
  actions?: ReactNode;
}) {
  if (!children && !actions) return null;
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="min-w-0 text-sm text-muted-foreground">{children}</div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** A plain array as a `DataTable` list (one page, the query states of its source). */
export function staticList<Row>(
  rows: readonly Row[],
  query: DataTableList<Row>['query'],
): DataTableList<Row> {
  return {
    rows,
    page: 1,
    hasNext: false,
    hasPrevious: false,
    isShortPage: false,
    next: () => undefined,
    previous: () => undefined,
    query,
  };
}

/**
 * Editors work on a snapshot of the entry taken when they open (a background refetch never
 * replaces what the user is editing, nor the `version` a save is based on). After
 * `409 version_conflict` the user asks for the current version: this refetches the list (or
 * detail) and returns the entry with `id`, or `undefined` when it is no longer listed.
 */
export async function refetchEntry<Row extends { id: string }>(
  refetch: () => Promise<{ data?: unknown }>,
  id: string,
  pick: (data: unknown) => readonly Row[] = (data) =>
    (data as { data?: Row[] } | undefined)?.data ?? [],
): Promise<Row | undefined> {
  const result = await refetch();
  return pick(result.data).find((row) => row.id === id);
}

/** The editor of a section: closed, creating, or editing a snapshot of one entry. */
export type EditorState<Row> = { mode: 'create' } | { mode: 'edit'; row: Row } | null;

/**
 * Editor state with the snapshot rule of `refetchEntry`: `reload()` replaces the snapshot with
 * the current version (or closes the editor with a message when the entry is gone).
 */
export function useEntryEditor<Row extends { id: string }>(
  refetch: () => Promise<{ data?: unknown }>,
  pick?: (data: unknown) => readonly Row[],
) {
  const [editor, setEditor] = useState<EditorState<Row>>(null);
  const editingId = editor?.mode === 'edit' ? editor.row.id : null;
  const reload = useCallback(async () => {
    if (!editingId) return;
    const fresh = await refetchEntry(refetch, editingId, pick);
    if (fresh) {
      setEditor({ mode: 'edit', row: fresh });
    } else {
      setEditor(null);
      toast.error('It is no longer listed: it may have been deleted meanwhile.');
    }
  }, [editingId, pick, refetch]);
  const close = useCallback(() => setEditor(null), []);
  return { editor, setEditor, reload, close };
}

/**
 * The entry a confirmation acts on (delete), snapshotted when the dialog opens: the `version` sent
 * is the one the user saw. After `409 version_conflict` (shown in the dialog) `refresh()` takes
 * the current version, so a second, explicit confirm applies to it.
 */
export function useEntryTarget<Row extends { id: string }>(
  refetch: () => Promise<{ data?: unknown }>,
  pick?: (data: unknown) => readonly Row[],
) {
  const [target, setTarget] = useState<Row | null>(null);
  const targetId = target?.id ?? null;
  const refresh = useCallback(async () => {
    if (!targetId) return;
    const fresh = await refetchEntry(refetch, targetId, pick);
    setTarget((current) => (current?.id === targetId ? (fresh ?? null) : current));
  }, [pick, refetch, targetId]);
  return { target, setTarget, refresh };
}

// ---------------------------------------------------------------------------------------------
// Fields bound to react-hook-form (labels visible, "(required)" in text, messages linked).
// ---------------------------------------------------------------------------------------------

interface FieldProps<T extends FieldValues> {
  control: Control<T>;
  name: FieldPath<T>;
  label: string;
  hint?: ReactNode;
  required?: boolean;
  disabled?: boolean;
}

export function TextField<T extends FieldValues>({
  control,
  name,
  label,
  hint,
  required,
  disabled,
  mono,
  type = 'text',
  inputMode,
  maxLength,
}: FieldProps<T> & {
  mono?: boolean;
  type?: 'text' | 'email' | 'date';
  inputMode?: 'text' | 'numeric' | 'decimal' | 'email';
  maxLength?: number;
}) {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel required={required}>{label}</FormLabel>
          <FormControl>
            <Input
              {...field}
              value={String(field.value ?? '')}
              type={type}
              inputMode={inputMode}
              maxLength={maxLength}
              autoComplete="off"
              spellCheck={false}
              disabled={disabled}
              className={mono ? 'font-mono text-xs' : undefined}
            />
          </FormControl>
          {hint ? <FormDescription>{hint}</FormDescription> : null}
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

export function TextareaField<T extends FieldValues>({
  control,
  name,
  label,
  hint,
  required,
  disabled,
  mono,
  rows = 3,
}: FieldProps<T> & { mono?: boolean; rows?: number }) {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel required={required}>{label}</FormLabel>
          <FormControl>
            <Textarea
              {...field}
              value={String(field.value ?? '')}
              rows={rows}
              spellCheck={false}
              disabled={disabled}
              className={mono ? 'font-mono text-xs' : undefined}
            />
          </FormControl>
          {hint ? <FormDescription>{hint}</FormDescription> : null}
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

/** A "one per line" list with its live count. */
export function LinesField<T extends FieldValues>({
  control,
  name,
  label,
  hint,
  required,
  max,
  noun,
  mono,
  rows = 4,
}: FieldProps<T> & { max: number; noun: string; mono?: boolean; rows?: number }) {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => {
        const count = linesOf(String(field.value ?? '')).length;
        return (
          <FormItem>
            <FormLabel required={required}>{label}</FormLabel>
            <FormControl>
              <Textarea
                {...field}
                value={String(field.value ?? '')}
                rows={rows}
                spellCheck={false}
                className={mono ? 'font-mono text-xs' : undefined}
              />
            </FormControl>
            <FormDescription>
              {hint ? <>{hint} </> : null}One per line ({count} of at most {max} {noun}).
            </FormDescription>
            <FormMessage />
          </FormItem>
        );
      }}
    />
  );
}

export interface ChoiceOption {
  readonly value: string;
  readonly label: string;
  /** A machine code shown after the label (detector id, reason code). */
  readonly code?: string;
}

/** A labelled native `<select>` (keyboard and phone friendly). */
export function SelectField<T extends FieldValues>({
  control,
  name,
  label,
  hint,
  required,
  disabled,
  options,
  emptyOption,
}: FieldProps<T> & { options: readonly ChoiceOption[]; emptyOption?: string }) {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel required={required}>{label}</FormLabel>
          <FormControl>
            <select
              name={field.name}
              ref={field.ref}
              value={String(field.value ?? '')}
              onChange={(event) => field.onChange(event.target.value)}
              onBlur={field.onBlur}
              disabled={disabled}
              className="h-9 w-full min-w-0 rounded-md border border-input bg-card px-2 text-sm text-foreground shadow-xs outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/40 disabled:opacity-50 aria-invalid:border-destructive"
            >
              {emptyOption !== undefined ? <option value="">{emptyOption}</option> : null}
              {options.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </FormControl>
          {hint ? <FormDescription>{hint}</FormDescription> : null}
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

/** An on/off setting (`role="switch"`) with its label beside it. */
export function SwitchField<T extends FieldValues>({
  control,
  name,
  label,
  hint,
  disabled,
}: FieldProps<T>) {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <div className="flex items-center gap-3">
            <FormControl>
              <Switch
                ref={field.ref}
                checked={field.value === true}
                onCheckedChange={(value) => field.onChange(value)}
                onBlur={field.onBlur}
                disabled={disabled}
              />
            </FormControl>
            <FormLabel className="font-normal">{label}</FormLabel>
          </div>
          {hint ? <FormDescription>{hint}</FormDescription> : null}
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

/** A single checkbox (a statement the user confirms or a flag). */
export function CheckboxField<T extends FieldValues>({
  control,
  name,
  label,
  hint,
  disabled,
}: FieldProps<T>) {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <div className="flex items-start gap-2">
            <FormControl>
              <Checkbox
                ref={field.ref}
                checked={field.value === true}
                onCheckedChange={(value) => field.onChange(value === true)}
                onBlur={field.onBlur}
                disabled={disabled}
                className="mt-0.5"
              />
            </FormControl>
            <FormLabel className="leading-snug font-normal">{label}</FormLabel>
          </div>
          {hint ? <FormDescription>{hint}</FormDescription> : null}
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

/**
 * Several values of a list as checkboxes in a `fieldset` named by its legend. Values the options
 * do not know (a deleted pattern still selected by a rule) stay selected until unchecked.
 */
export function ChecklistField<T extends FieldValues>({
  control,
  name,
  legend,
  hint,
  options,
  columns = 2,
  disabled,
}: {
  control: Control<T>;
  name: FieldPath<T>;
  legend: string;
  hint?: ReactNode;
  options: readonly ChoiceOption[];
  columns?: 1 | 2 | 3;
  disabled?: boolean;
}) {
  const baseId = useId();
  return (
    <FormField
      control={control}
      name={name}
      render={({ field, fieldState }) => {
        const current = Array.isArray(field.value) ? (field.value as string[]) : [];
        const known = new Set(options.map((option) => option.value));
        const unknown = current.filter((value) => !known.has(value));
        const all: ChoiceOption[] = [
          ...options,
          ...unknown.map((value) => ({
            value,
            label: 'Not found (deleted or not loaded)',
            code: value,
          })),
        ];
        const toggle = (value: string, on: boolean) => {
          const order = all.map((option) => option.value);
          const next = new Set(current);
          if (on) next.add(value);
          else next.delete(value);
          field.onChange(order.filter((v) => next.has(v)));
        };
        const hintId = `${baseId}-hint`;
        const errorId = `${baseId}-error`;
        const describedBy =
          [hint ? hintId : null, fieldState.error ? errorId : null].filter(Boolean).join(' ') ||
          undefined;
        return (
          <fieldset className="grid min-w-0 gap-2" aria-describedby={describedBy}>
            <legend className="mb-1 text-sm font-medium">{legend}</legend>
            {hint ? (
              <p id={hintId} className="text-xs text-muted-foreground">
                {hint}
              </p>
            ) : null}
            <div
              className={cn(
                'grid gap-x-4 gap-y-2',
                columns === 2 && 'sm:grid-cols-2',
                columns === 3 && 'sm:grid-cols-3',
              )}
            >
              {all.map((option, index) => {
                const id = `${baseId}-${index}`;
                return (
                  <div key={option.value} className="flex min-w-0 items-start gap-2">
                    <Checkbox
                      id={id}
                      ref={index === 0 ? field.ref : undefined}
                      checked={current.includes(option.value)}
                      onCheckedChange={(value) => toggle(option.value, value === true)}
                      disabled={disabled}
                      className="mt-0.5"
                    />
                    <Label
                      htmlFor={id}
                      className="block min-w-0 leading-snug font-normal break-words"
                    >
                      {option.label}
                      {option.code ? (
                        <>
                          {' '}
                          <span className="font-mono text-xs text-muted-foreground">
                            {option.code}
                          </span>
                        </>
                      ) : null}
                    </Label>
                  </div>
                );
              })}
            </div>
            {fieldState.error ? (
              <p id={errorId} className="text-xs font-medium text-destructive">
                {fieldState.error.message}
              </p>
            ) : null}
          </fieldset>
        );
      }}
    />
  );
}

/** A group of related inputs with a visible heading. */
export function FieldGroup({
  legend,
  description,
  children,
}: {
  legend: string;
  description?: ReactNode;
  children: ReactNode;
}) {
  return (
    <fieldset className="grid min-w-0 gap-4 rounded-md border p-3 [&>*]:min-w-0">
      <legend className="px-1 text-sm font-semibold">{legend}</legend>
      {description ? <p className="text-xs text-muted-foreground">{description}</p> : null}
      {children}
    </fieldset>
  );
}

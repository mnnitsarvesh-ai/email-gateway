'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import Link from 'next/link';
import { useEffect, useId, useState, type ReactNode } from 'react';
import { useForm } from 'react-hook-form';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { FormErrorSummary } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
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
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { type ApiError } from '@/lib/api/errors';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { ReportSection } from '@/features/reports/report-state';
import {
  ENGINE_LABELS,
  engineFields,
  engineFormDefaults,
  engineFormSchema,
  engineSettingsBody,
  fieldKey,
  formatSetting,
  getPath,
  type EngineField,
  type EngineFormValues,
  type EngineName,
  type EngineView,
} from './scan-engine-fields';

/** `/settings?tab=scanning`: every engine's settings; editable with `scan:settings_manage`. */
export function ScanSettingsPanel() {
  const query = useApiQuery('ScanSettingsController_list_v1');
  const canEdit = useCan('ScanSettingsController_replace_v1');
  if (query.isLoading) return <LoadingState label="Loading scan settings" rows={8} />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return null;
  return (
    <div className="grid gap-4">
      <p className="text-sm text-muted-foreground">{query.data.note}</p>
      {query.data.data.map((view) => (
        <EngineCard
          key={view.engine}
          view={view}
          canEdit={canEdit}
          onConflict={() => void query.refetch()}
        />
      ))}
    </div>
  );
}

function EngineMeta({ view }: { view: EngineView }) {
  return (
    <span className="flex flex-wrap items-center gap-2">
      {view.required ? <ToneBadge tone="info">Required engine</ToneBadge> : null}
      {view.override ? (
        view.overrideApplied ? (
          <ToneBadge tone="purple">Your override applies</ToneBadge>
        ) : (
          <ToneBadge tone="warning">Stored override not applied</ToneBadge>
        )
      ) : (
        <ToneBadge tone="neutral">Platform settings</ToneBadge>
      )}
      <span>Version {view.version}</span>
      {view.updatedAt ? (
        <span>
          · Changed <DateTime value={view.updatedAt} />
        </span>
      ) : null}
    </span>
  );
}

function Violations({ view }: { view: EngineView }) {
  if (view.violations.length === 0) return null;
  return (
    <div
      role="note"
      className="rounded-md bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground"
    >
      <p className="font-medium">
        The stored override no longer fits the platform bounds and is ignored:
      </p>
      <ul className="list-disc pl-5">
        {view.violations.map((v) => (
          <li key={`${v.path}-${v.code}`}>
            <span className="font-mono">{v.path}</span>: {v.message}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Read-only list of the effective values (overridden ones marked). */
export function EngineSummary({ view }: { view: EngineView }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-1.5 text-sm sm:grid-cols-[minmax(12rem,auto)_1fr]">
      {view.engine === 'sandbox' ? (
        <div className="contents">
          <dt className="text-muted-foreground">Execution</dt>
          <dd>
            {humanize(view.execution)}
            {view.feature.attachmentSandbox ? '' : ' (not part of your plan)'}
          </dd>
        </div>
      ) : null}
      {engineFields(view).map((def) => (
        <div key={def.path} className="contents">
          <dt className="text-muted-foreground">{def.label}</dt>
          <dd className="flex flex-wrap items-center gap-2 break-words">
            <span>{formatSetting(def, getPath(view.effective, def.path))}</span>
            {getPath(view.override, def.path) !== undefined ? (
              <ToneBadge tone="purple">Override</ToneBadge>
            ) : null}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function EngineCard({
  view,
  canEdit,
  onConflict,
}: {
  view: EngineView;
  canEdit: boolean;
  onConflict: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [resetting, setResetting] = useState(false);
  const reset = useApiMutation('ScanSettingsController_reset_v1', {
    successMessage: `${ENGINE_LABELS[view.engine]}: back to the platform settings.`,
    invalidates: ['ScanSettingsController_list_v1'],
  });
  return (
    <ReportSection
      title={ENGINE_LABELS[view.engine]}
      description={<EngineMeta view={view} />}
      actions={
        canEdit ? (
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setEditing((v) => !v)}
              aria-expanded={editing}
            >
              {editing ? 'Close editor' : 'Edit'}
            </Button>
            {view.override ? (
              <Button variant="ghost" size="sm" onClick={() => setResetting(true)}>
                Reset to platform
              </Button>
            ) : null}
          </>
        ) : null
      }
    >
      <Violations view={view} />
      {editing ? (
        <EngineForm view={view} onDone={() => setEditing(false)} onConflict={onConflict} />
      ) : (
        <EngineSummary view={view} />
      )}
      <ConfirmDialog
        open={resetting}
        onOpenChange={(open) => {
          setResetting(open);
          if (!open) reset.reset();
        }}
        title={`Reset ${ENGINE_LABELS[view.engine]}?`}
        description="Your override is removed and the platform settings apply again (workers pick it up within their settings cache time)."
        confirmLabel="Reset to platform"
        destructive
        onConfirm={async () => {
          const outcome = await reset.submit({
            path: { engine: view.engine },
            query: { expectedVersion: view.version },
          });
          if (!outcome.ok && outcome.error.status === 409) onConflict();
          return outcome.ok;
        }}
        error={reset.error ? <ErrorState error={reset.error} compact /> : null}
      />
    </ReportSection>
  );
}

function EngineForm({
  view,
  onDone,
  onConflict,
}: {
  view: EngineView;
  onDone: () => void;
  onConflict: () => void;
}) {
  const fields = engineFields(view);
  const form = useForm<EngineFormValues>({
    mode: 'onSubmit',
    reValidateMode: 'onChange',
    defaultValues: engineFormDefaults(view),
    resolver: zodResolver(engineFormSchema(view) as never) as never,
  });
  const [messages, setMessages] = useState<string[]>([]);
  const mutation = useApiMutation('ScanSettingsController_replace_v1', {
    successMessage: `${ENGINE_LABELS[view.engine]} settings saved.`,
    invalidates: ['ScanSettingsController_list_v1'],
  });
  useEffect(() => {
    form.reset(engineFormDefaults(view));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when a new version arrives
  }, [view.version]);

  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await mutation.submit({
      path: { engine: view.engine },
      body: { expectedVersion: view.version, settings: engineSettingsBody(view, values) },
    });
    if (outcome.ok) {
      onDone();
      return;
    }
    setMessages(
      scanErrorMessages(outcome.error, fields, (path, message) => {
        form.setError(`${fieldKey(path)}.value`, {
          type: 'server',
          message,
        });
      }),
    );
    if (outcome.error.status === 409) onConflict();
  });

  return (
    <form
      onSubmit={(event) => void submit(event)}
      className="grid gap-4"
      noValidate
      aria-label={`${ENGINE_LABELS[view.engine]} settings`}
    >
      <FormErrorSummary messages={messages} requestId={mutation.error?.requestId} />
      <p className="text-xs text-muted-foreground">
        Switch on “Override” for each value your organization sets; the others follow the platform.
      </p>
      <div className="grid gap-3">
        {fields.map((def) => (
          <EngineFieldRow key={def.path} def={def} view={view} form={form} />
        ))}
      </div>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={mutation.isPending || mutation.retryAfterSeconds > 0}>
          {mutation.isPending
            ? 'Saving …'
            : mutation.retryAfterSeconds > 0
              ? `Try again in ${mutation.retryAfterSeconds} s`
              : 'Save override'}
        </Button>
        <Button type="button" variant="outline" onClick={onDone}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

/**
 * `422 scan_settings_invalid` carries `violations: [{ path, code, message }]`: violations on a
 * known field go to that field; the rest and every other error go to the form summary.
 */
export function scanErrorMessages(
  error: ApiError,
  fields: readonly EngineField[],
  setFieldError: (path: string, message: string) => void,
): string[] {
  const violations = Array.isArray(error.details.violations)
    ? (error.details.violations as { path?: unknown; message?: unknown }[])
    : [];
  if (error.status === 422 && violations.length > 0) {
    const rest: string[] = [];
    for (const v of violations) {
      const path = typeof v.path === 'string' ? v.path : '';
      const message = typeof v.message === 'string' ? v.message : 'Invalid value';
      const def = fields.find(
        (f) => path === f.path || path.startsWith(`${f.path}.`) || path.startsWith(`${f.path}[`),
      );
      if (def) setFieldError(def.path, message);
      else rest.push(path ? `${path}: ${message}` : message);
    }
    return rest.length > 0
      ? rest
      : ['Some values are outside what the platform allows; see the fields below.'];
  }
  if (error.status === 409) {
    return [
      `${error.messages.join(' ')} The latest settings were loaded; review them and save again.`,
    ];
  }
  if (error.status === 429 && error.retryAfterSeconds) {
    return [`Too many requests. Try again in ${error.retryAfterSeconds} s.`];
  }
  return error.messages;
}

function EngineFieldRow({
  def,
  view,
  form,
}: {
  def: EngineField;
  view: EngineView;
  form: ReturnType<typeof useForm<EngineFormValues>>;
}) {
  const key = fieldKey(def.path);
  const id = useId();
  const state = form.watch(key);
  const error = form.formState.errors[key]?.value?.message;
  const on = Boolean(state?.on);
  const platformValue = formatSetting(
    def,
    getPath(view.platform, def.path) ?? getPath(view.effective, def.path),
  );
  const setValue = (value: unknown) =>
    form.setValue(`${key}.value`, value, {
      shouldDirty: true,
      shouldValidate: form.formState.isSubmitted,
    });
  const describedBy = `${id}-hint${error ? ` ${id}-error` : ''}`;
  const f = def.field;
  let control: ReactNode;
  if (f.kind === 'boolean') {
    control = (
      <Switch
        id={id}
        checked={Boolean(state?.value)}
        disabled={!on}
        onCheckedChange={(v) => setValue(v)}
        aria-describedby={describedBy}
      />
    );
  } else if (f.kind === 'select') {
    control = (
      <Select
        value={typeof state?.value === 'string' ? state.value : undefined}
        onValueChange={setValue}
        disabled={!on}
      >
        <SelectTrigger
          id={id}
          className="min-w-44"
          aria-describedby={describedBy}
          aria-invalid={error ? true : undefined}
        >
          <SelectValue placeholder="Choose …" />
        </SelectTrigger>
        <SelectContent>
          {f.options.map((option) => (
            <SelectItem key={option} value={option}>
              {humanize(option)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    );
  } else if (f.kind === 'number') {
    control = (
      <Input
        id={id}
        type="number"
        inputMode="decimal"
        min={f.min}
        max={f.max}
        step={f.integer ? 1 : 'any'}
        disabled={!on}
        value={
          typeof state?.value === 'string' || typeof state?.value === 'number'
            ? String(state.value)
            : ''
        }
        onChange={(event) => setValue(event.target.value)}
        aria-describedby={describedBy}
        aria-invalid={error ? true : undefined}
        className="w-44"
      />
    );
  } else if (f.kind === 'domains') {
    control = (
      <Textarea
        id={id}
        rows={3}
        disabled={!on}
        value={typeof state?.value === 'string' ? state.value : ''}
        onChange={(event) => setValue(event.target.value)}
        aria-describedby={describedBy}
        aria-invalid={error ? true : undefined}
        className="max-w-md font-mono text-xs"
        spellCheck={false}
      />
    );
  } else {
    const selected = Array.isArray(state?.value) ? (state.value as string[]) : [];
    control = (
      <fieldset
        id={id}
        aria-describedby={describedBy}
        disabled={!on}
        className="grid max-h-48 grid-cols-2 gap-1 overflow-y-auto rounded-md border p-2 sm:grid-cols-3"
      >
        <legend className="sr-only">{def.label}</legend>
        {f.options.map((option) => {
          const optionId = `${id}-${option}`;
          return (
            <div key={option} className="flex items-center gap-1.5">
              <Checkbox
                id={optionId}
                checked={selected.includes(option)}
                disabled={!on}
                onCheckedChange={(checked) =>
                  setValue(
                    checked === true ? [...selected, option] : selected.filter((s) => s !== option),
                  )
                }
              />
              <label htmlFor={optionId} className="text-xs">
                {humanize(option)}
              </label>
            </div>
          );
        })}
      </fieldset>
    );
  }
  return (
    <div className="grid gap-1.5 rounded-md border p-3 sm:grid-cols-[minmax(14rem,18rem)_1fr] sm:gap-4">
      <div className="grid content-start gap-1">
        <Label htmlFor={id} className="leading-snug">
          {def.label}
        </Label>
        <div className="flex items-center gap-2">
          <Checkbox
            id={`${id}-on`}
            aria-label={`Override ${def.label}`}
            checked={on}
            onCheckedChange={(checked) =>
              form.setValue(`${key}.on`, checked === true, {
                shouldDirty: true,
              })
            }
          />
          <label htmlFor={`${id}-on`} className="text-xs">
            Override
          </label>
        </div>
      </div>
      <div className="grid content-start gap-1">
        {control}
        <p id={`${id}-hint`} className="text-xs text-muted-foreground">
          Platform: {platformValue}
          {def.help ? ` · ${def.help}` : ''}
        </p>
        {error ? (
          <p id={`${id}-error`} className="text-xs font-medium text-destructive">
            {String(error)}
          </p>
        ) : null}
      </div>
    </div>
  );
}

/**
 * Read-only engine settings for the URL protection and attachment pages, with a link to the
 * editor (`/settings?tab=scanning`).
 */
export function EngineSettingsReadOnly({ engine }: { engine: EngineName }) {
  const query = useApiQuery('ScanSettingsController_list_v1');
  const canEdit = useCan('ScanSettingsController_replace_v1');
  const view = query.data?.data.find((entry) => entry.engine === engine);
  return (
    <ReportSection
      title={`${ENGINE_LABELS[engine]} engine settings`}
      description={view ? <EngineMeta view={view} /> : undefined}
      actions={
        <Link
          href="/settings?tab=scanning"
          className="text-sm font-medium text-primary hover:underline"
        >
          {canEdit ? 'Change in Settings' : 'View all scan settings'}
        </Link>
      }
    >
      {query.isLoading ? (
        <LoadingState label="Loading engine settings" rows={5} />
      ) : query.error ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} compact />
      ) : view ? (
        <>
          <Violations view={view} />
          <EngineSummary view={view} />
        </>
      ) : (
        <p className="text-sm text-muted-foreground">
          The api reported no settings for this engine.
        </p>
      )}
    </ReportSection>
  );
}

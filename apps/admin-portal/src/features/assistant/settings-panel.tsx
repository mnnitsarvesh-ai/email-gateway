'use client';

import { useEffect, useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { ReportSection } from '@/features/reports/report-state';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber } from '@/lib/format';
import type { AssistantSettings, AssistantUsage } from './types';

/**
 * Settings → AI assistant (step AI-1 D13): `assistant:configure` turns the assistant on for the
 * organization (only with the explicit external-processing acknowledgement and when the platform
 * operator enabled the `ai_assistant` feature), sets the daily token budget and the content
 * retention, and reads the usage of the last 30 days. Saves use `expectedRowVersion` (CAS).
 */

export const ACKNOWLEDGEMENT_TEXT =
  'Conversation text and masked metadata of this organization are processed by the configured external AI provider';
export const RETENTION_MIN_DAYS = 1;
export const RETENTION_MAX_DAYS = 365;
const BUDGET_MAX = Number.MAX_SAFE_INTEGER;
export const USAGE_DAYS = 30;

const optionalBudget = z.preprocess(
  (value) => (value === '' || value === null || value === undefined ? null : value),
  z
    .union([
      z.null(),
      z.coerce
        .number({ message: 'Enter a number of tokens or leave it empty' })
        .int('Enter whole tokens')
        .min(1, 'At least 1 token')
        .max(BUDGET_MAX, 'Too large'),
    ])
    .nullable(),
);

export const assistantSettingsSchema = z
  .object({
    enabled: z.boolean(),
    externalProcessingAcknowledged: z.boolean(),
    dailyTokenBudget: optionalBudget,
    retentionDays: z.coerce
      .number({ message: 'Enter a number of days' })
      .int('Enter whole days')
      .min(RETENTION_MIN_DAYS, `At least ${RETENTION_MIN_DAYS} day`)
      .max(RETENTION_MAX_DAYS, `At most ${RETENTION_MAX_DAYS} days`),
  })
  .strict()
  .superRefine((values, context) => {
    if (values.enabled && !values.externalProcessingAcknowledged) {
      context.addIssue({
        code: 'custom',
        path: ['externalProcessingAcknowledged'],
        message: 'Confirm the external processing before you turn the assistant on.',
      });
    }
  });

type FormInput = z.input<typeof assistantSettingsSchema>;
export type AssistantSettingsValues = z.output<typeof assistantSettingsSchema>;

function defaultsOf(settings: AssistantSettings): FormInput {
  return {
    enabled: settings.enabled,
    externalProcessingAcknowledged: settings.externalProcessingAcknowledged,
    dailyTokenBudget: settings.dailyTokenBudget === null ? '' : String(settings.dailyTokenBudget),
    retentionDays: settings.retentionDays,
  };
}

/** The PUT body (`expectedRowVersion` = the version the form was loaded from). */
export function settingsBody(
  values: AssistantSettingsValues,
  rowVersion: number,
): RequestBody<'AssistantSettingsController_update_v1'> {
  return {
    expectedRowVersion: rowVersion,
    enabled: values.enabled,
    externalProcessingAcknowledged: values.externalProcessingAcknowledged,
    dailyTokenBudget: values.dailyTokenBudget ?? null,
    retentionDays: values.retentionDays,
    dataSharing: 'metadata',
  };
}

function isoDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** `from`/`to` of the last `days` UTC days, today included. */
export function usageRange(
  now: Date = new Date(),
  days = USAGE_DAYS,
): { from: string; to: string } {
  const from = new Date(now.getTime() - (days - 1) * 86_400_000);
  return { from: isoDay(from), to: isoDay(now) };
}

function formatCost(micros: number | null): string {
  if (micros === null) return '—';
  return new Intl.NumberFormat(undefined, {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: 4,
  }).format(micros / 1_000_000);
}

type UsageRow = AssistantUsage['rows'][number];

function UsageTable() {
  const range = useMemo(() => usageRange(), []);
  const usage = useApiQuery('AssistantUsageController_get_v1', { query: range });
  const columns = useMemo<DataTableColumn<UsageRow>[]>(
    () => [
      { id: 'day', header: 'Day (UTC)', cell: ({ row }) => row.original.day },
      {
        id: 'model',
        header: 'Model',
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.provider} / {row.original.model}
          </span>
        ),
      },
      { id: 'turns', header: 'Questions', cell: ({ row }) => formatNumber(row.original.turns) },
      {
        id: 'inputTokens',
        header: 'Input tokens',
        cell: ({ row }) => formatNumber(row.original.inputTokens),
      },
      {
        id: 'outputTokens',
        header: 'Output tokens',
        cell: ({ row }) => formatNumber(row.original.outputTokens),
      },
      {
        id: 'cacheReadTokens',
        header: 'Cache read',
        cell: ({ row }) => formatNumber(row.original.cacheReadTokens),
      },
      {
        id: 'cacheWriteTokens',
        header: 'Cache write',
        cell: ({ row }) => formatNumber(row.original.cacheWriteTokens),
      },
      { id: 'cost', header: 'Cost', cell: ({ row }) => formatCost(row.original.costMicros) },
    ],
    [],
  );
  const rows = useMemo(() => [...(usage.data?.rows ?? [])].reverse(), [usage.data]);
  const totals = usage.data?.totals;
  return (
    <div className="grid gap-2">
      <DataTable<UsageRow>
        tableId="assistant-usage"
        caption={`AI assistant usage from ${range.from} to ${range.to} (UTC)`}
        columns={columns}
        list={{
          rows,
          page: 1,
          hasNext: false,
          hasPrevious: false,
          isShortPage: false,
          next: () => undefined,
          previous: () => undefined,
          query: {
            isLoading: usage.isLoading,
            isFetching: usage.isFetching,
            error: usage.error,
            refetch: () => usage.refetch(),
          },
        }}
        getRowId={(row) => `${row.day}|${row.provider}|${row.model}`}
        emptyState={
          <p className="p-4 text-sm text-muted-foreground">
            No questions were asked in the last {USAGE_DAYS} days.
          </p>
        }
        toolbar={false}
        pagination={false}
      />
      {totals ? (
        <p className="text-sm text-muted-foreground">
          Last {USAGE_DAYS} days: {formatNumber(totals.turns)} questions,{' '}
          {formatNumber(totals.inputTokens)} input and {formatNumber(totals.outputTokens)} output
          tokens{totals.costMicros !== null ? `, ${formatCost(totals.costMicros)}` : ''}.
        </p>
      ) : null}
    </div>
  );
}

export function AssistantSettingsForm({
  settings,
  onReload,
}: {
  settings: AssistantSettings;
  onReload: () => Promise<unknown>;
}) {
  const form = useZodForm(assistantSettingsSchema, { defaultValues: defaultsOf(settings) });
  const [messages, setMessages] = useState<string[]>([]);
  const [conflict, setConflict] = useState(false);
  const mutation = useApiMutation('AssistantSettingsController_update_v1', {
    successMessage: 'AI assistant settings saved.',
    invalidates: ['AssistantSettingsController_get_v1', 'AssistantStatusController_get_v1'],
  });
  useEffect(() => {
    form.reset(defaultsOf(settings));
    setConflict(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when the stored version changes
  }, [settings.rowVersion]);

  const enabled = form.watch('enabled');
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    setConflict(false);
    const outcome = await mutation.submit({ body: settingsBody(values, settings.rowVersion) });
    if (outcome.ok) return;
    if (outcome.error.status === 409 && outcome.error.code === 'assistant_settings_conflict') {
      setConflict(true);
      setMessages([
        'Someone else changed these settings after you opened them. Reload the current settings, then apply your change again.',
      ]);
      return;
    }
    if (outcome.error.code === 'assistant_not_enabled') {
      setMessages([
        'The platform operator has not enabled the AI assistant feature for this organization, so it cannot be turned on.',
      ]);
      return;
    }
    setMessages(applyApiErrors(form, outcome.error));
  });

  return (
    <Form {...form}>
      <form
        onSubmit={(event) => void submit(event)}
        className="grid max-w-2xl gap-5"
        noValidate
        aria-label="AI assistant settings"
      >
        <FormErrorSummary messages={messages} requestId={mutation.error?.requestId} />
        {conflict ? (
          <Button
            type="button"
            variant="outline"
            className="justify-self-start"
            onClick={() => void onReload()}
          >
            Reload the current settings
          </Button>
        ) : null}
        {!settings.featureEnabled ? (
          <p className="rounded-md border border-dashed px-3 py-2 text-sm text-muted-foreground">
            The AI assistant feature is not enabled for this organization. A platform operator
            enables it; until then the assistant cannot be turned on.
          </p>
        ) : null}
        <FormField
          control={form.control}
          name="enabled"
          render={({ field }) => (
            <FormItem className="flex flex-row items-center gap-3">
              <FormControl>
                <Switch
                  checked={field.value}
                  onCheckedChange={field.onChange}
                  disabled={!settings.featureEnabled && !field.value}
                />
              </FormControl>
              <FormLabel>Turn on the AI assistant for this organization</FormLabel>
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="externalProcessingAcknowledged"
          render={({ field }) => (
            <FormItem className="flex flex-row items-start gap-3">
              <FormControl>
                <Checkbox
                  checked={field.value}
                  onCheckedChange={(value) => field.onChange(value === true)}
                  className="mt-0.5"
                />
              </FormControl>
              <div className="grid gap-1">
                <FormLabel required={enabled}>{ACKNOWLEDGEMENT_TEXT}</FormLabel>
                <FormDescription>
                  Required to turn the assistant on. No message bodies or attachments are sent.
                  {settings.externalProcessingAcknowledgedAt ? (
                    <>
                      {' '}
                      Acknowledged <DateTime value={settings.externalProcessingAcknowledgedAt} />.
                    </>
                  ) : null}
                </FormDescription>
                <FormMessage />
              </div>
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="dailyTokenBudget"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Daily token budget</FormLabel>
              <FormControl>
                <Input
                  type="number"
                  inputMode="numeric"
                  min={1}
                  name={field.name}
                  ref={field.ref}
                  onBlur={field.onBlur}
                  value={
                    typeof field.value === 'number' || typeof field.value === 'string'
                      ? String(field.value)
                      : ''
                  }
                  onChange={(event) => field.onChange(event.target.value)}
                  placeholder={String(settings.effectiveDailyTokenBudget)}
                  className="w-48"
                />
              </FormControl>
              <FormDescription>
                Tokens per UTC day for the whole organization. Leave empty for the platform default
                (now {formatNumber(settings.effectiveDailyTokenBudget)}); the platform maximum
                applies.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="retentionDays"
          render={({ field }) => (
            <FormItem>
              <FormLabel required>Conversation retention (days)</FormLabel>
              <FormControl>
                <Input
                  type="number"
                  inputMode="numeric"
                  min={RETENTION_MIN_DAYS}
                  max={RETENTION_MAX_DAYS}
                  name={field.name}
                  ref={field.ref}
                  onBlur={field.onBlur}
                  value={
                    typeof field.value === 'number' || typeof field.value === 'string'
                      ? String(field.value)
                      : ''
                  }
                  onChange={(event) => field.onChange(event.target.value)}
                  className="w-32"
                />
              </FormControl>
              <FormDescription>
                Questions, answers and result cards are deleted this many days after the last
                question of a conversation ({RETENTION_MIN_DAYS} to {RETENTION_MAX_DAYS}).
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <div className="grid gap-1 text-sm">
          <span className="font-medium">Data shared with the AI provider</span>
          <span>Metadata only</span>
          <span className="text-muted-foreground">
            Your questions and masked record metadata (no message bodies or attachments).
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={mutation.isPending || mutation.retryAfterSeconds > 0}>
            {mutation.isPending
              ? 'Saving …'
              : mutation.retryAfterSeconds > 0
                ? `Try again in ${mutation.retryAfterSeconds} s`
                : 'Save settings'}
          </Button>
          {settings.updatedAt ? (
            <span className="text-xs text-muted-foreground">
              Last changed <DateTime value={settings.updatedAt} />
            </span>
          ) : null}
        </div>
      </form>
    </Form>
  );
}

/** The "AI assistant" tab of Settings (gate `AssistantSettingsController_get_v1`). */
export function AssistantSettingsPanel() {
  const settings = useApiQuery('AssistantSettingsController_get_v1');
  const canUsage = useCan('AssistantUsageController_get_v1');
  if (settings.isLoading) return <LoadingState label="Loading AI assistant settings" rows={5} />;
  if (settings.error)
    return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  if (!settings.data) return null;
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <ReportSection title="AI assistant">
        <AssistantSettingsForm settings={settings.data} onReload={() => settings.refetch()} />
      </ReportSection>
      {canUsage ? (
        <ReportSection title={`Usage, last ${USAGE_DAYS} days`} className="xl:col-span-2">
          <UsageTable />
        </ReportSection>
      ) : null}
    </div>
  );
}

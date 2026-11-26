'use client';

import { useEffect, useId, useState } from 'react';
import { z } from 'zod';
import { DateTime } from '@/components/domain/date-time';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { DetailList } from '@/features/domains/kit';
import { ReportSection } from '@/features/reports/report-state';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { formatNumber } from '@/lib/format';
import type { AssistantSettings, DataSharing, EffectiveLimits } from '@/features/assistant/types';
import { DATA_SHARING_HELP, adminErrorText } from './model';
import { TenantKeySection } from './tenant-key';

const optionalTokens = z.preprocess(
  (value) => (value === '' || value === null || value === undefined ? null : value),
  z
    .union([
      z.null(),
      z.coerce
        .number({ message: 'Enter a number of tokens or leave it empty' })
        .int('Enter whole tokens')
        .min(1, 'At least 1 token')
        .max(Number.MAX_SAFE_INTEGER, 'Too large'),
    ])
    .nullable(),
);

export function limitsSchema(settings: Pick<AssistantSettings, 'effectiveLimits'>) {
  const { min, max } = settings.effectiveLimits.retentionDays;
  return z
    .object({
      dailyTokenBudget: optionalTokens,
      userDailyTokenBudget: optionalTokens,
      retentionDays: z.coerce
        .number({ message: 'Enter a number of days' })
        .int('Enter whole days')
        .min(min, `At least ${min} day${min === 1 ? '' : 's'}`)
        .max(max, `At most ${max} days`),
      dataSharing: z.enum(['metadata', 'pseudonymized']),
      useTenantKey: z.boolean(),
      tenantKeyFallbackToPlatform: z.boolean(),
    })
    .strict()
    .superRefine((values, context) => {
      const tenantMax = settings.effectiveLimits.tenantDailyTokensMax;
      if (values.dailyTokenBudget !== null && values.dailyTokenBudget > tenantMax)
        context.addIssue({
          code: 'custom',
          path: ['dailyTokenBudget'],
          message: `At most ${formatNumber(tenantMax)} tokens (the platform maximum)`,
        });
    });
}

type LimitsSchema = ReturnType<typeof limitsSchema>;
type FormInput = z.input<LimitsSchema>;
export type LimitsValues = z.output<LimitsSchema>;

function defaultsOf(settings: AssistantSettings): FormInput {
  return {
    dailyTokenBudget: settings.dailyTokenBudget === null ? '' : String(settings.dailyTokenBudget),
    userDailyTokenBudget:
      settings.userDailyTokenBudget === null ? '' : String(settings.userDailyTokenBudget),
    retentionDays: settings.retentionDays,
    dataSharing: settings.dataSharing,
    useTenantKey: settings.useTenantKey,
    tenantKeyFallbackToPlatform: settings.tenantKeyFallbackToPlatform,
  };
}

/**
 * The PUT body: the enable switch and the acknowledgement are sent unchanged (Settings → AI
 * assistant owns them), everything this tab edits explicitly.
 */
export function limitsBody(
  values: LimitsValues,
  settings: AssistantSettings,
): RequestBody<'AssistantSettingsController_update_v1'> {
  return {
    expectedRowVersion: settings.rowVersion,
    enabled: settings.enabled,
    externalProcessingAcknowledged: settings.externalProcessingAcknowledged,
    dailyTokenBudget: values.dailyTokenBudget ?? null,
    retentionDays: values.retentionDays,
    dataSharing: values.dataSharing,
    userDailyTokenBudget: values.userDailyTokenBudget ?? null,
    useTenantKey: values.useTenantKey,
    tenantKeyFallbackToPlatform: values.tenantKeyFallbackToPlatform,
  };
}

function seconds(value: number): string {
  if (value % 3600 === 0) return `${value / 3600} h`;
  if (value % 60 === 0) return `${value / 60} min`;
  return `${value} s`;
}

/** The read-only effective limits (D1). */
export function EffectiveLimitsList({ limits }: { limits: EffectiveLimits }) {
  return (
    <DetailList
      items={[
        {
          label: 'Questions per person',
          value: `${formatNumber(limits.turnsPerUserPerMinute)} per minute`,
        },
        { label: 'Message length', value: `${formatNumber(limits.messageMaxChars)} characters` },
        {
          label: 'Tools per answer',
          value: `${formatNumber(limits.toolCallsPerTurn)} calls in ${formatNumber(limits.toolRoundsPerTurn)} rounds`,
        },
        { label: 'Answer time limit', value: seconds(limits.turnDeadlineSeconds) },
        {
          label: 'Platform daily cap',
          value: limits.platformDailyCapSet ? 'Set by the platform' : 'None',
        },
        {
          label: 'Highest organization budget',
          value: `${formatNumber(limits.tenantDailyTokensMax)} tokens per day`,
        },
        {
          label: 'Reports per person',
          value: `${formatNumber(limits.reportsPerUserPerDay)} per day`,
        },
        {
          label: 'Report emails',
          value: `${formatNumber(limits.reportEmailsPerUserPerDay)} per person, ${formatNumber(limits.reportEmailsPerTenantPerDay)} per organization per day`,
        },
        { label: 'Confirmation validity', value: seconds(limits.confirmationTtlSeconds) },
        {
          label: 'Retention bounds',
          value: `${limits.retentionDays.min} to ${limits.retentionDays.max} days`,
        },
      ]}
    />
  );
}

const DATA_SHARING_OPTIONS: ReadonlyArray<{ value: DataSharing; label: string }> = [
  { value: 'metadata', label: 'Metadata (values as they are)' },
  { value: 'pseudonymized', label: 'Pseudonymized (placeholders for personal data)' },
];

function numberField(value: unknown): string {
  return typeof value === 'number' || typeof value === 'string' ? String(value) : '';
}

export function LimitsForm({
  settings,
  onReload,
}: {
  settings: AssistantSettings;
  onReload: () => Promise<unknown>;
}) {
  const form = useZodForm(limitsSchema(settings), { defaultValues: defaultsOf(settings) });
  const [messages, setMessages] = useState<string[]>([]);
  const [conflict, setConflict] = useState(false);
  const sharingId = useId();
  const sharingHelpId = useId();
  const mutation = useApiMutation('AssistantSettingsController_update_v1', {
    successMessage: 'AI administration settings saved.',
    invalidates: ['AssistantSettingsController_get_v1', 'AssistantStatusController_get_v1'],
  });
  useEffect(() => {
    form.reset(defaultsOf(settings));
    setConflict(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when the stored version changes
  }, [settings.rowVersion]);

  const keyUsable = settings.tenantKeysOffered.enabled && settings.tenantKey?.status === 'valid';
  const useTenantKey = form.watch('useTenantKey');
  const dataSharing = form.watch('dataSharing');
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    setConflict(false);
    const outcome = await mutation.submit({ body: limitsBody(values, settings) });
    if (outcome.ok) return;
    const coded = adminErrorText(outcome.error.code);
    if (outcome.error.code === 'assistant_settings_conflict') setConflict(true);
    if (coded) {
      setMessages([coded]);
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
        aria-label="AI limits and data sharing"
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
        <FormField
          control={form.control}
          name="dailyTokenBudget"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Organization daily token budget</FormLabel>
              <FormControl>
                <Input
                  type="number"
                  inputMode="numeric"
                  min={1}
                  name={field.name}
                  ref={field.ref}
                  onBlur={field.onBlur}
                  value={numberField(field.value)}
                  onChange={(event) => field.onChange(event.target.value)}
                  placeholder={String(settings.effectiveDailyTokenBudget)}
                  className="w-48"
                />
              </FormControl>
              <FormDescription>
                Tokens per UTC day for everyone together. Empty = the platform default (now{' '}
                {formatNumber(settings.effectiveDailyTokenBudget)}).
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="userDailyTokenBudget"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Daily token budget per person</FormLabel>
              <FormControl>
                <Input
                  type="number"
                  inputMode="numeric"
                  min={1}
                  name={field.name}
                  ref={field.ref}
                  onBlur={field.onBlur}
                  value={numberField(field.value)}
                  onChange={(event) => field.onChange(event.target.value)}
                  placeholder="No limit"
                  className="w-48"
                />
              </FormControl>
              <FormDescription>
                Tokens per UTC day for each person. Empty = no per-person limit; at most the
                organization&apos;s budget.
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
                  min={settings.effectiveLimits.retentionDays.min}
                  max={settings.effectiveLimits.retentionDays.max}
                  name={field.name}
                  ref={field.ref}
                  onBlur={field.onBlur}
                  value={numberField(field.value)}
                  onChange={(event) => field.onChange(event.target.value)}
                  className="w-32"
                />
              </FormControl>
              <FormDescription>
                Questions, answers, result cards, feedback comments and placeholder mappings are
                deleted this many days after the last question of a conversation.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="dataSharing"
          render={({ field }) => (
            <FormItem>
              <FormLabel htmlFor={sharingId}>Data shared with the AI provider</FormLabel>
              <Select value={field.value} onValueChange={field.onChange}>
                <SelectTrigger
                  id={sharingId}
                  className="w-full max-w-sm"
                  aria-describedby={sharingHelpId}
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {DATA_SHARING_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p id={sharingHelpId} className="text-sm text-muted-foreground">
                {DATA_SHARING_HELP[dataSharing]}
              </p>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="useTenantKey"
          render={({ field }) => (
            <FormItem className="flex flex-row items-start gap-3">
              <FormControl>
                <Switch
                  checked={field.value}
                  onCheckedChange={field.onChange}
                  disabled={!keyUsable && !field.value}
                />
              </FormControl>
              <div className="grid gap-1">
                <FormLabel>Use your organization&apos;s provider key</FormLabel>
                <FormDescription>
                  {keyUsable
                    ? 'Questions use the key stored below instead of the platform’s provider account.'
                    : 'Needs a valid key stored below (when the platform offers it).'}
                </FormDescription>
              </div>
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="tenantKeyFallbackToPlatform"
          render={({ field }) => (
            <FormItem className="flex flex-row items-start gap-3">
              <FormControl>
                <Switch
                  checked={field.value}
                  onCheckedChange={field.onChange}
                  disabled={!useTenantKey && !field.value}
                />
              </FormControl>
              <div className="grid gap-1">
                <FormLabel>Fall back to the platform&apos;s provider</FormLabel>
                <FormDescription>
                  When your key fails or is rejected, answer with the platform&apos;s provider
                  instead of failing. Your daily budgets still apply.
                </FormDescription>
              </div>
            </FormItem>
          )}
        />
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={mutation.isPending || mutation.retryAfterSeconds > 0}>
            {mutation.isPending
              ? 'Saving …'
              : mutation.retryAfterSeconds > 0
                ? `Try again in ${mutation.retryAfterSeconds} s`
                : 'Save'}
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

/** Limits and provider tab (D1, D3, D7): gate `AssistantSettingsController_get_v1`. */
export function LimitsTab() {
  const settings = useApiQuery('AssistantSettingsController_get_v1');
  if (settings.isLoading) return <LoadingState label="Loading the AI settings" rows={5} />;
  if (settings.error)
    return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  if (!settings.data) return null;
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <ReportSection title="Budgets, retention and data sharing">
        <LimitsForm settings={settings.data} onReload={() => settings.refetch()} />
      </ReportSection>
      <ReportSection
        title="Effective limits"
        description="Set by the platform; they apply to every organization."
      >
        <EffectiveLimitsList limits={settings.data.effectiveLimits} />
      </ReportSection>
      <ReportSection title="Your own AI provider key" className="xl:col-span-2">
        <TenantKeySection settings={settings.data} />
      </ReportSection>
    </div>
  );
}

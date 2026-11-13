'use client';

import { useEffect, useState } from 'react';
import type { FieldPath } from 'react-hook-form';
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { type ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { DetailList, Section } from '@/features/messages/controls';
import {
  SETTINGS_SELF_RELEASE_LEVELS,
  SETTINGS_SELF_RELEASE_REASONS,
  settingsBody,
  settingsFormDefaults,
  settingsFormSchema,
  type SettingsFormValues,
} from './forms';
import type { SettingsBody } from './types';

/** Quarantine settings (`/quarantine/settings`): read with `quarantine:read`, edit with `settings:manage`. */
export function SettingsTab() {
  const settings = useApiQuery('QuarantineToolsController_getSettings_v1');
  if (settings.isLoading) return <LoadingState label="Loading quarantine settings" rows={8} />;
  if (settings.error || !settings.data) {
    return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  }
  return <SettingsForm current={settings.data} />;
}

type BoolField = Extract<
  FieldPath<SettingsFormValues>,
  | 'release.allowHardBlocks'
  | 'endUser.enabled'
  | 'endUser.preview'
  | 'endUser.selfRelease'
  | 'endUser.requestRelease'
  | 'digest.allowOptOut'
  | 'digest.includeSubject'
  | 'alerts.approvalRequests'
  | 'alerts.hardBlocks'
  | 'notices.senderOnReject'
  | 'download.enabled'
>;
type NumberField = Extract<
  FieldPath<SettingsFormValues>,
  'review.days' | 'approvals.requestTtlHours' | 'digest.maxEntries' | 'alerts.minIntervalMinutes'
>;

function SettingsForm({ current }: { current: SettingsBody }) {
  const canEdit = useCan('QuarantineToolsController_putSettings_v1');
  const [messages, setMessages] = useState<string[]>([]);
  const form = useZodForm(settingsFormSchema, {
    defaultValues: settingsFormDefaults(current.effective),
  });
  useEffect(() => {
    form.reset(settingsFormDefaults(current.effective));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when the stored version changes
  }, [current.rowVersion]);
  const save = useApiMutation('QuarantineToolsController_putSettings_v1', {
    invalidates: [
      'QuarantineToolsController_getSettings_v1',
      'QuarantineToolsController_catalog_v1',
    ],
    successMessage: 'Quarantine settings saved.',
  });
  const disabled = !canEdit || save.isPending;
  const b = current.bounds;

  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await save.submit({ body: settingsBody(values, current) });
    if (outcome.ok) return;
    setMessages(settingsErrors(outcome.error, form));
  });

  const bool = (name: BoolField, label: string, description?: string) => (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem className="flex flex-row items-start gap-3">
          <FormControl>
            <Switch
              checked={field.value}
              onCheckedChange={field.onChange}
              disabled={disabled}
              onBlur={field.onBlur}
              ref={field.ref}
            />
          </FormControl>
          <div className="grid gap-0.5">
            <FormLabel>{label}</FormLabel>
            {description ? <FormDescription>{description}</FormDescription> : null}
            <FormMessage />
          </div>
        </FormItem>
      )}
    />
  );
  const number = (name: NumberField, label: string, min: number, max: number, unit: string) => (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel>{label}</FormLabel>
          <FormControl>
            <Input
              type="number"
              inputMode="numeric"
              min={min}
              max={max}
              className="max-w-32"
              disabled={disabled}
              name={field.name}
              ref={field.ref}
              onBlur={field.onBlur}
              value={Number.isFinite(field.value) ? field.value : ''}
              onChange={(event) =>
                field.onChange(event.target.value === '' ? Number.NaN : Number(event.target.value))
              }
            />
          </FormControl>
          <FormDescription>
            {min}–{max} {unit}
          </FormDescription>
          <FormMessage />
        </FormItem>
      )}
    />
  );

  return (
    <Form {...form}>
      <form
        className="grid max-w-3xl gap-4"
        onSubmit={(event) => void submit(event)}
        noValidate
        aria-label="Quarantine settings"
      >
        {!canEdit ? (
          <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
            You can view these settings. Changing them needs the settings:manage permission.
          </p>
        ) : null}
        {current.invalidStored ? (
          <p className="rounded-md bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground">
            The stored settings were invalid, so the defaults apply. Saving replaces them.
          </p>
        ) : null}
        <FormErrorSummary messages={messages} requestId={save.error?.requestId} />
        <Section title="Review and approvals">
          {number('review.days', 'Review hold (days)', 1, b.maxReviewDays, 'days')}
          {number(
            'approvals.requestTtlHours',
            'Release request lifetime (hours)',
            b.requestTtlHours.min,
            b.requestTtlHours.max,
            'hours',
          )}
          {bool(
            'release.allowHardBlocks',
            'Allow releasing hard-blocked mail',
            'Hard-blocked entries always need an approver; when off they cannot be released at all.',
          )}
        </Section>
        <Section title="End-user self-service">
          {bool('endUser.enabled', 'Recipients can see their quarantined mail')}
          {bool('endUser.preview', 'Recipients can open the sanitized preview')}
          {bool('endUser.selfRelease', 'Recipients can release some messages themselves')}
          <FormField
            control={form.control}
            name="endUser.selfReleaseReasons"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Reasons recipients may release themselves</FormLabel>
                <div className="flex flex-wrap gap-4">
                  {SETTINGS_SELF_RELEASE_REASONS.map((reason) => {
                    const checked = field.value.includes(reason);
                    return (
                      <label key={reason} className="flex items-center gap-2 text-sm">
                        <Checkbox
                          checked={checked}
                          disabled={disabled}
                          onCheckedChange={(next) =>
                            field.onChange(
                              next === true
                                ? [...field.value, reason]
                                : field.value.filter((value) => value !== reason),
                            )
                          }
                        />
                        {humanize(reason)}
                      </label>
                    );
                  })}
                </div>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="endUser.selfReleaseMaxLevel"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Highest risk level recipients may release</FormLabel>
                <Select value={field.value} onValueChange={field.onChange} disabled={disabled}>
                  <FormControl>
                    <SelectTrigger className="min-w-40">
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {SETTINGS_SELF_RELEASE_LEVELS.map((level) => (
                      <SelectItem key={level} value={level}>
                        {humanize(level)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          {bool('endUser.requestRelease', 'Recipients can request a release')}
        </Section>
        <Section title="Digest">
          {bool('digest.allowOptOut', 'Recipients may opt out of the digest')}
          {bool('digest.includeSubject', 'Include subjects in the digest')}
          {number(
            'digest.maxEntries',
            'Entries per digest',
            b.digestMaxEntries.min,
            b.digestMaxEntries.max,
            'entries',
          )}
        </Section>
        <Section title="Alerts and notices">
          {bool('alerts.approvalRequests', 'Alert approvers about new approval requests')}
          {bool('alerts.hardBlocks', 'Alert about hard-blocked mail')}
          {number(
            'alerts.minIntervalMinutes',
            'Minimum interval between alerts (minutes)',
            b.alertMinIntervalMinutes.min,
            b.alertMinIntervalMinutes.max,
            'minutes',
          )}
          {bool(
            'notices.senderOnReject',
            'Notify senders of rejected outbound and internal mail by default',
          )}
        </Section>
        <Section title="Downloads">
          {bool(
            'download.enabled',
            'Allow downloads of clean quarantined content',
            'Users with the quarantine:download permission re-enter their password for each download.',
          )}
        </Section>
        <Section
          title="Managed elsewhere"
          description="Organization settings; shown for reference."
        >
          <DetailList
            items={[
              {
                label: 'Hold period',
                value: `${current.effective.hold.days} days (at most ${b.maxHoldDays})`,
              },
              {
                label: 'Digest schedule',
                value: current.effective.digestSchedule.enabled
                  ? `${current.effective.digestSchedule.schedule} (${current.effective.digestSchedule.timeZone})`
                  : 'Off',
              },
            ]}
          />
        </Section>
        {canEdit ? (
          <Button
            type="submit"
            className="justify-self-start"
            disabled={save.isPending || save.retryAfterSeconds > 0}
          >
            {save.isPending ? 'Saving …' : 'Save settings'}
          </Button>
        ) : null}
      </form>
    </Form>
  );
}

/** `400 quarantine_settings_invalid` violations go to their fields; the rest to the summary. */
function settingsErrors(
  error: ApiError,
  form: ReturnType<typeof useZodForm<typeof settingsFormSchema>>,
): string[] {
  const violations = error.details.violations;
  if (error.code === 'quarantine_settings_invalid' && Array.isArray(violations)) {
    const rest: string[] = [];
    for (const violation of violations as { path?: unknown; message?: unknown }[]) {
      const path =
        typeof violation.path === 'string' ? violation.path.replace(/^settings\./, '') : '';
      const message = typeof violation.message === 'string' ? violation.message : 'Invalid value';
      if (path && path in flatten(form.getValues())) {
        form.setError(path as FieldPath<SettingsFormValues>, { type: 'server', message });
      } else {
        rest.push(path ? `${path}: ${message}` : message);
      }
    }
    return rest;
  }
  if (error.code === 'quarantine_settings_conflict') {
    return [
      'The settings were changed by someone else. Reload the page to see the current values.',
    ];
  }
  return applyApiErrors(form, error);
}

function flatten(value: object, prefix = ''): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, inner] of Object.entries(value) as [string, unknown][]) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (inner && typeof inner === 'object' && !Array.isArray(inner))
      Object.assign(out, flatten(inner, path));
    else out[path] = inner;
  }
  return out;
}

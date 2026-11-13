'use client';

import { useEffect, useState } from 'react';
import { z } from 'zod';
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
import { Switch } from '@/components/ui/switch';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatUtc } from '@/lib/format';

type Settings = SuccessBody<'OrganizationConfigurationController_getSettings_v1'>;
type SettingsBody = RequestBody<'OrganizationConfigurationController_updateSettings_v1'>;

const CRON_FIELD = /^[A-Za-z0-9*,/-]+$/;

/** Form schema (strict) mirroring `PUT /organizations/{id}/settings` (preferences untouched). */
export function organizationSettingsSchema(maxRetentionDays: number | null) {
  return z
    .object({
      timezone: z.string().trim().min(1, 'Enter an IANA time zone, e.g. Europe/Berlin').max(64),
      locale: z
        .string()
        .trim()
        .min(2, 'Use a BCP 47 tag of 2 to 16 characters, e.g. en-GB')
        .max(16, 'Use a BCP 47 tag of 2 to 16 characters, e.g. en-GB'),
      quarantineRetentionDays: z.coerce
        .number({ message: 'Enter a number of days' })
        .int('Enter whole days')
        .min(1, 'At least 1 day')
        .max(maxRetentionDays ?? 65535, `At most ${maxRetentionDays ?? 65535} days`),
      digestEnabled: z.boolean(),
      digestSchedule: z
        .string()
        .trim()
        .refine(
          (value) => {
            const fields = value.split(/\s+/);
            return fields.length === 5 && fields.every((f) => CRON_FIELD.test(f));
          },
          { message: 'Use 5 cron fields: minute hour day-of-month month day-of-week' },
        ),
      notificationEmail: z
        .string()
        .trim()
        .max(320)
        .refine((value) => value === '' || z.email().safeParse(value).success, {
          message: 'Enter an email address or leave it empty',
        }),
      mfaRequired: z.boolean(),
    })
    .strict();
}

export type OrganizationSettingsValues = z.output<ReturnType<typeof organizationSettingsSchema>>;

export function settingsDefaults(settings: Settings): OrganizationSettingsValues {
  return {
    timezone: settings.timezone,
    locale: settings.locale,
    quarantineRetentionDays: settings.quarantineRetentionDays,
    digestEnabled: settings.digestEnabled,
    digestSchedule: settings.digestSchedule,
    notificationEmail: settings.notificationEmail ?? '',
    mfaRequired: settings.mfaRequired,
  };
}

/** Only the changed fields (the api changes the given fields; at least one). */
export function settingsBody(
  values: OrganizationSettingsValues,
  current: Settings,
): SettingsBody | null {
  const body: SettingsBody = {};
  if (values.timezone !== current.timezone) body.timezone = values.timezone;
  if (values.locale !== current.locale) body.locale = values.locale;
  if (values.quarantineRetentionDays !== current.quarantineRetentionDays)
    body.quarantineRetentionDays = values.quarantineRetentionDays;
  if (values.digestEnabled !== current.digestEnabled) body.digestEnabled = values.digestEnabled;
  if (values.digestSchedule !== current.digestSchedule) body.digestSchedule = values.digestSchedule;
  const email = values.notificationEmail === '' ? null : values.notificationEmail;
  if (email !== current.notificationEmail) body.notificationEmail = email;
  if (values.mfaRequired !== current.mfaRequired) body.mfaRequired = values.mfaRequired;
  return Object.keys(body).length > 0 ? body : null;
}

/** Organization settings (`GET/PUT /organizations/{id}/settings`): read-only without the right. */
export function OrganizationSettingsPanel({ organizationId }: { organizationId: string }) {
  const query = useApiQuery('OrganizationConfigurationController_getSettings_v1', {
    path: { id: organizationId },
  });
  const canEdit = useCan('OrganizationConfigurationController_updateSettings_v1');
  if (query.isLoading) return <LoadingState label="Loading organization settings" rows={6} />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return null;
  return canEdit ? (
    <OrganizationSettingsForm organizationId={organizationId} settings={query.data} />
  ) : (
    <SettingsSummary settings={query.data} />
  );
}

export function SettingsSummary({ settings }: { settings: Settings }) {
  const rows: [string, string][] = [
    ['Time zone', settings.timezone],
    ['Locale', settings.locale],
    [
      'Quarantine retention',
      `${settings.quarantineRetentionDays} days${settings.quarantineRetentionMaxDays ? ` (at most ${settings.quarantineRetentionMaxDays})` : ''}`,
    ],
    ['Quarantine digest', settings.digestEnabled ? `On (${settings.digestSchedule})` : 'Off'],
    ['Notification email', settings.notificationEmail ?? 'Not set'],
    ['MFA required for every user', settings.mfaRequired ? 'Yes' : 'No'],
    ['Last changed', formatUtc(settings.updatedAt)],
  ];
  return (
    <dl className="grid max-w-2xl grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
      {rows.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="break-words">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function OrganizationSettingsForm({
  organizationId,
  settings,
}: {
  organizationId: string;
  settings: Settings;
}) {
  const schema = organizationSettingsSchema(settings.quarantineRetentionMaxDays);
  const form = useZodForm(schema, { defaultValues: settingsDefaults(settings) });
  const [messages, setMessages] = useState<string[]>([]);
  const mutation = useApiMutation('OrganizationConfigurationController_updateSettings_v1', {
    successMessage: 'Organization settings saved.',
    invalidates: ['OrganizationConfigurationController_getSettings_v1'],
  });
  useEffect(() => {
    form.reset(settingsDefaults(settings));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when the stored settings change
  }, [settings.updatedAt]);

  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const body = settingsBody(values, settings);
    if (!body) {
      setMessages(['Nothing changed.']);
      return;
    }
    const outcome = await mutation.submit({ path: { id: organizationId }, body });
    if (!outcome.ok) setMessages(applyApiErrors(form, outcome.error));
  });

  return (
    <Form {...form}>
      <form
        onSubmit={(event) => void submit(event)}
        className="grid max-w-2xl gap-4"
        noValidate
        aria-label="Organization settings"
      >
        <FormErrorSummary messages={messages} requestId={mutation.error?.requestId} />
        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="timezone"
            render={({ field }) => (
              <FormItem>
                <FormLabel required>Time zone</FormLabel>
                <FormControl>
                  <Input {...field} autoComplete="off" />
                </FormControl>
                <FormDescription>IANA name, e.g. Asia/Kolkata or UTC.</FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="locale"
            render={({ field }) => (
              <FormItem>
                <FormLabel required>Locale</FormLabel>
                <FormControl>
                  <Input {...field} autoComplete="off" />
                </FormControl>
                <FormDescription>BCP 47 tag, e.g. en-GB.</FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>
        <FormField
          control={form.control}
          name="quarantineRetentionDays"
          render={({ field }) => (
            <FormItem>
              <FormLabel required>Quarantine retention (days)</FormLabel>
              <FormControl>
                <Input
                  type="number"
                  inputMode="numeric"
                  min={1}
                  max={settings.quarantineRetentionMaxDays ?? undefined}
                  name={field.name}
                  ref={field.ref}
                  onBlur={field.onBlur}
                  value={
                    typeof field.value === 'number' || typeof field.value === 'string'
                      ? String(field.value)
                      : ''
                  }
                  onChange={(event) => field.onChange(event.target.value)}
                  className="w-40"
                />
              </FormControl>
              <FormDescription>
                1 to {settings.quarantineRetentionMaxDays ?? 'the platform maximum'} days (your plan
                limit and the platform setting).
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="digestEnabled"
          render={({ field }) => (
            <FormItem className="flex flex-row items-center gap-3">
              <FormControl>
                <Switch checked={field.value} onCheckedChange={field.onChange} />
              </FormControl>
              <FormLabel>Send quarantine digests to recipients</FormLabel>
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="digestSchedule"
          render={({ field }) => (
            <FormItem>
              <FormLabel required>Digest schedule</FormLabel>
              <FormControl>
                <Input {...field} className="font-mono" autoComplete="off" />
              </FormControl>
              <FormDescription>
                5-field cron in the organization&apos;s time zone, e.g. 0 8 * * 1-5.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="notificationEmail"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Notification email</FormLabel>
              <FormControl>
                <Input {...field} type="email" autoComplete="off" />
              </FormControl>
              <FormDescription>
                Organization contact for alerts; leave empty to remove it.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="mfaRequired"
          render={({ field }) => (
            <FormItem className="flex flex-row items-center gap-3">
              <FormControl>
                <Switch checked={field.value} onCheckedChange={field.onChange} />
              </FormControl>
              <FormLabel>Require MFA for every user</FormLabel>
            </FormItem>
          )}
        />
        <Button
          type="submit"
          className="justify-self-start"
          disabled={mutation.isPending || mutation.retryAfterSeconds > 0}
        >
          {mutation.isPending
            ? 'Saving …'
            : mutation.retryAfterSeconds > 0
              ? `Try again in ${mutation.retryAfterSeconds} s`
              : 'Save settings'}
        </Button>
      </form>
    </Form>
  );
}

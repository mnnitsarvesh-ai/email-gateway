'use client';

import { useEffect, useState, type ComponentProps } from 'react';
import { z } from 'zod';
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
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { ReportSection } from '@/features/reports/report-state';

type NotificationSettings = SuccessBody<'NotificationsController_settings_v1'>;
type Bounds = NotificationSettings['bounds'];

/* ------------------------------------------------------------------------------------------ */
/* Organization alert settings (`GET/PUT /notifications/settings`)                             */
/* ------------------------------------------------------------------------------------------ */

const throttle = (b: { minThrottleMinutes: number; maxThrottleMinutes: number }) =>
  z.coerce
    .number({ message: 'Enter minutes' })
    .int('Enter whole minutes')
    .min(b.minThrottleMinutes, `At least ${b.minThrottleMinutes} minutes`)
    .max(b.maxThrottleMinutes, `At most ${b.maxThrottleMinutes} minutes`);

export function alertSettingsSchema(bounds: Bounds) {
  return z
    .object({
      threatEnabled: z.boolean(),
      threatMinSeverity: z.enum(['medium', 'high']),
      threatThrottle: throttle(bounds.threatDetected),
      dnsEnabled: z.boolean(),
      dnsThrottle: throttle(bounds.domainDnsFailed),
      webhookEnabled: z.boolean(),
      webhookThrottle: throttle(bounds.webhookDisabled),
      includeContact: z.boolean(),
    })
    .strict();
}

export type AlertSettingsValues = z.output<ReturnType<typeof alertSettingsSchema>>;

export function alertDefaults(view: NotificationSettings): AlertSettingsValues {
  const a = view.settings.alerts;
  return {
    threatEnabled: a.threatDetected.enabled,
    threatMinSeverity: a.threatDetected.minSeverity,
    threatThrottle: a.threatDetected.throttleMinutes,
    dnsEnabled: a.domainDnsFailed.enabled,
    dnsThrottle: a.domainDnsFailed.throttleMinutes,
    webhookEnabled: a.webhookDisabled.enabled,
    webhookThrottle: a.webhookDisabled.throttleMinutes,
    includeContact: a.includeOrganizationContact,
  };
}

export function alertSettingsBody(
  values: AlertSettingsValues,
  rowVersion: number,
): RequestBody<'NotificationsController_putSettings_v1'> {
  return {
    settings: {
      alerts: {
        threatDetected: {
          enabled: values.threatEnabled,
          minSeverity: values.threatMinSeverity,
          throttleMinutes: values.threatThrottle,
        },
        domainDnsFailed: { enabled: values.dnsEnabled, throttleMinutes: values.dnsThrottle },
        webhookDisabled: {
          enabled: values.webhookEnabled,
          throttleMinutes: values.webhookThrottle,
        },
        includeOrganizationContact: values.includeContact,
      },
    },
    expectedRowVersion: rowVersion,
  };
}

export function AlertSettingsPanel() {
  const query = useApiQuery('NotificationsController_settings_v1');
  const canEdit = useCan('NotificationsController_putSettings_v1');
  if (query.isLoading) return <LoadingState label="Loading alert settings" rows={6} />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return null;
  return (
    <ReportSection
      title="Organization alerts"
      description="Emails the platform sends to administrators of your organization."
    >
      {query.data.invalidStored ? (
        <p
          role="note"
          className="rounded-md bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground"
        >
          The stored alert settings no longer fit the platform bounds; the defaults below apply
          until they are saved again.
        </p>
      ) : null}
      <AlertSettingsForm
        view={query.data}
        readOnly={!canEdit}
        onConflict={() => void query.refetch()}
      />
    </ReportSection>
  );
}

function NumberInput({
  field,
  min,
  max,
  disabled,
  ...rest
}: Omit<ComponentProps<typeof Input>, 'value' | 'onChange' | 'min' | 'max'> & {
  field: {
    name: string;
    value: unknown;
    onChange: (value: string) => void;
    onBlur: () => void;
    ref: (instance: HTMLInputElement | null) => void;
  };
  min: number;
  max: number;
  disabled?: boolean;
}) {
  return (
    <Input
      {...rest}
      type="number"
      inputMode="numeric"
      min={min}
      max={max}
      disabled={disabled}
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
  );
}

function AlertSettingsForm({
  view,
  readOnly,
  onConflict,
}: {
  view: NotificationSettings;
  readOnly: boolean;
  onConflict: () => void;
}) {
  const form = useZodForm(alertSettingsSchema(view.bounds), { defaultValues: alertDefaults(view) });
  const [messages, setMessages] = useState<string[]>([]);
  const mutation = useApiMutation('NotificationsController_putSettings_v1', {
    successMessage: 'Alert settings saved.',
    invalidates: ['NotificationsController_settings_v1'],
  });
  useEffect(() => {
    form.reset(alertDefaults(view));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset to the stored version
  }, [view.rowVersion]);
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await mutation.submit({ body: alertSettingsBody(values, view.rowVersion) });
    if (outcome.ok) return;
    if (outcome.error.status === 409) {
      setMessages([
        `${outcome.error.messages.join(' ')} The latest settings were loaded; review them and save again.`,
      ]);
      onConflict();
      return;
    }
    setMessages(applyApiErrors(form, outcome.error));
  });
  const b = view.bounds;
  const toggle = (
    name: 'threatEnabled' | 'dnsEnabled' | 'webhookEnabled' | 'includeContact',
    label: string,
    hint?: string,
  ) => (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem className="flex flex-row flex-wrap items-center gap-3">
          <FormControl>
            <Switch checked={field.value} onCheckedChange={field.onChange} disabled={readOnly} />
          </FormControl>
          <FormLabel>{label}</FormLabel>
          {hint ? <FormDescription className="basis-full">{hint}</FormDescription> : null}
        </FormItem>
      )}
    />
  );
  const minutes = (
    name: 'threatThrottle' | 'dnsThrottle' | 'webhookThrottle',
    bounds: { minThrottleMinutes: number; maxThrottleMinutes: number },
  ) => (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel>At most one alert every (minutes)</FormLabel>
          <FormControl>
            <NumberInput
              field={field}
              min={bounds.minThrottleMinutes}
              max={bounds.maxThrottleMinutes}
              disabled={readOnly}
            />
          </FormControl>
          <FormDescription>
            {bounds.minThrottleMinutes} to {bounds.maxThrottleMinutes} minutes.
          </FormDescription>
          <FormMessage />
        </FormItem>
      )}
    />
  );
  return (
    <Form {...form}>
      <form
        onSubmit={(event) => void submit(event)}
        className="grid max-w-2xl gap-5"
        noValidate
        aria-label="Organization alerts"
      >
        <FormErrorSummary messages={messages} requestId={mutation.error?.requestId} />
        {readOnly ? (
          <p className="text-sm text-muted-foreground">
            You can view these settings; changing them needs settings:manage.
          </p>
        ) : null}
        <fieldset className="grid gap-3 rounded-md border p-3">
          <legend className="px-1 text-sm font-medium">Threat detected</legend>
          {toggle('threatEnabled', 'Send threat alerts')}
          <FormField
            control={form.control}
            name="threatMinSeverity"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Minimum severity</FormLabel>
                <Select value={field.value} onValueChange={field.onChange} disabled={readOnly}>
                  <FormControl>
                    <SelectTrigger className="w-40">
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          {minutes('threatThrottle', b.threatDetected)}
        </fieldset>
        <fieldset className="grid gap-3 rounded-md border p-3">
          <legend className="px-1 text-sm font-medium">Domain DNS check failed</legend>
          {toggle('dnsEnabled', 'Send DNS failure alerts')}
          {minutes('dnsThrottle', b.domainDnsFailed)}
        </fieldset>
        <fieldset className="grid gap-3 rounded-md border p-3">
          <legend className="px-1 text-sm font-medium">Webhook disabled</legend>
          {toggle('webhookEnabled', 'Send webhook alerts')}
          {minutes('webhookThrottle', b.webhookDisabled)}
        </fieldset>
        {toggle(
          'includeContact',
          'Also send to the organization notification email',
          'The address in the organization settings.',
        )}
        {readOnly ? null : (
          <Button
            type="submit"
            className="justify-self-start"
            disabled={mutation.isPending || mutation.retryAfterSeconds > 0}
          >
            {mutation.isPending
              ? 'Saving …'
              : mutation.retryAfterSeconds > 0
                ? `Try again in ${mutation.retryAfterSeconds} s`
                : 'Save alert settings'}
          </Button>
        )}
      </form>
    </Form>
  );
}

/* ------------------------------------------------------------------------------------------ */
/* Personal preferences (`GET/PUT /notifications/preferences`, self-service)                   */
/* ------------------------------------------------------------------------------------------ */

type Preferences = SuccessBody<'NotificationsController_preferences_v1'>;
type Kind = Preferences['kinds'][number];

export const KIND_LABELS: Record<Kind, string> = {
  threat_detected: 'Threat detected',
  domain_dns_failed: 'Domain DNS check failed',
  webhook_disabled: 'Webhook disabled',
  policy_alert: 'Policy alerts',
  quarantine_admin_alert: 'Quarantine administrator alerts',
  quarantine_approval_requested: 'Quarantine release approval requested',
};

export const preferencesSchema = z
  .object({
    optOut: z
      .array(
        z.enum([
          'threat_detected',
          'domain_dns_failed',
          'webhook_disabled',
          'policy_alert',
          'quarantine_admin_alert',
          'quarantine_approval_requested',
        ]),
      )
      .max(6),
    quarantineDigestOptOut: z.boolean(),
  })
  .strict();

export function PreferencesPanel() {
  const query = useApiQuery('NotificationsController_preferences_v1');
  if (query.isLoading)
    return <LoadingState label="Loading your notification preferences" rows={5} />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return null;
  return (
    <ReportSection
      title="Your notifications"
      description="Which emails you receive. Changes apply to your account only."
    >
      <PreferencesForm preferences={query.data} />
    </ReportSection>
  );
}

function PreferencesForm({ preferences }: { preferences: Preferences }) {
  const form = useZodForm(preferencesSchema, {
    defaultValues: {
      optOut: [...preferences.optOut],
      quarantineDigestOptOut: preferences.quarantineDigestOptOut,
    },
  });
  const [messages, setMessages] = useState<string[]>([]);
  const mutation = useApiMutation('NotificationsController_putPreferences_v1', {
    successMessage: 'Notification preferences saved.',
    invalidates: ['NotificationsController_preferences_v1'],
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await mutation.submit({ body: preferencesSchema.parse(values) });
    if (!outcome.ok) setMessages(applyApiErrors(form, outcome.error));
  });
  return (
    <Form {...form}>
      <form
        onSubmit={(event) => void submit(event)}
        className="grid max-w-2xl gap-4"
        noValidate
        aria-label="Your notifications"
      >
        <FormErrorSummary messages={messages} requestId={mutation.error?.requestId} />
        {preferences.invalidStored ? (
          <p role="note" className="text-sm text-muted-foreground">
            Your stored preferences could not be read; saving replaces them.
          </p>
        ) : null}
        <FormField
          control={form.control}
          name="optOut"
          render={({ field }) => (
            <FormItem>
              <fieldset className="grid gap-2">
                <legend className="pb-1 text-sm font-medium">Email me about</legend>
                {preferences.kinds.map((kind) => {
                  const id = `pref-${kind}`;
                  const optedOut = field.value.includes(kind);
                  return (
                    <div key={kind} className="flex items-center gap-2">
                      <Checkbox
                        id={id}
                        checked={!optedOut}
                        onCheckedChange={(checked) =>
                          field.onChange(
                            checked === true
                              ? field.value.filter((k) => k !== kind)
                              : [...field.value, kind],
                          )
                        }
                      />
                      <label htmlFor={id} className="text-sm">
                        {KIND_LABELS[kind]}
                      </label>
                    </div>
                  );
                })}
              </fieldset>
              <FormDescription>
                Only alerts your role receives are sent; unchecking opts you out.
              </FormDescription>
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="quarantineDigestOptOut"
          render={({ field }) => (
            <FormItem className="flex flex-row flex-wrap items-center gap-3">
              <FormControl>
                <Switch
                  checked={!field.value}
                  onCheckedChange={(on) => field.onChange(!on)}
                  disabled={!preferences.quarantineDigestOptOutAllowed}
                />
              </FormControl>
              <FormLabel>Receive the quarantine digest</FormLabel>
              {!preferences.quarantineDigestOptOutAllowed ? (
                <FormDescription className="basis-full">
                  Your organization requires the quarantine digest; it cannot be switched off.
                </FormDescription>
              ) : null}
            </FormItem>
          )}
        />
        <Button
          type="submit"
          className="justify-self-start"
          disabled={mutation.isPending || mutation.retryAfterSeconds > 0}
        >
          {mutation.isPending ? 'Saving …' : 'Save preferences'}
        </Button>
      </form>
    </Form>
  );
}

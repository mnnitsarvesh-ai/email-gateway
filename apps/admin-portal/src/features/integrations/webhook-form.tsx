'use client';

import { XIcon } from 'lucide-react';
import { useId, useState, type ReactNode } from 'react';
import { Controller, type UseFormReturn } from 'react-hook-form';
import { z } from 'zod';
import { Combobox } from '@/components/combobox';
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
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useDebouncedValue } from '@/hooks/use-debounced-value';
import { type ApiError } from '@/lib/api/errors';
import { useApiQuery } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { LabelledSelect } from '@/features/domains/kit';
import { DIRECTIONS, SCAN_VERDICTS, SEVERITIES, type Webhook } from './model';

const EVENT_TYPES = [
  'email.received',
  'email.scanned',
  'email.threat.detected',
  'email.policy.triggered',
  'email.quarantined',
  'email.released',
  'email.delivered',
  'email.rejected',
  'domain.verified',
  'domain.dns.failed',
] as const;

/**
 * The webhook form (create and edit), mirroring the request schema: name, description, https URL,
 * 1–10 event types, optional filters (directions, own domain ids ≤ 20, minimum severity,
 * verdicts), status on create and the concurrency cap.
 */
export const webhookSchema = z
  .object({
    name: z.string().trim().min(1, 'Enter a name').max(1020),
    description: z.string().trim().max(2048),
    url: z
      .string()
      .trim()
      .min(1, 'Enter the endpoint URL')
      .max(2048)
      .refine((value) => {
        try {
          const url = new URL(value);
          return (
            (url.protocol === 'https:' || url.protocol === 'http:') &&
            !url.username &&
            !url.password &&
            !url.hash
          );
        } catch {
          return false;
        }
      }, 'Enter an absolute https URL without credentials or #fragment'),
    eventTypes: z.array(z.enum(EVENT_TYPES)).min(1, 'Choose at least one event type').max(10),
    directions: z.array(z.enum(DIRECTIONS)).max(3),
    domainIds: z.array(z.string().uuid()).max(20, 'At most 20 domains'),
    minSeverity: z.enum(['', ...SEVERITIES]),
    verdicts: z.array(z.enum(SCAN_VERDICTS)).max(7),
    status: z.enum(['active', 'paused']),
    maxConcurrency: z
      .string()
      .regex(/^([1-9]|[12]\d|3[0-2])?$/, 'A whole number from 1 to 32, or empty for the default'),
  })
  .strict();

export type WebhookValues = z.output<typeof webhookSchema>;

function filtersOf(values: WebhookValues) {
  const filters = {
    ...(values.directions.length > 0 ? { directions: values.directions } : {}),
    ...(values.domainIds.length > 0 ? { domainIds: values.domainIds } : {}),
    ...(values.minSeverity ? { minSeverity: values.minSeverity } : {}),
    ...(values.verdicts.length > 0 ? { verdicts: values.verdicts } : {}),
  };
  return Object.keys(filters).length > 0 ? filters : null;
}

export function webhookCreateBody(
  values: WebhookValues,
): RequestBody<'WebhooksController_create_v1'> {
  const filters = filtersOf(values);
  return {
    name: values.name,
    ...(values.description ? { description: values.description } : {}),
    url: values.url,
    eventTypes: values.eventTypes,
    ...(filters ? { filters } : {}),
    status: values.status,
    ...(values.maxConcurrency ? { maxConcurrency: Number(values.maxConcurrency) } : {}),
  };
}

export function webhookUpdateBody(
  webhook: Pick<Webhook, 'rowVersion'>,
  values: WebhookValues,
): RequestBody<'WebhooksController_update_v1'> {
  return {
    expectedRowVersion: webhook.rowVersion,
    name: values.name,
    description: values.description || null,
    url: values.url,
    eventTypes: values.eventTypes,
    filters: filtersOf(values),
    maxConcurrency: values.maxConcurrency ? Number(values.maxConcurrency) : null,
  };
}

export function webhookDefaults(webhook?: Webhook): z.input<typeof webhookSchema> {
  return {
    name: webhook?.name ?? '',
    description: webhook?.description ?? '',
    url: webhook?.url ?? '',
    eventTypes: webhook?.eventTypes ?? [],
    directions: webhook?.filters?.directions ?? [],
    domainIds: webhook?.filters?.domainIds ?? [],
    minSeverity: webhook?.filters?.minSeverity ?? '',
    verdicts: webhook?.filters?.verdicts ?? [],
    status: webhook?.status === 'paused' ? 'paused' : 'active',
    maxConcurrency: webhook?.maxConcurrency ? String(webhook.maxConcurrency) : '',
  };
}

/** Domain name of a filter id (fetched per chip; ids that do not resolve are shown as ids). */
function DomainChip({ id, onRemove }: { id: string; onRemove: () => void }) {
  const domain = useApiQuery('DomainsController_get_v1', { path: { id } }, { retry: false });
  const label = domain.data?.unicodeName ?? id;
  return (
    <li className="inline-flex items-center gap-1 rounded-sm bg-secondary px-1.5 py-0.5 text-xs">
      {label}
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove ${label}`}
        className="rounded-sm hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        <XIcon className="size-3" aria-hidden />
      </button>
    </li>
  );
}

function DomainFilter({ value, onChange }: { value: string[]; onChange: (ids: string[]) => void }) {
  const [search, setSearch] = useState('');
  const debounced = useDebouncedValue(search, 300);
  const domains = useApiQuery('DomainsController_list_v1', {
    query: { limit: 20, ...(debounced ? { q: debounced } : {}) },
  });
  return (
    <div className="grid gap-2">
      <Label htmlFor="webhook-domain-filter">Domains (optional, up to 20)</Label>
      <Combobox
        id="webhook-domain-filter"
        label="Add a domain to the filter"
        options={(domains.data?.data ?? [])
          .filter((d) => !value.includes(d.id))
          .map((d) => ({ value: d.id, label: d.unicodeName }))}
        value={null}
        onChange={(id) => id && value.length < 20 && onChange([...value, id])}
        onSearch={setSearch}
        loading={domains.isFetching}
        placeholder="Add a domain …"
        searchPlaceholder="Search domains"
      />
      {value.length > 0 ? (
        <ul className="flex flex-wrap gap-1" aria-label="Domains in the filter">
          {value.map((id) => (
            <DomainChip key={id} id={id} onRemove={() => onChange(value.filter((v) => v !== id))} />
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function CheckboxGroup<T extends string>({
  legend,
  options,
  value,
  onChange,
  describe,
  error,
}: {
  legend: string;
  options: readonly T[];
  value: readonly T[];
  onChange: (value: T[]) => void;
  describe?: (option: T) => string | undefined;
  error?: string;
}) {
  const id = useId();
  return (
    <fieldset className="grid gap-2">
      <legend className="mb-1 text-sm font-medium">{legend}</legend>
      <ul className="grid gap-1.5 sm:grid-cols-2">
        {options.map((option) => (
          <li key={option} className="flex items-start gap-2">
            <Checkbox
              id={`${id}-${option}`}
              checked={value.includes(option)}
              onCheckedChange={(next) =>
                onChange(next === true ? [...value, option] : value.filter((v) => v !== option))
              }
            />
            <Label htmlFor={`${id}-${option}`} className="grid gap-0.5 font-normal">
              <span className="font-mono text-xs">{option}</span>
              {describe?.(option) ? (
                <span className="text-xs text-muted-foreground">{describe(option)}</span>
              ) : null}
            </Label>
          </li>
        ))}
      </ul>
      {error ? (
        <p className="text-xs font-medium text-destructive" role="alert">
          {error}
        </p>
      ) : null}
    </fieldset>
  );
}

export function webhookErrorMessages(
  form: UseFormReturn<z.input<typeof webhookSchema>, unknown, WebhookValues>,
  error: ApiError,
): string[] {
  if (error.code === 'webhook_url_not_allowed') {
    form.setError('url', {
      type: 'server',
      message: `${error.messages.join(' ')}${typeof error.details.reason === 'string' ? ` (${error.details.reason})` : ''}`,
    });
    return [];
  }
  if (error.code === 'webhook_filter_invalid')
    return [
      `${error.messages.join(' ')}${typeof error.details.path === 'string' ? ` (${error.details.path})` : ''}`,
    ];
  if (error.code === 'webhook_limit_reached')
    return [
      'Your organization has reached its webhook limit. Delete a webhook you no longer need.',
    ];
  if (error.code === 'webhooks_not_enabled') return ['Webhooks are not part of your plan.'];
  if (error.code === 'webhook_version_conflict')
    return [
      'Someone else changed this webhook. Close the dialog to load the current version and try again.',
    ];
  return applyApiErrors(form, error);
}

/** Create or edit a webhook; `onSubmit` sends it and returns the error to show, if any. */
export function WebhookForm({
  webhook,
  submitLabel,
  pending,
  onSubmit,
  extra,
}: {
  webhook?: Webhook;
  submitLabel: string;
  pending: boolean;
  onSubmit: (values: WebhookValues) => Promise<ApiError | null>;
  extra?: ReactNode;
}) {
  const [messages, setMessages] = useState<string[]>([]);
  const [requestId, setRequestId] = useState<string | null>(null);
  const canReadDomains = useCan('DomainsController_list_v1');
  const catalog = useApiQuery('WebhooksController_eventTypes_v1');
  const form = useZodForm(webhookSchema, { defaultValues: webhookDefaults(webhook) });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const error = await onSubmit(values);
    if (!error) return;
    setRequestId(error.requestId);
    setMessages(webhookErrorMessages(form, error));
  });
  const types = (catalog.data?.data ?? []).filter((t) => t.subscribable);
  const describe = (type: string) => types.find((t) => t.type === type)?.description;
  const severities = catalog.data?.severities ?? SEVERITIES;
  const severityId = useId();

  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label={webhook ? 'Edit webhook' : 'Create webhook'}
        onSubmit={(e) => void submit(e)}
      >
        <FormErrorSummary messages={messages} requestId={requestId} />
        {extra}
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Name (required)</FormLabel>
              <FormControl>
                <Input autoComplete="off" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="url"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Endpoint URL (required)</FormLabel>
              <FormControl>
                <Input
                  type="url"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="https://hooks.example.com/email-gateway"
                  {...field}
                />
              </FormControl>
              <FormDescription>
                An https URL on an allowed port (443 by default); private, loopback and internal
                hosts are refused.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Description (optional)</FormLabel>
              <FormControl>
                <Textarea rows={2} {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        {catalog.isLoading ? (
          <LoadingState label="Loading event types" rows={3} />
        ) : catalog.error ? (
          <ErrorState error={catalog.error} onRetry={() => void catalog.refetch()} compact />
        ) : (
          <Controller
            control={form.control}
            name="eventTypes"
            render={({ field, fieldState }) => (
              <CheckboxGroup
                legend="Event types (1–10, required)"
                options={types.map((t) => t.type) as (typeof EVENT_TYPES)[number][]}
                value={field.value}
                onChange={field.onChange}
                describe={describe}
                error={fieldState.error?.message}
              />
            )}
          />
        )}
        <details className="rounded-md border p-3">
          <summary className="cursor-pointer text-sm font-medium">Filters (optional)</summary>
          <div className="mt-3 grid gap-4">
            <p className="text-xs text-muted-foreground">
              An event is delivered when every filter you set matches it. Domain events carry no
              direction or verdict and pass those filters.
            </p>
            <Controller
              control={form.control}
              name="directions"
              render={({ field }) => (
                <CheckboxGroup
                  legend="Directions"
                  options={DIRECTIONS}
                  value={field.value}
                  onChange={field.onChange}
                />
              )}
            />
            {canReadDomains ? (
              <Controller
                control={form.control}
                name="domainIds"
                render={({ field, fieldState }) => (
                  <div className="grid gap-1">
                    <DomainFilter value={field.value} onChange={field.onChange} />
                    {fieldState.error ? (
                      <p className="text-xs font-medium text-destructive">
                        {fieldState.error.message}
                      </p>
                    ) : null}
                  </div>
                )}
              />
            ) : null}
            <Controller
              control={form.control}
              name="minSeverity"
              render={({ field }) => (
                <LabelledSelect
                  id={severityId}
                  label="Minimum severity"
                  value={field.value || 'any'}
                  onChange={(value) => field.onChange(value === 'any' ? '' : value)}
                  options={[
                    { value: 'any', label: 'Any severity' },
                    ...severities.map((s) => ({ value: s, label: humanize(s) })),
                  ]}
                />
              )}
            />
            <Controller
              control={form.control}
              name="verdicts"
              render={({ field }) => (
                <CheckboxGroup
                  legend="Scan verdicts"
                  options={SCAN_VERDICTS}
                  value={field.value}
                  onChange={field.onChange}
                />
              )}
            />
          </div>
        </details>
        {!webhook ? (
          <FormField
            control={form.control}
            name="status"
            render={({ field }) => (
              <FormItem className="flex flex-row items-start gap-2">
                <FormControl>
                  <Checkbox
                    checked={field.value === 'paused'}
                    onCheckedChange={(v) => field.onChange(v === true ? 'paused' : 'active')}
                  />
                </FormControl>
                <div className="grid gap-1">
                  <FormLabel className="font-normal">Create paused</FormLabel>
                  <FormDescription>
                    Paused webhooks record nothing; activate when your receiver is ready.
                  </FormDescription>
                </div>
              </FormItem>
            )}
          />
        ) : null}
        <FormField
          control={form.control}
          name="maxConcurrency"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Maximum parallel deliveries (optional)</FormLabel>
              <FormControl>
                <Input inputMode="numeric" className="w-32" {...field} />
              </FormControl>
              <FormDescription>1 to 32; empty uses the platform default.</FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button type="submit" className="justify-self-start" disabled={pending}>
          {pending ? 'Saving …' : submitLabel}
        </Button>
      </form>
    </Form>
  );
}

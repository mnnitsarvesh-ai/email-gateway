'use client';

import { PlusIcon, ServerIcon, Trash2Icon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useFieldArray, type Path } from 'react-hook-form';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { EmptyState } from '@/components/states/empty-state';
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
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { MutationError } from './kit';

type Destinations = SuccessBody<'DomainDestinationsController_get_v1'>;
type Provider = SuccessBody<'DestinationProvidersController_list_v1'>['data'][number];

const TLS_MODES = ['none', 'opportunistic', 'required', 'verify'] as const;
const TLS_LABEL: Record<(typeof TLS_MODES)[number], string> = {
  none: 'None (plain text)',
  opportunistic: 'Opportunistic (STARTTLS when offered)',
  required: 'Required (encrypted, any certificate)',
  verify: 'Verify (encrypted, certificate checked)',
};

const serverSchema = z
  .object({
    host: z.string().trim().min(1, 'Enter a host name or IP address').max(255),
    port: z.coerce.number().int('Whole number').min(1).max(65535),
    priority: z.coerce.number().int('Whole number').min(0).max(65535),
    tlsMode: z.enum(TLS_MODES),
    tlsVerifyNames: z
      .string()
      .trim()
      .regex(/^([A-Za-z0-9.:-]{1,512})?$/, 'Letters, digits, dots, colons and hyphens only'),
  })
  .strict();

/** PUT /domains/{id}/destinations: a union on `provider`; built by `destinationsBody`. */
export const destinationsSchema = z
  .object({
    provider: z.enum(['custom', 'microsoft_365', 'google_workspace']),
    host: z.string().trim().max(255),
    servers: z.array(serverSchema).max(10, 'At most 10 servers'),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.provider === 'microsoft_365' && !value.host) {
      ctx.addIssue({
        code: 'custom',
        path: ['host'],
        message: 'Enter the host from the Microsoft 365 admin center',
      });
    }
    if (value.provider === 'custom' && value.servers.length === 0) {
      ctx.addIssue({ code: 'custom', path: ['servers'], message: 'Add at least one server' });
    }
  });

export type DestinationsValues = z.output<typeof destinationsSchema>;

export function destinationsBody(
  values: DestinationsValues,
): RequestBody<'DomainDestinationsController_replace_v1'> {
  if (values.provider === 'microsoft_365') return { provider: 'microsoft_365', host: values.host };
  if (values.provider === 'google_workspace') return { provider: 'google_workspace' };
  return {
    provider: 'custom',
    servers: values.servers.map((server) => ({
      host: server.host,
      port: server.port,
      priority: server.priority,
      tlsMode: server.tlsMode,
      ...(server.tlsMode === 'verify' && server.tlsVerifyNames
        ? { tlsVerifyNames: server.tlsVerifyNames }
        : {}),
    })),
  };
}

const NEW_SERVER = {
  host: '',
  port: 25,
  priority: 10,
  tlsMode: 'opportunistic' as const,
  tlsVerifyNames: '',
};

function defaultsFrom(current: Destinations): z.input<typeof destinationsSchema> {
  const provider = current.provider ?? 'custom';
  return {
    provider,
    host: provider === 'microsoft_365' ? (current.servers[0]?.host ?? '') : '',
    servers:
      provider === 'custom' && current.servers.length > 0
        ? current.servers.map((server) => ({
            host: server.host,
            port: server.port,
            priority: server.priority,
            tlsMode: server.tlsMode,
            tlsVerifyNames: server.tlsVerifyNames ?? '',
          }))
        : [NEW_SERVER],
  };
}

function CurrentServers({ current }: { current: Destinations }) {
  if (current.servers.length === 0) {
    return (
      <EmptyState
        icon={ServerIcon}
        title="No destination servers"
        description="Approved inbound mail for this domain is held (no_destination) until destinations are set."
      />
    );
  }
  return (
    <div className="grid gap-2">
      <p className="text-sm">
        Provider: <span className="font-medium">{humanize(current.provider ?? 'custom')}</span>
      </p>
      <ol className="grid gap-1" aria-label="Destination servers in delivery order">
        {current.servers.map((server) => (
          <li
            key={server.id}
            className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border px-3 py-2 text-sm"
          >
            <code className="font-mono text-xs break-all">
              {server.host}:{server.port}
            </code>
            <span className="text-xs text-muted-foreground">priority {server.priority}</span>
            <span className="text-xs text-muted-foreground">TLS {humanize(server.tlsMode)}</span>
            {!server.enabled ? <span className="text-xs">(disabled)</span> : null}
          </li>
        ))}
      </ol>
    </div>
  );
}

function EditorForm({
  domainId,
  current,
  providers,
  onSaved,
  onCancel,
}: {
  domainId: string;
  current: Destinations;
  providers: readonly Provider[];
  onSaved?: () => void;
  onCancel?: () => void;
}) {
  const form = useZodForm(destinationsSchema, { defaultValues: defaultsFrom(current) });
  const servers = useFieldArray({ control: form.control, name: 'servers' });
  const [messages, setMessages] = useState<string[]>([]);
  const save = useApiMutation('DomainDestinationsController_replace_v1', {
    successMessage: 'Destination servers saved.',
    invalidates: ['DomainDestinationsController_get_v1'],
  });
  const provider = form.watch('provider');
  const presets = new Map(providers.map((p) => [p.provider, p]));
  const preset = presets.get(provider);
  const maxServers = presets.get('custom')?.maxServers ?? 10;

  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await save.submit({ path: { id: domainId }, body: destinationsBody(values) });
    if (outcome.ok) {
      onSaved?.();
      return;
    }
    const error = outcome.error;
    // 422 refusals name the request field (`host`, `servers.<i>.host`, …) and a stable reason.
    if (
      error instanceof ApiError &&
      error.status === 422 &&
      typeof error.details.field === 'string'
    ) {
      form.setError(error.details.field as Path<z.input<typeof destinationsSchema>>, {
        type: 'server',
        message: `${error.messages.join(' ')}${typeof error.details.reason === 'string' ? ` (${error.details.reason})` : ''}`,
      });
      setMessages([]);
      return;
    }
    setMessages(applyApiErrors(form, error));
  });

  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        aria-label="Destination servers"
        noValidate
        onSubmit={(event) => void submit(event)}
      >
        <FormErrorSummary messages={messages} requestId={save.error?.requestId} />
        <FormField
          control={form.control}
          name="provider"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Mail system</FormLabel>
              <FormControl>
                <RadioGroup
                  value={field.value}
                  onValueChange={field.onChange}
                  className="grid gap-2"
                >
                  {(['custom', 'microsoft_365', 'google_workspace'] as const)
                    .filter((value) => value === 'custom' || presets.has(value))
                    .map((value) => (
                      <div key={value} className="flex items-start gap-2 text-sm">
                        <RadioGroupItem value={value} id={`destination-provider-${value}`} />
                        <Label htmlFor={`destination-provider-${value}`} className="font-normal">
                          <span className="grid gap-0.5">
                            <span className="font-medium">
                              {presets.get(value)?.displayName ??
                                (value === 'custom' ? 'Your own servers' : humanize(value))}
                            </span>
                            <span className="text-xs text-muted-foreground">
                              {value === 'custom'
                                ? 'Exchange, Postfix or any SMTP server you operate.'
                                : value === 'microsoft_365'
                                  ? 'Port 25 with verified TLS; the host comes from the Microsoft 365 admin center.'
                                  : 'The preset Google servers with verified TLS.'}
                            </span>
                          </span>
                        </Label>
                      </div>
                    ))}
                </RadioGroup>
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        {provider === 'microsoft_365' ? (
          <FormField
            control={form.control}
            name="host"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Microsoft 365 MX host (required)</FormLabel>
                <FormControl>
                  <Input
                    placeholder={preset?.hostHint ?? 'contoso-com.mail.protection.outlook.com'}
                    autoComplete="off"
                    spellCheck={false}
                    {...field}
                  />
                </FormControl>
                <FormDescription>
                  Must match {preset?.hostPatterns.join(' or ') ?? '*.mail.protection.outlook.com'}.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        ) : null}
        {provider === 'google_workspace' ? (
          <div className="grid gap-1 text-sm">
            <p>These servers are set, in this order:</p>
            <ul className="grid gap-0.5 text-xs">
              {(preset?.defaultServers ?? []).map((server) => (
                <li key={server.host}>
                  <code className="font-mono">{server.host}</code> priority {server.priority}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {provider === 'custom' ? (
          <fieldset className="grid min-w-0 gap-3 [&>*]:min-w-0">
            <legend className="mb-1 text-sm font-medium">Servers (tried in priority order)</legend>
            {servers.fields.map((item, index) => {
              const tls = form.watch(`servers.${index}.tlsMode`);
              return (
                <div
                  key={item.id}
                  className="grid gap-3 rounded-md border p-3 sm:grid-cols-2 lg:grid-cols-[2fr_6rem_6rem_1.5fr_auto]"
                  aria-label={`Server ${index + 1}`}
                  role="group"
                >
                  <FormField
                    control={form.control}
                    name={`servers.${index}.host`}
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Host (required)</FormLabel>
                        <FormControl>
                          <Input
                            autoComplete="off"
                            spellCheck={false}
                            placeholder="mx1.example.com"
                            {...field}
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name={`servers.${index}.port`}
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Port</FormLabel>
                        <FormControl>
                          <Input
                            type="number"
                            inputMode="numeric"
                            name={field.name}
                            ref={field.ref}
                            onBlur={field.onBlur}
                            value={
                              typeof field.value === 'number' || typeof field.value === 'string'
                                ? String(field.value)
                                : ''
                            }
                            onChange={(event) => field.onChange(event.target.value)}
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name={`servers.${index}.priority`}
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Priority</FormLabel>
                        <FormControl>
                          <Input
                            type="number"
                            inputMode="numeric"
                            name={field.name}
                            ref={field.ref}
                            onBlur={field.onBlur}
                            value={
                              typeof field.value === 'number' || typeof field.value === 'string'
                                ? String(field.value)
                                : ''
                            }
                            onChange={(event) => field.onChange(event.target.value)}
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name={`servers.${index}.tlsMode`}
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>TLS</FormLabel>
                        <Select value={field.value} onValueChange={field.onChange}>
                          <FormControl>
                            <SelectTrigger className="w-full">
                              <SelectValue />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {TLS_MODES.map((mode) => (
                              <SelectItem key={mode} value={mode}>
                                {TLS_LABEL[mode]}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <div className="flex items-end">
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      aria-label={`Remove server ${index + 1}`}
                      disabled={servers.fields.length <= 1}
                      onClick={() => servers.remove(index)}
                    >
                      <Trash2Icon aria-hidden />
                    </Button>
                  </div>
                  {tls === 'verify' ? (
                    <FormField
                      control={form.control}
                      name={`servers.${index}.tlsVerifyNames`}
                      render={({ field }) => (
                        <FormItem className="sm:col-span-2 lg:col-span-5">
                          <FormLabel>Certificate names</FormLabel>
                          <FormControl>
                            <Input
                              autoComplete="off"
                              spellCheck={false}
                              placeholder="nexthop:.example.com"
                              {...field}
                            />
                          </FormControl>
                          <FormDescription>
                            A Postfix match list; empty means nexthop.
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  ) : null}
                </div>
              );
            })}
            {form.formState.errors.servers?.message ? (
              <p className="text-xs font-medium text-destructive" role="alert">
                {form.formState.errors.servers.message}
              </p>
            ) : null}
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="justify-self-start"
              disabled={servers.fields.length >= maxServers}
              onClick={() => servers.append(NEW_SERVER)}
            >
              <PlusIcon aria-hidden />
              Add server
            </Button>
          </fieldset>
        ) : null}
        <p className="text-xs text-muted-foreground">
          Saving replaces every destination of the domain at once; the gateway follows within
          seconds.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button type="submit" disabled={save.isPending || save.retryAfterSeconds > 0}>
            {save.isPending ? 'Saving …' : 'Save destinations'}
          </Button>
          {onCancel ? (
            <Button type="button" variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
          ) : null}
        </div>
      </form>
    </Form>
  );
}

/**
 * Where a domain's approved inbound mail is delivered (`GET/PUT/DELETE /domains/{id}/destinations`,
 * presets from `GET /destination-providers`; changing them needs `domain:routing_manage`).
 */
export function DestinationsEditor({
  domainId,
  onSaved,
  startEditing = false,
}: {
  domainId: string;
  onSaved?: () => void;
  startEditing?: boolean;
}) {
  const canEdit = useCan('DomainDestinationsController_replace_v1');
  const current = useApiQuery('DomainDestinationsController_get_v1', { path: { id: domainId } });
  const providers = useApiQuery('DestinationProvidersController_list_v1');
  const [editing, setEditing] = useState(startEditing);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const remove = useApiMutation('DomainDestinationsController_remove_v1', {
    successMessage: 'Destination servers removed.',
    invalidates: ['DomainDestinationsController_get_v1'],
  });
  useEffect(() => {
    if (startEditing) setEditing(true);
  }, [startEditing]);

  if (current.isLoading || providers.isLoading)
    return <LoadingState label="Loading destination servers" rows={3} />;
  if (current.error)
    return <ErrorState error={current.error} onRetry={() => void current.refetch()} />;
  if (providers.error)
    return <ErrorState error={providers.error} onRetry={() => void providers.refetch()} />;
  if (!current.data) return null;

  if (editing && canEdit) {
    return (
      <EditorForm
        domainId={domainId}
        current={current.data}
        providers={providers.data?.data ?? []}
        onSaved={() => {
          setEditing(false);
          onSaved?.();
        }}
        onCancel={() => setEditing(false)}
      />
    );
  }
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <CurrentServers current={current.data} />
      <Can op="DomainDestinationsController_replace_v1">
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => setEditing(true)}>
            {current.data.servers.length > 0 ? 'Edit destinations' : 'Set destinations'}
          </Button>
          {current.data.servers.length > 0 ? (
            <Button variant="ghost" onClick={() => setConfirmRemove(true)}>
              Remove all destinations
            </Button>
          ) : null}
        </div>
      </Can>
      <ConfirmDialog
        open={confirmRemove}
        onOpenChange={(open) => {
          setConfirmRemove(open);
          if (!open) remove.reset();
        }}
        title="Remove every destination server?"
        description="Approved inbound mail for this domain is then held (no_destination) until destinations are set again."
        confirmLabel="Remove destinations"
        destructive
        error={<MutationError error={remove.error} />}
        onConfirm={async () => (await remove.submit({ path: { id: domainId } })).ok}
      />
    </div>
  );
}

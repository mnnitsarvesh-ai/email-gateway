'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { z } from 'zod';
import { PageHeader } from '@/components/page-header';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
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
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { QueryView, Section } from '@/features/domains/kit';
import { PROVIDERS, PROVIDER_LABEL, errorHint, type Catalog, type Provider } from './model';

/** POST /provider-connections `{ provider, displayName }` (1–128 characters, no control chars). */
export const newConnectionSchema = z
  .object({
    provider: z.enum(['microsoft_365', 'google_workspace']),
    displayName: z
      .string()
      .trim()
      .min(1, 'Enter a name')
      .max(128, 'At most 128 characters')
      .regex(/^[^\p{Cc}]+$/u, 'No control characters'),
  })
  .strict();

const URL_SHAPE = {
  provider: z.enum(['microsoft_365', 'google_workspace']).optional().catch(undefined),
};

const PROVIDER_DESCRIPTION: Record<Provider, string> = {
  microsoft_365:
    'Exchange Online: inbound through the gateway to your tenant, outbound and internal mail relayed through the gateway with tenant proof.',
  google_workspace:
    'Gmail: inbound gateway, outbound and internal routing through the gateway, SMTP relay settings for devices and applications.',
};

/** `/integrations/providers/new`: choose the provider and name the connection. */
export function NewConnectionPage() {
  return (
    <RouteGate gate={['ProviderConnectionsController_create_v1']}>
      <NewConnection />
    </RouteGate>
  );
}

function NewConnection() {
  const catalog = useApiQuery('ProviderCatalogController_get_v1');
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title="Connect Microsoft 365 or Google Workspace"
        breadcrumbs={[
          { label: 'Integrations', href: '/integrations' },
          { label: 'New connection' },
        ]}
        description="The gateway requests read-only access to your tenant and never changes your mail-flow settings there: you apply every customer-side change yourself from a setup guide written for your tenant."
      />
      <QueryView query={catalog} label="providers" notFound="inline">
        {(data) => <NewConnectionForm catalog={data} />}
      </QueryView>
    </div>
  );
}

function NewConnectionForm({ catalog }: { catalog: Catalog }) {
  const router = useRouter();
  const [{ provider: preset }] = useUrlState(URL_SHAPE);
  const [messages, setMessages] = useState<string[]>([]);
  const create = useApiMutation('ProviderConnectionsController_create_v1', {
    invalidates: ['ProviderConnectionsController_list_v1'],
    successMessage: 'Connection created.',
  });
  const form = useZodForm(newConnectionSchema, {
    defaultValues: { provider: preset ?? 'microsoft_365', displayName: '' },
  });
  const provider = form.watch('provider');
  const profile = catalog.providers.find((p) => p.provider === provider)?.profiles[0];

  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await create.submit({ body: newConnectionSchema.parse(values) });
    if (!outcome.ok) {
      const hint = errorHint(outcome.error.code);
      return setMessages([...applyApiErrors(form, outcome.error), ...(hint ? [hint] : [])]);
    }
    router.push(`/integrations/providers/${outcome.data.id}?tab=setup`);
  });

  return (
    <Section title="New connection">
      <Form {...form}>
        <form
          className="grid max-w-2xl min-w-0 gap-5"
          noValidate
          aria-label="New connection"
          onSubmit={(event) => void submit(event)}
        >
          <FormErrorSummary messages={messages} requestId={create.error?.requestId} />
          <FormField
            control={form.control}
            name="provider"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Provider</FormLabel>
                <FormControl>
                  <RadioGroup
                    value={field.value}
                    onValueChange={field.onChange}
                    className="grid gap-3 sm:grid-cols-2"
                  >
                    {PROVIDERS.map((value) => {
                      const id = `provider-${value}`;
                      return (
                        <label
                          key={value}
                          htmlFor={id}
                          className="flex cursor-pointer items-start gap-3 rounded-md border p-3 has-[[data-state=checked]]:border-primary"
                        >
                          <RadioGroupItem id={id} value={value} className="mt-1" />
                          <span className="grid gap-1">
                            <span className="font-medium">{PROVIDER_LABEL[value]}</span>
                            <span className="text-xs text-muted-foreground">
                              {PROVIDER_DESCRIPTION[value]}
                            </span>
                          </span>
                        </label>
                      );
                    })}
                  </RadioGroup>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          {profile ? (
            <div className="grid gap-1 rounded-md border p-3 text-sm">
              <p className="font-medium">
                Access requested: {profile.title}
                {profile.readOnly ? ' (read-only)' : ''}
              </p>
              <p className="text-muted-foreground">{profile.description}</p>
              <ul className="list-disc pl-5 font-mono text-xs break-all">
                {profile.permissions.map((permission) => (
                  <li key={permission}>{permission}</li>
                ))}
              </ul>
            </div>
          ) : null}
          <FormField
            control={form.control}
            name="displayName"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Connection name (required)</FormLabel>
                <FormControl>
                  <Input autoComplete="off" {...field} />
                </FormControl>
                <FormDescription>
                  For example the tenant or business unit, such as “Contoso production”.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? 'Creating …' : 'Create and continue'}
            </Button>
            <Button type="button" variant="ghost" onClick={() => router.push('/integrations')}>
              Cancel
            </Button>
          </div>
        </form>
      </Form>
    </Section>
  );
}

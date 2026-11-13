'use client';

import { KeyRoundIcon, PlusIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Controller } from 'react-hook-form';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { PageHeader } from '@/components/page-header';
import { SecretRevealDialog } from '@/components/secret-reveal-dialog';
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
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem, RequestBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan, usePermissions } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { FormDialog, MutationError } from '@/features/domains/kit';
import { PermissionMatrix, type Permission } from '@/features/roles/permission-matrix';

type ApiKey = ListItem<'ApiKeysController_list_v1'>;

const MAX_EXPIRY_DAYS = 3650;

/** POST /api-keys: name, scopes (the caller's own tenant permissions), optional expiry day. */
export const apiKeySchema = z
  .object({
    name: z.string().trim().min(1, 'Enter a name').max(255),
    scopes: z.array(z.string()).min(1, 'Choose at least one scope').max(100),
    expiresOn: z
      .string()
      .regex(/^(\d{4}-\d{2}-\d{2})?$/, 'Enter a date')
      .refine(
        (day) => !day || Date.parse(`${day}T23:59:59.000Z`) > Date.now(),
        'Choose a future date',
      )
      .refine(
        (day) =>
          !day || Date.parse(`${day}T23:59:59.000Z`) <= Date.now() + MAX_EXPIRY_DAYS * 86_400_000,
        'Choose a date within ten years',
      ),
  })
  .strict();

export function apiKeyBody(
  values: z.output<typeof apiKeySchema>,
): RequestBody<'ApiKeysController_create_v1'> {
  return {
    name: values.name,
    scopes: values.scopes,
    ...(values.expiresOn ? { expiresAt: `${values.expiresOn}T23:59:59.000Z` } : {}),
  };
}

/** Scopes an API key may carry: the caller's own tenant permissions (platform ones never). */
export function grantableScopes(
  held: ReadonlySet<string>,
  catalog: readonly Permission[] | undefined,
): Permission[] {
  const tenant = [...held].filter((p) => !p.startsWith('platform:'));
  if (catalog) return catalog.filter((p) => tenant.includes(p.key));
  return tenant
    .sort()
    .map((key) => ({ key, description: '', category: key.split(':')[0] ?? 'other' }));
}

function CreateKey({ onCreated }: { onCreated: (key: { name: string; key: string }) => void }) {
  const held = usePermissions();
  const canCatalog = useCan('PermissionsController_list_v1');
  const catalog = useApiQuery('PermissionsController_list_v1', undefined, { enabled: canCatalog });
  const [messages, setMessages] = useState<string[]>([]);
  const create = useApiMutation('ApiKeysController_create_v1', {
    invalidates: ['ApiKeysController_list_v1'],
    successMessage: null,
  });
  const form = useZodForm(apiKeySchema, { defaultValues: { name: '', scopes: [], expiresOn: '' } });
  const scopes = grantableScopes(held, catalog.data?.data);
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await create.submit({ body: apiKeyBody(values) });
    if (!outcome.ok) {
      const lines = applyApiErrors(form, outcome.error);
      return setMessages(
        outcome.error.status === 403
          ? [...lines, 'API keys can only carry permissions you hold yourself.']
          : lines,
      );
    }
    // The key is in this response only (P12): hand it over and drop the mutation's copy.
    onCreated({ name: outcome.data.apiKey.name, key: outcome.data.key });
    create.reset();
  });
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label="Create API key"
        onSubmit={(e) => void submit(e)}
      >
        <FormErrorSummary messages={messages} requestId={create.error?.requestId} />
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Name (required)</FormLabel>
              <FormControl>
                <Input autoComplete="off" placeholder="SIEM export" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="expiresOn"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Expires on (optional)</FormLabel>
              <FormControl>
                <Input type="date" {...field} />
              </FormControl>
              <FormDescription>End of that day, UTC. Empty: until revoked.</FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <Controller
          control={form.control}
          name="scopes"
          render={({ field, fieldState }) => (
            <div className="grid gap-2">
              <span className="text-sm font-medium">
                Scopes (at least one; only permissions you hold)
              </span>
              <PermissionMatrix catalog={scopes} value={field.value} onChange={field.onChange} />
              {fieldState.error ? (
                <p className="text-xs font-medium text-destructive" role="alert">
                  {fieldState.error.message}
                </p>
              ) : null}
            </div>
          )}
        />
        <Button type="submit" className="justify-self-start" disabled={create.isPending}>
          {create.isPending ? 'Creating …' : 'Create API key'}
        </Button>
      </form>
    </Form>
  );
}

function KeyState({ apiKey }: { apiKey: ApiKey }) {
  if (apiKey.revokedAt) return <ToneBadge tone="neutral">Revoked</ToneBadge>;
  if (apiKey.expiresAt && Date.parse(apiKey.expiresAt) <= Date.now())
    return <ToneBadge tone="warning">Expired</ToneBadge>;
  return <ToneBadge tone="success">Active</ToneBadge>;
}

/** `/integrations/api-keys`: list, create (key shown once), revoke (typed confirmation). */
export function ApiKeysPage() {
  return (
    <RouteGate gate={['ApiKeysController_list_v1']}>
      <ApiKeys />
    </RouteGate>
  );
}

function ApiKeys() {
  const canRevoke = useCan('ApiKeysController_revoke_v1');
  const list = useCursorList('ApiKeysController_list_v1', {});
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<{ name: string; key: string } | null>(null);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);
  const revoke = useApiMutation('ApiKeysController_revoke_v1', {
    invalidates: ['ApiKeysController_list_v1'],
    successMessage: 'API key revoked.',
  });
  const columns = useMemo<DataTableColumn<ApiKey>[]>(
    () => [
      {
        id: 'name',
        header: 'Name',
        meta: { label: 'Name' },
        cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
      },
      {
        id: 'prefix',
        header: 'Prefix',
        meta: { label: 'Prefix' },
        cell: ({ row }) => <code className="font-mono text-xs">{row.original.prefix}…</code>,
      },
      {
        id: 'state',
        header: 'State',
        meta: { label: 'State' },
        cell: ({ row }) => <KeyState apiKey={row.original} />,
      },
      {
        id: 'scopes',
        header: 'Scopes',
        meta: { label: 'Scopes' },
        cell: ({ row }) => (
          <span className="text-xs" title={row.original.scopes.join(', ')}>
            {row.original.scopes.length} permission{row.original.scopes.length === 1 ? '' : 's'}
          </span>
        ),
      },
      {
        id: 'createdBy',
        header: 'Created by',
        meta: { label: 'Created by' },
        cell: ({ row }) =>
          row.original.createdBy?.displayName ?? (
            <span className="text-muted-foreground">Unknown</span>
          ),
      },
      {
        id: 'lastUsedAt',
        header: 'Last used',
        meta: { label: 'Last used' },
        cell: ({ row }) => <DateTime value={row.original.lastUsedAt} />,
      },
      {
        id: 'expiresAt',
        header: 'Expires',
        meta: { label: 'Expires' },
        cell: ({ row }) => <DateTime value={row.original.expiresAt} emptyLabel="Never" />,
      },
    ],
    [],
  );
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title="API keys"
        breadcrumbs={[{ label: 'Integrations', href: '/integrations' }, { label: 'API keys' }]}
        description="Server-to-server access to the REST API (X-API-Key header). A key acts within your organization with the scopes it was given; the key itself is shown once."
        actions={
          <Can op="ApiKeysController_create_v1">
            <Button onClick={() => setCreating(true)}>
              <PlusIcon aria-hidden />
              New API key
            </Button>
          </Can>
        }
      />
      <DataTable
        tableId="api-keys"
        caption="API keys"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        rowActions={
          canRevoke
            ? (row) =>
                row.revokedAt
                  ? []
                  : [{ label: 'Revoke', destructive: true, onSelect: () => setRevoking(row) }]
            : undefined
        }
        emptyState={
          <EmptyState
            icon={KeyRoundIcon}
            title="No API keys"
            description="Create a key for an integration that calls the REST API."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <span className="font-medium">{row.name}</span>
            <span className="flex items-center gap-2 text-xs">
              <code className="font-mono">{row.prefix}…</code> <KeyState apiKey={row} />
            </span>
          </div>
        )}
      />
      <FormDialog open={creating} onOpenChange={setCreating} title="New API key" wide>
        <CreateKey
          onCreated={(key) => {
            setCreating(false);
            setCreated(key);
          }}
        />
      </FormDialog>
      <SecretRevealDialog
        open={created !== null}
        title={`API key ${created?.name ?? ''}`}
        description="Send it in the X-API-Key header. It is shown only now; revoke the key and create a new one if it is lost."
        secrets={created ? [{ label: 'API key', value: created.key }] : []}
        onClose={() => setCreated(null)}
      />
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRevoking(null);
            revoke.reset();
          }
        }}
        title={`Revoke ${revoking?.name ?? 'the API key'}?`}
        description="Every request with this key is refused immediately. This cannot be undone."
        confirmLabel="Revoke key"
        destructive
        typedConfirmation={revoking?.name}
        error={<MutationError error={revoke.error} />}
        onConfirm={async () =>
          revoking ? (await revoke.submit({ path: { id: revoking.id } })).ok : false
        }
      />
    </div>
  );
}

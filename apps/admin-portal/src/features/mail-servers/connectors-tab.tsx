'use client';

import { CableIcon, PlusIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { SecretRevealDialog } from '@/components/secret-reveal-dialog';
import { EmptyState } from '@/components/states/empty-state';
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
import { Textarea } from '@/components/ui/textarea';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useCursorList } from '@/lib/api/hooks';
import type { ListItem, RequestBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan } from '@/lib/auth/me';
import { FilterSelect, FormDialog, MutationError, splitList } from '@/features/domains/kit';

type Connector = ListItem<'SmtpConnectorsController_list_v1'>;
type AuthType = Connector['authType'];

const AUTH_TYPES: readonly AuthType[] = ['sasl', 'source_ip', 'client_certificate'];
export const AUTH_LABEL: Record<AuthType, string> = {
  sasl: 'SMTP AUTH (username and password)',
  source_ip: 'Source IP networks',
  client_certificate: 'Client certificate',
};
const AUTH_SHORT: Record<AuthType, string> = {
  sasl: 'SMTP AUTH',
  source_ip: 'Source IP',
  client_certificate: 'Client certificate',
};

const URL_SHAPE = {
  cstatus: z.enum(['active', 'disabled']).optional().catch(undefined),
  authType: z.enum(['sasl', 'source_ip', 'client_certificate']).optional().catch(undefined),
};

const name = z
  .string()
  .trim()
  .min(1, 'Enter a name')
  .max(128)
  .regex(/^[^\p{Cc}]+$/u, 'No control characters');

/** POST /smtp-connectors (form values; `connectorCreateBody` builds the request per type). */
export const connectorCreateSchema = z
  .object({
    name,
    authType: z.enum(['sasl', 'source_ip', 'client_certificate']),
    networks: z.string().max(4000),
    certificateFingerprintSha256: z
      .string()
      .trim()
      .regex(
        /^([0-9A-Fa-f]{2}:?){31}[0-9A-Fa-f]{2}$|^$/,
        'Enter the 64 hex characters (colons optional)',
      ),
    requireTls: z.boolean(),
  })
  .strict()
  .superRefine((value, ctx) => {
    const networks = splitList(value.networks);
    if (value.authType === 'source_ip' && networks.length === 0)
      ctx.addIssue({ code: 'custom', path: ['networks'], message: 'Add at least one network' });
    if (networks.length > 20)
      ctx.addIssue({ code: 'custom', path: ['networks'], message: 'At most 20 networks' });
    if (value.authType === 'client_certificate' && !value.certificateFingerprintSha256)
      ctx.addIssue({
        code: 'custom',
        path: ['certificateFingerprintSha256'],
        message: 'Enter the certificate fingerprint',
      });
  });

export function connectorCreateBody(
  values: z.output<typeof connectorCreateSchema>,
): RequestBody<'SmtpConnectorsController_create_v1'> {
  const networks = splitList(values.networks);
  if (values.authType === 'sasl') return { name: values.name, authType: 'sasl' };
  if (values.authType === 'source_ip')
    return { name: values.name, authType: 'source_ip', networks, requireTls: values.requireTls };
  return {
    name: values.name,
    authType: 'client_certificate',
    certificateFingerprintSha256: values.certificateFingerprintSha256,
    ...(networks.length > 0 ? { networks } : {}),
  };
}

/** PATCH /smtp-connectors/{id}: name, networks (not for SASL), requireTls (source IP only). */
export const connectorUpdateSchema = z
  .object({ name, networks: z.string().max(4000), requireTls: z.boolean() })
  .strict();

export function connectorUpdateBody(
  connector: Pick<Connector, 'authType'>,
  values: z.output<typeof connectorUpdateSchema>,
): RequestBody<'SmtpConnectorsController_update_v1'> {
  const networks = splitList(values.networks);
  if (connector.authType === 'sasl') return { name: values.name };
  if (connector.authType === 'source_ip')
    return { name: values.name, networks, requireTls: values.requireTls };
  return { name: values.name, networks };
}

function ConnectorForm({
  mode,
  connector,
  onDone,
  onCreated,
}: {
  mode: 'create' | 'edit';
  connector?: Connector;
  onDone: () => void;
  onCreated?: (credentials: { username: string; password: string }) => void;
}) {
  const [messages, setMessages] = useState<string[]>([]);
  const create = useApiMutation('SmtpConnectorsController_create_v1', {
    invalidates: ['SmtpConnectorsController_list_v1'],
    successMessage: 'Connector created.',
  });
  const update = useApiMutation('SmtpConnectorsController_update_v1', {
    invalidates: ['SmtpConnectorsController_list_v1'],
    successMessage: 'Connector saved.',
  });
  const form = useZodForm(connectorCreateSchema, {
    defaultValues: {
      name: connector?.name ?? '',
      authType: connector?.authType ?? 'sasl',
      networks: connector?.networks.map((n) => n.cidr).join('\n') ?? '',
      certificateFingerprintSha256: connector?.certificateFingerprintSha256 ?? '',
      requireTls: connector?.requireTls ?? true,
    },
  });
  const authType = form.watch('authType');
  const pending = create.isPending || update.isPending;

  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    if (mode === 'create') {
      const outcome = await create.submit({ body: connectorCreateBody(values) });
      if (!outcome.ok) return setMessages(applyApiErrors(form, outcome.error));
      // The SASL password is in this response only (P12): hand it to the one-time dialog.
      if (outcome.data.credentials) onCreated?.(outcome.data.credentials);
      create.reset();
      onDone();
      return;
    }
    if (!connector) return;
    const outcome = await update.submit({
      path: { id: connector.id },
      body: connectorUpdateBody(
        connector,
        connectorUpdateSchema.parse({
          name: values.name,
          networks: values.networks,
          requireTls: values.requireTls,
        }),
      ),
    });
    if (!outcome.ok) return setMessages(applyApiErrors(form, outcome.error));
    onDone();
  });

  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label={mode === 'create' ? 'Create connector' : 'Edit connector'}
        onSubmit={(e) => void submit(e)}
      >
        <FormErrorSummary
          messages={messages}
          requestId={(create.error ?? update.error)?.requestId}
        />
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
          name="authType"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Authentication</FormLabel>
              <Select value={field.value} onValueChange={field.onChange} disabled={mode === 'edit'}>
                <FormControl>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {AUTH_TYPES.map((type) => (
                    <SelectItem key={type} value={type}>
                      {AUTH_LABEL[type]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormDescription>
                {authType === 'sasl'
                  ? 'The gateway generates a username and password, shown once after creation.'
                  : authType === 'source_ip'
                    ? 'Never use source IP connectors for shared mail platforms such as Microsoft 365 or Google Workspace.'
                    : 'The SHA-256 fingerprint of the certificate your server presents on port 25.'}
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        {authType !== 'sasl' ? (
          <FormField
            control={form.control}
            name="networks"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Networks{authType === 'source_ip' ? ' (required)' : ' (optional)'}
                </FormLabel>
                <FormControl>
                  <Textarea
                    rows={4}
                    spellCheck={false}
                    placeholder={'192.0.2.0/27\n2001:db8:10::/48'}
                    {...field}
                  />
                </FormControl>
                <FormDescription>
                  One public CIDR per line (IPv4 /16 or longer, IPv6 /48 or longer), at most 20.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        ) : null}
        {authType === 'client_certificate' && mode === 'create' ? (
          <FormField
            control={form.control}
            name="certificateFingerprintSha256"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Certificate SHA-256 fingerprint (required)</FormLabel>
                <FormControl>
                  <Input autoComplete="off" spellCheck={false} className="font-mono" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        ) : null}
        {authType === 'source_ip' ? (
          <FormField
            control={form.control}
            name="requireTls"
            render={({ field }) => (
              <FormItem className="flex flex-row items-start gap-2">
                <FormControl>
                  <Checkbox
                    checked={field.value}
                    onCheckedChange={(v) => field.onChange(v === true)}
                  />
                </FormControl>
                <div className="grid gap-1">
                  <FormLabel className="font-normal">Require TLS (STARTTLS)</FormLabel>
                  <FormDescription>Turn off only for servers that cannot encrypt.</FormDescription>
                </div>
              </FormItem>
            )}
          />
        ) : null}
        <Button type="submit" className="justify-self-start" disabled={pending}>
          {pending ? 'Saving …' : mode === 'create' ? 'Create connector' : 'Save connector'}
        </Button>
      </form>
    </Form>
  );
}

function StatusBadge({ status }: { status: Connector['status'] }) {
  return (
    <ToneBadge tone={status === 'active' ? 'success' : 'neutral'}>
      {status === 'active' ? 'Active' : 'Disabled'}
    </ToneBadge>
  );
}

function Identity({ connector }: { connector: Connector }) {
  if (connector.authType === 'sasl')
    return (
      <code className="font-mono text-xs">{connector.saslUsername ?? 'username not set'}</code>
    );
  if (connector.authType === 'client_certificate' && connector.certificateFingerprintSha256)
    return (
      <code className="font-mono text-xs break-all" title={connector.certificateFingerprintSha256}>
        {connector.certificateFingerprintSha256.slice(0, 16)}…
      </code>
    );
  return (
    <span className="text-xs">
      {connector.networks.length === 0
        ? 'No networks'
        : connector.networks.map((n) => n.cidr).join(', ')}
    </span>
  );
}

/** SMTP connectors (`/smtp-connectors`): relay authorization of the tenant's own servers. */
export function ConnectorsTab() {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const canManage = useCan('SmtpConnectorsController_update_v1');
  const list = useCursorList('SmtpConnectorsController_list_v1', {
    ...(filters.cstatus ? { status: filters.cstatus } : {}),
    ...(filters.authType ? { authType: filters.authType } : {}),
  });
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Connector | null>(null);
  const [rotating, setRotating] = useState<Connector | null>(null);
  const [deleting, setDeleting] = useState<Connector | null>(null);
  const [toggling, setToggling] = useState<Connector | null>(null);
  const [secret, setSecret] = useState<{
    username: string;
    password: string;
    title: string;
  } | null>(null);

  const rotate = useApiMutation('SmtpConnectorsController_rotateSecret_v1', {
    invalidates: ['SmtpConnectorsController_list_v1'],
  });
  const remove = useApiMutation('SmtpConnectorsController_remove_v1', {
    invalidates: ['SmtpConnectorsController_list_v1'],
    successMessage: 'Connector deleted.',
  });
  const toggle = useApiMutation('SmtpConnectorsController_update_v1', {
    invalidates: ['SmtpConnectorsController_list_v1'],
    successMessage: 'Connector updated.',
  });

  const columns = useMemo<DataTableColumn<Connector>[]>(
    () => [
      {
        id: 'name',
        header: 'Name',
        meta: { label: 'Name' },
        cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
      },
      {
        id: 'authType',
        header: 'Authentication',
        meta: { label: 'Authentication' },
        cell: ({ row }) => AUTH_SHORT[row.original.authType],
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => <StatusBadge status={row.original.status} />,
      },
      {
        id: 'identity',
        header: 'Username / networks',
        meta: { label: 'Username / networks' },
        cell: ({ row }) => <Identity connector={row.original} />,
      },
      {
        id: 'tls',
        header: 'TLS',
        meta: { label: 'TLS' },
        cell: ({ row }) => (row.original.requireTls ? 'Required' : 'Optional'),
      },
      {
        id: 'secretSetAt',
        header: 'Secret set',
        meta: { label: 'Secret set' },
        cell: ({ row }) =>
          row.original.authType === 'sasl' ? (
            <DateTime value={row.original.secretSetAt} />
          ) : (
            <span className="text-muted-foreground">No secret</span>
          ),
      },
      {
        id: 'createdAt',
        header: 'Created',
        meta: { label: 'Created' },
        cell: ({ row }) => <DateTime value={row.original.createdAt} />,
      },
    ],
    [],
  );

  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          Connectors let your own mail servers relay outbound mail through the gateway.
        </p>
        <Can op="SmtpConnectorsController_create_v1">
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon aria-hidden />
            New connector
          </Button>
        </Can>
      </div>
      <DataTable
        tableId="smtp-connectors"
        caption="SMTP connectors"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        filters={
          <>
            <FilterSelect
              label="Status"
              value={filters.cstatus}
              onChange={(cstatus) =>
                setFilters({ cstatus: cstatus as 'active' | 'disabled' | undefined })
              }
              options={[
                { value: 'active', label: 'Active' },
                { value: 'disabled', label: 'Disabled' },
              ]}
            />
            <FilterSelect
              label="Authentication"
              value={filters.authType}
              onChange={(authType) => setFilters({ authType: authType as AuthType | undefined })}
              options={AUTH_TYPES.map((t) => ({ value: t, label: AUTH_SHORT[t] }))}
            />
          </>
        }
        isFiltered={Boolean(filters.cstatus || filters.authType)}
        onClearFilters={() => setFilters({ cstatus: undefined, authType: undefined })}
        rowActions={
          canManage
            ? (row) => [
                { label: 'Edit', onSelect: () => setEditing(row) },
                {
                  label: row.status === 'active' ? 'Disable' : 'Enable',
                  onSelect: () => setToggling(row),
                },
                ...(row.authType === 'sasl'
                  ? [{ label: 'Rotate password', onSelect: () => setRotating(row) }]
                  : []),
                { label: 'Delete', destructive: true, onSelect: () => setDeleting(row) },
              ]
            : undefined
        }
        emptyState={
          <EmptyState
            icon={CableIcon}
            title="No SMTP connectors"
            description="Create a connector so your mail servers can relay outbound mail through the gateway."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <span className="font-medium">{row.name}</span>
            <span className="flex flex-wrap items-center gap-2 text-xs">
              {AUTH_SHORT[row.authType]} <StatusBadge status={row.status} />
            </span>
            <Identity connector={row} />
          </div>
        )}
      />
      <FormDialog open={creating} onOpenChange={setCreating} title="New SMTP connector">
        <ConnectorForm
          mode="create"
          onDone={() => setCreating(false)}
          onCreated={(credentials) => setSecret({ ...credentials, title: 'Connector credentials' })}
        />
      </FormDialog>
      <FormDialog
        open={editing !== null}
        onOpenChange={(open) => !open && setEditing(null)}
        title={`Edit ${editing?.name ?? 'connector'}`}
      >
        {editing ? (
          <ConnectorForm mode="edit" connector={editing} onDone={() => setEditing(null)} />
        ) : null}
      </FormDialog>
      <ConfirmDialog
        open={toggling !== null}
        onOpenChange={(open) => {
          if (!open) {
            setToggling(null);
            toggle.reset();
          }
        }}
        title={
          toggling?.status === 'active'
            ? `Disable ${toggling.name}?`
            : `Enable ${toggling?.name ?? ''}?`
        }
        description={
          toggling?.status === 'active'
            ? 'The connector stops authorizing relays within about 30 seconds.'
            : 'The connector authorizes relays again within about 30 seconds.'
        }
        confirmLabel={toggling?.status === 'active' ? 'Disable' : 'Enable'}
        destructive={toggling?.status === 'active'}
        error={<MutationError error={toggle.error} />}
        onConfirm={async () => {
          if (!toggling) return false;
          return (
            await toggle.submit({
              path: { id: toggling.id },
              body: { status: toggling.status === 'active' ? 'disabled' : 'active' },
            })
          ).ok;
        }}
      />
      <ConfirmDialog
        open={rotating !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRotating(null);
            rotate.reset();
          }
        }}
        title={`Rotate the password of ${rotating?.name ?? ''}?`}
        description="A new password is generated and shown once. The current password stops working immediately; update your mail server right away."
        confirmLabel="Rotate password"
        destructive
        error={<MutationError error={rotate.error} />}
        onConfirm={async () => {
          if (!rotating) return false;
          const outcome = await rotate.submit({ path: { id: rotating.id } });
          if (outcome.ok) {
            setSecret({ ...outcome.data.credentials, title: 'New connector password' });
            rotate.reset();
          }
          return outcome.ok;
        }}
      />
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
            remove.reset();
          }
        }}
        title={`Delete ${deleting?.name ?? 'connector'}?`}
        description="The connector and its networks are removed; servers using it can no longer relay."
        confirmLabel="Delete connector"
        destructive
        error={<MutationError error={remove.error} />}
        onConfirm={async () =>
          deleting ? (await remove.submit({ path: { id: deleting.id } })).ok : false
        }
      />
      <SecretRevealDialog
        open={secret !== null}
        title={secret?.title ?? 'Connector credentials'}
        description="Configure your mail server with these SMTP AUTH credentials (submission port 587, STARTTLS). The password is shown only now."
        secrets={
          secret
            ? [
                { label: 'Username', value: secret.username },
                { label: 'Password', value: secret.password },
              ]
            : []
        }
        onClose={() => setSecret(null)}
      />
    </div>
  );
}

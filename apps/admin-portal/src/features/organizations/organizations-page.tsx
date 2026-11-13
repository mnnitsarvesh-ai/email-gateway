'use client';

import { PlusIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { toast } from 'sonner';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
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
import { Label } from '@/components/ui/label';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useCursorList } from '@/lib/api/hooks';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useMe, usePermissions } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import { SelectFilter, TextFilter } from '@/features/reports/filters';
import { navGate } from '@/features/reports/nav-gate';
import { OrganizationDetail } from './organization-detail-page';
import { createOrganizationBody, createOrganizationSchema } from './schemas';

type OrgRow = ListItem<'OrganizationsController_list_v1'>;
export type Organization = SuccessBody<'OrganizationsController_get_v1'>;

export const ORG_STATUS_TONE = {
  active: 'success',
  suspended: 'warning',
  pending_deletion: 'orange',
  deleted: 'neutral',
} as const;

export function OrganizationStatusBadge({ status }: { status: Organization['status'] }) {
  return <ToneBadge tone={ORG_STATUS_TONE[status]}>{humanize(status)}</ToneBadge>;
}

export const ORGANIZATIONS_URL_SHAPE = {
  q: z.string().trim().min(1).max(63).optional().catch(undefined),
  status: z
    .enum(['active', 'suspended', 'pending_deletion', 'deleted'])
    .optional()
    .catch(undefined),
  kind: z.enum(['customer', 'platform']).optional().catch(undefined),
  planCode: z
    .string()
    .regex(/^[a-z0-9_-]+$/)
    .max(32)
    .optional()
    .catch(undefined),
  deploymentMode: z.enum(['saas', 'dedicated']).optional().catch(undefined),
};

/**
 * `/organizations` (design §1.3 row 3): platform users (`platform:organizations`) get the
 * catalogue; everybody else sees their own organization (id from `GET /auth/me`).
 */
export function OrganizationsPage() {
  return (
    <RouteGate gate={navGate('organizations')}>
      <OrganizationsContent />
    </RouteGate>
  );
}

function OrganizationsContent() {
  const permissions = usePermissions();
  const me = useMe();
  if (permissions.has('platform:organizations')) return <Catalogue />;
  const own = me.data?.organization.id;
  if (!own) return <LoadingState label="Loading your organization" rows={4} />;
  return <OrganizationDetail organizationId={own} tenantView />;
}

const columns: DataTableColumn<OrgRow>[] = [
  {
    id: 'name',
    header: 'Organization',
    meta: { label: 'Organization' },
    cell: ({ row }) => (
      <span className="grid min-w-0">
        <Link
          href={`/organizations/${row.original.id}`}
          className="truncate font-medium text-primary hover:underline"
        >
          {row.original.name}
        </Link>
        <span className="font-mono text-xs text-muted-foreground">{row.original.slug}</span>
      </span>
    ),
  },
  {
    id: 'status',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => <OrganizationStatusBadge status={row.original.status} />,
  },
  {
    id: 'kind',
    header: 'Kind',
    meta: { label: 'Kind' },
    cell: ({ row }) => humanize(row.original.kind),
  },
  {
    id: 'plan',
    header: 'Plan',
    meta: { label: 'Plan' },
    cell: ({ row }) => (
      <span>
        {row.original.plan.name}{' '}
        <span className="font-mono text-xs text-muted-foreground">{row.original.plan.code}</span>
      </span>
    ),
  },
  {
    id: 'deployment',
    header: 'Deployment',
    meta: { label: 'Deployment' },
    cell: ({ row }) =>
      `${row.original.deploymentMode === 'saas' ? 'SaaS' : 'Dedicated'} · ${row.original.dataRegion}`,
  },
  {
    id: 'createdAt',
    header: 'Created',
    meta: { label: 'Created' },
    cell: ({ row }) => <DateTime value={row.original.createdAt} />,
  },
];

function Catalogue() {
  const [state, setState] = useUrlState(ORGANIZATIONS_URL_SHAPE);
  const [creating, setCreating] = useState(false);
  const list = useCursorList('OrganizationsController_list_v1', {
    ...(state.q ? { q: state.q } : {}),
    ...(state.status ? { status: state.status } : {}),
    ...(state.kind ? { kind: state.kind } : {}),
    ...(state.planCode ? { planCode: state.planCode } : {}),
    ...(state.deploymentMode ? { deploymentMode: state.deploymentMode } : {}),
  });
  const isFiltered = Boolean(
    state.q || state.status || state.kind || state.planCode || state.deploymentMode,
  );
  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Organizations"
        description="Every tenant of the platform. Dedicated deployment provisioning arrives in step 8.3."
        actions={
          <Can op="OrganizationsController_create_v1">
            <Button onClick={() => setCreating(true)}>
              <PlusIcon aria-hidden />
              Create organization
            </Button>
          </Can>
        }
      />
      <DataTable<OrgRow>
        tableId="organizations"
        caption="Organizations"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        search={{
          value: state.q ?? '',
          onChange: (q) => setState({ q: q.trim() || undefined }),
          label: 'Search by name or slug prefix',
        }}
        isFiltered={isFiltered}
        onClearFilters={() =>
          setState({
            q: undefined,
            status: undefined,
            kind: undefined,
            planCode: undefined,
            deploymentMode: undefined,
          })
        }
        emptyState={<EmptyState title="No organizations yet" />}
        filters={
          <>
            <SelectFilter
              label="Status"
              value={state.status}
              onChange={(status) => setState({ status })}
              options={(['active', 'suspended', 'pending_deletion', 'deleted'] as const).map(
                (value) => ({ value, label: humanize(value) }),
              )}
            />
            <SelectFilter
              label="Kind"
              value={state.kind}
              onChange={(kind) => setState({ kind })}
              options={[
                { value: 'customer', label: 'Customer' },
                { value: 'platform', label: 'Platform' },
              ]}
            />
            <SelectFilter
              label="Deployment"
              value={state.deploymentMode}
              onChange={(deploymentMode) => setState({ deploymentMode })}
              options={[
                { value: 'saas', label: 'SaaS' },
                { value: 'dedicated', label: 'Dedicated' },
              ]}
            />
            <TextFilter
              label="Plan code"
              value={state.planCode}
              onChange={(planCode) => setState({ planCode })}
              validate={(v) =>
                /^[a-z0-9_-]{1,32}$/.test(v) ? null : 'Lower-case letters, digits, _ and -'
              }
              mono
            />
          </>
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <Link
              href={`/organizations/${row.id}`}
              className="font-medium text-primary hover:underline"
            >
              {row.name}
            </Link>
            <span className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <OrganizationStatusBadge status={row.status} />
              {row.plan.name} · {row.deploymentMode === 'saas' ? 'SaaS' : 'Dedicated'}
            </span>
          </div>
        )}
      />
      <CreateOrganizationDialog open={creating} onOpenChange={setCreating} />
    </div>
  );
}

export function CreateOrganizationDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const router = useRouter();
  const [messages, setMessages] = useState<string[]>([]);
  const form = useZodForm(createOrganizationSchema, {
    defaultValues: {
      name: '',
      slug: '',
      planCode: '',
      deploymentMode: 'saas',
      dataRegion: '',
      deploymentRegion: '',
      deploymentEnvironment: '',
      adminEmail: '',
      adminDisplayName: '',
    },
  });
  const mutation = useApiMutation('OrganizationsController_create_v1', {
    invalidates: ['OrganizationsController_list_v1'],
  });
  const dedicated = form.watch('deploymentMode') === 'dedicated';
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await mutation.submit({ body: createOrganizationBody(values) });
    if (!outcome.ok) {
      setMessages(applyApiErrors(form, outcome.error));
      return;
    }
    const created = outcome.data;
    const invitation = created.initialAdmin
      ? created.initialAdmin.invitationSent
        ? ` An invitation was sent to ${created.initialAdmin.email}.`
        : ` The invitation email to ${created.initialAdmin.email} could not be sent; resend it from Users.`
      : '';
    toast.success(`Organization ${created.name} created.${invitation}`);
    form.reset();
    onOpenChange(false);
    router.push(`/organizations/${created.id}`);
  });
  const text = (
    name:
      | 'name'
      | 'slug'
      | 'planCode'
      | 'dataRegion'
      | 'deploymentRegion'
      | 'deploymentEnvironment'
      | 'adminEmail'
      | 'adminDisplayName',
    label: string,
    options: { required?: boolean; hint?: string; mono?: boolean; type?: string } = {},
  ) => (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel required={options.required}>{label}</FormLabel>
          <FormControl>
            <Input
              {...field}
              type={options.type ?? 'text'}
              autoComplete="off"
              className={options.mono ? 'font-mono' : undefined}
            />
          </FormControl>
          {options.hint ? <FormDescription>{options.hint}</FormDescription> : null}
          <FormMessage />
        </FormItem>
      )}
    />
  );
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Create organization</DialogTitle>
          <DialogDescription>
            Creates the tenant with its plan&apos;s limits and features, default settings and a
            deployment record.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form
            onSubmit={(event) => void submit(event)}
            className="grid gap-4"
            noValidate
            aria-label="Create organization"
          >
            <FormErrorSummary messages={messages} requestId={mutation.error?.requestId} />
            <div className="grid gap-4 sm:grid-cols-2">
              {text('name', 'Name', { required: true })}
              {text('slug', 'Slug', {
                required: true,
                mono: true,
                hint: 'Permanent; lower-case letters, digits and hyphens.',
              })}
              {text('planCode', 'Plan code', { required: true, mono: true, hint: 'e.g. business' })}
              {text('dataRegion', 'Data region', {
                required: true,
                mono: true,
                hint: 'e.g. ap-south-1',
              })}
            </div>
            <FormField
              control={form.control}
              name="deploymentMode"
              render={({ field }) => (
                <FormItem>
                  <FormLabel required>Deployment mode</FormLabel>
                  <FormControl>
                    <RadioGroup
                      value={field.value}
                      onValueChange={field.onChange}
                      className="flex gap-6"
                    >
                      <div className="flex items-center gap-2">
                        <RadioGroupItem value="saas" id="org-mode-saas" />
                        <Label htmlFor="org-mode-saas" className="font-normal">
                          SaaS (shared)
                        </Label>
                      </div>
                      <div className="flex items-center gap-2">
                        <RadioGroupItem value="dedicated" id="org-mode-dedicated" />
                        <Label htmlFor="org-mode-dedicated" className="font-normal">
                          Dedicated
                        </Label>
                      </div>
                    </RadioGroup>
                  </FormControl>
                  <FormDescription>
                    A dedicated organization is recorded with a deployment in provisioning;
                    provisioning itself arrives in step 8.3.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            {dedicated ? (
              <div className="grid gap-4 sm:grid-cols-2">
                {text('deploymentRegion', 'Deployment region', { required: true, mono: true })}
                {text('deploymentEnvironment', 'Deployment environment', {
                  required: true,
                  mono: true,
                  hint: 'e.g. prod',
                })}
              </div>
            ) : null}
            <fieldset className="grid gap-4 rounded-md border p-3">
              <legend className="px-1 text-sm font-medium">First administrator (optional)</legend>
              <div className="grid gap-4 sm:grid-cols-2">
                {text('adminEmail', 'Administrator email', { type: 'email' })}
                {text('adminDisplayName', 'Administrator name')}
              </div>
            </fieldset>
            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={mutation.isPending || mutation.retryAfterSeconds > 0}>
                {mutation.isPending ? 'Creating …' : 'Create organization'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

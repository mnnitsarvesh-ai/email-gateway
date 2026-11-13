'use client';

import { UserPlusIcon, UsersIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMemo, useState } from 'react';
import { Controller } from 'react-hook-form';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';

import { Can } from '@/lib/auth/can';
import { useCan } from '@/lib/auth/me';
import { FilterSelect, FormDialog } from '@/features/domains/kit';
import {
  NO_ESCALATION_HINT,
  ROLE_KEY,
  USER_STATUSES,
  USER_STATUS_LABEL,
  UserStatusBadge,
  type User,
} from './model';
import { RolePicker } from './role-picker';

const URL_SHAPE = {
  q: z.string().max(320).optional().catch(undefined),
  role: z
    .string()
    .regex(/^[a-z][a-z0-9_]{1,63}$/)
    .optional()
    .catch(undefined),
  status: z.enum(['invited', 'active', 'disabled', 'locked']).optional().catch(undefined),
};

/** POST /users/invitations: `{ email, displayName, roleKeys[1..20] }`. */
export const inviteSchema = z
  .object({
    email: z.string().trim().email('Enter an email address').max(320),
    displayName: z.string().trim().min(1, 'Enter a name').max(255),
    roleKeys: z.array(z.string().regex(ROLE_KEY)).min(1, 'Choose at least one role').max(20),
  })
  .strict();

function InviteForm({ onDone }: { onDone: (userId: string) => void }) {
  const [messages, setMessages] = useState<string[]>([]);
  const invite = useApiMutation('UsersController_invite_v1', {
    invalidates: ['UsersController_list_v1'],
    successMessage: 'Invitation sent.',
  });
  const form = useZodForm(inviteSchema, {
    defaultValues: { email: '', displayName: '', roleKeys: [] },
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await invite.submit({ body: values });
    if (outcome.ok) return onDone(outcome.data.id);
    const lines = applyApiErrors(form, outcome.error);
    setMessages(outcome.error.status === 403 ? [...lines, NO_ESCALATION_HINT] : lines);
  });
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label="Invite user"
        onSubmit={(e) => void submit(e)}
      >
        <FormErrorSummary messages={messages} requestId={invite.error?.requestId} />
        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Email (required)</FormLabel>
              <FormControl>
                <Input type="email" autoComplete="off" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="displayName"
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
        <Controller
          control={form.control}
          name="roleKeys"
          render={({ field, fieldState }) => (
            <RolePicker
              legend="Roles (at least one)"
              value={field.value}
              onChange={field.onChange}
              error={fieldState.error?.message}
            />
          )}
        />
        <p className="text-xs text-muted-foreground">
          The invitation e-mail contains a link to set a password; it expires after a few days and
          can be resent.
        </p>
        <Button
          type="submit"
          className="justify-self-start"
          disabled={invite.isPending || invite.retryAfterSeconds > 0}
        >
          {invite.isPending ? 'Sending …' : 'Send invitation'}
        </Button>
      </form>
    </Form>
  );
}

/** Users of the organization (`GET /users`, v0; `q` email/name prefix, `role`, `status`). */
export function UsersTab() {
  const router = useRouter();
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const canReadRoles = useCan('RolesController_list_v1');
  const canInvite = useCan('UsersController_invite_v1');
  const roles = useApiQuery('RolesController_list_v1', undefined, { enabled: canReadRoles });
  const [inviting, setInviting] = useState(false);
  const list = useCursorList('UsersController_list_v1', {
    ...(filters.q ? { q: filters.q } : {}),
    ...(filters.role ? { role: filters.role } : {}),
    ...(filters.status ? { status: filters.status } : {}),
  });

  const columns = useMemo<DataTableColumn<User>[]>(
    () => [
      {
        id: 'name',
        header: 'User',
        meta: { label: 'User' },
        cell: ({ row }) => (
          <span className="grid">
            <Link
              href={`/users/${row.original.id}`}
              className="font-medium text-primary hover:underline"
            >
              {row.original.displayName}
            </Link>
            <span className="text-xs text-muted-foreground">{row.original.email}</span>
          </span>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => <UserStatusBadge status={row.original.status} />,
      },
      {
        id: 'roles',
        header: 'Roles',
        meta: { label: 'Roles' },
        cell: ({ row }) => row.original.roles.map((r) => r.name).join(', ') || 'No roles',
      },
      {
        id: 'mfa',
        header: 'MFA',
        meta: { label: 'MFA' },
        cell: ({ row }) => (row.original.mfaEnabled ? 'Enabled' : 'Off'),
      },
      {
        id: 'lastLoginAt',
        header: 'Last sign-in',
        meta: { label: 'Last sign-in' },
        cell: ({ row }) => <DateTime value={row.original.lastLoginAt} />,
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
      <div className="flex justify-end">
        <Can op="UsersController_invite_v1">
          <Button size="sm" onClick={() => setInviting(true)}>
            <UserPlusIcon aria-hidden />
            Invite user
          </Button>
        </Can>
      </div>
      <DataTable
        tableId="users"
        caption="Users"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.email}
        search={{
          value: filters.q ?? '',
          onChange: (value) => setFilters({ q: value || undefined }),
          label: 'Search users by email or name prefix',
          placeholder: 'Search users',
        }}
        filters={
          <>
            <FilterSelect
              label="Status"
              value={filters.status}
              onChange={(status) => setFilters({ status: status as User['status'] | undefined })}
              options={USER_STATUSES.map((s) => ({ value: s, label: USER_STATUS_LABEL[s] }))}
            />
            {canReadRoles ? (
              <FilterSelect
                label="Role"
                value={filters.role}
                onChange={(role) => setFilters({ role })}
                options={(roles.data?.data ?? []).map((r) => ({ value: r.key, label: r.name }))}
              />
            ) : null}
          </>
        }
        isFiltered={Boolean(filters.q || filters.role || filters.status)}
        onClearFilters={() => setFilters({ q: undefined, role: undefined, status: undefined })}
        rowActions={(row) => [{ label: 'Open', onSelect: () => router.push(`/users/${row.id}`) }]}
        emptyState={
          <EmptyState
            icon={UsersIcon}
            title="No users yet"
            action={
              canInvite ? (
                <Button size="sm" onClick={() => setInviting(true)}>
                  Invite user
                </Button>
              ) : undefined
            }
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <Link href={`/users/${row.id}`} className="font-medium text-primary hover:underline">
              {row.displayName}
            </Link>
            <span className="text-xs text-muted-foreground">{row.email}</span>
            <UserStatusBadge status={row.status} />
          </div>
        )}
      />
      <FormDialog open={inviting} onOpenChange={setInviting} title="Invite a user" wide>
        <InviteForm
          onDone={(id) => {
            setInviting(false);
            router.push(`/users/${id}`);
          }}
        />
      </FormDialog>
    </div>
  );
}

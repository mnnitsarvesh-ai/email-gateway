'use client';

import { Building2Icon, PlusIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { z } from 'zod';
import { Combobox } from '@/components/combobox';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
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
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Textarea } from '@/components/ui/textarea';
import { useDebouncedValue } from '@/hooks/use-debounced-value';
import { type ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem, RequestBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan } from '@/lib/auth/me';
import { FormDialog, MutationError } from '@/features/domains/kit';

type Department = ListItem<'DepartmentsController_list_v1'>;
type Member = ListItem<'DepartmentsController_listMembers_v1'>;

/** POST/PATCH /departments: name (1–128), description (1–512, optional). */
export const departmentSchema = z
  .object({
    name: z.string().trim().min(1, 'Enter a name').max(128),
    description: z.string().trim().max(512),
  })
  .strict();

export function departmentCreateBody(
  values: z.output<typeof departmentSchema>,
): RequestBody<'DepartmentsController_create_v1'> {
  return { name: values.name, ...(values.description ? { description: values.description } : {}) };
}

export function departmentUpdateBody(
  department: Pick<Department, 'name' | 'description' | 'rowVersion'>,
  values: z.output<typeof departmentSchema>,
): RequestBody<'DepartmentsController_update_v1'> {
  const description = values.description || null;
  return {
    expectedRowVersion: department.rowVersion,
    ...(values.name !== department.name ? { name: values.name } : {}),
    ...(description !== department.description ? { description } : {}),
  };
}

/** POST /departments/{id}/members: exactly one of `{ address }` or `{ userId }`. */
export const memberSchema = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('address'),
      address: z
        .string()
        .trim()
        .min(3)
        .max(320)
        .regex(/^[^\s@]+@[^\s@]+$/, 'Enter an email address'),
    })
    .strict(),
  z.object({ kind: z.literal('user'), userId: z.string().uuid('Choose a user') }).strict(),
]);

export function memberBody(
  values: z.output<typeof memberSchema>,
): RequestBody<'DepartmentsController_addMember_v1'> {
  return values.kind === 'address' ? { address: values.address } : { userId: values.userId };
}

function conflictMessage(error: ApiError): string[] {
  if (error.code === 'department_conflict')
    return [
      'Someone else changed this department. Close the dialog and try again with the current version.',
    ];
  if (error.code === 'department_name_taken') return ['Another department already has this name.'];
  if (error.code === 'department_limit_reached')
    return ['Your organization has reached its department limit.'];
  return [];
}

function DepartmentForm({ department, onDone }: { department?: Department; onDone: () => void }) {
  const [messages, setMessages] = useState<string[]>([]);
  const create = useApiMutation('DepartmentsController_create_v1', {
    invalidates: ['DepartmentsController_list_v1'],
    successMessage: 'Department created.',
  });
  const update = useApiMutation('DepartmentsController_update_v1', {
    invalidates: ['DepartmentsController_list_v1'],
    successMessage: 'Department saved.',
  });
  const form = useZodForm(departmentSchema, {
    defaultValues: { name: department?.name ?? '', description: department?.description ?? '' },
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = department
      ? await update.submit({
          path: { departmentId: department.id },
          body: departmentUpdateBody(department, values),
        })
      : await create.submit({ body: departmentCreateBody(values) });
    if (outcome.ok) return onDone();
    const specific = conflictMessage(outcome.error);
    setMessages(specific.length > 0 ? specific : applyApiErrors(form, outcome.error));
  });
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label={department ? 'Edit department' : 'Create department'}
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
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Description (optional)</FormLabel>
              <FormControl>
                <Textarea rows={3} {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button
          type="submit"
          className="justify-self-start"
          disabled={create.isPending || update.isPending}
        >
          {department ? 'Save department' : 'Create department'}
        </Button>
      </form>
    </Form>
  );
}

function AddMember({ departmentId }: { departmentId: string }) {
  const [kind, setKind] = useState<'address' | 'user'>('address');
  const [address, setAddress] = useState('');
  const [userId, setUserId] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const debounced = useDebouncedValue(search, 300);
  const [messages, setMessages] = useState<string[]>([]);
  const users = useApiQuery(
    'UsersController_list_v1',
    { query: { limit: 20, ...(debounced ? { q: debounced } : {}) } },
    { enabled: kind === 'user' },
  );
  const add = useApiMutation('DepartmentsController_addMember_v1', {
    invalidates: ['DepartmentsController_listMembers_v1', 'DepartmentsController_list_v1'],
    successMessage: 'Member added.',
  });
  return (
    <form
      className="grid gap-3 rounded-md border p-3"
      aria-label="Add member"
      onSubmit={(event) => {
        event.preventDefault();
        const parsed = memberSchema.safeParse(
          kind === 'address' ? { kind, address } : { kind, userId: userId ?? '' },
        );
        if (!parsed.success) return setMessages(parsed.error.issues.map((i) => i.message));
        setMessages([]);
        void add
          .submit({ path: { departmentId }, body: memberBody(parsed.data) })
          .then((outcome) => {
            if (outcome.ok) {
              setAddress('');
              setUserId(null);
            } else if (outcome.error.code === 'department_member_exists')
              setMessages(['This member is already in the department.']);
            else if (outcome.error.code === 'member_address_not_tenant')
              setMessages(['The address must belong to an active domain of your organization.']);
            else setMessages(outcome.error.messages);
          });
      }}
    >
      <FormErrorSummary messages={messages} requestId={add.error?.requestId} />
      <RadioGroup
        value={kind}
        onValueChange={(v) => setKind(v as 'address' | 'user')}
        className="flex flex-wrap gap-4"
        aria-label="Member type"
      >
        <div className="flex items-center gap-2">
          <RadioGroupItem id="member-kind-address" value="address" />
          <Label htmlFor="member-kind-address" className="font-normal">
            Address
          </Label>
        </div>
        <div className="flex items-center gap-2">
          <RadioGroupItem id="member-kind-user" value="user" />
          <Label htmlFor="member-kind-user" className="font-normal">
            User
          </Label>
        </div>
      </RadioGroup>
      {kind === 'address' ? (
        <div className="grid gap-2">
          <Label htmlFor="member-address">Email address</Label>
          <Input
            id="member-address"
            type="email"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="jane.doe@alpha.example.test"
          />
        </div>
      ) : (
        <div className="grid gap-2">
          <Label htmlFor="member-user">User</Label>
          <Combobox
            id="member-user"
            label="User"
            options={(users.data?.data ?? []).map((u) => ({
              value: u.id,
              label: u.displayName,
              description: u.email,
            }))}
            value={userId}
            onChange={setUserId}
            onSearch={setSearch}
            loading={users.isFetching}
            placeholder="Choose a user …"
            searchPlaceholder="Search by email or name"
          />
        </div>
      )}
      <Button type="submit" size="sm" className="justify-self-start" disabled={add.isPending}>
        Add member
      </Button>
    </form>
  );
}

function MembersPanel({ department }: { department: Department }) {
  const canManage = useCan('DepartmentsController_addMember_v1');
  const list = useCursorList(
    'DepartmentsController_listMembers_v1',
    {},
    { path: { departmentId: department.id } },
  );
  const [removing, setRemoving] = useState<Member | null>(null);
  const remove = useApiMutation('DepartmentsController_removeMember_v1', {
    invalidates: ['DepartmentsController_listMembers_v1', 'DepartmentsController_list_v1'],
    successMessage: 'Member removed.',
  });
  const columns = useMemo<DataTableColumn<Member>[]>(
    () => [
      {
        id: 'member',
        header: 'Member',
        meta: { label: 'Member' },
        cell: ({ row }) =>
          row.original.kind === 'address' ? (
            <UntrustedText value={row.original.address} />
          ) : (
            <span>
              User <code className="font-mono text-xs">{row.original.userId}</code>
            </span>
          ),
      },
      {
        id: 'kind',
        header: 'Type',
        meta: { label: 'Type' },
        cell: ({ row }) => (row.original.kind === 'address' ? 'Address' : 'User'),
      },
      {
        id: 'createdAt',
        header: 'Added',
        meta: { label: 'Added' },
        cell: ({ row }) => <DateTime value={row.original.createdAt} />,
      },
    ],
    [],
  );
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      {canManage ? <AddMember departmentId={department.id} /> : null}
      <DataTable
        tableId="department-members"
        caption={`Members of ${department.name}`}
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.address ?? row.userId ?? row.id}
        rowActions={
          canManage
            ? (row) => [{ label: 'Remove', destructive: true, onSelect: () => setRemoving(row) }]
            : undefined
        }
        emptyState={
          <EmptyState
            title="No members"
            description="Policies match senders and recipients against the department's members."
          />
        }
        mobileCard={(row) => <span>{row.address ?? row.userId}</span>}
      />
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRemoving(null);
            remove.reset();
          }
        }}
        title="Remove this member?"
        description="Policies referencing the department stop matching the member at the next evaluation."
        confirmLabel="Remove"
        destructive
        error={<MutationError error={remove.error} />}
        onConfirm={async () =>
          removing
            ? (
                await remove.submit({
                  path: { departmentId: department.id, memberId: removing.id },
                })
              ).ok
            : false
        }
      />
    </div>
  );
}

/** Departments (`/departments`, v0) and their members, the directory data policies reference. */
export function DepartmentsTab() {
  const canManage = useCan('DepartmentsController_update_v1');
  const list = useCursorList('DepartmentsController_list_v1', {});
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Department | null>(null);
  const [members, setMembers] = useState<Department | null>(null);
  const [deleting, setDeleting] = useState<Department | null>(null);
  const remove = useApiMutation('DepartmentsController_remove_v1', {
    invalidates: ['DepartmentsController_list_v1'],
    successMessage: 'Department deleted.',
  });
  const columns = useMemo<DataTableColumn<Department>[]>(
    () => [
      {
        id: 'name',
        header: 'Department',
        meta: { label: 'Department' },
        cell: ({ row }) => <span className="font-medium">{row.original.name}</span>,
      },
      {
        id: 'description',
        header: 'Description',
        meta: { label: 'Description' },
        cell: ({ row }) =>
          row.original.description ?? <span className="text-muted-foreground">None</span>,
      },
      {
        id: 'members',
        header: 'Members',
        meta: { label: 'Members', className: 'tabular-nums' },
        cell: ({ row }) => row.original.memberCount,
      },
      {
        id: 'updatedAt',
        header: 'Updated',
        meta: { label: 'Updated' },
        cell: ({ row }) => <DateTime value={row.original.updatedAt} />,
      },
    ],
    [],
  );
  const deleteError = remove.error;
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          Departments group addresses and users for policies (sender.department,
          recipient.department).
        </p>
        <Can op="DepartmentsController_create_v1">
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon aria-hidden />
            New department
          </Button>
        </Can>
      </div>
      <DataTable
        tableId="departments"
        caption="Departments"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        rowActions={(row) => [
          { label: 'Members', onSelect: () => setMembers(row) },
          ...(canManage
            ? [
                { label: 'Edit', onSelect: () => setEditing(row) },
                { label: 'Delete', destructive: true, onSelect: () => setDeleting(row) },
              ]
            : []),
        ]}
        emptyState={<EmptyState icon={Building2Icon} title="No departments yet" />}
        mobileCard={(row) => (
          <div className="grid gap-0.5">
            <span className="font-medium">{row.name}</span>
            <span className="text-xs text-muted-foreground">{row.memberCount} members</span>
          </div>
        )}
      />
      <FormDialog open={creating} onOpenChange={setCreating} title="New department">
        <DepartmentForm onDone={() => setCreating(false)} />
      </FormDialog>
      <FormDialog
        open={editing !== null}
        onOpenChange={(open) => !open && setEditing(null)}
        title={`Edit ${editing?.name ?? 'department'}`}
      >
        {editing ? <DepartmentForm department={editing} onDone={() => setEditing(null)} /> : null}
      </FormDialog>
      <FormDialog
        open={members !== null}
        onOpenChange={(open) => !open && setMembers(null)}
        title={`Members of ${members?.name ?? ''}`}
        wide
      >
        {members ? <MembersPanel department={members} /> : null}
      </FormDialog>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
            remove.reset();
          }
        }}
        title={`Delete ${deleting?.name ?? 'department'}?`}
        description="The department and its members are removed. It cannot be deleted while an active policy references it."
        confirmLabel="Delete department"
        destructive
        error={
          deleteError ? (
            <div className="grid gap-1">
              <MutationError error={deleteError} />
              {deleteError.code === 'department_in_use' ? (
                <p className="text-xs text-muted-foreground">
                  Referenced by{' '}
                  {Array.isArray(deleteError.details.policies)
                    ? deleteError.details.policies.length
                    : 'an'}{' '}
                  active polic
                  {Array.isArray(deleteError.details.policies) &&
                  deleteError.details.policies.length === 1
                    ? 'y'
                    : 'ies'}
                  . Change those policies first.
                </p>
              ) : null}
              {deleteError.code === 'department_conflict' ? (
                <p className="text-xs text-muted-foreground">
                  The department changed meanwhile; reload the list and try again.
                </p>
              ) : null}
            </div>
          ) : undefined
        }
        onConfirm={async () =>
          deleting
            ? (
                await remove.submit({
                  path: { departmentId: deleting.id },
                  query: { expectedRowVersion: deleting.rowVersion },
                })
              ).ok
            : false
        }
      />
    </div>
  );
}

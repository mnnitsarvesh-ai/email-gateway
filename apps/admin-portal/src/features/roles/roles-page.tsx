'use client';

import { CheckIcon, PlusIcon, ShieldCheckIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn, type DataTableList } from '@/components/data-table';
import { ToneBadge } from '@/components/domain/tone-badge';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery } from '@/lib/api/hooks';
import { Can } from '@/lib/auth/can';
import { RouteGate } from '@/lib/auth/route-gate';
import { FormDialog } from '@/features/domains/kit';
import { groupLabel, groupPermissions, type Permission, type Role } from './permission-matrix';
import { RoleForm } from './role-form';

const URL_SHAPE = { view: z.enum(['list', 'matrix']).default('list').catch('list') };

export function RoleTypeBadge({ system }: { system: boolean }) {
  return (
    <ToneBadge tone={system ? 'neutral' : 'info'}>
      {system ? 'System (read-only)' : 'Custom'}
    </ToneBadge>
  );
}

/** All roles × all permissions, read-only (the role catalogue at a glance). */
export function RoleMatrix({
  roles,
  catalog,
}: {
  roles: readonly Role[];
  catalog: readonly Permission[];
}) {
  return (
    <div className="relative overflow-x-auto rounded-lg border bg-card" data-testid="role-matrix">
      <table className="w-full border-collapse text-xs">
        <caption className="sr-only">Permissions granted by each role</caption>
        <thead className="bg-muted/50">
          <tr>
            <th
              scope="col"
              className="sticky left-0 z-10 bg-muted px-3 py-2 text-left font-semibold"
            >
              Permission
            </th>
            {roles.map((role) => (
              <th
                key={role.key}
                scope="col"
                className="px-2 py-2 text-center font-semibold whitespace-nowrap"
              >
                <Link href={`/roles/${role.key}`} className="hover:underline">
                  {role.name}
                </Link>
              </th>
            ))}
          </tr>
        </thead>
        {groupPermissions(catalog).map(([prefix, permissions]) => (
          <tbody key={prefix}>
            <tr className="border-t bg-muted/30">
              <th
                scope="rowgroup"
                colSpan={roles.length + 1}
                className="sticky left-0 px-3 py-1.5 text-left font-semibold"
              >
                {groupLabel(prefix)}
              </th>
            </tr>
            {permissions.map((permission) => (
              <tr key={permission.key} className="border-t">
                <th
                  scope="row"
                  className="sticky left-0 z-[1] bg-card px-3 py-1.5 text-left font-normal"
                  title={permission.description}
                >
                  <code className="font-mono">{permission.key}</code>
                </th>
                {roles.map((role) => {
                  const granted = role.permissions.includes(permission.key);
                  return (
                    <td key={role.key} className="px-2 py-1.5 text-center">
                      {granted ? (
                        <CheckIcon className="mx-auto size-3.5 text-success" aria-hidden />
                      ) : null}
                      <span className="sr-only">{granted ? 'Granted' : 'Not granted'}</span>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        ))}
      </table>
    </div>
  );
}

function staticList<Row>(
  rows: readonly Row[],
  query: DataTableList<Row>['query'],
): DataTableList<Row> {
  return {
    rows,
    page: 1,
    hasNext: false,
    hasPrevious: false,
    isShortPage: false,
    next: () => undefined,
    previous: () => undefined,
    query,
  };
}

/** `/roles`: system and custom roles, a read-only role × permission matrix, custom role creation. */
export function RolesPage() {
  return (
    <RouteGate gate={['RolesController_list_v1']}>
      <Roles />
    </RouteGate>
  );
}

function Roles() {
  const router = useRouter();
  const [state, setState] = useUrlState(URL_SHAPE);
  const [creating, setCreating] = useState(false);
  const roles = useApiQuery('RolesController_list_v1');
  const catalog = useApiQuery('PermissionsController_list_v1');
  const rows = roles.data?.data ?? [];
  const columns = useMemo<DataTableColumn<Role>[]>(
    () => [
      {
        id: 'name',
        header: 'Role',
        meta: { label: 'Role' },
        cell: ({ row }) => (
          <Link
            href={`/roles/${row.original.key}`}
            className="font-medium text-primary hover:underline"
          >
            {row.original.name}
          </Link>
        ),
      },
      {
        id: 'key',
        header: 'Key',
        meta: { label: 'Key' },
        cell: ({ row }) => <code className="font-mono text-xs">{row.original.key}</code>,
      },
      {
        id: 'type',
        header: 'Type',
        meta: { label: 'Type' },
        cell: ({ row }) => <RoleTypeBadge system={row.original.system} />,
      },
      {
        id: 'permissions',
        header: 'Permissions',
        meta: { label: 'Permissions', className: 'tabular-nums' },
        cell: ({ row }) => row.original.permissions.length,
      },
      {
        id: 'description',
        header: 'Description',
        meta: { label: 'Description' },
        cell: ({ row }) => (
          <span className="line-clamp-2 text-muted-foreground">
            {row.original.description ?? 'None'}
          </span>
        ),
      },
    ],
    [],
  );
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title="Roles and permissions"
        description="System roles are defined by the platform and read-only; custom roles combine the permissions you hold."
        actions={
          <Can op="RolesController_create_v1">
            <Button onClick={() => setCreating(true)} disabled={!catalog.data}>
              <PlusIcon aria-hidden />
              New custom role
            </Button>
          </Can>
        }
      />
      <Tabs
        value={state.view}
        onValueChange={(view) => setState({ view: view as 'list' | 'matrix' }, { push: true })}
      >
        <TabsList aria-label="Role views">
          <TabsTrigger value="list">Roles</TabsTrigger>
          <TabsTrigger value="matrix">Permission matrix</TabsTrigger>
        </TabsList>
        <TabsContent value="list" className="min-w-0">
          <DataTable
            tableId="roles"
            caption="Roles"
            columns={columns}
            list={staticList(rows, roles)}
            getRowId={(row) => row.key}
            getRowLabel={(row) => row.name}
            rowActions={(row) => [
              { label: 'Open', onSelect: () => router.push(`/roles/${row.key}`) },
            ]}
            emptyState={<EmptyState icon={ShieldCheckIcon} title="No roles" />}
            mobileCard={(row) => (
              <div className="grid gap-1">
                <Link
                  href={`/roles/${row.key}`}
                  className="font-medium text-primary hover:underline"
                >
                  {row.name}
                </Link>
                <span className="flex items-center gap-2 text-xs">
                  <RoleTypeBadge system={row.system} /> {row.permissions.length} permissions
                </span>
              </div>
            )}
          />
        </TabsContent>
        <TabsContent value="matrix" className="min-w-0">
          {roles.isLoading || catalog.isLoading ? (
            <LoadingState label="Loading the permission matrix" rows={6} variant="table" />
          ) : roles.error || catalog.error ? (
            <ErrorState
              error={roles.error ?? catalog.error}
              onRetry={() => {
                void roles.refetch();
                void catalog.refetch();
              }}
            />
          ) : (
            <RoleMatrix roles={rows} catalog={catalog.data?.data ?? []} />
          )}
        </TabsContent>
      </Tabs>
      <FormDialog open={creating} onOpenChange={setCreating} title="New custom role" wide>
        {catalog.data ? (
          <RoleForm
            catalog={catalog.data.data}
            onDone={(key) => {
              setCreating(false);
              router.push(`/roles/${key}`);
            }}
          />
        ) : null}
      </FormDialog>
    </div>
  );
}

'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DateTime } from '@/components/domain/date-time';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { Can } from '@/lib/auth/can';
import { RouteGate } from '@/lib/auth/route-gate';
import { DetailList, MutationError, QueryView, Section } from '@/features/domains/kit';
import { PermissionMatrix, type Permission, type Role } from './permission-matrix';
import { RoleForm } from './role-form';
import { RoleTypeBadge } from './roles-page';

const ROLE_KEY = /^[a-z][a-z0-9_]{1,63}$/;

function RoleContent({ role, catalog }: { role: Role; catalog: readonly Permission[] }) {
  const router = useRouter();
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const remove = useApiMutation('RolesController_remove_v1', {
    invalidates: ['RolesController_list_v1'],
    successMessage: `${role.name} deleted.`,
  });
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title={role.name}
        breadcrumbs={[{ label: 'Roles and permissions', href: '/roles' }, { label: role.name }]}
        description={
          <span className="inline-flex flex-wrap items-center gap-2">
            <code className="font-mono text-xs">{role.key}</code>
            <RoleTypeBadge system={role.system} />
          </span>
        }
        actions={
          !role.system ? (
            <Can op="RolesController_update_v1">
              {!editing ? (
                <Button variant="outline" onClick={() => setEditing(true)}>
                  Edit role
                </Button>
              ) : null}
              <Button variant="ghost" onClick={() => setDeleting(true)}>
                Delete role
              </Button>
            </Can>
          ) : null
        }
      />
      {role.system ? (
        <p className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">
          System roles are defined by the platform and cannot be changed or deleted (the api answers
          409). Create a custom role to combine permissions differently.
        </p>
      ) : null}
      <Section title="Details">
        <DetailList
          items={[
            { label: 'Description', value: role.description ?? 'None' },
            { label: 'Permissions', value: String(role.permissions.length) },
            { label: 'Updated', value: <DateTime value={role.updatedAt} /> },
          ]}
        />
      </Section>
      <Section
        title={editing ? 'Edit role' : 'Permissions'}
        description={
          editing
            ? 'Permissions you do not hold yourself cannot be granted.'
            : 'Grouped by resource.'
        }
      >
        {editing ? (
          <RoleForm catalog={catalog} role={role} onDone={() => setEditing(false)} />
        ) : role.permissions.length === 0 ? (
          <p className="text-sm text-muted-foreground">This role grants no permissions.</p>
        ) : (
          <PermissionMatrix catalog={catalog} value={role.permissions} readOnly />
        )}
      </Section>
      <ConfirmDialog
        open={deleting}
        onOpenChange={(open) => {
          setDeleting(open);
          if (!open) remove.reset();
        }}
        title={`Delete ${role.name}?`}
        description="Custom roles can be deleted only while no user holds them (the api answers 409 otherwise)."
        confirmLabel="Delete role"
        destructive
        error={
          remove.error ? (
            <div className="grid gap-1">
              <MutationError error={remove.error} />
              {remove.error.status === 409 ? (
                <p className="text-xs text-muted-foreground">
                  Remove the role from every user first.
                </p>
              ) : null}
            </div>
          ) : undefined
        }
        onConfirm={async () => {
          const outcome = await remove.submit({ path: { key: role.key } });
          if (outcome.ok) router.push('/roles');
          return outcome.ok;
        }}
      />
    </div>
  );
}

/** `/roles/[roleKey]`: one role's permission matrix; custom roles are editable (`role:manage`). */
export function RoleDetailPage({ roleKey }: { roleKey: string }) {
  return (
    <RouteGate gate={['RolesController_get_v1']}>
      <RoleLoader roleKey={roleKey} />
    </RouteGate>
  );
}

function RoleLoader({ roleKey }: { roleKey: string }) {
  const valid = ROLE_KEY.test(roleKey);
  const role = useApiQuery(
    'RolesController_get_v1',
    { path: { key: roleKey } },
    { enabled: valid, retry: false },
  );
  const catalog = useApiQuery('PermissionsController_list_v1', undefined, { enabled: valid });
  if (!valid) return <NotFoundView />;
  if (catalog.isLoading) return <LoadingState label="Loading permissions" rows={4} />;
  if (catalog.error)
    return <ErrorState error={catalog.error} onRetry={() => void catalog.refetch()} />;
  return (
    <QueryView query={role} label="role">
      {(data) => <RoleContent role={data} catalog={catalog.data?.data ?? []} />}
    </QueryView>
  );
}

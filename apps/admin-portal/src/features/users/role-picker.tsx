'use client';

import { useCallback, useId } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { useApiQuery } from '@/lib/api/hooks';
import { useCan, useMe, usePermissions } from '@/lib/auth/me';

/**
 * Permissions that open archived mail (step 8.6 D12, ADR-0089: `ARCHIVE_ACCESS_PERMISSIONS` of
 * the seed catalog). User managers may assign roles carrying them without holding them (the
 * api's delegation rule); every such assignment is audited `rbac.archive_access_granted`.
 */
export const ARCHIVE_ACCESS_PERMISSIONS: readonly string[] = [
  'archive:search',
  'archive:retrieve',
  'archive:export',
  'archive:legal_hold',
  'archive:manage',
  'ediscovery:manage',
];

const ARCHIVE_ACCESS = new Set(ARCHIVE_ACCESS_PERMISSIONS);

/** The role names among `after` (not in `before`) whose role grants archive access. */
export function useArchiveRolesAdded(): (
  before: readonly string[],
  after: readonly string[],
) => string[] {
  const canRead = useCan('RolesController_list_v1');
  const roles = useApiQuery('RolesController_list_v1', undefined, { enabled: canRead });
  const list = roles.data?.data;
  return useCallback(
    (before, after) =>
      (list ?? [])
        .filter(
          (role) =>
            after.includes(role.key) &&
            !before.includes(role.key) &&
            role.permissions.some((p) => ARCHIVE_ACCESS.has(p)),
        )
        .map((role) => role.name),
    [list],
  );
}

/** Confirmation before assigning a role that grants archived-mail access (step 8.6 D14). */
export function ArchiveAccessConfirmDialog({
  roles,
  onCancel,
  onConfirm,
}: {
  roles: readonly string[] | null;
  onCancel: () => void;
  onConfirm: () => unknown;
}) {
  return (
    <ConfirmDialog
      open={roles !== null && roles.length > 0}
      onOpenChange={(open) => (!open ? onCancel() : undefined)}
      title="Grant access to archived mail?"
      description={
        <div className="grid gap-2">
          <p>
            {roles && roles.length > 1 ? 'The roles' : 'The role'}{' '}
            <strong>{(roles ?? []).join(', ')}</strong>{' '}
            {roles && roles.length > 1 ? 'grant' : 'grants'} access to the organization’s archived
            mail: searching it, viewing journal records and, depending on the role, previewing,
            downloading and exporting messages and managing legal holds and retention.
          </p>
          <p>
            The assignment is recorded in the audit log and listed under Archive → Access audit.
          </p>
        </div>
      }
      confirmLabel="Grant archive access"
      onConfirm={onConfirm}
    />
  );
}

/**
 * Role checkboxes from `GET /roles`. Roles holding a permission the current user lacks are shown
 * but disabled: the api refuses to grant them (no escalation, docs/security/rbac.md). Archive
 * access is the exception for user managers (step 8.6: delegable, audited), but only in an MFA
 * session and never on their own account (`targetUserId` = the current user; the api's rule).
 */
export function RolePicker({
  value,
  onChange,
  legend = 'Roles',
  error,
  targetUserId,
}: {
  value: readonly string[];
  onChange: (value: string[]) => void;
  legend?: string;
  error?: string;
  /** The user whose roles change (absent for an invitation: a new user). */
  targetUserId?: string;
}) {
  const canRead = useCan('RolesController_list_v1');
  const permissions = usePermissions();
  const me = useMe().data;
  const manager = permissions.has('user:manage');
  const mfa = me?.session.mfaAuthenticated === true;
  const self = targetUserId !== undefined && me?.user.id === targetUserId;
  const delegable = manager && mfa && !self;
  const roles = useApiQuery('RolesController_list_v1', undefined, { enabled: canRead });
  const id = useId();
  if (!canRead)
    return (
      <p className="text-sm text-muted-foreground">
        Choosing roles needs the permission <code className="font-mono text-xs">role:read</code>.
      </p>
    );
  if (roles.isLoading) return <LoadingState label="Loading roles" rows={3} />;
  if (roles.error)
    return <ErrorState error={roles.error} onRetry={() => void roles.refetch()} compact />;
  const list = roles.data?.data ?? [];
  const archiveBlocked =
    manager &&
    !delegable &&
    list.some((role) => role.permissions.some((p) => ARCHIVE_ACCESS.has(p) && !permissions.has(p)));
  return (
    <fieldset className="grid gap-2" aria-describedby={error ? `${id}-error` : undefined}>
      <legend className="mb-1 text-sm font-medium">{legend}</legend>
      <ul className="grid gap-2 sm:grid-cols-2">
        {list.map((role) => {
          const lacking = role.permissions.filter(
            (p) => !permissions.has(p) && !(delegable && ARCHIVE_ACCESS.has(p)),
          );
          const archive = role.permissions.some((p) => ARCHIVE_ACCESS.has(p));
          const checked = value.includes(role.key);
          const checkboxId = `${id}-${role.key}`;
          return (
            <li key={role.key} className="flex items-start gap-2">
              <Checkbox
                id={checkboxId}
                checked={checked}
                disabled={lacking.length > 0 && !checked}
                onCheckedChange={(next) =>
                  onChange(
                    next === true ? [...value, role.key] : value.filter((k) => k !== role.key),
                  )
                }
              />
              <Label htmlFor={checkboxId} className="grid gap-0.5 font-normal">
                <span className="font-medium">{role.name}</span>
                <span className="text-xs text-muted-foreground">
                  {role.description ?? role.key}
                  {archive ? ' · grants access to archived mail' : ''}
                  {lacking.length > 0 ? ` · you lack ${lacking.length} of its permissions` : ''}
                </span>
              </Label>
            </li>
          );
        })}
      </ul>
      {archiveBlocked ? (
        <p className="text-xs text-muted-foreground">
          {self
            ? 'You cannot give yourself access to archived mail; another administrator must assign it.'
            : 'Roles that grant access to archived mail can be assigned only from a session signed in with multi-factor authentication.'}
        </p>
      ) : null}
      {error ? (
        <p id={`${id}-error`} className="text-xs font-medium text-destructive" role="alert">
          {error}
        </p>
      ) : null}
    </fieldset>
  );
}

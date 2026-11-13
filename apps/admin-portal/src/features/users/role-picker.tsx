'use client';

import { useId } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { useApiQuery } from '@/lib/api/hooks';
import { useCan, usePermissions } from '@/lib/auth/me';

/**
 * Role checkboxes from `GET /roles`. Roles holding a permission the current user lacks are shown
 * but disabled: the api refuses to grant them (no escalation, docs/security/rbac.md).
 */
export function RolePicker({
  value,
  onChange,
  legend = 'Roles',
  error,
}: {
  value: readonly string[];
  onChange: (value: string[]) => void;
  legend?: string;
  error?: string;
}) {
  const canRead = useCan('RolesController_list_v1');
  const permissions = usePermissions();
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
  return (
    <fieldset className="grid gap-2" aria-describedby={error ? `${id}-error` : undefined}>
      <legend className="mb-1 text-sm font-medium">{legend}</legend>
      <ul className="grid gap-2 sm:grid-cols-2">
        {list.map((role) => {
          const lacking = role.permissions.filter((p) => !permissions.has(p));
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
                  {lacking.length > 0 ? ` · you lack ${lacking.length} of its permissions` : ''}
                </span>
              </Label>
            </li>
          );
        })}
      </ul>
      {error ? (
        <p id={`${id}-error`} className="text-xs font-medium text-destructive" role="alert">
          {error}
        </p>
      ) : null}
    </fieldset>
  );
}

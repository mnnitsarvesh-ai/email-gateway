'use client';

import { CheckIcon } from 'lucide-react';
import { useId } from 'react';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import type { SuccessBody } from '@/lib/api/types';
import { humanize } from '@/lib/format';

export type Permission = SuccessBody<'PermissionsController_list_v1'>['data'][number];
export type Role = SuccessBody<'RolesController_get_v1'>;

/** Permissions grouped by resource prefix (`domain:read` → `domain`), in catalogue order. */
export function groupPermissions(catalog: readonly Permission[]): [string, Permission[]][] {
  const groups = new Map<string, Permission[]>();
  for (const permission of catalog) {
    const prefix = permission.key.split(':')[0] ?? permission.category;
    groups.set(prefix, [...(groups.get(prefix) ?? []), permission]);
  }
  return [...groups.entries()];
}

export function groupLabel(prefix: string): string {
  const special: Record<string, string> = {
    apikey: 'API keys',
    threat_intel: 'Threat intelligence',
    bec: 'BEC',
    dlp: 'DLP',
  };
  return special[prefix] ?? humanize(prefix);
}

/**
 * The permissions of a role grouped by resource, with the catalogue's descriptions. Editable for
 * custom roles: permissions the current user does not hold are disabled (the api refuses to grant
 * them: no escalation).
 */
export function PermissionMatrix({
  catalog,
  value,
  onChange,
  held,
  readOnly = false,
}: {
  catalog: readonly Permission[];
  value: readonly string[];
  onChange?: (value: string[]) => void;
  held?: ReadonlySet<string>;
  readOnly?: boolean;
}) {
  const id = useId();
  const granted = new Set(value);
  const known = new Set(catalog.map((p) => p.key));
  const unknown = value.filter((key) => !known.has(key));
  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      {groupPermissions(catalog).map(([prefix, permissions]) => {
        const visible = readOnly ? permissions.filter((p) => granted.has(p.key)) : permissions;
        if (visible.length === 0) return null;
        return (
          <fieldset key={prefix} className="grid gap-2 rounded-md border p-3">
            <legend className="px-1 text-sm font-semibold">{groupLabel(prefix)}</legend>
            <ul className="grid gap-2 md:grid-cols-2">
              {visible.map((permission) => {
                const checkboxId = `${id}-${permission.key}`;
                const lacking = held ? !held.has(permission.key) : false;
                return (
                  <li key={permission.key} className="flex items-start gap-2">
                    {readOnly ? (
                      <CheckIcon className="mt-0.5 size-4 shrink-0 text-success" aria-hidden />
                    ) : (
                      <Checkbox
                        id={checkboxId}
                        checked={granted.has(permission.key)}
                        disabled={lacking && !granted.has(permission.key)}
                        onCheckedChange={(next) =>
                          onChange?.(
                            next === true
                              ? [...value, permission.key]
                              : value.filter((key) => key !== permission.key),
                          )
                        }
                      />
                    )}
                    {readOnly ? (
                      <span className="grid gap-0.5 text-sm">
                        <code className="font-mono text-xs">{permission.key}</code>
                        <span className="text-xs text-muted-foreground">
                          {permission.description}
                        </span>
                      </span>
                    ) : (
                      <Label htmlFor={checkboxId} className="grid gap-0.5 font-normal">
                        <code className="font-mono text-xs">{permission.key}</code>
                        <span className="text-xs text-muted-foreground">
                          {permission.description}
                          {lacking ? ' · you do not hold this permission' : ''}
                        </span>
                      </Label>
                    )}
                  </li>
                );
              })}
            </ul>
          </fieldset>
        );
      })}
      {unknown.length > 0 ? (
        <p className="text-xs text-muted-foreground">
          Not in the catalogue visible to you: {unknown.join(', ')}
        </p>
      ) : null}
    </div>
  );
}

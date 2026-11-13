'use client';

import { useState } from 'react';
import { Controller } from 'react-hook-form';
import { z } from 'zod';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
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
import { Textarea } from '@/components/ui/textarea';
import { useApiMutation } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { usePermissions } from '@/lib/auth/me';
import { PermissionMatrix, type Permission, type Role } from './permission-matrix';

const base = {
  name: z.string().trim().min(1, 'Enter a name').max(255),
  description: z.string().trim().max(512),
  permissions: z
    .array(z.string().min(1).max(100))
    .min(1, 'Choose at least one permission')
    .max(100, 'At most 100 permissions'),
};

/** POST /roles: key (`^[a-z][a-z0-9_]{2,63}$`), name, description?, permissions. */
export const roleCreateSchema = z
  .object({
    key: z
      .string()
      .trim()
      .regex(
        /^[a-z][a-z0-9_]{2,63}$/,
        'Lower-case letters, digits and _, 3–64 characters, starting with a letter',
      ),
    ...base,
  })
  .strict();

/** PUT /roles/{key}: name, description?, permissions (custom roles only). */
export const roleUpdateSchema = z.object(base).strict();

export function roleCreateBody(
  values: z.output<typeof roleCreateSchema>,
): RequestBody<'RolesController_create_v1'> {
  return {
    key: values.key,
    name: values.name,
    ...(values.description ? { description: values.description } : {}),
    permissions: values.permissions,
  };
}

export function roleUpdateBody(
  values: z.output<typeof roleUpdateSchema>,
): RequestBody<'RolesController_update_v1'> {
  return {
    name: values.name,
    description: values.description || null,
    permissions: values.permissions,
  };
}

const ESCALATION =
  'You can only grant permissions you hold yourself; the api refused at least one of them.';

/** Create or edit a custom role (`role:manage`). */
export function RoleForm({
  catalog,
  role,
  onDone,
}: {
  catalog: readonly Permission[];
  role?: Role;
  onDone: (key: string) => void;
}) {
  const held = usePermissions();
  const [messages, setMessages] = useState<string[]>([]);
  const create = useApiMutation('RolesController_create_v1', {
    invalidates: ['RolesController_list_v1'],
    successMessage: 'Role created.',
  });
  const update = useApiMutation('RolesController_update_v1', {
    invalidates: ['RolesController_list_v1', 'RolesController_get_v1'],
    successMessage: 'Role saved.',
  });
  const form = useZodForm(roleCreateSchema, {
    defaultValues: {
      key: role?.key ?? '',
      name: role?.name ?? '',
      description: role?.description ?? '',
      permissions: role?.permissions ?? [],
    },
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = role
      ? await update.submit({
          path: { key: role.key },
          body: roleUpdateBody(
            roleUpdateSchema.parse({
              name: values.name,
              description: values.description,
              permissions: values.permissions,
            }),
          ),
        })
      : await create.submit({ body: roleCreateBody(values) });
    if (outcome.ok) return onDone(values.key);
    const lines = applyApiErrors(form, outcome.error);
    if (outcome.error.status === 403) setMessages([...lines, ESCALATION]);
    else if (outcome.error.status === 409)
      setMessages(
        [
          ...lines,
          role ? 'System roles cannot be changed.' : 'A role with this key exists.',
        ].filter((v, i, a) => a.indexOf(v) === i),
      );
    else setMessages(lines);
  });
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label={role ? 'Edit role' : 'Create role'}
        onSubmit={(e) => void submit(e)}
      >
        <FormErrorSummary
          messages={messages}
          requestId={(create.error ?? update.error)?.requestId}
        />
        {!role ? (
          <FormField
            control={form.control}
            name="key"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Key (required)</FormLabel>
                <FormControl>
                  <Input
                    autoComplete="off"
                    spellCheck={false}
                    className="font-mono"
                    placeholder="mail_flow_operator"
                    {...field}
                  />
                </FormControl>
                <FormDescription>
                  Used by the api and API clients; cannot be changed later.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        ) : null}
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
                <Textarea rows={2} {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <Controller
          control={form.control}
          name="permissions"
          render={({ field, fieldState }) => (
            <div className="grid gap-2">
              <span className="text-sm font-medium">Permissions</span>
              <PermissionMatrix
                catalog={catalog}
                value={field.value}
                onChange={field.onChange}
                held={held}
              />
              {fieldState.error ? (
                <p className="text-xs font-medium text-destructive" role="alert">
                  {fieldState.error.message}
                </p>
              ) : null}
            </div>
          )}
        />
        <Button
          type="submit"
          className="justify-self-start"
          disabled={create.isPending || update.isPending}
        >
          {role ? 'Save role' : 'Create role'}
        </Button>
      </form>
    </Form>
  );
}

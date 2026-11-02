import { z } from 'zod';
import { CUSTOM_ROLE_KEY_PATTERN, ROLE_KEY_PATTERN } from './role-rules';

/** Request and response shapes of `/permissions` and `/roles` (§4.2). */

export const RoleKeySchema = z.string().regex(ROLE_KEY_PATTERN, 'must be a role key');

const PermissionKeyListSchema = z
  .array(z.string().min(1).max(100))
  .min(1)
  .max(100)
  .transform((keys) => [...new Set(keys)].sort());

export const CreateRoleRequestSchema = z.object({
  key: z
    .string()
    .regex(CUSTOM_ROLE_KEY_PATTERN, 'must match ^[a-z][a-z0-9_]{2,63}$')
    .describe('Unique in the organization; system role keys are reserved'),
  name: z.string().trim().min(1).max(255),
  description: z.string().trim().max(512).nullable().optional(),
  permissions: PermissionKeyListSchema.describe('Tenant permission keys (no platform:*)'),
});

export const UpdateRoleRequestSchema = z.object({
  name: z.string().trim().min(1).max(255),
  description: z.string().trim().max(512).nullable().optional(),
  permissions: PermissionKeyListSchema.describe('Replaces the role permissions'),
});

export const PermissionResponseSchema = z.object({
  key: z.string(),
  description: z.string(),
  category: z.string(),
});

export const PermissionListResponseSchema = z.object({ data: z.array(PermissionResponseSchema) });

export const RoleResponseSchema = z.object({
  key: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  system: z.boolean().describe('Built-in role (read-only)'),
  permissions: z.array(z.string()),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});

export const RoleListResponseSchema = z.object({ data: z.array(RoleResponseSchema) });

export type CreateRoleRequest = z.output<typeof CreateRoleRequestSchema>;
export type UpdateRoleRequest = z.output<typeof UpdateRoleRequestSchema>;
export type PermissionView = z.output<typeof PermissionResponseSchema>;
export type RoleView = z.output<typeof RoleResponseSchema>;

import { z } from 'zod';
import { PageQuerySchema } from '../../http/pagination';
import { RoleKeySchema } from '../roles/roles.schemas';

/** Request and response shapes of `/users` (§4.2, D11). */

const EmailSchema = z.string().trim().toLowerCase().max(320).pipe(z.email());
const DisplayNameSchema = z.string().trim().min(1).max(255);
const ReasonSchema = z.string().trim().min(1).max(512);
const RoleKeyListSchema = z
  .array(RoleKeySchema)
  .min(1)
  .max(20)
  .transform((keys) => [...new Set(keys)]);

export const UserIdParamSchema = z.uuid();

export const UserListQuerySchema = PageQuerySchema.extend({
  status: z.enum(['invited', 'active', 'disabled', 'locked']).optional(),
  q: z.string().trim().min(1).max(320).optional().describe('Email or display-name prefix'),
  role: RoleKeySchema.optional().describe('Only users holding this role'),
});

export const InviteUserRequestSchema = z.object({
  email: EmailSchema,
  displayName: DisplayNameSchema,
  roleKeys: RoleKeyListSchema,
});

export const UpdateUserRequestSchema = z
  .object({ displayName: DisplayNameSchema.optional(), email: EmailSchema.optional() })
  .refine((v) => v.displayName !== undefined || v.email !== undefined, {
    message: 'provide displayName and/or email',
  });

export const UserStatusRequestSchema = z
  .object({
    status: z.enum(['active', 'disabled']),
    reason: ReasonSchema.optional().describe('Required when disabling'),
  })
  .refine((v) => v.status !== 'disabled' || v.reason !== undefined, {
    message: 'reason is required when disabling a user',
    path: ['reason'],
  });

export const UserRolesRequestSchema = z.object({ roleKeys: RoleKeyListSchema });

export const UserResponseSchema = z.object({
  id: z.uuid(),
  email: z.string(),
  displayName: z.string(),
  status: z.enum(['invited', 'active', 'disabled', 'locked']),
  statusReason: z.string().nullable(),
  roles: z.array(z.object({ key: z.string(), name: z.string() })),
  mfaEnabled: z.boolean(),
  emailVerified: z.boolean(),
  lockedUntil: z.iso.datetime().nullable().describe('Set while a login lockout is in effect'),
  lastLoginAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});

export const UserListResponseSchema = z.object({
  data: z.array(UserResponseSchema),
  nextCursor: z.string().nullable(),
});

export const InvitationResentResponseSchema = z.object({
  expiresAt: z.iso.datetime().describe('Expiry of the new invitation link'),
});

export type UserListQuery = z.output<typeof UserListQuerySchema>;
export type InviteUserRequest = z.output<typeof InviteUserRequestSchema>;
export type UpdateUserRequest = z.output<typeof UpdateUserRequestSchema>;
export type UserStatusRequest = z.output<typeof UserStatusRequestSchema>;
export type UserRolesRequest = z.output<typeof UserRolesRequestSchema>;
export type UserView = z.output<typeof UserResponseSchema>;

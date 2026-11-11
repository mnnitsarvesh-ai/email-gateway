import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';

/**
 * Shapes of the department routes (step 5.2 P5, P22): tenant departments and their members
 * (exactly one of a normalized address in an active domain of the organization or a user of the
 * organization). Policies reference departments and users by public id.
 */

const noControl = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
};
const text = (max: number) =>
  z.string().trim().min(1).max(max).refine(noControl, 'Must not contain control characters');
const IsoDate = z.iso.datetime();
const RowVersion = z.number().int().min(1).max(4_294_967_295);

export const DepartmentIdSchema = z.uuid();
export const MemberIdSchema = z.uuid();

export const DepartmentSchema = z.strictObject({
  id: z.uuid().describe('Public id (the id policies reference in `*.department`)'),
  name: z.string(),
  description: z.string().nullable(),
  memberCount: z.number().int().min(0),
  rowVersion: RowVersion.describe('`expectedRowVersion` of PATCH and DELETE'),
  createdByUserId: z.uuid().nullable(),
  updatedByUserId: z.uuid().nullable(),
  createdAt: IsoDate,
  updatedAt: IsoDate,
});
export type DepartmentView = z.output<typeof DepartmentSchema>;

export const DepartmentPageSchema = z.strictObject({
  data: z.array(DepartmentSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type DepartmentPage = z.output<typeof DepartmentPageSchema>;

export const DepartmentListQuerySchema = PageQuerySchema.strict();
export type DepartmentListQuery = z.output<typeof DepartmentListQuerySchema>;

export const DepartmentCreateSchema = z.strictObject({
  name: text(128).describe('Unique in the organization'),
  description: text(512).nullable().optional(),
});
export type DepartmentCreate = z.output<typeof DepartmentCreateSchema>;

export const DepartmentUpdateSchema = z
  .strictObject({
    name: text(128).optional(),
    description: text(512).nullable().optional(),
    expectedRowVersion: RowVersion.describe('Current `rowVersion` (409 department_conflict)'),
  })
  .refine((b) => b.name !== undefined || b.description !== undefined, {
    message: 'Nothing to change: give name and/or description',
  });
export type DepartmentUpdate = z.output<typeof DepartmentUpdateSchema>;
export const DepartmentUpdateDocSchema = z.strictObject({
  name: z.string().min(1).max(128).optional(),
  description: z.string().min(1).max(512).nullable().optional(),
  expectedRowVersion: RowVersion,
});

export const DepartmentDeleteQuerySchema = z.strictObject({
  expectedRowVersion: z.coerce
    .number()
    .int()
    .min(1)
    .max(4_294_967_295)
    .optional()
    .describe('When given, the delete applies only at this rowVersion'),
});
export type DepartmentDeleteQuery = z.output<typeof DepartmentDeleteQuerySchema>;

export const MemberSchema = z.strictObject({
  id: z.uuid(),
  departmentId: z.uuid(),
  kind: z.enum(['address', 'user']),
  address: z.string().nullable().describe('Normalized address (address members only)'),
  userId: z.uuid().nullable().describe('User public id (user members only)'),
  createdByUserId: z.uuid().nullable(),
  createdAt: IsoDate,
});
export type MemberView = z.output<typeof MemberSchema>;

export const MemberPageSchema = z.strictObject({
  data: z.array(MemberSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type MemberPage = z.output<typeof MemberPageSchema>;

export const MemberListQuerySchema = PageQuerySchema.strict();
export type MemberListQuery = z.output<typeof MemberListQuerySchema>;

export const MemberCreateSchema = z.union([
  z.strictObject({
    address: z
      .string()
      .trim()
      .min(3)
      .max(320)
      .refine(noControl, 'Must not contain control characters')
      .describe('An address in an active domain of the organization (normalized on write)'),
  }),
  z.strictObject({ userId: z.uuid().describe('A user of the organization') }),
]);
export type MemberCreate = z.output<typeof MemberCreateSchema>;

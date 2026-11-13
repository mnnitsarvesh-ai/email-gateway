import { z } from 'zod';
import type { RequestBody } from '@/lib/api/types';

const SLUG = /^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$/;
const RESERVED_SLUGS = ['platform', 'admin', 'api', 'www', 'system'];
const PLAN_CODE = /^[a-z0-9_-]+$/;
const REGION = /^[a-z]{2}-[a-z]+-\d$/;
const ENVIRONMENT = /^[a-z][a-z0-9-]{1,31}$/;

/**
 * Create organization (strict, mirrors `OrganizationsController_create_v1`): `deployment` is
 * required for `dedicated` and refused for `saas`; the initial admin is optional (both fields
 * or neither).
 */
export const createOrganizationSchema = z
  .object({
    name: z.string().trim().min(1, 'Enter a name').max(255),
    slug: z
      .string()
      .trim()
      .regex(SLUG, '3 to 63 lower-case letters, digits and hyphens; no hyphen at either end')
      .refine((value) => !RESERVED_SLUGS.includes(value), { message: 'This slug is reserved' }),
    planCode: z
      .string()
      .trim()
      .min(1, 'Enter a plan code')
      .max(32)
      .regex(PLAN_CODE, 'Lower-case letters, digits, _ and -'),
    deploymentMode: z.enum(['saas', 'dedicated']),
    dataRegion: z.string().trim().regex(REGION, 'A region such as ap-south-1'),
    deploymentRegion: z.string().trim(),
    deploymentEnvironment: z.string().trim(),
    adminEmail: z.string().trim().max(320),
    adminDisplayName: z.string().trim().max(255),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.deploymentMode === 'dedicated') {
      if (!REGION.test(value.deploymentRegion))
        ctx.addIssue({
          code: 'custom',
          path: ['deploymentRegion'],
          message: 'A region such as ap-south-1',
        });
      if (!ENVIRONMENT.test(value.deploymentEnvironment))
        ctx.addIssue({
          code: 'custom',
          path: ['deploymentEnvironment'],
          message: '2 to 32 characters: a lower-case letter, then letters, digits or hyphens',
        });
    }
    const hasEmail = value.adminEmail !== '';
    const hasName = value.adminDisplayName !== '';
    if (hasEmail && !z.email().safeParse(value.adminEmail).success)
      ctx.addIssue({ code: 'custom', path: ['adminEmail'], message: 'Enter an email address' });
    if (hasEmail !== hasName)
      ctx.addIssue({
        code: 'custom',
        path: [hasEmail ? 'adminDisplayName' : 'adminEmail'],
        message: 'Give both the email and the name of the first administrator, or neither',
      });
  });

export type CreateOrganizationValues = z.output<typeof createOrganizationSchema>;

export function createOrganizationBody(
  values: CreateOrganizationValues,
): RequestBody<'OrganizationsController_create_v1'> {
  return {
    name: values.name,
    slug: values.slug,
    planCode: values.planCode,
    deploymentMode: values.deploymentMode,
    dataRegion: values.dataRegion,
    ...(values.deploymentMode === 'dedicated'
      ? {
          deployment: {
            region: values.deploymentRegion,
            environment: values.deploymentEnvironment,
          },
        }
      : {}),
    ...(values.adminEmail
      ? { initialAdmin: { email: values.adminEmail, displayName: values.adminDisplayName } }
      : {}),
  };
}

/** Profile update (`PUT /organizations/{id}`): `planCode` only for platform users. */
export const profileSchema = z
  .object({
    name: z.string().trim().min(1, 'Enter a name').max(255),
    planCode: z.string().trim().max(32),
  })
  .strict()
  .refine((value) => value.planCode === '' || PLAN_CODE.test(value.planCode), {
    path: ['planCode'],
    message: 'Lower-case letters, digits, _ and -',
  });

export function profileBody(
  values: z.output<typeof profileSchema>,
  options: { includePlan: boolean; currentPlan: string },
): RequestBody<'OrganizationsController_update_v1'> {
  return {
    name: values.name,
    ...(options.includePlan && values.planCode && values.planCode !== options.currentPlan
      ? { planCode: values.planCode }
      : {}),
  };
}

/** A limit override (`PUT /organizations/{id}/limits/{limitKey}`). */
export const limitOverrideSchema = z
  .object({
    value: z.coerce
      .number({ message: 'Enter a number' })
      .int('Enter a whole number')
      .min(0, 'At least 0'),
  })
  .strict();

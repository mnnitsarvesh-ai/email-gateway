import { z } from 'zod';
import { PasswordSchema } from '../../../crypto/password-policy';

/**
 * Request and response shapes of the authentication endpoints (§4.1). The zod schemas are the
 * single source of truth: the controllers validate with them and document them with
 * `zodToOpenApi`.
 */

const EmailSchema = z.string().trim().toLowerCase().max(320).pipe(z.email());
const OrganizationSlugSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/, 'must be an organization slug');
/** Login and re-authentication passwords are checked, not policy-validated. */
const PresentedPasswordSchema = z.string().min(1).max(1024);
const OpaqueTokenSchema = z.string().min(1).max(128);
const TotpCodeSchema = z.string().regex(/^\d{6}$/, 'must be a 6-digit code');
const DisplayNameSchema = z.string().trim().min(1).max(255);

// ---- Requests ----------------------------------------------------------------------------

export const LoginRequestSchema = z.strictObject({
  email: EmailSchema,
  password: PresentedPasswordSchema,
  organization: OrganizationSlugSchema.optional(),
});

export const MfaVerifyRequestSchema = z
  .strictObject({
    mfaToken: OpaqueTokenSchema,
    code: TotpCodeSchema.optional(),
    recoveryCode: z.string().min(10).max(32).optional(),
  })
  .refine((v) => (v.code === undefined) !== (v.recoveryCode === undefined), {
    message: 'provide exactly one of code or recoveryCode',
  });

export const RefreshRequestSchema = z.strictObject({ refreshToken: OpaqueTokenSchema });

export const PasswordForgotRequestSchema = z.strictObject({
  email: EmailSchema,
  organization: OrganizationSlugSchema.optional(),
});

export const PasswordResetRequestSchema = z.strictObject({
  token: OpaqueTokenSchema,
  newPassword: PasswordSchema,
});

export const PasswordChangeRequestSchema = z.strictObject({
  currentPassword: PresentedPasswordSchema,
  newPassword: PasswordSchema,
});

export const TokenRequestSchema = z.strictObject({ token: OpaqueTokenSchema });

export const InvitationAcceptRequestSchema = z.strictObject({
  token: OpaqueTokenSchema,
  password: PasswordSchema,
  displayName: DisplayNameSchema.optional(),
});

export const TotpCodeRequestSchema = z.strictObject({ code: TotpCodeSchema });

export const MfaDisableRequestSchema = z.strictObject({
  password: PresentedPasswordSchema,
  code: TotpCodeSchema,
});

export const OverrideStartRequestSchema = z.strictObject({
  organizationId: z.uuid(),
  reason: z.string().trim().min(10).max(500),
  durationMinutes: z.number().int().min(5).max(240).default(30),
});

export const UuidParamSchema = z.uuid();

// ---- Responses ---------------------------------------------------------------------------

export const TokenResponseSchema = z.object({
  accessToken: z.string(),
  tokenType: z.literal('Bearer'),
  expiresIn: z.number().int().describe('Access-token lifetime in seconds'),
  refreshToken: z.string().describe('Single use: every refresh returns a new one'),
  refreshTokenExpiresAt: z.iso.datetime(),
  sessionId: z.uuid(),
  mfaEnrollmentRequired: z
    .boolean()
    .describe('The organization requires MFA and the user must enroll before anything else'),
  user: z.object({ id: z.uuid(), email: z.string(), displayName: z.string() }),
  organization: z.object({
    id: z.uuid(),
    slug: z.string(),
    name: z.string(),
    kind: z.enum(['customer', 'platform']),
  }),
});

export const MfaChallengeResponseSchema = z.object({
  mfaRequired: z.literal(true),
  mfaToken: z.string().describe('Pass to POST /api/v1/auth/mfa/verify'),
  expiresIn: z.number().int(),
});

export const LoginResponseSchema = z.union([TokenResponseSchema, MfaChallengeResponseSchema]);

export const MeResponseSchema = z.object({
  user: z.object({
    id: z.uuid(),
    email: z.string(),
    displayName: z.string(),
    status: z.string(),
  }),
  organization: z.object({
    id: z.uuid(),
    slug: z.string(),
    name: z.string(),
    kind: z.enum(['customer', 'platform']),
  }),
  roles: z.array(z.string()),
  permissions: z.array(z.string()),
  mfaEnabled: z.boolean(),
  emailVerified: z.boolean(),
  mfaEnrollmentRequired: z.boolean(),
  session: z.object({ id: z.uuid(), mfaAuthenticated: z.boolean() }),
  override: z
    .object({
      id: z.uuid(),
      reason: z.string(),
      organizationId: z.uuid(),
      expiresAt: z.iso.datetime(),
    })
    .nullable(),
});

export const SessionResponseSchema = z.object({
  id: z.uuid(),
  current: z.boolean(),
  authenticatedAt: z.iso.datetime(),
  lastUsedAt: z.iso.datetime().nullable(),
  expiresAt: z.iso.datetime(),
  ipAddress: z.string().nullable(),
  userAgent: z.string().nullable(),
  mfaAuthenticated: z.boolean(),
});

export const SessionListResponseSchema = z.object({ data: z.array(SessionResponseSchema) });

export const TotpSetupResponseSchema = z.object({
  secret: z.string().describe('Base32 TOTP secret (shown once)'),
  otpauthUri: z.string(),
});

export const RecoveryCodesResponseSchema = z.object({
  recoveryCodes: z.array(z.string()).length(10).describe('Shown once; each code works once'),
});

export const InvitationDetailsResponseSchema = z.object({
  email: z.string(),
  organizationName: z.string(),
  expiresAt: z.iso.datetime(),
});

export const OverrideResponseSchema = z.object({
  overrideId: z.uuid(),
  accessToken: z.string().describe('Not refreshable; expires with the override'),
  tokenType: z.literal('Bearer'),
  expiresAt: z.iso.datetime(),
  organization: z.object({ id: z.uuid(), slug: z.string(), name: z.string() }),
});

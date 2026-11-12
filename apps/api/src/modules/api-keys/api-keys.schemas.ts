import { z } from 'zod';
import { PageQuerySchema } from '../../http/pagination';

/** Request and response shapes of `/api-keys` (§4.2, D11). */

export const ApiKeyIdParamSchema = z.uuid();

export const ApiKeyListQuerySchema = PageQuerySchema.strict();

export const CreateApiKeyRequestSchema = z.strictObject({
  name: z.string().trim().min(1).max(255),
  scopes: z
    .array(z.string().min(1).max(100))
    .min(1)
    .max(100)
    .transform((keys) => [...new Set(keys)].sort())
    .describe(
      'Tenant permission keys the key may use; never apikey:manage, role:manage, session:manage',
    ),
  expiresAt: z.iso
    .datetime({ offset: true })
    .optional()
    .describe('Default now + 365 days, at most now + 730 days'),
});

export const ApiKeyResponseSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  prefix: z.string().describe('First 16 characters of the key, safe to display'),
  scopes: z.array(z.string()),
  createdBy: z.object({ id: z.uuid(), displayName: z.string() }).nullable(),
  lastUsedAt: z.iso.datetime().nullable(),
  expiresAt: z.iso.datetime().nullable(),
  revokedAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
});

export const ApiKeyListResponseSchema = z.object({
  data: z.array(ApiKeyResponseSchema),
  nextCursor: z.string().nullable(),
});

export const CreatedApiKeyResponseSchema = z.object({
  apiKey: ApiKeyResponseSchema,
  key: z.string().describe('The full key. Shown once; store it securely'),
});

export type ApiKeyListQuery = z.output<typeof ApiKeyListQuerySchema>;
export type CreateApiKeyRequest = z.output<typeof CreateApiKeyRequestSchema>;
export type ApiKeyView = z.output<typeof ApiKeyResponseSchema>;
export type CreatedApiKeyView = z.output<typeof CreatedApiKeyResponseSchema>;

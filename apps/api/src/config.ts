import {
  baseConfigSchema,
  databaseConfigSchema,
  databaseReadConfigSchema,
  httpConfigSchema,
  loadConfig,
  redisConfigSchema,
  s3ConfigSchema,
} from '@email-gateway/config';
import { z } from 'zod';

export const apiConfigSchema = baseConfigSchema
  .extend(httpConfigSchema(3000).shape)
  .extend(databaseConfigSchema.shape)
  // Control plane only: list/search/report reads may use the replica (ADR-0014).
  .extend(databaseReadConfigSchema.shape)
  .extend(redisConfigSchema.shape)
  .extend(s3ConfigSchema.shape)
  .extend({
    /** Comma-separated allow-list of admin portal origins. */
    CORS_ORIGINS: z
      .string()
      .default('')
      .transform((v) =>
        v
          .split(',')
          .map((o) => o.trim())
          .filter(Boolean),
      ),
  });

export type ApiConfig = z.infer<typeof apiConfigSchema>;

export const loadApiConfig = (env: NodeJS.ProcessEnv = process.env): Readonly<ApiConfig> =>
  loadConfig(apiConfigSchema, env);

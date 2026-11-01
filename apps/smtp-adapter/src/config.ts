import {
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  redisConfigSchema,
} from '@email-gateway/config';
import { z } from 'zod';

export const configSchema = baseConfigSchema
  .extend(httpConfigSchema(3010).shape)
  .extend(databaseConfigSchema.shape)
  .extend(redisConfigSchema.shape)
  .extend({
    POLICY_PORT: z.coerce.number().int().min(1).max(65535).default(10040),
    POLICY_HOST: z.string().default('0.0.0.0'),
  });

export type SmtpAdapterConfig = z.infer<typeof configSchema>;

export const loadSmtpAdapterConfig = (
  env: NodeJS.ProcessEnv = process.env,
): Readonly<SmtpAdapterConfig> => loadConfig(configSchema, env);

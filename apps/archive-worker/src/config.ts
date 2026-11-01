import {
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  rabbitmqConfigSchema,
  s3ConfigSchema,
} from '@email-gateway/config';
import type { z } from 'zod';

export const configSchema = baseConfigSchema
  .extend(httpConfigSchema(3060).shape)
  .extend(databaseConfigSchema.shape)
  .extend(rabbitmqConfigSchema.shape)
  .extend(s3ConfigSchema.shape);

export type WorkerConfig = z.infer<typeof configSchema>;

export const loadWorkerConfig = (env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> =>
  loadConfig(configSchema, env);

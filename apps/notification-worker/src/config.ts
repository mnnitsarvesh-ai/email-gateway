import {
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
} from '@email-gateway/config';
import type { z } from 'zod';

export const configSchema = baseConfigSchema
  .extend(httpConfigSchema(3050).shape)
  .extend(databaseConfigSchema.shape);

export type WorkerConfig = z.infer<typeof configSchema>;

export const loadWorkerConfig = (env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> =>
  loadConfig(configSchema, env);

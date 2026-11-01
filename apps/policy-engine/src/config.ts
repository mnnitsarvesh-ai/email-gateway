import {
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  rabbitmqConfigSchema,
  redisConfigSchema,
} from '@email-gateway/config';
import type { z } from 'zod';

export const configSchema = baseConfigSchema
  .extend(httpConfigSchema(3030).shape)
  .extend(databaseConfigSchema.shape)
  .extend(rabbitmqConfigSchema.shape)
  .extend(redisConfigSchema.shape);

export type WorkerConfig = z.infer<typeof configSchema>;

export const loadWorkerConfig = (env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> =>
  loadConfig(configSchema, env);

import { Test, type TestingModule } from '@nestjs/testing';
import { DatabaseModule, MetricsModule, RedisModule, S3Module } from '@email-gateway/common';
import { s3ConfigSchema, type S3Config } from '@email-gateway/config';
import { z } from 'zod';
import { BouncesModule, type BouncesModuleOptions } from '../../src/bounces/bounces.module';
import { bouncesConfigShape } from '../../src/bounces/bounces.config';
import { IngestionModule } from '../../src/ingestion/ingestion.module';
import { ingestionConfigShape } from '../../src/ingestion/ingestion.config';
import { SmtpSharedModule } from '../../src/shared/shared.module';

/** Values from the repository's .env (loaded by vitest.integration.config.ts). Never printed. */
export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set (see .env)`);
  return value;
}

export function s3Config(overrides: Partial<S3Config> = {}): S3Config {
  return { ...s3ConfigSchema.parse(process.env), ...overrides };
}

export interface AdapterStackOptions {
  /** Replaces the S3 configuration (e.g. an unreachable endpoint). */
  s3?: Partial<S3Config>;
  ingestion?: Partial<z.infer<z.ZodObject<typeof ingestionConfigShape>>>;
  bounces?: Partial<BouncesModuleOptions['config']>;
  internalNetworks?: string;
}

/**
 * The in-process part of smtp-adapter that LMTP ingestion and the bounce handler need: the
 * writer database, Redis, MinIO, metrics, the shared reputation recorder, and both modules with
 * every listener on a free port of 127.0.0.1.
 */
export async function startAdapterStack(options: AdapterStackOptions = {}): Promise<TestingModule> {
  const ingestion = {
    ...z.object(ingestionConfigShape).parse(process.env),
    LMTP_INBOUND_PORT: 0,
    LMTP_OUTBOUND_PORT: 0,
    ...options.ingestion,
  };
  const bounces: BouncesModuleOptions['config'] = {
    ...z.object(bouncesConfigShape).parse(process.env),
    GATEWAY_TRACE_SECRET: ingestion.GATEWAY_TRACE_SECRET,
    GATEWAY_TRACE_ID: ingestion.GATEWAY_TRACE_ID,
    POSTFIX_OUTBOUND_MYHOSTNAME: 'out.gateway.local',
    LMTP_BOUNCE_PORT: 0,
    ...options.bounces,
  };
  const internalNetworks = options.internalNetworks ?? '127.0.0.0/8,::1/128';
  const moduleRef = await Test.createTestingModule({
    imports: [
      DatabaseModule.forRoot({ url: requireEnv('DATABASE_URL') }),
      RedisModule.forRoot({ url: requireEnv('REDIS_URL') }),
      S3Module.forRoot(s3Config(options.s3)),
      MetricsModule.forRoot({ service: 'smtp-adapter' }),
      SmtpSharedModule,
      IngestionModule.forRoot({
        config: ingestion,
        listenHost: '127.0.0.1',
        internalNetworks,
        logLevel: 'silent',
      }),
      BouncesModule.forRoot({
        config: bounces,
        listenHost: '127.0.0.1',
        internalNetworks,
        logLevel: 'silent',
      }),
    ],
  }).compile();
  await moduleRef.init();
  return moduleRef;
}

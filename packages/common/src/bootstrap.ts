import {
  type DynamicModule,
  type INestApplication,
  type MiddlewareConsumer,
  Module,
  type NestModule,
  VersioningType,
} from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { createLogger, type Logger } from '@email-gateway/logger';
import { CorrelationIdMiddleware } from './correlation/correlation-id.middleware';
import { AllExceptionsFilter } from './errors/all-exceptions.filter';
import { NestPinoLogger } from './logging/nest-logger';

export interface ServiceOptions {
  name: string;
  version: string;
  logLevel: string;
}

/** Applies correlation ids to every route. Imported by `configureHttpApp` consumers' root module. */
@Module({ providers: [CorrelationIdMiddleware] })
export class CorrelationModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(CorrelationIdMiddleware).forRoutes('*path');
  }
}

/**
 * Cross-cutting HTTP setup shared by every service: URI versioning (`/v1/...`, health stays
 * unversioned), the global exception filter, graceful shutdown and no framework fingerprint.
 */
export function configureHttpApp(app: INestApplication, logger: Logger): void {
  app.enableVersioning({ type: VersioningType.URI, defaultVersion: '1' });
  app.useGlobalFilters(new AllExceptionsFilter(logger));
  app.enableShutdownHooks();
  const httpAdapter = app.getHttpAdapter().getInstance() as { disable?: (key: string) => void };
  httpAdapter.disable?.('x-powered-by');
}

export interface BootstrapOptions extends ServiceOptions {
  rootModule: DynamicModule;
  port: number;
  host: string;
  /** Extra per-service setup (e.g. OpenAPI docs) before listening. */
  configure?: (app: INestApplication, logger: Logger) => void | Promise<void>;
}

export async function bootstrapService(options: BootstrapOptions): Promise<INestApplication> {
  const logger = createLogger({
    service: options.name,
    level: options.logLevel,
    version: options.version,
  });
  process.on('unhandledRejection', (reason) =>
    logger.error({ err: reason }, 'Unhandled promise rejection'),
  );

  try {
    const app = await NestFactory.create(options.rootModule, {
      logger: new NestPinoLogger(logger),
      bufferLogs: true,
    });
    configureHttpApp(app, logger);
    await options.configure?.(app, logger);
    await app.listen(options.port, options.host);
    logger.info({ port: options.port }, `${options.name} listening`);
    return app;
  } catch (err) {
    logger.fatal({ err }, `${options.name} failed to start`);
    process.exit(1);
  }
}

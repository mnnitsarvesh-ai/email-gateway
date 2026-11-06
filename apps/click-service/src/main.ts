import './instrumentation';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import {
  HealthService,
  MetricsService,
  NestPinoLogger,
  PrismaService,
  RedisService,
} from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import { close, createAdminServer, listen } from './admin/admin-server';
import { AppModule, SERVICE_NAME } from './app.module';
import { loadClickConfig } from './config';
import { configurePublicApp } from './http/configure';

/**
 * Two listeners: the public one (CLICK_HTTP_PORT: `/c/:token`, `/c/:token/continue`, CSS) and
 * the admin one (CLICK_ADMIN_PORT: health and metrics), sharing one Nest container.
 */
async function main(): Promise<void> {
  const config = loadClickConfig();
  const logger = createLogger({
    service: SERVICE_NAME,
    level: config.LOG_LEVEL,
    version: config.SERVICE_VERSION,
  });
  process.on('unhandledRejection', (reason) =>
    logger.error(
      { errName: reason instanceof Error ? reason.name : typeof reason },
      'Unhandled promise rejection',
    ),
  );
  try {
    const app = await NestFactory.create<NestExpressApplication>(
      AppModule.forRoot(config, logger),
      { logger: new NestPinoLogger(logger), bufferLogs: true },
    );
    configurePublicApp(app, {
      trustProxyHops: config.CLICK_TRUST_PROXY,
      hsts: config.NODE_ENV === 'production',
      logger,
    });
    await app.listen(config.CLICK_HTTP_PORT, config.HTTP_HOST);
    const health = new HealthService([app.get(PrismaService), app.get(RedisService)], {
      name: SERVICE_NAME,
      version: config.SERVICE_VERSION,
    });
    const admin = createAdminServer({ health, metrics: app.get(MetricsService), logger });
    await listen(admin, config.CLICK_ADMIN_PORT, config.HTTP_HOST);
    const shutdown = (): void => {
      void close(admin);
    };
    process.once('SIGTERM', shutdown);
    process.once('SIGINT', shutdown);
    logger.info(
      { port: config.CLICK_HTTP_PORT, adminPort: config.CLICK_ADMIN_PORT },
      `${SERVICE_NAME} listening`,
    );
  } catch (err) {
    logger.fatal(
      { errName: err instanceof Error ? err.name : typeof err },
      `${SERVICE_NAME} failed to start`,
    );
    process.exit(1);
  }
}

void main();

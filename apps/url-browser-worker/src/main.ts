import { bootstrapService } from '@email-gateway/common';
import { AppModule, SERVICE_NAME } from './app.module';
import { loadWorkerConfig } from './config';

// Refuses to start when a database, S3, Redis or token/cache key is present (U15).
const config = loadWorkerConfig();

void bootstrapService({
  name: SERVICE_NAME,
  version: config.SERVICE_VERSION,
  logLevel: config.LOG_LEVEL,
  rootModule: AppModule.forRoot(config),
  port: config.URL_BROWSER_HTTP_PORT,
  host: config.HTTP_HOST,
});

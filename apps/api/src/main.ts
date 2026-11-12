import './instrumentation';
import { bootstrapService } from '@email-gateway/common';
import helmet from 'helmet';
import { AppModule, SERVICE_NAME } from './app.module';
import { loadApiConfig } from './config';
import { configureApiApp } from './http/configure-api-app';
import { setupOpenApiOutsideProduction } from './http/openapi';

const config = loadApiConfig();

void bootstrapService({
  name: SERVICE_NAME,
  version: config.SERVICE_VERSION,
  logLevel: config.LOG_LEVEL,
  rootModule: AppModule.forRoot(config),
  port: config.HTTP_PORT,
  host: config.HTTP_HOST,
  configure: (app) => {
    // Business routes under /api/v1 (ADR-0015); probes stay at /health/*.
    configureApiApp(app, config);
    app.use(helmet());
    app.enableCors({ origin: config.CORS_ORIGINS, credentials: true });
    // Step 6.1 D13: /docs and /docs-json are never served in production.
    setupOpenApiOutsideProduction(app, config);
  },
});

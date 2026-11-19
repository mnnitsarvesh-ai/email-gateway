import './instrumentation';
import { bootstrapService } from '@email-gateway/common';
import { AppModule, SERVICE_NAME } from './app.module';
import { loadWorkerConfig } from './config';

const config = loadWorkerConfig();

void bootstrapService({
  name: SERVICE_NAME,
  version: config.SERVICE_VERSION,
  logLevel: config.LOG_LEVEL,
  rootModule: AppModule.forRoot(config),
  // D11: /health/live, /health/ready and /metrics only, on INTEGRATION_WORKER_HTTP_PORT.
  port: config.INTEGRATION_WORKER_HTTP_PORT,
  host: config.HTTP_HOST,
});

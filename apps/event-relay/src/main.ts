import './instrumentation';
import { bootstrapService } from '@email-gateway/common';
import { AppModule, SERVICE_NAME } from './app.module';
import { loadRelayConfig } from './config';

const config = loadRelayConfig();

void bootstrapService({
  name: SERVICE_NAME,
  version: config.SERVICE_VERSION,
  logLevel: config.LOG_LEVEL,
  rootModule: AppModule.forRoot(config),
  port: config.HTTP_PORT,
  host: config.HTTP_HOST,
});

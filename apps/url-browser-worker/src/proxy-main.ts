import { bootstrapService } from '@email-gateway/common';
import { loadProxyConfig } from './config';
import { PROXY_SERVICE_NAME, ProxyAppModule } from './proxy/proxy.app.module';

const config = loadProxyConfig();

void bootstrapService({
  name: PROXY_SERVICE_NAME,
  version: config.SERVICE_VERSION,
  logLevel: config.LOG_LEVEL,
  rootModule: ProxyAppModule.forRoot(config),
  port: config.URL_EGRESS_ADMIN_PORT,
  host: config.HTTP_HOST,
});

import { type DynamicModule, Module } from '@nestjs/common';
import { HealthModule, MetricsModule } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import type { ProxyConfig } from '../config';
import { EgressProxyService, PROXY_CONFIG, PROXY_LOGGER } from './egress-proxy.service';

export const PROXY_SERVICE_NAME = 'url-egress-proxy';

@Module({})
class EgressProxyModule {
  static forRoot(config: Readonly<ProxyConfig>): DynamicModule {
    const logger = createLogger({
      service: PROXY_SERVICE_NAME,
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    });
    return {
      module: EgressProxyModule,
      providers: [
        { provide: PROXY_CONFIG, useValue: config },
        { provide: PROXY_LOGGER, useValue: logger },
        EgressProxyService,
      ],
      exports: [EgressProxyService],
    };
  }
}

/**
 * url-egress-proxy (U15): the authenticated, SSRF-guarded forward proxy of the browser worker
 * (and, in egress mode 2, of every fetcher). The Nest app is the admin listener only
 * (URL_EGRESS_ADMIN_PORT: health, metrics); the proxy listens on URL_EGRESS_PORT.
 */
@Module({})
export class ProxyAppModule {
  static forRoot(config: Readonly<ProxyConfig>): DynamicModule {
    const proxyModule = EgressProxyModule.forRoot(config);
    return {
      module: ProxyAppModule,
      imports: [
        MetricsModule.forRoot({ service: PROXY_SERVICE_NAME }),
        proxyModule,
        HealthModule.forRoot({
          service: { name: PROXY_SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [EgressProxyService],
          imports: [proxyModule],
        }),
      ],
    };
  }
}

import { Inject, Injectable, type OnApplicationShutdown, type OnModuleInit } from '@nestjs/common';
import { MetricsService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import type { HealthDetails } from '@email-gateway/shared-types';
import {
  createEgressProxy,
  parseDialMap,
  RestrictedResolver,
  SsrfGuard,
  type EgressProxy,
  type EgressProxyHooks,
} from '@email-gateway/url-security';
import type { ProxyConfig } from '../config';

export const PROXY_CONFIG = Symbol('PROXY_CONFIG');
export const PROXY_LOGGER = Symbol('PROXY_LOGGER');

/** Egress proxy series (step 4.3 U18) plus `url_fetch_blocked_total{component="proxy"}`. */
export function proxyHooks(metrics: MetricsService): EgressProxyHooks {
  const connections = metrics.counter(
    'url_egress_connections_total',
    'Egress proxy requests and tunnels by result',
    ['result'],
  );
  const blocked = metrics.counter(
    'url_egress_blocked_total',
    'Targets refused by the egress proxy guard',
    ['reason'],
  );
  const fetchBlocked = metrics.counter(
    'url_fetch_blocked_total',
    'Targets refused by the SSRF guard',
    ['reason', 'component'],
  );
  const bytes = metrics.counter('url_egress_bytes_total', 'Bytes relayed by the egress proxy', [
    'direction',
  ]);
  const active = metrics.gauge('url_egress_active_connections', 'Open egress proxy connections');
  active.set(0);
  return {
    onConnection: (result) => connections.inc({ result }),
    onBlocked: (reason) => {
      blocked.inc({ reason });
      fetchBlocked.inc({ reason, component: 'proxy' });
    },
    onBytes: (direction, n) => bytes.inc({ direction }, n),
    onActive: (n) => active.set(n),
  };
}

/**
 * The url-egress-proxy listener (U8 egress mode 2, U15): `createEgressProxy` of url-security with
 * the shared SsrfGuard + RestrictedResolver (URL_DNS_*, allowed ports, deny lists, the TEST-ONLY
 * allow list), authenticated by URL_EGRESS_PROXY_TOKEN. Readiness: listening.
 */
@Injectable()
export class EgressProxyService implements OnModuleInit, OnApplicationShutdown {
  readonly healthName = 'egress-proxy';
  private proxy: EgressProxy | undefined;
  private port: number | undefined;

  constructor(
    @Inject(PROXY_CONFIG) private readonly config: Readonly<ProxyConfig>,
    @Inject(PROXY_LOGGER) private readonly logger: Logger,
    @Inject(MetricsService) private readonly metrics: MetricsService,
  ) {}

  async onModuleInit(): Promise<void> {
    const env = { nodeEnv: this.config.NODE_ENV, appEnv: this.config.APP_ENV };
    const clickHost = this.config.URL_CLICK_BASE_URL
      ? new URL(this.config.URL_CLICK_BASE_URL).hostname.replace(/^\[|\]$/g, '')
      : null;
    const guard = new SsrfGuard({
      allowedPorts: this.config.URL_FETCH_ALLOWED_PORTS.map(Number),
      denyCidrs: this.config.URL_FETCH_DENY_CIDRS,
      denyHosts: this.config.URL_FETCH_DENY_HOSTS,
      testAllowCidrs: this.config.URL_FETCH_TEST_ALLOW_CIDRS,
      clickHost,
      nodeEnv: this.config.NODE_ENV,
      appEnv: this.config.APP_ENV,
    });
    const resolver = new RestrictedResolver({
      servers: this.config.URL_DNS_SERVERS,
      timeoutMs: this.config.URL_DNS_TIMEOUT_MS,
      tries: this.config.URL_DNS_TRIES,
    });
    this.proxy = createEgressProxy({
      token: this.config.URL_EGRESS_PROXY_TOKEN,
      guard,
      resolver,
      maxConnections: this.config.URL_EGRESS_MAX_CONNECTIONS,
      maxBytesPerConnection: this.config.URL_EGRESS_MAX_BYTES_PER_CONNECTION,
      idleTimeoutMs: this.config.URL_EGRESS_IDLE_TIMEOUT_MS,
      maxConnectionMs: this.config.URL_EGRESS_MAX_CONNECTION_MS,
      connectTimeoutMs: this.config.URL_FETCH_CONNECT_TIMEOUT_MS,
      dialMap: parseDialMap(this.config.URL_FETCH_TEST_DIAL_MAP, env),
      hooks: proxyHooks(this.metrics),
    });
    this.port = await this.proxy.listen(this.config.URL_EGRESS_PORT, this.config.HTTP_HOST);
    this.logger.info({ port: this.port }, 'egress proxy listening');
  }

  /** Bound port (tests listen on 0). */
  get listeningPort(): number | undefined {
    return this.port;
  }

  checkHealth(): Promise<HealthDetails> {
    if (!this.proxy?.server.listening)
      return Promise.reject(new Error('egress proxy not listening'));
    return Promise.resolve({ activeConnections: this.proxy.activeConnections });
  }

  async onApplicationShutdown(): Promise<void> {
    await this.proxy?.close();
  }
}

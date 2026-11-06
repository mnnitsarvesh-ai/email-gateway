import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { RedisService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { CLICK_DB_TX_MAX_WAIT_MS, type ClickConfig } from '../config';
import { ClickController } from '../http/click.controller';
import { ClickMetrics } from './click-metrics';
import { ClickRepository, PrismaClickRepository } from './click-repository';
import { ClickService } from './click.service';
import { ClickEventWriter } from './event-writer';
import { RateLimiter } from './rate-limiter';
import { Rechecker } from './recheck';
import { buildUrlRuntime, type UrlRuntime } from './url-runtime';

export const CLICK_CONFIG = Symbol('CLICK_CONFIG');
export const CLICK_LOGGER = Symbol('CLICK_LOGGER');
export const URL_RUNTIME = Symbol('URL_RUNTIME');

/** Rate limiter Redis timeout: a slow Redis must not delay clicks (it fails open). */
export const RATE_LIMIT_TIMEOUT_MS = 250;

@Injectable()
class ClickLifecycle implements OnApplicationShutdown {
  constructor(
    @Inject(ClickEventWriter) private readonly writer: ClickEventWriter,
    @Inject(CLICK_LOGGER) private readonly logger: Logger,
  ) {}

  /** Lets pending click event writes finish (bounded) before the database client closes. */
  async onApplicationShutdown(): Promise<void> {
    const drained = await this.writer.drain(10_000);
    if (!drained)
      this.logger.warn(
        { pending: this.writer.pendingCount },
        'click events still pending at shutdown',
      );
  }
}

/** The time-of-click feature (U14): routes, algorithm, recheck, rate limits, event writes. */
@Module({})
export class ClickModule {
  static forRoot(config: Readonly<ClickConfig>, logger: Logger): DynamicModule {
    return {
      module: ClickModule,
      controllers: [ClickController],
      providers: [
        { provide: CLICK_CONFIG, useValue: config },
        { provide: CLICK_LOGGER, useValue: logger },
        ClickMetrics,
        { provide: ClickRepository, useClass: PrismaClickRepository },
        {
          provide: URL_RUNTIME,
          inject: [RedisService, ClickRepository, ClickMetrics],
          useFactory: (redis: RedisService, repository: ClickRepository, metrics: ClickMetrics) =>
            buildUrlRuntime(config, {
              redis: redis.client,
              feedQuery: (kind, hashes) => repository.feedRows(kind, hashes),
              metrics,
            }),
        },
        {
          provide: RateLimiter,
          inject: [RedisService],
          useFactory: (redis: RedisService) =>
            new RateLimiter(
              redis.client,
              {
                ipPerMinute: config.CLICK_RATE_LIMIT_IP_PER_MINUTE,
                tokenPerMinute: config.CLICK_RATE_LIMIT_TOKEN_PER_MINUTE,
                invalidPerMinute: config.CLICK_RATE_LIMIT_INVALID_PER_MINUTE,
              },
              RATE_LIMIT_TIMEOUT_MS,
            ),
        },
        {
          provide: Rechecker,
          inject: [ClickRepository, URL_RUNTIME, ClickMetrics],
          useFactory: (repository: ClickRepository, runtime: UrlRuntime, metrics: ClickMetrics) =>
            new Rechecker(repository, runtime, metrics, {
              budgetMs: config.CLICK_RECHECK_BUDGET_MS,
              suspiciousHops: config.URL_FETCH_SUSPICIOUS_HOPS,
              highScore: config.URL_LOOKALIKE_HIGH_SCORE,
            }),
        },
        {
          provide: ClickEventWriter,
          inject: [ClickRepository, ClickMetrics],
          useFactory: (repository: ClickRepository, metrics: ClickMetrics) =>
            new ClickEventWriter(repository, metrics, logger, {
              waitMs: config.CLICK_EVENT_WRITE_WAIT_MS,
              maxPending: config.CLICK_EVENT_MAX_PENDING,
              txTimeoutMs: config.CLICK_DB_TX_TIMEOUT_MS,
              maxWaitMs: CLICK_DB_TX_MAX_WAIT_MS,
            }),
        },
        {
          provide: ClickService,
          inject: [ClickRepository, RateLimiter, Rechecker, ClickEventWriter, ClickMetrics],
          useFactory: (
            repository: ClickRepository,
            limiter: RateLimiter,
            rechecker: Rechecker,
            writer: ClickEventWriter,
            metrics: ClickMetrics,
          ) =>
            new ClickService(repository, limiter, rechecker, writer, metrics, logger, {
              tokenKeys: config.tokenKeys,
              platform: config.platform,
              continueTtlSeconds: config.CLICK_CONTINUE_TTL_SECONDS,
              storeClientNetwork: config.CLICK_STORE_CLIENT_NETWORK,
            }),
        },
        ClickLifecycle,
      ],
      exports: [ClickService, ClickMetrics],
    };
  }
}

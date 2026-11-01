import {
  type DynamicModule,
  Global,
  Inject,
  Injectable,
  Module,
  type OnModuleDestroy,
} from '@nestjs/common';
import { Redis } from 'ioredis';
import type { HealthIndicator } from '../health/health-indicator';

const REDIS_OPTIONS = Symbol('REDIS_OPTIONS');

export interface RedisModuleOptions {
  url: string;
}

/** Cache, rate limits and ephemeral state. Never the source of truth. */
@Injectable()
export class RedisService implements OnModuleDestroy, HealthIndicator {
  readonly healthName = 'redis';
  readonly client: Redis;

  constructor(@Inject(REDIS_OPTIONS) options: RedisModuleOptions) {
    this.client = new Redis(options.url, { lazyConnect: false, maxRetriesPerRequest: 2 });
  }

  async checkHealth(): Promise<void> {
    const reply = await this.client.ping();
    if (reply !== 'PONG') throw new Error('unexpected PING reply');
  }

  async onModuleDestroy(): Promise<void> {
    await this.client.quit();
  }
}

@Global()
@Module({})
export class RedisModule {
  static forRoot(options: RedisModuleOptions): DynamicModule {
    return {
      module: RedisModule,
      providers: [{ provide: REDIS_OPTIONS, useValue: options }, RedisService],
      exports: [RedisService],
    };
  }
}

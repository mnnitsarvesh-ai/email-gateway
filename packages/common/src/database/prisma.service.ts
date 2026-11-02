import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@email-gateway/database';
import type { HealthIndicator } from '../health/health-indicator';
import { DATABASE_OPTIONS, type DatabaseModuleOptions } from './database.options';

/** The writer connection. Data-plane services must use this, never a read replica. */
@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy, HealthIndicator
{
  readonly healthName = 'mysql';

  constructor(@Inject(DATABASE_OPTIONS) options: DatabaseModuleOptions) {
    super({ datasourceUrl: options.url });
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }

  async checkHealth(): Promise<void> {
    await this.$queryRaw`SELECT 1`;
  }
}

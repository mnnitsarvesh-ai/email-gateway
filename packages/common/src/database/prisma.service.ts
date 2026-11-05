import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { databaseClientUrl, PrismaClient, socketTimeoutFromEnv } from '@email-gateway/database';
import type { HealthIndicator } from '../health/health-indicator';
import { DATABASE_OPTIONS, type DatabaseModuleOptions } from './database.options';

/** The socket timeout a module's clients use: the option, else the environment (default 0). */
export function socketTimeoutOf(options: { socketTimeoutSeconds?: number }): number {
  return options.socketTimeoutSeconds ?? socketTimeoutFromEnv(process.env);
}

/**
 * The writer connection. Data-plane services must use this, never a read replica. The URL goes
 * through the shared `databaseClientUrl` (step 4.2 §6.2 F2), as the replica's does.
 */
@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy, HealthIndicator
{
  readonly healthName = 'mysql';

  constructor(@Inject(DATABASE_OPTIONS) options: DatabaseModuleOptions) {
    super({
      datasourceUrl: databaseClientUrl(options.url, {
        socketTimeoutSeconds: socketTimeoutOf(options),
      }),
    });
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

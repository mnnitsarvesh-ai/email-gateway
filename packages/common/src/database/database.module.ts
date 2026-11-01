import {
  type DynamicModule,
  Global,
  Inject,
  Injectable,
  Module,
  type OnModuleDestroy,
  type OnModuleInit,
} from '@nestjs/common';
import { PrismaClient } from '@email-gateway/database';
import type { HealthIndicator } from '../health/health-indicator';

const DATABASE_OPTIONS = Symbol('DATABASE_OPTIONS');

export interface DatabaseModuleOptions {
  url: string;
}

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

@Global()
@Module({})
export class DatabaseModule {
  static forRoot(options: DatabaseModuleOptions): DynamicModule {
    return {
      module: DatabaseModule,
      providers: [{ provide: DATABASE_OPTIONS, useValue: options }, PrismaService],
      exports: [PrismaService],
    };
  }
}

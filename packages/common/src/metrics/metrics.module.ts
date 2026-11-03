import { type DynamicModule, Global, Module } from '@nestjs/common';
import { MetricsController } from './metrics.controller';
import { METRICS_OPTIONS, type MetricsModuleOptions, MetricsService } from './metrics.service';

/**
 * Prometheus metrics (step 2.2 D16): a global `MetricsService` with a dedicated registry and the
 * public, unversioned `GET /metrics` scrape endpoint. Register once in the app module.
 */
@Global()
@Module({})
export class MetricsModule {
  static forRoot(options: MetricsModuleOptions): DynamicModule {
    return {
      module: MetricsModule,
      controllers: [MetricsController],
      providers: [{ provide: METRICS_OPTIONS, useValue: options }, MetricsService],
      exports: [MetricsService],
    };
  }
}

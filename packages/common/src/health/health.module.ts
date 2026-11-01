import { type DynamicModule, Module, type Type } from '@nestjs/common';
import {
  HEALTH_INDICATORS,
  type HealthIndicator,
  SERVICE_INFO,
  type ServiceInfo,
} from './health-indicator';
import { HealthController } from './health.controller';
import { HealthService } from './health.service';

export interface HealthModuleOptions {
  service: ServiceInfo;
  /** Providers (already registered by other modules) that implement HealthIndicator. */
  indicators: Type<HealthIndicator>[];
}

@Module({})
export class HealthModule {
  static forRoot(options: HealthModuleOptions): DynamicModule {
    return {
      module: HealthModule,
      controllers: [HealthController],
      providers: [
        HealthService,
        { provide: SERVICE_INFO, useValue: options.service },
        {
          provide: HEALTH_INDICATORS,
          useFactory: (...indicators: HealthIndicator[]) => indicators,
          inject: options.indicators,
        },
      ],
    };
  }
}

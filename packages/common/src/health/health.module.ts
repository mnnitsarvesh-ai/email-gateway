import { type DynamicModule, type ForwardReference, Module, type Type } from '@nestjs/common';
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
  /**
   * Non-global modules that export some of the `indicators` (e.g. the email-worker's
   * ScanningModule with its own broker connection, step 4.1 S1). Global modules need no entry.
   */
  imports?: Array<Type | DynamicModule | Promise<DynamicModule> | ForwardReference>;
}

@Module({})
export class HealthModule {
  static forRoot(options: HealthModuleOptions): DynamicModule {
    return {
      module: HealthModule,
      ...(options.imports ? { imports: options.imports } : {}),
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

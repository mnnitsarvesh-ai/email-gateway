import { type DynamicModule, Module, type Type } from '@nestjs/common';
import type { HealthIndicator } from '@email-gateway/common';
import { EmlStore } from './eml-store';
import { LmtpInboundListener, LmtpOutboundListener } from './ingestion.listeners';
import { IngestionMetrics } from './ingestion.metrics';
import { INGESTION_OPTIONS, type IngestionModuleOptions } from './ingestion.options';
import { IngestionRepository } from './ingestion.repository';
import { IngestionService } from './ingestion.service';

export { LmtpInboundListener, LmtpOutboundListener } from './ingestion.listeners';
export type { IngestionModuleOptions } from './ingestion.options';

/** Readiness checks `lmtp-inbound` and `lmtp-outbound`. */
export const INGESTION_HEALTH_INDICATORS: Type<HealthIndicator>[] = [
  LmtpInboundListener,
  LmtpOutboundListener,
];

/**
 * Durable LMTP ingestion (step 2.2 D7, D8): listeners `:10050` (inbound) and `:10051`
 * (outbound). Requires the global PrismaService (writer), S3Service and MetricsService.
 */
@Module({})
export class IngestionModule {
  static forRoot(options: IngestionModuleOptions): DynamicModule {
    return {
      module: IngestionModule,
      global: true,
      providers: [
        { provide: INGESTION_OPTIONS, useValue: options },
        IngestionMetrics,
        IngestionRepository,
        EmlStore,
        IngestionService,
        LmtpInboundListener,
        LmtpOutboundListener,
      ],
      exports: [LmtpInboundListener, LmtpOutboundListener],
    };
  }
}

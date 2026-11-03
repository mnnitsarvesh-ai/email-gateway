import { type DynamicModule, Module, type Type } from '@nestjs/common';
import type { HealthIndicator } from '@email-gateway/common';
import { LmtpBounceListener } from './bounce-listener';
import { BounceNoticeService } from './bounce-notice.service';
import { BOUNCES_OPTIONS, type BouncesModuleOptions } from './bounces.options';
import { BouncesRepository } from './bounces.repository';

export { LmtpBounceListener } from './bounce-listener';
export type { BouncesModuleOptions } from './bounces.options';

/** Readiness check `lmtp-bounces`. */
export const BOUNCES_HEALTH_INDICATORS: Type<HealthIndicator>[] = [LmtpBounceListener];

/**
 * Bounce-notice handler (step 2.2 D13): LMTP `:10052`. Requires the global PrismaService
 * (writer), MetricsService and ReputationRecorder (SmtpSharedModule).
 */
@Module({})
export class BouncesModule {
  static forRoot(options: BouncesModuleOptions): DynamicModule {
    return {
      module: BouncesModule,
      global: true,
      providers: [
        { provide: BOUNCES_OPTIONS, useValue: options },
        BouncesRepository,
        BounceNoticeService,
        LmtpBounceListener,
      ],
      exports: [LmtpBounceListener],
    };
  }
}

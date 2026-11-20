import { type DynamicModule, Module, type Type } from '@nestjs/common';
import type { HealthIndicator } from '@email-gateway/common';
import { EmlStore } from '../ingestion/eml-store';
import { InstanceSizeStore } from '../policy/instance-size.store';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { TenancyModule } from '../tenancy/tenancy.module';
import { IntakeStateStore } from './intake-state.store';
import { JournalIntakeCountersService } from './journal-intake-counters.service';
import { JournalIntakeListener } from './journal-intake.listener';
import { JournalIntakeMetrics } from './journal-intake.metrics';
import { JOURNAL_INTAKE_OPTIONS, type JournalIntakeModuleOptions } from './journal-intake.options';
import { JournalIntakePolicy } from './journal-intake-policy.service';
import { JournalIntakeRepository } from './journal-intake.repository';
import { JournalIntakeService } from './journal-intake.service';
import { JournalIntakeSourceCache } from './source-cache';
import { JournalIntakeSourceRepository } from './source-snapshot';

export { JournalIntakeListener } from './journal-intake.listener';
export type { JournalIntakeModuleOptions } from './journal-intake.options';

/** Readiness check `lmtp-journal` (only while intake is on). */
export const JOURNAL_INTAKE_HEALTH_INDICATORS: Type<HealthIndicator>[] = [JournalIntakeListener];

/**
 * Journal-only intake (step 8.6 D2, ADR-0087): the RCPT policy branch (`JournalIntakePolicy`,
 * injected optionally by `PolicyDecisionService`), the journal LMTP listener `:10053` with its
 * service and repository, the source cache and the per-source counters. Imported by `AppModule`
 * only while intake is on (JOURNAL_INTAKE_ENABLED and JOURNAL_INTAKE_DOMAIN). Global so the
 * policy module and the health module see its exports. Needs the global DatabaseModule (writer),
 * RedisModule, S3Module, MetricsModule, the adapter's ADAPTER_CONFIG / ADAPTER_LOGGER and the
 * ProviderRelayModule (egress index, DKIM verifier).
 */
@Module({})
export class JournalIntakeModule {
  static forRoot(options: JournalIntakeModuleOptions): DynamicModule {
    return {
      module: JournalIntakeModule,
      global: true,
      imports: [TenancyModule, RateLimitModule],
      providers: [
        { provide: JOURNAL_INTAKE_OPTIONS, useValue: options },
        JournalIntakeMetrics,
        JournalIntakeSourceRepository,
        JournalIntakeSourceCache,
        IntakeStateStore,
        InstanceSizeStore,
        JournalIntakeCountersService,
        JournalIntakePolicy,
        EmlStore,
        JournalIntakeRepository,
        JournalIntakeService,
        JournalIntakeListener,
      ],
      exports: [JournalIntakePolicy, JournalIntakeListener, JournalIntakeCountersService],
    };
  }
}

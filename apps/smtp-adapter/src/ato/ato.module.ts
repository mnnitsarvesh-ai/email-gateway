import { Module } from '@nestjs/common';
import { AtoRestrictionService } from './restriction.service';
import { AtoTelemetryRecorder } from './telemetry-recorder';

/**
 * Account takeover telemetry and enforcement of the smtp-adapter (step 8.4 D4, D14, ADR-0073).
 * Imported by the SASL, connector, policy and tenancy modules; Nest keeps one instance of each
 * provider (one buffer, one flusher). Needs the global DatabaseModule (writer), RedisModule,
 * MetricsModule and the adapter's ADAPTER_CONFIG / ADAPTER_LOGGER.
 */
@Module({
  providers: [AtoTelemetryRecorder, AtoRestrictionService],
  exports: [AtoTelemetryRecorder, AtoRestrictionService],
})
export class AtoModule {}

import { Global, Module } from '@nestjs/common';
import { TenancyModule } from '../tenancy/tenancy.module';
import { EgressIndexService } from './egress-index.service';
import { ProbeRecorderRepository } from './probe-recorder.repository';
import { ProofVerifier } from './proof-verifier';
import { ProviderRelayMetrics } from './provider-relay.metrics';
import { ProviderRelayIngestion } from './provider-relay-ingestion.service';
import { ProviderRelayPolicy } from './provider-relay-policy.service';
import { ProviderRelayResolver } from './provider-relay-resolver.service';
import { RelayCountersService } from './relay-counters.service';
import { RelayMarkerStore } from './relay-marker.store';

/**
 * Provider relay of Microsoft 365 / Google Workspace outbound and internal mail (step 8.2 D7, D8,
 * D10, D18; ADR-0078, ADR-0079): egress ranges, resolution on the relay listener, the END-OF-
 * MESSAGE marker, the proof at LMTP ingestion, probe interception and the hourly counters. The
 * mail path never calls a provider API (I1). Global, so the policy and ingestion services inject
 * its two hooks optionally (absent in suites that boot only step 2.2 modules). Needs the global
 * DatabaseModule (writer), RedisModule, MetricsModule and the adapter's ADAPTER_CONFIG /
 * ADAPTER_LOGGER providers.
 */
@Global()
@Module({
  imports: [TenancyModule],
  providers: [
    ProviderRelayMetrics,
    EgressIndexService,
    ProviderRelayResolver,
    RelayMarkerStore,
    ProofVerifier,
    ProbeRecorderRepository,
    RelayCountersService,
    ProviderRelayPolicy,
    ProviderRelayIngestion,
  ],
  exports: [ProviderRelayPolicy, ProviderRelayIngestion, EgressIndexService, RelayCountersService],
})
export class ProviderRelayModule {}

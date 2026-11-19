import { Injectable } from '@nestjs/common';
import { type Counter, type Gauge, MetricsService } from '@email-gateway/common';
import type { ProofResult, ProofRule, RelayProvider } from '@email-gateway/mail-routing';

/** `smtp_provider_relay_total{result}` (D18): one per recipient decision of a provider session. */
export type RelayDecision =
  | 'accepted'
  | 'probe'
  | 'not_active'
  | 'suspended'
  | 'null_sender_refused'
  | 'no_connection'
  | 'tls_required'
  /** END-OF-MESSAGE without a resolvable connector any more (deferred). */
  | 'state_changed';

/** `smtp_provider_probe_observations_total{result}`. */
export type ProbeObservationResult = ProofResult | 'duplicate' | 'error';

/** Provider relay metrics of the smtp-adapter (step 8.2 D18; names are a dashboard contract). */
@Injectable()
export class ProviderRelayMetrics {
  private readonly relay: Counter<'provider' | 'result'>;
  private readonly proof: Counter<'provider' | 'rule' | 'result'>;
  private readonly probes: Counter<'provider' | 'result'>;
  private readonly egressRanges: Gauge<'provider'>;
  private readonly egressLoadErrors: Counter;
  private readonly counterFlushErrors: Counter;
  private readonly markerErrors: Counter<'operation'>;

  constructor(metrics: MetricsService) {
    this.relay = metrics.counter(
      'smtp_provider_relay_total',
      'Provider relay recipient decisions on the relay listener (step 8.2 D7)',
      ['provider', 'result'],
    );
    this.proof = metrics.counter(
      'smtp_provider_proof_total',
      'Provider relay proof rule results at LMTP ingestion (step 8.2 D8)',
      ['provider', 'rule', 'result'],
    );
    this.probes = metrics.counter(
      'smtp_provider_probe_observations_total',
      'Intercepted validation probes (step 8.2 D10)',
      ['provider', 'result'],
    );
    this.egressRanges = metrics.gauge(
      'smtp_provider_egress_ranges',
      'Provider egress ranges loaded in memory',
      ['provider'],
    );
    this.egressLoadErrors = metrics.counter(
      'smtp_provider_egress_load_errors_total',
      'Failed loads of the provider egress ranges (the last loaded set is kept)',
    );
    this.counterFlushErrors = metrics.counter(
      'smtp_provider_relay_counter_flush_errors_total',
      'Failed flushes of the hourly provider relay counters',
    );
    this.markerErrors = metrics.counter(
      'smtp_provider_relay_marker_errors_total',
      'Redis failures writing or reading the provider relay marker (fail closed)',
      ['operation'],
    );
  }

  decision(provider: RelayProvider, result: RelayDecision): void {
    this.relay.inc({ provider, result });
  }

  proofRule(provider: RelayProvider, rule: ProofRule, result: ProofResult): void {
    this.proof.inc({ provider, rule, result });
  }

  probe(provider: RelayProvider, result: ProbeObservationResult): void {
    this.probes.inc({ provider, result });
  }

  egressLoaded(provider: RelayProvider, count: number): void {
    this.egressRanges.set({ provider }, count);
  }

  egressLoadFailed(): void {
    this.egressLoadErrors.inc();
  }

  counterFlushFailed(): void {
    this.counterFlushErrors.inc();
  }

  markerFailed(operation: 'write' | 'read'): void {
    this.markerErrors.inc({ operation });
  }
}

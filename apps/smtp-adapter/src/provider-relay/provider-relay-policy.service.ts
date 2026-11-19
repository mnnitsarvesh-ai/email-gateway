import { Inject, Injectable } from '@nestjs/common';
import type { Logger } from '@email-gateway/logger';
import { isProbeDomain, probeTokenOf } from '@email-gateway/mail-routing';
import { ADAPTER_CONFIG, ADAPTER_LOGGER } from '../config';
import { parseIpKey } from '../connectors/addresses';
import type { ConnectorView } from '../connectors/connector-resolver.service';
import type { PolicyRequest } from '../policy/policy-protocol';
import { MUST_STARTTLS } from '../shared/replies';
import type { ProviderRelayConfig } from './provider-relay.config';
import { ProviderRelayMetrics } from './provider-relay.metrics';
import {
  NULL_SENDER_REFUSED,
  PROBE_RECIPIENT_REFUSED,
  PROVIDER_RELAY_NOT_ACTIVE,
  PROVIDER_RELAY_STATE_CHANGED,
  PROVIDER_RELAY_SUSPENDED,
} from './provider-relay.replies';
import {
  isProviderRelayConnector,
  type ProviderRelayConnectorView,
  ProviderRelayResolver,
} from './provider-relay-resolver.service';
import { RelayMarkerStore } from './relay-marker.store';

/** The policy request cannot carry a provider relay marker (no or malformed `queue_id`). */
export class MarkerQueueIdError extends Error {}

const domainOf = (address: string | undefined): string | null => {
  if (!address) return null;
  const at = address.lastIndexOf('@');
  return at <= 0 || at === address.length - 1 ? null : address.slice(at + 1);
};

/**
 * The provider relay's part of the in-session policy (step 8.2 D7, D8.1, D10), called by
 * `PolicyDecisionService` through a few additive hooks:
 *
 * - `refusesProbeRecipient`: probe-domain recipients outside the `relay` context → `550 5.1.1`;
 * - `resolve`: the last connector branch of the `relay` context (after certificate and source IP);
 * - `checkRecipient`: the provider-relay replies of D7.4/D7.5 (TLS, probe recipients, outbound
 *   mode, null sender, unmatched provider clients counted as `no_connection`);
 * - `endOfMessage`: the marker `sa:prelay:{queueId}` before `DUNNO`; a Redis error propagates and
 *   the policy answers `DEFER_IF_PERMIT 4.3.5` (I7). A provider-egress client whose session no
 *   longer resolves at END-OF-MESSAGE is deferred (never relayed without a marker);
 * - `isSharedProviderClient`: the client is in an active provider egress set (relay enabled).
 */
@Injectable()
export class ProviderRelayPolicy {
  private readonly logger: Logger;

  constructor(
    private readonly resolver: ProviderRelayResolver,
    private readonly markers: RelayMarkerStore,
    private readonly metrics: ProviderRelayMetrics,
    @Inject(ADAPTER_CONFIG)
    private readonly config: Pick<ProviderRelayConfig, 'PROVIDER_PROBE_DOMAIN'>,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'provider-relay-policy' });
  }

  private isProbe(recipient: string | undefined): boolean {
    const domain = domainOf(recipient);
    return domain !== null && isProbeDomain(domain, this.config.PROVIDER_PROBE_DOMAIN);
  }

  /** D10: a probe-domain recipient in any context other than `relay` is refused. */
  refusesProbeRecipient(request: PolicyRequest, context: string): boolean {
    return context !== 'relay' && this.isProbe(request.recipient);
  }

  resolve(request: PolicyRequest): Promise<ProviderRelayConnectorView | null> {
    return this.resolver.resolve(request);
  }

  /**
   * The client is shared provider infrastructure: its address is in the active egress set of a
   * provider (always false while the relay is disabled). Throws before the ranges were ever
   * loaded (the policy fails closed).
   */
  isSharedProviderClient(clientAddress: string | undefined): boolean {
    return this.resolver.providersOf(clientAddress).length > 0;
  }

  /**
   * The provider-relay answer for one recipient after connector resolution, or null to continue
   * with the existing step 2.2 checks (sender, DKIM readiness, suppressions, limits, size).
   */
  checkRecipient(
    request: PolicyRequest,
    context: 'submission' | 'relay',
    connector: ConnectorView | null,
  ): string | null {
    const probe = this.isProbe(request.recipient);
    if (!isProviderRelayConnector(connector)) {
      if (probe) return PROBE_RECIPIENT_REFUSED;
      if (connector === null && context === 'relay') {
        const [provider] = this.resolver.providersOf(request.client_address);
        if (provider !== undefined) {
          if ((request.sender ?? '') === '') {
            this.metrics.decision(provider, 'null_sender_refused');
            return NULL_SENDER_REFUSED;
          }
          this.metrics.decision(provider, 'no_connection');
        }
      }
      return null;
    }
    const { provider, outboundMode } = connector.providerRelay;
    // Provider relay connectors always require TLS (D7.1), whatever the column says.
    if (!request.encryption_protocol) {
      this.metrics.decision(provider, 'tls_required');
      return MUST_STARTTLS;
    }
    if (probe) {
      if (probeTokenOf(request.recipient ?? '', this.config.PROVIDER_PROBE_DOMAIN) === null) {
        return PROBE_RECIPIENT_REFUSED;
      }
      this.metrics.decision(provider, 'probe');
      return null;
    }
    if (outboundMode === 'probe_only') {
      this.metrics.decision(provider, 'not_active');
      return PROVIDER_RELAY_NOT_ACTIVE;
    }
    if (outboundMode === 'suspended') {
      this.metrics.decision(provider, 'suspended');
      return PROVIDER_RELAY_SUSPENDED;
    }
    this.metrics.decision(provider, 'accepted');
    return null;
  }

  /**
   * D8.1: the marker of a provider-relay session, written before END-OF-MESSAGE says DUNNO.
   * Returns an answer that replaces DUNNO, or null. A provider-egress client that resolves to no
   * connector at END-OF-MESSAGE (its recipients were accepted at RCPT, so the relay state changed
   * in between: connection, connector or domain link, an expired resolution cache) is deferred:
   * without the marker the message would be ingested without the tenant and DKIM proof.
   */
  async endOfMessage(
    request: PolicyRequest,
    connector: ConnectorView | null,
  ): Promise<string | null> {
    if (!isProviderRelayConnector(connector)) {
      if (connector !== null) return null;
      const [provider] = this.resolver.providersOf(request.client_address);
      if (provider === undefined) return null;
      this.metrics.decision(provider, 'state_changed');
      this.logger.warn(
        { queueId: request.queue_id ?? null, provider },
        'provider relay session no longer resolves at END-OF-MESSAGE; deferring',
      );
      return PROVIDER_RELAY_STATE_CHANGED;
    }
    const queueId = request.queue_id ?? '';
    if (!/^[A-Za-z0-9]{1,32}$/.test(queueId)) {
      throw new MarkerQueueIdError('END-OF-MESSAGE without a usable queue_id');
    }
    const relay = connector.providerRelay;
    try {
      await this.markers.write(queueId, {
        v: 1,
        organizationId: connector.organizationId.toString(),
        connectionPublicId: relay.connectionPublicId,
        provider: relay.provider,
        tenantId: relay.tenantId,
        outboundMode: relay.outboundMode,
        tlsProtocol: request.encryption_protocol ? request.encryption_protocol.slice(0, 16) : null,
        tlsCipher: request.encryption_cipher ? request.encryption_cipher.slice(0, 64) : null,
        clientAddress: parseIpKey(request.client_address)?.text ?? 'unknown',
      });
    } catch (err) {
      this.metrics.markerFailed('write');
      this.logger.error(
        { err, queueId, provider: relay.provider },
        'provider relay marker write failed; deferring',
      );
      throw err;
    }
    return null;
  }
}

import { describe, expect, it, vi } from 'vitest';
import type { RelayProvider } from '@email-gateway/mail-routing';
import {
  FakeRedis,
  metricValue,
  newMetrics,
  redisService,
  silentLogger,
  testConfig,
} from '../../integration/in-session-support/fakes';
import type { AtoRestrictionService } from '../ato/restriction.service';
import type { AtoTelemetryRecorder } from '../ato/telemetry-recorder';
import type { ConnectorResolver, ConnectorView } from '../connectors/connector-resolver.service';
import type { DkimReadinessService } from '../outbound/dkim-readiness.service';
import type { SuppressionService } from '../outbound/suppression.service';
import { InstanceSizeStore } from '../policy/instance-size.store';
import { PolicyDecisionService } from '../policy/policy-decision.service';
import type { FixedWindowLimiter } from '../rate-limit/fixed-window-limiter';
import {
  DUNNO,
  MUST_STARTTLS,
  POLICY_TEMPFAIL,
  RELAY_DENIED,
  SENDER_NOT_AUTHORIZED,
  UNKNOWN_USER,
} from '../shared/replies';
import type { ReputationRecorder } from '../shared/reputation';
import type { DomainPolicyService, DomainPolicyView } from '../tenancy/domain-policy.service';
import type { RecipientValidator } from '../tenancy/recipient-validator.service';
import type { TenantLimitsService } from '../tenancy/tenant-limits.service';
import { EgressIndexUnavailableError } from './egress-index.service';
import { ProviderRelayMetrics } from './provider-relay.metrics';
import {
  NULL_SENDER_REFUSED,
  PROBE_RECIPIENT_REFUSED,
  PROVIDER_RELAY_NOT_ACTIVE,
  PROVIDER_RELAY_STATE_CHANGED,
  PROVIDER_RELAY_SUSPENDED,
} from './provider-relay.replies';
import { ProviderRelayPolicy } from './provider-relay-policy.service';
import type {
  ProviderRelayConnectorView,
  ProviderRelayResolver,
  RelayOutboundMode,
} from './provider-relay-resolver.service';
import { relayMarkerKey, RelayMarkerStore } from './relay-marker.store';

const ORG = 7n;
const OTHER_ORG = 8n;
const NON_PROVIDER_IP = '203.0.113.9';
const PROVIDER_IP = '40.92.1.2';
const PROBE = 'eg-probe-abcdefghijklmnopqrstuvwxyz@probe.mail-gateway.test';

function view(name: string): DomainPolicyView {
  return {
    domainId: 100n,
    domainPublicId: '0190a0a0-0000-7000-8000-000000000000',
    organizationId: ORG,
    name,
    inboundEnabled: true,
    outboundEnabled: true,
    recipientValidation: 'none',
    rejectUnknownRecipients: false,
    maxMessageSizeBytes: null,
    hasActiveDkimKey: true,
  };
}

function relayConnector(
  outboundMode: RelayOutboundMode = 'active',
  provider: RelayProvider = 'microsoft_365',
): ProviderRelayConnectorView {
  return {
    id: 9n,
    publicId: '0190a0a0-0000-7000-8000-00000000beef',
    organizationId: ORG,
    authType: 'provider_relay',
    requireTls: true,
    networks: [],
    providerRelay: {
      provider,
      connectionId: 5n,
      connectionPublicId: '0190a0a0-0000-7000-8000-000000000c05',
      outboundMode,
      tenantId: '11111111-2222-3333-4444-555555555555',
    },
  };
}

function harness(options: { withRelay?: boolean } = {}) {
  const redis = new FakeRedis();
  const metrics = newMetrics();
  const config = testConfig();
  const connectors = {
    bySaslUsername: vi.fn(() => Promise.resolve<ConnectorView | null>(null)),
    byCertificateFingerprint: vi.fn(() => Promise.resolve<ConnectorView | null>(null)),
    byClientAddress: vi.fn(() => Promise.resolve<ConnectorView | null>(null)),
  };
  let relayView: ProviderRelayConnectorView | null = null;
  let egressLoaded = true;
  const resolver = {
    enabled: true,
    resolve: vi.fn(() =>
      egressLoaded ? Promise.resolve(relayView) : Promise.reject(new EgressIndexUnavailableError()),
    ),
    providersOf: vi.fn((address: string | undefined): RelayProvider[] => {
      if (!egressLoaded) throw new EgressIndexUnavailableError();
      return address === PROVIDER_IP ? ['microsoft_365'] : [];
    }),
  };
  const relayMetrics = new ProviderRelayMetrics(metrics);
  const policy = new ProviderRelayPolicy(
    resolver as unknown as ProviderRelayResolver,
    new RelayMarkerStore(redisService(redis), config),
    relayMetrics,
    config,
    silentLogger(),
  );
  const service = new PolicyDecisionService(
    {
      get: (name: string) =>
        Promise.resolve(
          name === 'tenant.test'
            ? view(name)
            : name === 'victim.test'
              ? { ...view(name), domainId: 101n, organizationId: OTHER_ORG }
              : null,
        ),
    } as unknown as DomainPolicyService,
    {
      get: () =>
        Promise.resolve({
          inboundRecipientsPerMinute: 100,
          outboundRecipientsPerMinute: 100,
          outboundRecipientsPerDay: 1000,
          maxMessageSizeBytes: null,
        }),
    } as unknown as TenantLimitsService,
    { validate: () => Promise.resolve('accept') } as unknown as RecipientValidator,
    { exceeded: () => Promise.resolve(false) } as unknown as FixedWindowLimiter,
    connectors as unknown as ConnectorResolver,
    { isSuppressed: () => Promise.resolve(false) } as unknown as SuppressionService,
    { isReady: () => Promise.resolve(true) } as unknown as DkimReadinessService,
    new InstanceSizeStore(redisService(redis)),
    { record: () => Promise.resolve() } as unknown as ReputationRecorder,
    metrics,
    config,
    silentLogger(),
    // Step 8.4 (ATO): no restriction, telemetry off (not under test here).
    { sendBlock: () => Promise.resolve(null) } as unknown as AtoRestrictionService,
    { enabled: false, recordSubmission: () => {} } as unknown as AtoTelemetryRecorder,
    options.withRelay === false ? undefined : policy,
  );
  return {
    service,
    redis,
    metrics,
    connectors,
    resolver,
    setRelay: (value: ProviderRelayConnectorView | null) => {
      relayView = value;
    },
    unloadEgress: () => {
      egressLoaded = false;
    },
  };
}

const rcpt = (overrides: Record<string, string> = {}) => ({
  request: 'smtpd_access_policy',
  protocol_state: 'RCPT',
  policy_context: 'relay',
  client_address: PROVIDER_IP,
  instance: '1a2b.5f3a2b1c.1a2b3.0',
  sender: 'alice@tenant.test',
  recipient: 'bob@external.test',
  encryption_protocol: 'TLSv1.3',
  encryption_cipher: 'TLS_AES_256_GCM_SHA384',
  ...overrides,
});

const eom = (overrides: Record<string, string> = {}) =>
  rcpt({
    protocol_state: 'END-OF-MESSAGE',
    recipient: '',
    queue_id: '4XyZ12AbCd',
    size: '1200',
    ...overrides,
  });

const relayTotal = (metrics: ReturnType<typeof newMetrics>, result: string) =>
  metricValue(metrics, 'smtp_provider_relay_total', { provider: 'microsoft_365', result });

describe('provider relay resolution order (D7.3)', () => {
  it('certificate and source-IP connectors win; the provider relay is never asked', async () => {
    const h = harness();
    h.setRelay(relayConnector());
    h.connectors.byClientAddress.mockResolvedValueOnce({
      id: 1n,
      publicId: 'ip-connector',
      organizationId: ORG,
      authType: 'source_ip',
      requireTls: false,
      networks: [],
    });
    expect(await h.service.decide(rcpt({ recipient: PROBE }))).toBe(PROBE_RECIPIENT_REFUSED);
    expect(await h.service.decide(rcpt())).toBe(DUNNO);
    // Asked only for the second decision, where no source-IP connector matched.
    expect(h.resolver.resolve).toHaveBeenCalledTimes(1);
  });

  it('a source-IP connector keeps its step 2.2 behaviour', async () => {
    const h = harness();
    h.connectors.byClientAddress.mockResolvedValue({
      id: 1n,
      publicId: 'ip-connector',
      organizationId: ORG,
      authType: 'source_ip',
      requireTls: false,
      networks: [],
    });
    expect(await h.service.decide(rcpt({ encryption_protocol: '' }))).toBe(DUNNO);
    expect(
      await h.service.decide(rcpt({ client_address: NON_PROVIDER_IP, sender: 'x@other.test' })),
    ).toBe(SENDER_NOT_AUTHORIZED);
    expect(h.resolver.resolve).not.toHaveBeenCalled();
  });

  it('a certificate connector wins over the provider relay', async () => {
    const h = harness();
    h.setRelay(relayConnector('probe_only'));
    h.connectors.byCertificateFingerprint.mockResolvedValue({
      id: 2n,
      publicId: 'cert-connector',
      organizationId: ORG,
      authType: 'client_certificate',
      requireTls: true,
      networks: [],
    });
    expect(await h.service.decide(rcpt({ ccert_fingerprint: 'AB'.repeat(32) }))).toBe(DUNNO);
    expect(h.resolver.resolve).not.toHaveBeenCalled();
  });

  it("a shared provider certificate never captures another organization's provider traffic", async () => {
    const h = harness();
    // Organization 7 registered the provider's shared outbound certificate as its connector.
    h.connectors.byCertificateFingerprint.mockResolvedValue({
      id: 2n,
      publicId: 'squatted-cert',
      organizationId: ORG,
      authType: 'client_certificate',
      requireTls: true,
      networks: [],
    });
    // Organization 8's sender, linked to its own provider connection: the provider relay.
    h.setRelay({ ...relayConnector('active'), organizationId: OTHER_ORG });
    const victim = rcpt({ ccert_fingerprint: 'AB'.repeat(32), sender: 'ceo@victim.test' });
    expect(await h.service.decide(victim)).toBe(DUNNO);
    expect(h.resolver.resolve).toHaveBeenCalledTimes(1);
    expect(await relayTotal(h.metrics, 'accepted')).toBe(1);
    // Without a provider-relay connection: the plain relay denial, not the squatter's connector.
    h.setRelay(null);
    expect(await h.service.decide(victim)).toBe(RELAY_DENIED);
    // The same certificate from outside the provider ranges is still organization 7's connector.
    expect(
      await h.service.decide(
        rcpt({
          client_address: NON_PROVIDER_IP,
          ccert_fingerprint: 'AB'.repeat(32),
          sender: 'ceo@victim.test',
        }),
      ),
    ).toBe(SENDER_NOT_AUTHORIZED);
  });

  it("a legacy source-IP connector on provider ranges serves only its own organization's senders", async () => {
    const h = harness();
    h.connectors.byClientAddress.mockResolvedValue({
      id: 1n,
      publicId: 'legacy-ip-connector',
      organizationId: ORG,
      authType: 'source_ip',
      requireTls: false,
      networks: [],
    });
    h.setRelay({ ...relayConnector('active'), organizationId: OTHER_ORG });
    expect(await h.service.decide(rcpt({ sender: 'ceo@victim.test' }))).toBe(DUNNO);
    expect(await relayTotal(h.metrics, 'accepted')).toBe(1);
    expect(await h.service.decide(rcpt())).toBe(DUNNO);
    // The organization's own sender used the legacy connector, not the relay.
    expect(h.resolver.resolve).toHaveBeenCalledTimes(1);
  });
});

describe('provider relay replies (D7.4, D7.5, D7.7)', () => {
  it('accepts an active connection and counts it', async () => {
    const h = harness();
    h.setRelay(relayConnector('active'));
    expect(await h.service.decide(rcpt())).toBe(DUNNO);
    expect(await relayTotal(h.metrics, 'accepted')).toBe(1);
  });

  it('requires TLS whatever the connector column says', async () => {
    const h = harness();
    h.setRelay({ ...relayConnector('active'), requireTls: false });
    expect(await h.service.decide(rcpt({ encryption_protocol: '' }))).toBe(MUST_STARTTLS);
    expect(await relayTotal(h.metrics, 'tls_required')).toBe(1);
  });

  it('probe_only: probes accepted, every other recipient 451 not active', async () => {
    const h = harness();
    h.setRelay(relayConnector('probe_only'));
    expect(await h.service.decide(rcpt({ recipient: PROBE }))).toBe(DUNNO);
    expect(await h.service.decide(rcpt())).toBe(PROVIDER_RELAY_NOT_ACTIVE);
    expect(PROVIDER_RELAY_NOT_ACTIVE).toMatch(/^451 4\.7\.1 /);
    expect(await relayTotal(h.metrics, 'probe')).toBe(1);
    expect(await relayTotal(h.metrics, 'not_active')).toBe(1);
  });

  it('suspended: 451 suspended', async () => {
    const h = harness();
    h.setRelay(relayConnector('suspended'));
    expect(await h.service.decide(rcpt())).toBe(PROVIDER_RELAY_SUSPENDED);
    expect(await relayTotal(h.metrics, 'suspended')).toBe(1);
  });

  it('refuses a malformed probe address even on a provider session', async () => {
    const h = harness();
    h.setRelay(relayConnector('active'));
    expect(
      await h.service.decide(rcpt({ recipient: 'eg-probe-short@probe.mail-gateway.test' })),
    ).toBe(PROBE_RECIPIENT_REFUSED);
  });

  it('refuses null senders from provider ranges', async () => {
    const h = harness();
    expect(await h.service.decide(rcpt({ sender: '' }))).toBe(NULL_SENDER_REFUSED);
    expect(await relayTotal(h.metrics, 'null_sender_refused')).toBe(1);
  });

  it('an unmatched provider client gets the plain relay denial (no oracle), counted', async () => {
    const h = harness();
    expect(await h.service.decide(rcpt())).toBe(RELAY_DENIED);
    expect(await relayTotal(h.metrics, 'no_connection')).toBe(1);
    // A non-provider client is not counted at all.
    expect(await h.service.decide(rcpt({ client_address: '203.0.113.9' }))).toBe(RELAY_DENIED);
    expect(await relayTotal(h.metrics, 'no_connection')).toBe(1);
  });

  it('fails closed before the egress ranges were ever loaded', async () => {
    const h = harness();
    h.unloadEgress();
    expect(await h.service.decide(rcpt())).toBe(POLICY_TEMPFAIL);
  });
});

describe('probe recipients outside provider-relay sessions (D10)', () => {
  it.each(['inbound', 'submission', 'reinject-inbound', 'reinject-outbound'])(
    'refuses them in the %s context',
    async (context) => {
      const h = harness();
      expect(
        await h.service.decide(
          rcpt({ policy_context: context, recipient: PROBE, sasl_username: 'egc-x' }),
        ),
      ).toBe(UNKNOWN_USER);
    },
  );

  it('refuses subdomains of the probe domain and non-provider relay sessions', async () => {
    const h = harness();
    expect(
      await h.service.decide(
        rcpt({ policy_context: 'inbound', recipient: 'x@a.probe.mail-gateway.test' }),
      ),
    ).toBe(UNKNOWN_USER);
    expect(await h.service.decide(rcpt({ client_address: '203.0.113.9', recipient: PROBE }))).toBe(
      UNKNOWN_USER,
    );
  });

  it('without the provider relay module nothing changes (step 2.2 behaviour)', async () => {
    const h = harness({ withRelay: false });
    expect(await h.service.decide(rcpt({ policy_context: 'inbound', recipient: PROBE }))).toBe(
      RELAY_DENIED,
    );
    expect(await h.service.decide(rcpt({ sender: '' }))).toBe(RELAY_DENIED);
  });
});

describe('END-OF-MESSAGE marker (D8.1)', () => {
  it('writes sa:prelay:{queueId} v1 with the TTL before DUNNO', async () => {
    const h = harness();
    h.setRelay(relayConnector('active'));
    expect(await h.service.decide(eom())).toBe(DUNNO);
    const raw = await h.redis.get(relayMarkerKey('4XyZ12AbCd'));
    expect(JSON.parse(raw!)).toEqual({
      v: 1,
      organizationId: '7',
      connectionPublicId: '0190a0a0-0000-7000-8000-000000000c05',
      provider: 'microsoft_365',
      tenantId: '11111111-2222-3333-4444-555555555555',
      outboundMode: 'active',
      tlsProtocol: 'TLSv1.3',
      tlsCipher: 'TLS_AES_256_GCM_SHA384',
      clientAddress: PROVIDER_IP,
    });
    // Never below Postfix's maximal_queue_lifetime (5 d), whatever the configured lifetime.
    expect(h.redis.ttlMs.get(relayMarkerKey('4XyZ12AbCd'))).toBe(432_000 * 1000);
  });

  it('defers a provider client whose session no longer resolves (no marker-less relay)', async () => {
    const h = harness();
    h.setRelay(relayConnector('active'));
    expect(await h.service.decide(rcpt())).toBe(DUNNO);
    // The connection was disabled (or the link removed) between RCPT and END-OF-MESSAGE.
    h.setRelay(null);
    expect(await h.service.decide(eom())).toBe(PROVIDER_RELAY_STATE_CHANGED);
    expect(PROVIDER_RELAY_STATE_CHANGED).toMatch(/^DEFER_IF_PERMIT 4\.7\.1 /);
    expect(h.redis.store.has(relayMarkerKey('4XyZ12AbCd'))).toBe(false);
    expect(await relayTotal(h.metrics, 'state_changed')).toBe(1);
  });

  it('writes no marker for other sessions and other contexts', async () => {
    const h = harness();
    expect(await h.service.decide(eom({ client_address: NON_PROVIDER_IP }))).toBe(DUNNO);
    expect(
      await h.service.decide(eom({ policy_context: 'submission', sasl_username: 'egc-x' })),
    ).toBe(DUNNO);
    expect(h.redis.store.size).toBe(0);
  });

  it('a Redis failure defers (DEFER_IF_PERMIT 4.3.5)', async () => {
    const h = harness();
    h.setRelay(relayConnector('active'));
    // Only the marker write fails (the size lookup before it still works).
    h.redis.set = () => Promise.reject(new Error('redis unavailable'));
    expect(await h.service.decide(eom())).toBe(POLICY_TEMPFAIL);
    expect(
      await metricValue(h.metrics, 'smtp_provider_relay_marker_errors_total', {
        operation: 'write',
      }),
    ).toBe(1);
  });

  it('a provider session without a usable queue_id defers', async () => {
    const h = harness();
    h.setRelay(relayConnector('active'));
    expect(await h.service.decide(eom({ queue_id: '' }))).toBe(POLICY_TEMPFAIL);
    expect(await h.service.decide(eom({ queue_id: 'bad id!' }))).toBe(POLICY_TEMPFAIL);
  });
});

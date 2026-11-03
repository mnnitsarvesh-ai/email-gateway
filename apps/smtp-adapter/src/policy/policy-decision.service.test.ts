import { describe, expect, it, vi } from 'vitest';
import {
  FakeRedis,
  metricValue,
  newMetrics,
  redisService,
  silentLogger,
  testConfig,
} from '../../integration/in-session-support/fakes';
import type { ConnectorResolver, ConnectorView } from '../connectors/connector-resolver.service';
import type { DkimReadinessService } from '../outbound/dkim-readiness.service';
import type { SuppressionService } from '../outbound/suppression.service';
import type { FixedWindowLimiter, RateScope } from '../rate-limit/fixed-window-limiter';
import {
  DUNNO,
  MUST_STARTTLS,
  NOT_READY_FOR_OUTBOUND,
  POLICY_TEMPFAIL,
  RATE_LIMITED,
  RELAY_DENIED,
  SENDER_NOT_AUTHORIZED,
  SIGNING_UNAVAILABLE,
  SUPPRESSED,
  TOO_BIG,
  TOO_BIG_FOR_RECIPIENT,
  UNKNOWN_USER,
} from '../shared/replies';
import type { ReputationRecorder } from '../shared/reputation';
import type { DomainPolicyService, DomainPolicyView } from '../tenancy/domain-policy.service';
import type { RecipientValidator } from '../tenancy/recipient-validator.service';
import type { TenantLimits, TenantLimitsService } from '../tenancy/tenant-limits.service';
import { InstanceSizeStore } from './instance-size.store';
import {
  actionLabel,
  POLICY_CONTEXTS,
  PolicyDecisionService,
  splitAddress,
} from './policy-decision.service';

const ORG = 7n;
const OTHER_ORG = 8n;

function view(name: string, overrides: Partial<DomainPolicyView> = {}): DomainPolicyView {
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
    ...overrides,
  };
}

function connector(overrides: Partial<ConnectorView> = {}): ConnectorView {
  return {
    id: 1n,
    publicId: '0190a0a0-0000-7000-8000-00000000c0de',
    organizationId: ORG,
    authType: 'sasl',
    requireTls: true,
    networks: [],
    ...overrides,
  };
}

function harness(env: Record<string, string> = {}) {
  const views = new Map<string, DomainPolicyView>([
    ['tenant.test', view('tenant.test')],
    ['other.test', view('other.test', { organizationId: OTHER_ORG, domainId: 200n })],
  ]);
  const limits: TenantLimits = {
    inboundRecipientsPerMinute: 100,
    outboundRecipientsPerMinute: 10,
    outboundRecipientsPerDay: 1000,
    maxMessageSizeBytes: null,
  };
  const exceeded = new Set<RateScope>();
  const domains = {
    get: vi.fn((name: string) => Promise.resolve(views.get(name.toLowerCase()) ?? null)),
  };
  const tenantLimits = { get: vi.fn(() => Promise.resolve({ ...limits })) };
  const recipients = { validate: vi.fn(() => Promise.resolve<'accept' | 'reject'>('accept')) };
  const limiter = {
    exceeded: vi.fn((scope: RateScope) => Promise.resolve(exceeded.has(scope))),
  };
  const connectors = {
    bySaslUsername: vi.fn((_: string) => Promise.resolve<ConnectorView | null>(null)),
    byCertificateFingerprint: vi.fn((_: string) => Promise.resolve<ConnectorView | null>(null)),
    byClientAddress: vi.fn(() => Promise.resolve<ConnectorView | null>(null)),
  };
  const suppressions = { isSuppressed: vi.fn(() => Promise.resolve(false)) };
  const dkim = { isReady: vi.fn(() => Promise.resolve(true)) };
  const redis = new FakeRedis();
  const reputation = { record: vi.fn(() => Promise.resolve()) };
  const metrics = newMetrics();
  const service = new PolicyDecisionService(
    domains as unknown as DomainPolicyService,
    tenantLimits as unknown as TenantLimitsService,
    recipients as unknown as RecipientValidator,
    limiter as unknown as FixedWindowLimiter,
    connectors as unknown as ConnectorResolver,
    suppressions as unknown as SuppressionService,
    dkim as unknown as DkimReadinessService,
    new InstanceSizeStore(redisService(redis)),
    reputation as unknown as ReputationRecorder,
    metrics,
    testConfig(env),
    silentLogger(),
  );
  return {
    service,
    views,
    limits,
    exceeded,
    domains,
    tenantLimits,
    recipients,
    limiter,
    connectors,
    suppressions,
    dkim,
    redis,
    reputation,
    metrics,
  };
}

const base = {
  request: 'smtpd_access_policy',
  protocol_state: 'RCPT',
  client_address: '203.0.113.9',
  instance: '1a2b.5f3a2b1c.1a2b3.0',
  sender: 'alice@tenant.test',
  recipient: 'bob@tenant.test',
};
const inbound = (extra: Record<string, string> = {}) => ({
  ...base,
  sender: 'someone@internet.example',
  policy_context: 'inbound',
  ...extra,
});
const submission = (extra: Record<string, string> = {}) => ({
  ...base,
  policy_context: 'submission',
  sasl_username: 'egc-abc',
  encryption_protocol: 'TLSv1.3',
  recipient: 'carol@remote.example',
  ...extra,
});

describe('helpers', () => {
  it('splits addresses at the last @ and refuses empty parts', () => {
    expect(splitAddress('a@b@c.test')).toEqual({ local: 'a@b', domain: 'c.test' });
    expect(splitAddress('@x.test')).toBeNull();
    expect(splitAddress('x@')).toBeNull();
    expect(splitAddress('')).toBeNull();
    expect(splitAddress(undefined)).toBeNull();
  });

  it('labels actions', () => {
    expect(actionLabel(DUNNO)).toBe('dunno');
    expect(actionLabel(RELAY_DENIED)).toBe('reject');
    expect(actionLabel(RATE_LIMITED)).toBe('defer');
    expect(actionLabel(POLICY_TEMPFAIL)).toBe('tempfail');
  });
});

describe('PolicyDecisionService: request validation (fail closed)', () => {
  it.each([
    ['missing policy_context', { policy_context: '' }],
    ['unknown policy_context', { policy_context: 'outbound' }],
    ['wrong request type', { request: 'junk' }],
    ['unexpected protocol_state', { protocol_state: 'DATA' }],
    ['missing protocol_state', { protocol_state: '' }],
  ])('%s → tempfail', async (_, extra) => {
    const h = harness();
    expect(await h.service.decide(inbound(extra))).toBe(POLICY_TEMPFAIL);
    expect(h.domains.get).not.toHaveBeenCalled();
  });

  it('counts unknown contexts under context="unknown"', async () => {
    const h = harness();
    await h.service.decide(inbound({ policy_context: 'nope' }));
    expect(
      await metricValue(h.metrics, 'smtp_policy_decisions_total', {
        context: 'unknown',
        action: 'tempfail',
      }),
    ).toBe(1);
  });

  it('tempfails on a thrown error (database down)', async () => {
    const h = harness();
    h.domains.get.mockRejectedValueOnce(new Error('db down'));
    expect(await h.service.decide(inbound())).toBe(POLICY_TEMPFAIL);
  });

  it('tempfails when the decision exceeds SMTP_POLICY_DECISION_TIMEOUT_MS', async () => {
    const h = harness({ SMTP_POLICY_DECISION_TIMEOUT_MS: '20' });
    h.domains.get.mockReturnValueOnce(new Promise(() => undefined));
    expect(await h.service.decide(inbound())).toBe(POLICY_TEMPFAIL);
  });

  it('tempfails when Redis rate limiting fails (never DUNNO)', async () => {
    const h = harness();
    h.limiter.exceeded.mockRejectedValueOnce(new Error('redis down'));
    expect(await h.service.decide(inbound())).toBe(POLICY_TEMPFAIL);
  });
});

describe('PolicyDecisionService: inbound (D4)', () => {
  it('passes a valid recipient with DUNNO and records metrics', async () => {
    const h = harness();
    expect(await h.service.decide(inbound())).toBe(DUNNO);
    expect(h.limiter.exceeded).toHaveBeenCalledWith('ip', '203.0.113.9', 3000, expect.any(Date));
    expect(h.limiter.exceeded).toHaveBeenCalledWith('tenant_in', '7', 100, expect.any(Date));
    expect(
      await metricValue(h.metrics, 'smtp_policy_decisions_total', {
        context: 'inbound',
        action: 'dunno',
      }),
    ).toBe(1);
    expect(
      await metricValue(h.metrics, 'smtp_policy_decision_seconds', { context: 'inbound' }),
    ).toBe(1);
  });

  it('rejects unknown, malformed and inbound-disabled recipient domains', async () => {
    const h = harness();
    h.views.set('nomail.test', view('nomail.test', { inboundEnabled: false }));
    expect(await h.service.decide(inbound({ recipient: 'x@unknown.test' }))).toBe(RELAY_DENIED);
    expect(await h.service.decide(inbound({ recipient: 'no-at-sign' }))).toBe(RELAY_DENIED);
    expect(await h.service.decide(inbound({ recipient: 'x@nomail.test' }))).toBe(RELAY_DENIED);
    expect(h.limiter.exceeded).not.toHaveBeenCalled();
  });

  it('defers over the per-client-IP rate', async () => {
    const h = harness();
    h.exceeded.add('ip');
    expect(await h.service.decide(inbound())).toBe(RATE_LIMITED);
    expect(h.tenantLimits.get).not.toHaveBeenCalled();
  });

  it('defers over the per-tenant inbound rate', async () => {
    const h = harness();
    h.exceeded.add('tenant_in');
    expect(await h.service.decide(inbound())).toBe(RATE_LIMITED);
    expect(h.recipients.validate).not.toHaveBeenCalled();
  });

  it('rejects an unknown recipient when the validator says so (authoritative mode)', async () => {
    const h = harness();
    h.recipients.validate.mockResolvedValueOnce('reject');
    expect(await h.service.decide(inbound())).toBe(UNKNOWN_USER);
    expect(h.recipients.validate).toHaveBeenCalledWith(h.views.get('tenant.test'), 'bob');
  });

  it('rejects a declared SIZE above min(domain, organization) limit', async () => {
    const h = harness();
    h.views.set('tenant.test', view('tenant.test', { maxMessageSizeBytes: 5000 }));
    h.tenantLimits.get.mockResolvedValue({ ...h.limits, maxMessageSizeBytes: 3000 });
    expect(await h.service.decide(inbound({ size: '3001' }))).toBe(TOO_BIG_FOR_RECIPIENT);
    expect(await h.service.decide(inbound({ size: '3000' }))).toBe(DUNNO);
  });

  it('records the smallest limit per instance and enforces it at END-OF-MESSAGE', async () => {
    const h = harness();
    h.views.set('big.test', view('big.test', { maxMessageSizeBytes: 9000 }));
    h.views.set('small.test', view('small.test', { maxMessageSizeBytes: 4000 }));
    expect(await h.service.decide(inbound({ recipient: 'a@big.test' }))).toBe(DUNNO);
    expect(await h.service.decide(inbound({ recipient: 'b@small.test' }))).toBe(DUNNO);
    expect(await h.service.decide(inbound({ recipient: 'c@big.test' }))).toBe(DUNNO);
    expect(h.redis.store.get(`sa:inst:${base.instance}`)?.value).toBe('4000');
    expect(h.redis.ttlMs.get(`sa:inst:${base.instance}`)).toBe(900_000);
    const eom = { protocol_state: 'END-OF-MESSAGE' };
    expect(await h.service.decide(inbound({ ...eom, size: '4001' }))).toBe(TOO_BIG);
    expect(await h.service.decide(inbound({ ...eom, size: '4000' }))).toBe(DUNNO);
  });

  it('answers DUNNO at END-OF-MESSAGE when no recipient set a limit', async () => {
    const h = harness();
    expect(
      await h.service.decide(inbound({ protocol_state: 'END-OF-MESSAGE', size: '999999999' })),
    ).toBe(DUNNO);
  });

  it('tempfails at END-OF-MESSAGE when Redis fails or the instance is missing', async () => {
    const h = harness();
    expect(
      await h.service.decide(inbound({ protocol_state: 'END-OF-MESSAGE', instance: '' })),
    ).toBe(POLICY_TEMPFAIL);
    h.redis.failing = true;
    expect(await h.service.decide(inbound({ protocol_state: 'END-OF-MESSAGE' }))).toBe(
      POLICY_TEMPFAIL,
    );
  });

  it('tempfails at RCPT when a size limit applies but the instance attribute is missing', async () => {
    const h = harness();
    h.views.set('tenant.test', view('tenant.test', { maxMessageSizeBytes: 5000 }));
    expect(await h.service.decide(inbound({ instance: '' }))).toBe(POLICY_TEMPFAIL);
  });
});

describe('PolicyDecisionService: submission and relay (D11)', () => {
  it('passes an authorized submission and records the reputation event', async () => {
    const h = harness();
    h.connectors.bySaslUsername.mockResolvedValue(connector());
    expect(await h.service.decide(submission())).toBe(DUNNO);
    expect(h.connectors.bySaslUsername).toHaveBeenCalledWith('egc-abc');
    expect(h.suppressions.isSuppressed).toHaveBeenCalledWith(
      ORG,
      'carol@remote.example',
      expect.any(Date),
    );
    expect(h.reputation.record).toHaveBeenCalledWith(ORG, 'submitted');
  });

  it('denies relay without a SASL username or with an unknown/inactive connector', async () => {
    const h = harness();
    expect(await h.service.decide(submission({ sasl_username: '' }))).toBe(RELAY_DENIED);
    expect(await h.service.decide(submission())).toBe(RELAY_DENIED);
  });

  it.each([
    ['null sender', { sender: '' }],
    ['non-tenant sender domain', { sender: 'x@unknown.test' }],
    ['sender domain of another organization', { sender: 'x@other.test' }],
  ])('refuses a %s', async (_, extra) => {
    const h = harness();
    h.connectors.bySaslUsername.mockResolvedValue(connector());
    expect(await h.service.decide(submission(extra))).toBe(SENDER_NOT_AUTHORIZED);
  });

  it('refuses a sender domain that is not outbound-enabled', async () => {
    const h = harness();
    h.connectors.bySaslUsername.mockResolvedValue(connector());
    h.views.set('tenant.test', view('tenant.test', { outboundEnabled: false }));
    expect(await h.service.decide(submission())).toBe(SENDER_NOT_AUTHORIZED);
  });

  it('refuses a sender domain without an active DKIM key unless DKIM is optional', async () => {
    const h = harness();
    h.connectors.bySaslUsername.mockResolvedValue(connector());
    h.views.set('tenant.test', view('tenant.test', { hasActiveDkimKey: false }));
    expect(await h.service.decide(submission())).toBe(NOT_READY_FOR_OUTBOUND);

    const optional = harness({ SMTP_OUTBOUND_REQUIRE_DKIM: 'false' });
    optional.connectors.bySaslUsername.mockResolvedValue(connector());
    optional.views.set('tenant.test', view('tenant.test', { hasActiveDkimKey: false }));
    expect(await optional.service.decide(submission())).toBe(DUNNO);
  });

  it('refuses a suppressed recipient (reputation: suppressed)', async () => {
    const h = harness();
    h.connectors.bySaslUsername.mockResolvedValue(connector());
    h.suppressions.isSuppressed.mockResolvedValue(true);
    expect(await h.service.decide(submission())).toBe(SUPPRESSED);
    expect(h.reputation.record).toHaveBeenCalledWith(ORG, 'suppressed');
  });

  it('defers over the per-minute or per-day outbound rate (reputation: rate_limited)', async () => {
    const h = harness();
    h.connectors.bySaslUsername.mockResolvedValue(connector());
    h.exceeded.add('tenant_out');
    expect(await h.service.decide(submission())).toBe(RATE_LIMITED);
    // The daily counter is not consumed by a deferred per-minute attempt.
    expect(h.limiter.exceeded).not.toHaveBeenCalledWith(
      'tenant_out_day',
      expect.anything(),
      expect.anything(),
      expect.anything(),
    );
    h.exceeded.clear();
    h.exceeded.add('tenant_out_day');
    expect(await h.service.decide(submission())).toBe(RATE_LIMITED);
    expect(h.limiter.exceeded).toHaveBeenCalledWith('tenant_out_day', '7', 1000, expect.any(Date));
    expect(h.reputation.record).toHaveBeenCalledWith(ORG, 'rate_limited');
  });

  it('refuses a declared SIZE above the organization limit', async () => {
    const h = harness();
    h.connectors.bySaslUsername.mockResolvedValue(connector());
    h.tenantLimits.get.mockResolvedValue({ ...h.limits, maxMessageSizeBytes: 1000 });
    expect(await h.service.decide(submission({ size: '1001' }))).toBe(TOO_BIG);
    expect(await h.service.decide(submission({ size: '10' }))).toBe(DUNNO);
  });

  it('relay: a certificate connector wins over a source-IP connector', async () => {
    const h = harness();
    const certificate = connector({ id: 2n, authType: 'client_certificate' });
    h.connectors.byCertificateFingerprint.mockResolvedValue(certificate);
    h.connectors.byClientAddress.mockResolvedValue(
      connector({ id: 3n, authType: 'source_ip', organizationId: OTHER_ORG }),
    );
    expect(
      await h.service.decide(
        submission({ policy_context: 'relay', sasl_username: '', ccert_fingerprint: 'AB:CD' }),
      ),
    ).toBe(DUNNO);
    expect(h.connectors.byClientAddress).not.toHaveBeenCalled();
  });

  it('relay: falls back to the public-key fingerprint, then to the client IP', async () => {
    const h = harness();
    h.connectors.byCertificateFingerprint.mockImplementation((fp: string) =>
      Promise.resolve(fp === 'PK' ? connector({ authType: 'client_certificate' }) : null),
    );
    expect(
      await h.service.decide(
        submission({
          policy_context: 'relay',
          ccert_fingerprint: 'CERT',
          ccert_pubkey_fingerprint: 'PK',
        }),
      ),
    ).toBe(DUNNO);

    const byIp = harness();
    byIp.connectors.byClientAddress.mockResolvedValue(connector({ authType: 'source_ip' }));
    expect(await byIp.service.decide(submission({ policy_context: 'relay' }))).toBe(DUNNO);
    expect(byIp.connectors.byClientAddress).toHaveBeenCalledWith(
      expect.objectContaining({ text: '203.0.113.9', version: 4 }),
    );
  });

  it('relay: a certificate connector with networks refuses other client IPs', async () => {
    const h = harness();
    h.connectors.byCertificateFingerprint.mockResolvedValue(
      connector({
        authType: 'client_certificate',
        networks: [
          {
            version: 4,
            start: Buffer.from([198, 51, 100, 0]),
            end: Buffer.from([198, 51, 100, 255]),
          },
        ],
      }),
    );
    const relay = { policy_context: 'relay', ccert_fingerprint: 'AB' };
    expect(await h.service.decide(submission(relay))).toBe(RELAY_DENIED);
    expect(await h.service.decide(submission({ ...relay, client_address: '198.51.100.7' }))).toBe(
      DUNNO,
    );
  });

  it('relay: a source-IP connector requiring TLS refuses plaintext sessions', async () => {
    const h = harness();
    h.connectors.byClientAddress.mockResolvedValue(connector({ authType: 'source_ip' }));
    expect(
      await h.service.decide(submission({ policy_context: 'relay', encryption_protocol: '' })),
    ).toBe(MUST_STARTTLS);

    const optional = harness();
    optional.connectors.byClientAddress.mockResolvedValue(
      connector({ authType: 'source_ip', requireTls: false }),
    );
    expect(
      await optional.service.decide(
        submission({ policy_context: 'relay', encryption_protocol: '' }),
      ),
    ).toBe(DUNNO);
  });

  it('relay: no certificate and no matching network → relay denied', async () => {
    const h = harness();
    expect(await h.service.decide(submission({ policy_context: 'relay' }))).toBe(RELAY_DENIED);
    expect(
      await h.service.decide(submission({ policy_context: 'relay', client_address: 'unknown' })),
    ).toBe(RELAY_DENIED);
  });
});

describe('PolicyDecisionService: reinjection (D11)', () => {
  const reinjectIn = (recipient: string) => ({
    ...base,
    policy_context: 'reinject-inbound',
    recipient,
  });
  const reinjectOut = (extra: Record<string, string> = {}) => ({
    ...base,
    policy_context: 'reinject-outbound',
    recipient: 'carol@remote.example',
    ...extra,
  });

  it('reinject-inbound accepts only tenant domains', async () => {
    const h = harness();
    expect(await h.service.decide(reinjectIn('bob@tenant.test'))).toBe(DUNNO);
    expect(await h.service.decide(reinjectIn('bob@internet.example'))).toBe(RELAY_DENIED);
    expect(
      await h.service.decide({
        ...reinjectIn('bob@tenant.test'),
        protocol_state: 'END-OF-MESSAGE',
      }),
    ).toBe(POLICY_TEMPFAIL);
  });

  it('reinject-outbound passes a signed-ready tenant sender (reputation: relayed)', async () => {
    const h = harness();
    expect(await h.service.decide(reinjectOut())).toBe(DUNNO);
    expect(h.dkim.isReady).toHaveBeenCalledWith('tenant.test');
    expect(h.reputation.record).toHaveBeenCalledWith(ORG, 'relayed');
  });

  it('reinject-outbound refuses non-tenant and outbound-disabled senders', async () => {
    const h = harness();
    expect(await h.service.decide(reinjectOut({ sender: 'x@internet.example' }))).toBe(
      SENDER_NOT_AUTHORIZED,
    );
    expect(await h.service.decide(reinjectOut({ sender: '' }))).toBe(SENDER_NOT_AUTHORIZED);
    h.views.set('tenant.test', view('tenant.test', { outboundEnabled: false }));
    expect(await h.service.decide(reinjectOut())).toBe(SENDER_NOT_AUTHORIZED);
  });

  it('reinject-outbound refuses suppressed recipients and defers without a signing key', async () => {
    const h = harness();
    h.suppressions.isSuppressed.mockResolvedValueOnce(true);
    expect(await h.service.decide(reinjectOut())).toBe(SUPPRESSED);
    h.dkim.isReady.mockResolvedValueOnce(false);
    expect(await h.service.decide(reinjectOut())).toBe(SIGNING_UNAVAILABLE);
  });
});

describe('PolicyDecisionService: reserved bounce-notice domain (D13)', () => {
  it('refuses bounce-notices@<POSTFIX_BOUNCE_DOMAIN> and its subdomains in every context', async () => {
    const h = harness();
    // Even a tenant that somehow registered the name never gets past the policy.
    h.views.set('bounces.gateway.internal', view('bounces.gateway.internal'));
    h.connectors.bySaslUsername.mockResolvedValue(connector());
    const recipients = [
      'bounce-notices@bounces.gateway.internal',
      'Bounce-Notices@BOUNCES.GATEWAY.INTERNAL',
      'bounce-notices@bounces.gateway.internal.',
      'x@sub.bounces.gateway.internal',
    ];
    for (const context of POLICY_CONTEXTS) {
      for (const recipient of recipients) {
        expect(
          await h.service.decide({ ...base, policy_context: context, recipient }),
          `${context} ${recipient}`,
        ).toBe(RELAY_DENIED);
      }
    }
    expect(h.suppressions.isSuppressed).not.toHaveBeenCalled();
    // A look-alike outside the reserved name is not affected.
    expect(await h.service.decide(submission({ recipient: 'x@notbounces.gateway.internal' }))).toBe(
      DUNNO,
    );
  });

  it('honours a configured POSTFIX_BOUNCE_DOMAIN', async () => {
    const h = harness({ POSTFIX_BOUNCE_DOMAIN: 'dsn.example.internal' });
    h.connectors.bySaslUsername.mockResolvedValue(connector());
    expect(
      await h.service.decide(submission({ recipient: 'bounce-notices@dsn.example.internal' })),
    ).toBe(RELAY_DENIED);
  });
});

describe('PolicyDecisionService: never OK', () => {
  it('replaces an OK coming from anywhere with a tempfail', async () => {
    const h = harness();
    // Simulate a regression where a branch would return OK.
    h.domains.get.mockImplementation(() => Promise.resolve(null));
    const spy = vi
      .spyOn(h.service as unknown as { dispatch: () => Promise<string> }, 'dispatch')
      .mockResolvedValue('OK');
    expect(await h.service.decide(inbound())).toBe(POLICY_TEMPFAIL);
    spy.mockRestore();
  });
});

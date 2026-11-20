import { describe, expect, it, vi } from 'vitest';
import {
  FakeRedis,
  jsonCache,
  metricValue,
  newMetrics,
  redisService,
  silentLogger,
  testConfig,
} from '../../integration/in-session-support/fakes';
import type { AtoRestrictionService } from '../ato/restriction.service';
import type { AtoTelemetryRecorder } from '../ato/telemetry-recorder';
import type { ConnectorResolver } from '../connectors/connector-resolver.service';
import type { DkimReadinessService } from '../outbound/dkim-readiness.service';
import type { SuppressionService } from '../outbound/suppression.service';
import { InstanceSizeStore } from '../policy/instance-size.store';
import { PolicyDecisionService } from '../policy/policy-decision.service';
import { postfixAction } from '../policy/policy-protocol';
import {
  type EgressIndexService,
  EgressIndexUnavailableError,
} from '../provider-relay/egress-index.service';
import { FixedWindowLimiter } from '../rate-limit/fixed-window-limiter';
import {
  DUNNO,
  INTAKE_ONE_DESTINATION,
  INTAKE_SENDER_NOT_AUTHORIZED,
  INTAKE_UNAVAILABLE,
  MUST_STARTTLS,
  POLICY_TEMPFAIL,
  RATE_LIMITED,
  RELAY_DENIED,
  TOO_BIG,
  TOO_BIG_FOR_RECIPIENT,
  UNKNOWN_USER,
} from '../shared/replies';
import type { ReputationRecorder } from '../shared/reputation';
import type { DomainPolicyService, DomainPolicyView } from '../tenancy/domain-policy.service';
import type { RecipientValidator } from '../tenancy/recipient-validator.service';
import type { TenantLimitsService } from '../tenancy/tenant-limits.service';
import type { IntakeMarker, IntakeStateStore, TransactionKind } from './intake-state.store';
import type { JournalIntakeCountersService } from './journal-intake-counters.service';
import { JournalIntakeMetrics } from './journal-intake.metrics';
import { JournalIntakePolicy } from './journal-intake-policy.service';
import { JournalIntakeSourceCache } from './source-cache';
import type { IntakeSourceSnapshot, JournalIntakeSourceRepository } from './source-snapshot';
import { intakeCredentials, testIntakeSecret } from './testing/fixtures';
import {
  snapshotFixture,
  TEST_M365_CLIENT,
  TEST_ONPREM_CLIENT,
  testEgressIndex,
} from './testing/snapshots';

const DOMAIN = 'journal.gateway.test';
const secret = testIntakeSecret();
const m365 = intakeCredentials(secret, '0190a0a0-0000-7000-8000-00000000a042', 1, DOMAIN);
const onprem = intakeCredentials(secret, '0190a0a0-0000-7000-8000-00000000a043', 1, DOMAIN);

/** In-memory IntakeStateStore (claim semantics of the Lua script). */
class FakeState {
  readonly kinds = new Map<string, TransactionKind>();
  readonly markers = new Map<string, IntakeMarker>();
  failing = false;

  claim(instance: string, kind: TransactionKind): Promise<boolean> {
    if (this.failing) return Promise.reject(new Error('redis unavailable'));
    const current = this.kinds.get(instance);
    if (current === undefined) this.kinds.set(instance, kind);
    return Promise.resolve(current === undefined || current === kind);
  }

  kindOf(instance: string): Promise<TransactionKind | null> {
    return Promise.resolve(this.kinds.get(instance) ?? null);
  }

  writeMarker(queueId: string, marker: IntakeMarker): Promise<void> {
    if (this.failing) return Promise.reject(new Error('redis unavailable'));
    this.markers.set(queueId, marker);
    return Promise.resolve();
  }

  readMarker(queueId: string): Promise<IntakeMarker | null> {
    return Promise.resolve(this.markers.get(queueId) ?? null);
  }
}

function harness(env: Record<string, string> = {}) {
  const config = testConfig({
    JOURNAL_INTAKE_DOMAIN: DOMAIN,
    JOURNAL_INTAKE_RATE_PER_SOURCE_PER_MINUTE: '3',
    JOURNAL_INTAKE_MAX_MESSAGE_BYTES: '10000000',
    ...env,
  });
  const snapshots = new Map<string, IntakeSourceSnapshot>([
    [m365.addressHash, snapshotFixture('microsoft_365_journal')],
    [
      onprem.addressHash,
      snapshotFixture('exchange_onprem_journal', { source: { id: '43', publicId: 'p43' } }),
    ],
  ]);
  const repository = {
    loadByAddressHash: vi.fn((hash: string) => Promise.resolve(snapshots.get(hash) ?? null)),
  };
  const redis = new FakeRedis();
  const metrics = newMetrics();
  const cache = new JournalIntakeSourceCache(
    jsonCache(redis, metrics),
    repository as unknown as JournalIntakeSourceRepository,
    config,
  );
  let index = testEgressIndex();
  let egressLoaded = true;
  const egress = {
    current: () => {
      if (!egressLoaded) throw new EgressIndexUnavailableError();
      return index;
    },
  };
  const state = new FakeState();
  const counters = { record: vi.fn() };
  const sizes = new InstanceSizeStore(redisService(redis));
  const intakeMetrics = new JournalIntakeMetrics(metrics);
  const policy = new JournalIntakePolicy(
    cache,
    egress as unknown as EgressIndexService,
    new FixedWindowLimiter(redisService(redis), metrics),
    sizes,
    state as unknown as IntakeStateStore,
    counters as unknown as JournalIntakeCountersService,
    intakeMetrics,
    config,
    silentLogger(),
  );
  const tenant: DomainPolicyView = {
    domainId: 100n,
    domainPublicId: '0190a0a0-0000-7000-8000-000000000000',
    organizationId: 7n,
    name: 'tenant.test',
    inboundEnabled: true,
    outboundEnabled: true,
    recipientValidation: 'none',
    rejectUnknownRecipients: false,
    maxMessageSizeBytes: null,
    hasActiveDkimKey: true,
  };
  const domains = {
    get: vi.fn((name: string) =>
      Promise.resolve(name.toLowerCase() === 'tenant.test' ? tenant : null),
    ),
  };
  const decisions = new PolicyDecisionService(
    domains as unknown as DomainPolicyService,
    {
      get: () =>
        Promise.resolve({
          inboundRecipientsPerMinute: 100,
          outboundRecipientsPerMinute: 10,
          outboundRecipientsPerDay: 100,
          maxMessageSizeBytes: null,
        }),
    } as unknown as TenantLimitsService,
    { validate: () => Promise.resolve('accept') } as unknown as RecipientValidator,
    new FixedWindowLimiter(redisService(redis), metrics),
    {} as ConnectorResolver,
    {} as SuppressionService,
    {} as DkimReadinessService,
    sizes,
    { record: () => Promise.resolve() } as unknown as ReputationRecorder,
    metrics,
    config,
    silentLogger(),
    {} as AtoRestrictionService,
    { enabled: false } as unknown as AtoTelemetryRecorder,
    undefined,
    policy,
  );
  return {
    policy,
    decisions,
    snapshots,
    repository,
    redis,
    metrics,
    state,
    counters,
    sizes,
    domains,
    setIndex: (value: typeof index) => (index = value),
    unloadEgress: () => (egressLoaded = false),
  };
}

let instanceSeq = 0;
const rcpt = (recipient: string, extra: Record<string, string> = {}) => ({
  request: 'smtpd_access_policy',
  protocol_state: 'RCPT',
  policy_context: 'inbound',
  instance: `1a2b.5f3a2b1c.1a2b3.${(instanceSeq += 1)}`,
  client_address: TEST_M365_CLIENT,
  encryption_protocol: 'TLSv1.3',
  sender: 'journal-agent@example.com',
  recipient,
  ...extra,
});

describe('JournalIntakePolicy at RCPT (D2.2)', () => {
  it('accepts a Microsoft 365 source from its egress range and records the size limit', async () => {
    const h = harness();
    const request = rcpt(m365.address, { size: '1000' });
    expect(await h.decisions.decide(request)).toBe(DUNNO);
    expect(h.state.kinds.get(request.instance)).toBe('src:42');
    expect(await h.sizes.limit(request.instance)).toBe(10_000_000);
    // Never resolved as a tenant domain.
    expect(h.domains.get).not.toHaveBeenCalled();
    expect(h.counters.record).not.toHaveBeenCalled();
  });

  it('matches the address case-insensitively', async () => {
    const h = harness();
    expect(await h.decisions.decide(rcpt(m365.address.toUpperCase()))).toBe(DUNNO);
  });

  it.each([
    ['not an intake local part', `postmaster@${DOMAIN}`],
    ['a malformed token', `journal-short@${DOMAIN}`],
    ['an unknown token', `journal-${'a'.repeat(26)}@${DOMAIN}`],
  ])('refuses %s with 550 5.1.1 (metrics only)', async (_name, recipient) => {
    const h = harness();
    expect(await h.decisions.decide(rcpt(recipient))).toBe(UNKNOWN_USER);
    expect(h.counters.record).not.toHaveBeenCalled();
    expect(
      await metricValue(h.metrics, 'journal_intake_refusals_total', {
        stage: 'rcpt',
        code: 'unknown_address',
      }),
    ).toBe(1);
  });

  it('a subdomain of the intake domain is neither intake nor a tenant domain', async () => {
    const h = harness();
    expect(await h.decisions.decide(rcpt(`journal-${m365.token}@sub.${DOMAIN}`))).toBe(
      RELAY_DENIED,
    );
  });

  const refusals: [
    string,
    Parameters<typeof snapshotFixture>[1],
    Record<string, string>,
    string,
    string,
  ][] = [
    ['disabled source', { source: { status: 'disabled' } }, {}, UNKNOWN_USER, 'refused_address'],
    [
      'paused source',
      { source: { status: 'paused' } },
      {},
      INTAKE_UNAVAILABLE,
      'refused_unavailable',
    ],
    [
      'archiving disabled',
      { organization: { archivingEnabled: false } },
      {},
      INTAKE_UNAVAILABLE,
      'refused_unavailable',
    ],
    [
      'missing feature',
      { organization: { journalIntakeFeature: false } },
      {},
      INTAKE_UNAVAILABLE,
      'refused_unavailable',
    ],
    [
      'client outside the egress set',
      {},
      { client_address: '192.0.2.44' },
      INTAKE_SENDER_NOT_AUTHORIZED,
      'refused_network',
    ],
    [
      'connection disabled',
      { connection: { status: 'disabled' } },
      {},
      INTAKE_SENDER_NOT_AUTHORIZED,
      'refused_network',
    ],
    ['plaintext session', {}, { encryption_protocol: '' }, MUST_STARTTLS, 'refused_tls'],
    [
      'client certificate missing',
      { source: { clientCertFingerprints: ['ab'.repeat(32)] } },
      {},
      INTAKE_SENDER_NOT_AUTHORIZED,
      'refused_network',
    ],
  ];
  it.each(refusals)('%s', async (_name, overrides, extra, reply, counter) => {
    const h = harness();
    h.snapshots.set(m365.addressHash, snapshotFixture('microsoft_365_journal', overrides));
    const request = rcpt(m365.address, extra);
    expect(await h.decisions.decide(request)).toBe(reply);
    expect(h.counters.record).toHaveBeenCalledWith(
      42n,
      expect.objectContaining({ counts: { [counter]: 1 }, refusedAt: expect.any(Date) }),
      expect.any(Date),
    );
    // A refused recipient does not claim the transaction.
    expect(h.state.kinds.has(request.instance)).toBe(false);
  });

  it('wire forms of the new replies (contracts §34)', () => {
    expect(postfixAction(INTAKE_SENDER_NOT_AUTHORIZED)).toBe(
      '550 5.7.1 Journal intake sender not authorized',
    );
    expect(postfixAction(INTAKE_UNAVAILABLE)).toBe(
      '450 4.7.1 Journal intake temporarily unavailable',
    );
    expect(postfixAction(INTAKE_ONE_DESTINATION)).toBe('452 4.5.3 Error: too many recipients');
  });

  it('a client certificate fingerprint in Postfix form matches', async () => {
    const h = harness();
    const fp = 'ab'.repeat(32);
    h.snapshots.set(
      m365.addressHash,
      snapshotFixture('microsoft_365_journal', { source: { clientCertFingerprints: [fp] } }),
    );
    const postfixForm = fp.toUpperCase().match(/../g)!.join(':');
    expect(await h.decisions.decide(rcpt(m365.address, { ccert_fingerprint: postfixForm }))).toBe(
      DUNNO,
    );
  });

  it('on-premises: accepted from its networks, refused from a provider range', async () => {
    const h = harness();
    expect(
      await h.decisions.decide(rcpt(onprem.address, { client_address: TEST_ONPREM_CLIENT })),
    ).toBe(DUNNO);
    h.snapshots.set(
      onprem.addressHash,
      snapshotFixture('exchange_onprem_journal', {
        source: { id: '43', networks: ['198.51.100.0/24'] },
      }),
    );
    h.redis.store.clear();
    expect(await h.decisions.decide(rcpt(onprem.address))).toBe(INTAKE_SENDER_NOT_AUTHORIZED);
  });

  it('previous address: accepted within the overlap, refused after it', async () => {
    const h = harness();
    const future = new Date(Date.now() + 86_400_000).toISOString();
    h.snapshots.set(
      m365.addressHash,
      snapshotFixture('microsoft_365_journal', {
        source: { matchedPrevious: true, previousValidUntil: future },
      }),
    );
    expect(await h.decisions.decide(rcpt(m365.address))).toBe(DUNNO);
    h.redis.store.clear();
    h.snapshots.set(
      m365.addressHash,
      snapshotFixture('microsoft_365_journal', {
        source: {
          matchedPrevious: true,
          previousValidUntil: new Date(Date.now() - 1).toISOString(),
        },
      }),
    );
    expect(await h.decisions.decide(rcpt(m365.address))).toBe(UNKNOWN_USER);
  });

  it('caches sources (positive and negative) for JOURNAL_INTAKE_SOURCE_CACHE_SECONDS', async () => {
    const h = harness({ JOURNAL_INTAKE_SOURCE_CACHE_SECONDS: '45' });
    await h.decisions.decide(rcpt(m365.address));
    await h.decisions.decide(rcpt(m365.address));
    const unknown = `journal-${'b'.repeat(26)}@${DOMAIN}`;
    await h.decisions.decide(rcpt(unknown));
    await h.decisions.decide(rcpt(unknown));
    expect(h.repository.loadByAddressHash).toHaveBeenCalledTimes(2);
    expect(h.redis.ttlMs.get(`sa:jintake:src:${m365.addressHash}`)).toBe(45_000);
    // A pause is seen once the entry expires (here: removed).
    h.snapshots.set(
      m365.addressHash,
      snapshotFixture('microsoft_365_journal', { source: { status: 'paused' } }),
    );
    expect(await h.decisions.decide(rcpt(m365.address))).toBe(DUNNO);
    h.redis.store.delete(`sa:jintake:src:${m365.addressHash}`);
    expect(await h.decisions.decide(rcpt(m365.address))).toBe(INTAKE_UNAVAILABLE);
  });

  it('rate: per source (platform key) and per organization (plan limit)', async () => {
    const h = harness();
    for (let i = 0; i < 3; i += 1) expect(await h.decisions.decide(rcpt(m365.address))).toBe(DUNNO);
    expect(await h.decisions.decide(rcpt(m365.address))).toBe(RATE_LIMITED);
    expect(h.counters.record).toHaveBeenCalledWith(
      42n,
      expect.objectContaining({ counts: { refused_rate: 1 } }),
      expect.any(Date),
    );
    const org = harness();
    org.snapshots.set(
      m365.addressHash,
      snapshotFixture('microsoft_365_journal', { organization: { messagesPerMinute: 0 } }),
    );
    expect(await org.decisions.decide(rcpt(m365.address))).toBe(RATE_LIMITED);
  });

  it('size: min(source, plan, platform) at RCPT and END-OF-MESSAGE', async () => {
    const h = harness();
    h.snapshots.set(
      m365.addressHash,
      snapshotFixture('microsoft_365_journal', {
        source: { maxMessageBytes: 5000 },
        organization: { maxMessageBytes: 8000 },
      }),
    );
    expect(await h.decisions.decide(rcpt(m365.address, { size: '5001' }))).toBe(
      TOO_BIG_FOR_RECIPIENT,
    );
    const request = rcpt(m365.address, { size: '4000' });
    expect(await h.decisions.decide(request)).toBe(DUNNO);
    expect(await h.sizes.limit(request.instance)).toBe(5000);
    const eom = { ...request, protocol_state: 'END-OF-MESSAGE', size: '6000', queue_id: '4ZQ1' };
    expect(await h.decisions.decide(eom)).toBe(TOO_BIG);
    await new Promise((r) => setTimeout(r, 0));
    expect(h.counters.record).toHaveBeenLastCalledWith(
      42n,
      expect.objectContaining({ counts: { refused_size: 1 } }),
      expect.any(Date),
    );
    // A plan without the limit allows nothing.
    const none = harness();
    none.snapshots.set(
      m365.addressHash,
      snapshotFixture('microsoft_365_journal', { organization: { maxMessageBytes: 0 } }),
    );
    expect(await none.decisions.decide(rcpt(m365.address, { size: '1' }))).toBe(
      TOO_BIG_FOR_RECIPIENT,
    );
  });

  it('fails closed: unloaded egress index and Redis errors tempfail, never OK', async () => {
    const h = harness();
    h.unloadEgress();
    expect(await h.decisions.decide(rcpt(m365.address))).toBe(POLICY_TEMPFAIL);
    const r = harness();
    r.state.failing = true;
    expect(await r.decisions.decide(rcpt(m365.address))).toBe(POLICY_TEMPFAIL);
    const missing = harness();
    expect(await missing.decisions.decide({ ...rcpt(m365.address), instance: '' })).toBe(
      POLICY_TEMPFAIL,
    );
  });
});

describe('intake-only transactions (D2.2.5)', () => {
  it('intake first: a tenant recipient of the same transaction gets 452', async () => {
    const h = harness();
    const first = rcpt(m365.address);
    expect(await h.decisions.decide(first)).toBe(DUNNO);
    expect(
      await h.decisions.decide({ ...first, recipient: 'bob@tenant.test', sender: 'x@example.org' }),
    ).toBe(INTAKE_ONE_DESTINATION);
    // Another source in the same transaction too.
    expect(
      await h.decisions.decide({
        ...first,
        recipient: onprem.address,
        client_address: TEST_ONPREM_CLIENT,
      }),
    ).toBe(INTAKE_ONE_DESTINATION);
    // The same source again is fine.
    expect(await h.decisions.decide(first)).toBe(DUNNO);
  });

  it('tenant first: an intake recipient of the same transaction gets 452', async () => {
    const h = harness();
    const first = rcpt('bob@tenant.test', { sender: 'x@example.org' });
    expect(await h.decisions.decide(first)).toBe(DUNNO);
    expect(h.state.kinds.get(first.instance)).toBe('tenant');
    expect(await h.decisions.decide({ ...first, recipient: m365.address })).toBe(
      INTAKE_ONE_DESTINATION,
    );
    expect(await h.decisions.decide({ ...first, recipient: 'carol@tenant.test' })).toBe(DUNNO);
  });

  it('records nothing for tenant mail while intake is off', async () => {
    const h = harness({ JOURNAL_INTAKE_ENABLED: 'false' });
    const first = rcpt('bob@tenant.test', { sender: 'x@example.org' });
    expect(await h.decisions.decide(first)).toBe(DUNNO);
    expect(h.state.kinds.size).toBe(0);
    // And the intake domain is then just an unknown domain.
    expect(await h.decisions.decide(rcpt(m365.address))).toBe(RELAY_DENIED);
  });
});

describe('END-OF-MESSAGE marker', () => {
  it('writes the TLS and certificate facts of an intake transaction', async () => {
    const h = harness();
    const request = rcpt(m365.address, { size: '100' });
    await h.decisions.decide(request);
    const fp = 'cd'.repeat(32);
    expect(
      await h.decisions.decide({
        ...request,
        protocol_state: 'END-OF-MESSAGE',
        queue_id: '4ZABC123',
        ccert_fingerprint: fp,
      }),
    ).toBe(DUNNO);
    expect(h.state.markers.get('4ZABC123')).toEqual({
      v: 1,
      sourceId: '42',
      tls: true,
      tlsProtocol: 'TLSv1.3',
      certFingerprints: [fp],
      clientAddress: TEST_M365_CLIENT,
    });
  });

  it('writes nothing for tenant transactions and tempfails on Redis errors', async () => {
    const h = harness();
    const tenant = rcpt('bob@tenant.test', { sender: 'x@example.org' });
    await h.decisions.decide(tenant);
    expect(
      await h.decisions.decide({ ...tenant, protocol_state: 'END-OF-MESSAGE', queue_id: '4ZT1' }),
    ).toBe(DUNNO);
    expect(h.state.markers.size).toBe(0);
    const intake = rcpt(m365.address);
    await h.decisions.decide(intake);
    h.state.failing = true;
    expect(
      await h.decisions.decide({ ...intake, protocol_state: 'END-OF-MESSAGE', queue_id: '4ZT2' }),
    ).toBe(POLICY_TEMPFAIL);
    h.state.failing = false;
    expect(
      await h.decisions.decide({ ...intake, protocol_state: 'END-OF-MESSAGE', queue_id: '' }),
    ).toBe(POLICY_TEMPFAIL);
  });
});

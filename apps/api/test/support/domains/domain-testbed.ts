/**
 * The domains module's real services wired to `InMemoryDomainStore`, an in-memory KV store and
 * a scripted `DomainDnsChecker` (unit tests). Key generation and SecretBox encryption are real.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { Logger } from '@nestjs/common';
import type { DnsCheckOutcome } from '@email-gateway/database';
import { vi } from 'vitest';
import type { ApiKeyPrincipal, UserPrincipal } from '../../../src/auth-contracts/principal';
import { type ApiConfig, loadApiConfig } from '../../../src/config';
import { SecretBox } from '../../../src/crypto/secret-box';
import { noJitter } from '../../../src/modules/domains/domain/schedule';
import type {
  DomainCheckInput,
  DomainCheckOptions,
  DomainDnsChecker,
} from '../../../src/modules/domains/engine/domain-dns-checker';
import type {
  DomainCheckReport,
  RecordCheckResult,
} from '../../../src/modules/domains/engine/types';
import { DkimRotationService } from '../../../src/modules/domains/services/dkim-rotation.service';
import { DomainCheckScheduler } from '../../../src/modules/domains/services/domain-check-scheduler.service';
import { DomainConfigurationService } from '../../../src/modules/domains/services/domain-configuration.service';
import { DomainEventsService } from '../../../src/modules/domains/services/domain-events.service';
import { DomainVerificationService } from '../../../src/modules/domains/services/domain-verification.service';
import { DomainsService } from '../../../src/modules/domains/services/domains.service';
import { DomainOwnershipReader } from '../../../src/modules/domains/services/domain-ownership-reader';
import { DomainProviderOwnershipService } from '../../../src/modules/domains/services/domain-provider-ownership.service';
import type { BoundConnectionsReader } from '../../../src/modules/provider-connections/repositories/bound-connections.repository';
import type { IdempotencyService } from '../../../src/http/idempotency/idempotency.service';
import { InMemoryKeyValueStore } from '../in-memory-key-value-store';
import { TEST_DOMAIN_ENV } from '../test-env';
import { InMemoryDomainStore } from './in-memory-domain-store';
import type { OrganizationFeaturesService } from '../../../src/tenancy/organization-features.service';

export function testConfig(env: Record<string, string> = {}): ApiConfig {
  return loadApiConfig({
    ...TEST_DOMAIN_ENV,
    NODE_ENV: 'test',
    APP_ENV: 'ci',
    HTTP_PORT: '3000',
    DATABASE_URL: 'mysql://test:test@localhost:3306/test',
    REDIS_URL: 'redis://localhost:6379',
    S3_REGION: 'us-east-1',
    S3_BUCKET_MAIL: 'test-mail',
    S3_BUCKET_ARCHIVE: 'test-archive',
    AUTH_JWT_SECRET: randomBytes(32).toString('hex'),
    AUTH_TOKEN_PEPPER: randomBytes(32).toString('hex'),
    DATA_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
    AUTH_BACKGROUND_JOBS_ENABLED: 'false',
    ...env,
  });
}

/** Decides the outcome of each record key in the scripted checker. */
export type OutcomeScript = (recordKey: string) => DnsCheckOutcome;

const INDETERMINATE_EVIDENCE = {
  query: {
    upstream: 'system:127.0.0.1:53',
    outcome: 'indeterminate',
    reason: 'timeout',
    detail: 'no answer',
  },
};

/** A report for exactly the records the checker was asked about. */
export function scriptedReport(
  input: DomainCheckInput,
  script: OutcomeScript,
  gatewayHosts: readonly string[],
): DomainCheckReport {
  const keys = [
    ...(input.verification ? ['verification'] : []),
    ...gatewayHosts.map((h) => `mx:${h}`),
    'spf',
    ...input.dkimKeys.map((k) => `dkim:${k.selector}`),
    'dmarc',
  ];
  const records: RecordCheckResult[] = keys.map((recordKey) => {
    const outcome = script(recordKey);
    return {
      recordKey,
      outcome,
      observedValue: outcome === 'valid' || outcome === 'invalid' ? `observed ${recordKey}` : null,
      expectedValue:
        recordKey === 'spf'
          ? 'v=spf1 include:_spf.mail-gateway.test ~all'
          : `expected ${recordKey}`,
      warnings: [],
      evidence:
        outcome === 'indeterminate'
          ? INDETERMINATE_EVIDENCE
          : { query: { upstream: 'system:127.0.0.1:53', outcome: 'answer' } },
    };
  });
  const mxOutcome = script(`mx:${gatewayHosts[0]}`);
  return {
    checkedAt: new Date(),
    records,
    mx: {
      observed:
        mxOutcome === 'indeterminate'
          ? null
          : mxOutcome === 'missing'
            ? []
            : gatewayHosts.map((h, i) => ({ priority: (i + 1) * 10, exchange: h })),
      propagation: [],
    },
    spf: { lookupCount: 1, lookupCountExact: true, recommendedValue: 'v=spf1 ~all' },
    dmarc: {
      stage: 'missing',
      partial: false,
      recommendedValue: 'v=DMARC1; p=none',
      nextStep: 'publish',
    },
    indeterminate: records.some((r) => r.outcome === 'indeterminate'),
  };
}

export const ORG_A = 7n;
export const ORG_B = 8n;

export function userPrincipal(organizationId: bigint = ORG_A): UserPrincipal {
  return {
    kind: 'user',
    userId: 10n,
    userPublicId: randomUUID(),
    organizationId,
    organizationPublicId: randomUUID(),
    organizationKind: 'customer',
    sessionId: randomUUID(),
    mfaAuthenticated: true,
    mfaEnrollmentRequired: false,
    permissions: new Set(['domain:read', 'domain:manage', 'domain:dkim_rotate']),
  };
}

export function apiKeyPrincipal(organizationId: bigint = ORG_A): ApiKeyPrincipal {
  return {
    kind: 'api_key',
    apiKeyId: 5n,
    apiKeyPublicId: randomUUID(),
    organizationId,
    organizationPublicId: randomUUID(),
    permissions: new Set(['domain:manage']),
  };
}

export const client = { ip: '203.0.113.7', userAgent: 'vitest' };

export function createDomainTestbed(env: Record<string, string> = {}) {
  // Services log through Nest's Logger; unit tests assert behaviour, not log lines.
  Logger.overrideLogger(false);
  const config = testConfig(env);
  const store = new InMemoryDomainStore();
  const kv = new InMemoryKeyValueStore();
  const transactions = store.transactionRunner();
  const audit = store.auditService();
  const domains = store.domainsRepository();
  const verifications = store.verificationsRepository();
  const records = store.dnsRecordsRepository();
  const keys = store.dkimKeysRepository();
  const mx = store.mxObservationsRepository();
  const ownership = store.ownershipRepository();
  const jobs = store.jobsRepository();
  const secretBox = new SecretBox(config);
  const events = new DomainEventsService(audit, store.outboxRepository());
  const configuration = new DomainConfigurationService(
    config,
    transactions,
    secretBox,
    domains,
    verifications,
    records,
    keys,
  );
  const gatewayHosts = config.GATEWAY_MX_HOSTS.map((m) => m.host);
  let script: OutcomeScript = () => 'missing';
  const check = vi.fn((input: DomainCheckInput, _options: DomainCheckOptions) =>
    Promise.resolve(scriptedReport(input, script, gatewayHosts)),
  );
  const checker = { check } as unknown as DomainDnsChecker;
  // Step API-4 (B3): provider rows in the store, capable connections per organization.
  const providerVerifications = store.providerVerificationsRepository();
  const capableConnections = new Map<bigint, Array<{ id: bigint; publicId: string }>>();
  const connections = {
    ownershipCapableConnections: (scope: { organizationId: bigint }) =>
      Promise.resolve(
        (capableConnections.get(scope.organizationId) ?? []).map((c) => ({
          ...c,
          provider: 'microsoft_365' as const,
          displayName: 'Contoso tenant',
        })),
      ),
  } as unknown as BoundConnectionsReader;
  const ownershipReader = new DomainOwnershipReader(providerVerifications, connections);
  const verification = new DomainVerificationService(
    config,
    noJitter,
    kv,
    transactions,
    audit,
    domains,
    verifications,
    records,
    keys,
    mx,
    ownership,
    events,
    configuration,
    checker,
    ownershipReader,
  );
  const rotation = new DkimRotationService(
    config,
    kv,
    transactions,
    audit,
    domains,
    verifications,
    records,
    keys,
    jobs,
    configuration,
    events,
  );
  // Step 8.6 D13: the service profile of the organization (`gateway` unless a test says so).
  const profile: { value: 'gateway' | 'archive_only' } = { value: 'gateway' };
  // Step API-1: the organizations entitled to API mode (`api_mode_protection`).
  const apiModeEntitled = new Set<bigint>();
  const features = {
    serviceProfile: () => Promise.resolve(profile.value),
    isEffectivelyEnabled: (organizationId: bigint, key: string) =>
      Promise.resolve(key === 'api_mode_protection' && apiModeEntitled.has(organizationId)),
  } as unknown as OrganizationFeaturesService;
  const service = new DomainsService(
    config,
    transactions,
    audit,
    store.limitsService(),
    domains,
    verifications,
    records,
    keys,
    ownership,
    configuration,
    events,
    features,
    ownershipReader,
  );
  const idempotency = {
    execute: async <T>(
      _request: unknown,
      work: (tx: unknown) => Promise<{ statusCode: number; body: T }>,
    ) => ({ ...(await transactions.run((tx) => work(tx))), replayed: false }),
  } as unknown as IdempotencyService;
  const providerOwnership = new DomainProviderOwnershipService(
    config,
    kv,
    idempotency,
    transactions,
    audit,
    domains,
    ownership,
    providerVerifications,
    connections,
    verification,
    events,
  );
  const scheduler = new DomainCheckScheduler(
    config,
    kv,
    jobs,
    verification,
    rotation,
    providerOwnership,
  );
  return {
    config,
    store,
    kv,
    secretBox,
    check,
    /** Sets the outcome per record key of every following check. */
    script(next: OutcomeScript) {
      script = next;
    },
    configuration,
    verification,
    rotation,
    service,
    /** Step 8.6: the organization's service profile seen by `DomainsService`. */
    profile,
    /** Step API-1: organizations entitled to API mode. */
    apiModeEntitled,
    scheduler,
    /** Step API-4 (B3): provider ownership checks and the capable connections per organization. */
    providerOwnership,
    capableConnections,
    gatewayHosts,
    repos: { domains, verifications, records, keys, mx, ownership, jobs, providerVerifications },
  };
}

export type DomainTestbed = ReturnType<typeof createDomainTestbed>;

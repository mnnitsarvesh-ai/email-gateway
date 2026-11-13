import type { SuccessBody } from '@/lib/api/types';

/** Builders of api bodies for the WP4 page tests (typed against the OpenAPI schema). */

export const DOMAIN_ID = '0193a000-0000-7000-8000-000000000001';
export const OTHER_DOMAIN_ID = '0193a000-0000-7000-8000-0000000000ff';
const T = '2026-11-12T09:00:00.000Z';

type Domain = SuccessBody<'DomainsController_get_v1'>;

export function domainDetail(overrides: Partial<Domain> = {}): Domain {
  return {
    id: DOMAIN_ID,
    name: 'alpha.example.test',
    unicodeName: 'alpha.example.test',
    status: 'active',
    statusReason: null,
    inboundEnabled: true,
    outboundEnabled: true,
    verifiedAt: T,
    activatedAt: T,
    lastCheckedAt: T,
    nextCheckAt: '2026-11-12T10:00:00.000Z',
    createdAt: '2026-11-01T09:00:00.000Z',
    updatedAt: T,
    statusChangedAt: T,
    verification: {
      method: 'dns_txt',
      host: '_emailgateway-verify.alpha.example.test',
      value: 'eg-verify=abc123',
      status: 'verified',
      attempts: 2,
      lastCheckedAt: T,
      lastOutcome: 'valid',
      lastError: null,
      expiresAt: '2026-11-08T09:00:00.000Z',
      verifiedAt: T,
    },
    dkimKeys: [
      {
        selector: 'eg2026a',
        algorithm: 'rsa_2048',
        status: 'active',
        host: 'eg2026a._domainkey.alpha.example.test',
        createdAt: T,
        activatedAt: T,
        retireAfter: null,
        retiredAt: null,
      },
    ],
    ...overrides,
  };
}

export function domainSummary(i: number, overrides: Partial<Domain> = {}) {
  const d = domainDetail({
    id: `0193a000-0000-7000-8000-${String(i).padStart(12, '0')}`,
    name: `d${i}.example.test`,
    unicodeName: `d${i}.example.test`,
    ...overrides,
  });
  return {
    id: d.id,
    name: d.name,
    unicodeName: d.unicodeName,
    status: d.status,
    statusReason: d.statusReason,
    inboundEnabled: d.inboundEnabled,
    outboundEnabled: d.outboundEnabled,
    verifiedAt: d.verifiedAt,
    activatedAt: d.activatedAt,
    lastCheckedAt: d.lastCheckedAt,
    nextCheckAt: d.nextCheckAt,
    createdAt: d.createdAt,
    updatedAt: d.updatedAt,
  };
}

type StatusView = SuccessBody<'DomainDnsController_status_v1'>;

export function statusView(overrides: Partial<StatusView> = {}): StatusView {
  const check = (status: 'pending' | 'valid' | 'invalid' | 'missing') => ({
    status,
    lastOutcome: null,
    lastCheckedAt: T,
    warnings: [],
  });
  return {
    domainId: DOMAIN_ID,
    name: 'alpha.example.test',
    status: 'active',
    statusReason: null,
    readyForActivation: false,
    mailFlowReady: true,
    lastCheckedAt: T,
    nextCheckAt: null,
    checkFailures: 0,
    checks: {
      ownership: check('valid'),
      mx: {
        ...check('valid'),
        observed: [{ priority: 10, host: 'mx1.gateway.example.test', pointsToGateway: true }],
        propagation: [],
      },
      spf: { ...check('valid'), lookupCount: 3, recommendedValue: 'v=spf1 ~all' },
      dkim: { ...check('valid'), selectors: [] },
      dmarc: {
        ...check('missing'),
        stage: 'missing',
        recommendedValue: 'v=DMARC1; p=none',
        nextStep: 'Publish a DMARC record with p=none.',
      },
    },
    ...overrides,
  };
}

export function dnsRecords(): SuccessBody<'DomainDnsController_dnsRecords_v1'> {
  const base = {
    status: 'pending' as const,
    lastOutcome: null,
    observedValue: null,
    lastCheckedAt: null,
    lastError: null,
    warnings: [],
    priority: null,
  };
  return {
    domainId: DOMAIN_ID,
    records: [
      {
        ...base,
        key: 'verification',
        purpose: 'verification',
        requirement: 'activation',
        type: 'TXT',
        host: '_emailgateway-verify.alpha.example.test',
        name: '_emailgateway-verify',
        value: 'eg-verify=abc123',
        instructions: 'Publish this TXT record.',
      },
      {
        ...base,
        key: 'mx:mx1.gateway.example.test',
        purpose: 'mx',
        requirement: 'inbound',
        type: 'MX',
        host: 'alpha.example.test',
        name: '@',
        value: 'mx1.gateway.example.test',
        priority: 10,
        instructions: 'Point MX to the gateway.',
      },
    ],
    cleanup: [],
  };
}

export function destinations(
  overrides: Partial<SuccessBody<'DomainDestinationsController_get_v1'>> = {},
): SuccessBody<'DomainDestinationsController_get_v1'> {
  return {
    provider: 'custom',
    servers: [
      {
        id: '0193a000-0000-7000-8000-00000000c001',
        host: 'mx1.alpha.example.test',
        port: 25,
        priority: 10,
        tlsMode: 'required',
        tlsVerifyNames: null,
        enabled: true,
        createdAt: T,
        updatedAt: T,
      },
    ],
    ...overrides,
  };
}

export const PROVIDERS: SuccessBody<'DestinationProvidersController_list_v1'> = {
  data: [
    {
      provider: 'custom',
      displayName: 'Your own servers',
      hostHint: null,
      hostPatterns: [],
      port: 25,
      tlsMode: 'opportunistic',
      tlsVerifyNames: 'nexthop',
      maxServers: 10,
      defaultServers: null,
      documentationUrl: null,
    },
    {
      provider: 'microsoft_365',
      displayName: 'Microsoft 365',
      hostHint: 'contoso-com.mail.protection.outlook.com',
      hostPatterns: ['*.mail.protection.outlook.com'],
      port: 25,
      tlsMode: 'verify',
      tlsVerifyNames: 'mail.protection.outlook.com',
      maxServers: 1,
      defaultServers: null,
      documentationUrl: null,
    },
    {
      provider: 'google_workspace',
      displayName: 'Google Workspace',
      hostHint: null,
      hostPatterns: [],
      port: 25,
      tlsMode: 'verify',
      tlsVerifyNames: 'nexthop',
      maxServers: 5,
      defaultServers: [{ host: 'aspmx.l.google.com', priority: 1 }],
      documentationUrl: null,
    },
  ],
};

export function validation(
  overrides: Partial<SuccessBody<'DomainRecipientsController_get_v1'>> = {},
): SuccessBody<'DomainRecipientsController_get_v1'> {
  return {
    domainId: DOMAIN_ID,
    mode: 'accept_all',
    enforcement: 'reject',
    implemented: true,
    addressCount: 0,
    ...overrides,
  };
}

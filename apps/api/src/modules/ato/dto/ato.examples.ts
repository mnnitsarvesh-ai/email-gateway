import type {
  AccountDetailView,
  AccountPage,
  ActivityView,
  AttentionView,
  AuthEventPage,
  CapabilitiesView,
  OverviewView,
  ResponseDetailView,
  ResponsePage,
  RestrictionPage,
  RestrictionView,
  RulesView,
  ScorePage,
  SettingsView,
  SignalPage,
} from './ato.schemas';

/**
 * OpenAPI examples of the account takeover routes (step 8.4 §5.1). Identifiers are well-formed
 * placeholders; addresses use reserved example domains; IP addresses are documentation ranges
 * (RFC 5737); free-form tokens are placeholders containing `EXAMPLE`.
 */
const ID = {
  account: '0193b0a0-1111-7a00-8000-000000000001',
  account2: '0193b0a0-1111-7a00-8000-000000000002',
  incident: '0193b0a0-2222-7a00-8000-000000000001',
  response: '0193b0a0-3333-7a00-8000-000000000001',
  restriction: '0193b0a0-4444-7a00-8000-000000000001',
  context: '0193b0a0-5555-7a00-8000-000000000001',
  override: '0193b0a0-6666-7a00-8000-000000000001',
  user: '0193b0a0-7777-7a00-8000-000000000001',
  user2: '0193b0a0-7777-7a00-8000-000000000002',
  domain: '0193b0a0-8888-7a00-8000-000000000001',
  connector: '0193b0a0-9999-7a00-8000-000000000001',
} as const;
export const ATO_EXAMPLE_IDS = ID;

const capabilities: CapabilitiesView = {
  status: 'known',
  updatedAt: '2026-11-18T10:40:00.000Z',
  geoipCity: 'available',
  geoipAsn: 'available',
  geoipAnonymous: 'unavailable',
  dnsbl: 'unavailable',
  breachIntel: 'unavailable',
  becObservations: 'available',
  providers: [],
};

const restriction: RestrictionView = {
  id: ID.restriction,
  kind: 'send_block',
  scope: 'mailbox',
  connectorId: null,
  connectorName: null,
  mailboxAddress: 'jane.doe@corp.example',
  ipCidr: null,
  mode: 'reject',
  status: 'active',
  reasonCode: 'ato_response',
  responseId: ID.response,
  startsAt: '2026-11-18T10:45:00.000Z',
  expiresAt: '2026-11-18T14:45:00.000Z',
  liftedAt: null,
  liftReason: null,
};

const summary = {
  id: ID.account,
  kind: 'mailbox' as const,
  address: 'jane.doe@corp.example',
  displayName: null,
  domainId: ID.domain,
  status: 'active' as const,
  riskScore: 78,
  riskLevel: 'critical' as const,
  riskUpdatedAt: '2026-11-18T10:42:00.000Z',
  lastSignalAt: '2026-11-18T10:41:58.000Z',
  firstSeenAt: '2026-09-02T08:00:00.000Z',
  lastSeenAt: '2026-11-18T10:41:58.000Z',
  protected: false,
  activeIncident: { id: ID.incident, severity: 'critical' as const, status: 'open' as const },
  override: null,
};

const accountDetail: AccountDetailView = {
  ...summary,
  rowVersion: 3,
  explanation: {
    text: 'Risk 78 (critical): Impossible travel +35; Sign-in from a new ASN +18; Outbound volume spike +25',
    structured: {
      version: 'ato-score/1',
      score: 78,
      level: 'critical',
      top: [
        { code: 'ato.geo.impossible_travel', category: 'geography', contribution: 35 },
        { code: 'ato.access.new_asn', category: 'access_context', contribution: 18 },
        { code: 'ato.outbound.volume_spike', category: 'outbound_behaviour', contribution: 25 },
      ],
    },
  },
  overrideDetail: null,
  protection: { protected: false, reason: null, at: null },
  restrictions: [restriction],
  baseline: {
    version: 'ato-baseline/1',
    mature: true,
    eventCount: 412,
    activeDays: 26,
    windowStart: '2026-10-21T00:00:00.000Z',
    windowEnd: '2026-11-18T00:00:00.000Z',
    rebuiltAt: '2026-11-18T02:00:00.000Z',
    timeZone: 'Asia/Kolkata',
    prefixes: [{ prefix: '198.51.100.0/24', count: 380 }],
    countries: [{ countryCode: 'IN', count: 405 }],
    asns: [{ asn: 64500, count: 401 }],
    devices: [{ deviceHash: '9f2c4a1b7e3d5c60', count: 300 }],
    channels: ['portal', 'smtp'],
    hourHistogram: [
      0, 0, 0, 1, 5, 20, 40, 50, 45, 40, 35, 30, 30, 32, 30, 25, 20, 5, 2, 1, 1, 0, 0, 0,
    ],
    messageHourHistogram: [
      0, 0, 0, 0, 2, 10, 25, 30, 28, 26, 22, 20, 21, 20, 18, 15, 10, 3, 1, 0, 0, 0, 0, 0,
    ],
    volume: {
      medianDailyMessages: 42,
      maxDailyMessages: 120,
      medianDailyRecipients: 60,
      maxHourlyMessages: 30,
    },
  },
  trustedContexts: [
    {
      id: ID.context,
      kind: 'ip_cidr',
      value: '198.51.100.0/24',
      reason: 'Head office egress',
      source: 'analyst',
      incidentId: null,
      createdAt: '2026-11-01T09:00:00.000Z',
      expiresAt: '2027-05-01T09:00:00.000Z',
    },
  ],
  linkedAccounts: [{ id: ID.account2, kind: 'gateway_user', riskLevel: 'low' }],
  identities: [
    {
      provider: 'microsoft_entra',
      userPrincipalName: 'jane.doe@corp.example',
      firstSeenAt: '2026-11-19T10:05:00.000Z',
      lastSeenAt: '2026-11-20T08:31:12.000Z',
      integrationId: '0193b0a0-aaaa-7a00-8000-000000000001',
      directoryStatus: 'active',
    },
  ],
  capabilities,
};

const signal = {
  id: '3f1c2a9b8e7d6c5b4a39',
  ruleCode: 'ato.geo.impossible_travel',
  title: 'Impossible travel',
  category: 'geography' as const,
  strength: 'strong' as const,
  weight: 35,
  status: 'active' as const,
  occurrences: 1,
  detectedAt: '2026-11-18T10:41:58.000Z',
  firstOccurredAt: '2026-11-18T10:41:58.000Z',
  lastOccurredAt: '2026-11-18T10:41:58.000Z',
  explanation: 'Sign-in from DE 6400 km from the previous sign-in in IN 35 minutes earlier',
  evidence: { country: 'DE', previousCountry: 'IN', distanceKm: 6400, minutes: 35 },
  sourceKind: 'auth_event',
  incidentId: ID.incident,
  rulesVersion: 'ato-rules/1',
  dismissedAt: null,
  dismissReason: null,
};

const authEvent = {
  id: '7a6b5c4d3e2f1a0b9c8d',
  occurredAt: '2026-11-18T10:41:55.000Z',
  lastOccurredAt: '2026-11-18T10:41:55.000Z',
  source: 'portal_login' as const,
  channel: 'portal' as const,
  outcome: 'success' as const,
  failureCode: null,
  ipAddress: '203.0.113.45',
  ipPrefix: '203.0.113.0/24',
  geo: {
    status: 'located' as const,
    countryCode: 'DE',
    region: 'Hesse',
    city: 'Frankfurt am Main',
    latitude: 50.1109,
    longitude: 8.6821,
    accuracyKm: 20,
  },
  asn: 64501,
  asnOrg: 'EXAMPLE-HOSTING-AS',
  anonymizerFlags: null,
  reputation: null,
  device: { hash: '1a2b3c4d5e6f7a8b', label: 'Chrome on Windows' },
  mechanism: null,
  attemptCount: 1,
};

const responseView = {
  id: ID.response,
  actionType: 'restrict_smtp_sending' as const,
  provider: 'gateway',
  impact: 'high' as const,
  status: 'succeeded' as const,
  requiresApproval: true,
  authorization: 'manual' as const,
  incidentId: ID.incident,
  account: { id: ID.account, kind: 'mailbox' as const },
  target: { scope: 'mailbox' as const, connectorId: null, cidr: null },
  params: { durationMinutes: 240, mode: 'reject' as const, description: null },
  requestedBy: { type: 'user' as const, id: ID.user },
  requestReason: 'Impossible travel followed by an outbound burst',
  approvedBy: ID.user2,
  decidedAt: '2026-11-18T10:45:00.000Z',
  decisionReason: 'Confirmed with the user by phone',
  approvalExpiresAt: '2026-11-19T10:43:00.000Z',
  executedAt: '2026-11-18T10:45:00.000Z',
  completedAt: '2026-11-18T10:45:00.000Z',
  effectiveUntil: '2026-11-18T14:45:00.000Z',
  providerReference: null,
  providerStatus: 'applied' as const,
  resultCode: 'restriction_applied',
  attemptCount: 1,
  rollbackReason: null,
  canDecide: false,
  canRollback: true,
  createdAt: '2026-11-18T10:43:00.000Z',
  updatedAt: '2026-11-18T10:45:00.000Z',
};

const responseDetail: ResponseDetailView = {
  ...responseView,
  attempts: [
    {
      phase: 'authorize',
      attemptNo: 1,
      outcome: 'pending',
      providerStatus: null,
      errorCode: null,
      durationMs: 0,
      at: '2026-11-18T10:43:00.000Z',
    },
    {
      phase: 'execute',
      attemptNo: 1,
      outcome: 'succeeded',
      providerStatus: 'applied',
      errorCode: null,
      durationMs: 4,
      at: '2026-11-18T10:45:00.000Z',
    },
  ],
  restriction,
};

const zeroSeverity = { low: 0, medium: 0, high: 0, critical: 0 };

const overview: OverviewView = {
  generatedAt: '2026-11-18T11:00:00.000Z',
  range: '7d',
  from: '2026-11-11T11:00:00.000Z',
  to: '2026-11-18T11:00:00.000Z',
  monitoring: {
    featureEnabled: true,
    mode: 'monitor',
    learning: false,
    learningEndsAt: '2026-11-15T09:00:00.000Z',
  },
  accounts: {
    monitored: 1250,
    byKind: { mailbox: 1180, gateway_user: 60, smtp_connector: 10 },
    highRisk: 4,
    criticalRisk: 1,
  },
  incidents: {
    active: 3,
    activeBySeverity: { low: 0, medium: 1, high: 1, critical: 1 },
    critical: 1,
    openedInRange: 5,
    trend: [
      { bucketStart: '2026-11-17T00:00:00.000Z', ...zeroSeverity, high: 1 },
      { bucketStart: '2026-11-18T00:00:00.000Z', ...zeroSeverity, critical: 1 },
    ],
    resolvedInRange: { remediated: 1, falsePositive: 1, other: 0 },
  },
  logins: { failedInRange: 320, suspiciousInRange: 12 },
  outbound: { suspiciousInRange: 7, restrictedAccounts: 1, policyHeldInRange: 3 },
  geography: {
    available: true,
    reason: null,
    topCountries: [{ countryCode: 'IN', successfulAuth: 5400, newCountrySignals: 0 }],
    impossibleTravelInRange: 1,
  },
  responses: { pendingApproval: 1, executedInRange: 4, failedInRange: 0 },
  attention: { criticalIncidents: 1, pendingApprovals: 1 },
};

const attention: AttentionView = { criticalIncidents: 1, pendingApprovals: 1 };

const accountPage: AccountPage = { data: [summary], nextCursor: 'EXAMPLE-CURSOR' };
const signalPage: SignalPage = { data: [signal], nextCursor: null };
const authEventPage: AuthEventPage = { data: [authEvent], nextCursor: 'EXAMPLE-CURSOR' };
const scorePage: ScorePage = {
  data: [
    {
      id: '0f1e2d3c4b5a69788796',
      computedAt: '2026-11-18T10:42:00.000Z',
      score: 78,
      level: 'critical',
      previousScore: 22,
      previousLevel: 'low',
      trigger: 'signal',
      explanation: { version: 'ato-score/1', score: 78, level: 'critical' },
      scorerVersion: 'ato-score/1',
      rulesVersion: 'ato-rules/1',
      settingsVersion: 2,
    },
  ],
  nextCursor: null,
};
const activity: ActivityView = {
  account: ID.account,
  from: '2026-10-19T00:00:00.000Z',
  to: '2026-11-18T00:00:00.000Z',
  days: [
    {
      day: '2026-11-17T00:00:00.000Z',
      authSuccess: 6,
      authFailure: 0,
      messages: 48,
      recipients: 70,
      externalRecipients: 30,
      internalRecipients: 40,
      attachments: 5,
      findings: 0,
      maxHourMessages: 12,
      topRecipientDomains: [{ domain: 'partner.example', count: 18 }],
      content: { phishing: 0, spam: 0 },
    },
  ],
};
const responsePage: ResponsePage = { data: [responseView], nextCursor: null };
const restrictionPage: RestrictionPage = { data: [restriction], nextCursor: null };

const settings: SettingsView = {
  featureEnabled: true,
  version: 2,
  rowVersion: 2,
  schemaVersion: 'ato-settings/1',
  stored: { mode: 'monitor', notifications: { incidentMinSeverity: 'high' } },
  effective: {
    mode: 'monitor',
    learningDays: 14,
    scoring: { bands: { medium: 30, high: 50, critical: 75 } },
  },
  storedInvalid: false,
  learning: {
    active: false,
    startedAt: '2026-11-01T09:00:00.000Z',
    endsAt: '2026-11-15T09:00:00.000Z',
  },
  bounds: { learningDays: { min: 0, max: 60 } },
  capabilities,
  sources: [
    { source: 'portal_login', lastEventAt: '2026-11-18T10:41:55.000Z' },
    { source: 'account_change', lastEventAt: null },
    { source: 'smtp_auth', lastEventAt: '2026-11-18T10:30:00.000Z' },
    { source: 'smtp_submission', lastEventAt: '2026-11-18T10:30:02.000Z' },
    { source: 'outbound_message', lastEventAt: '2026-11-18T10:40:00.000Z' },
  ],
  identityProviders: [
    {
      provider: 'microsoft_entra',
      integrations: [
        {
          id: '0193b0a0-aaaa-7a00-8000-000000000001',
          provider: 'microsoft_entra',
          health: 'healthy',
        },
      ],
    },
    { provider: 'google_workspace', integrations: [] },
  ],
  policy: { atoFieldsInUse: false },
  automation: {
    platformEnabled: true,
    platformMaxPerHour: 10,
    approvalTtlHours: 24,
    maxActiveRestrictions: 500,
  },
  updatedAt: '2026-11-10T09:00:00.000Z',
};

const rules: RulesView = {
  rulesVersion: 'ato-rules/1',
  capabilities,
  data: [
    {
      id: 'G2',
      code: 'ato.geo.impossible_travel',
      title: 'Impossible travel',
      category: 'geography',
      strength: 'strong',
      kinds: ['mailbox', 'gateway_user', 'smtp_connector'],
      sources: ['portal_login', 'portal_mfa', 'smtp_auth', 'idp_sign_in'],
      correlation: false,
      baselineRelative: false,
      defaultWeight: 35,
      effective: { enabled: true, weight: 35, params: {} },
      params: [],
      capabilities: ['geoip_city'],
      availability: { available: true, reason: null, missing: [] },
      explanation: 'Sign-in from {country} {distanceKm} km from the previous sign-in',
    },
  ],
};

export const ATO_EXAMPLES = {
  overview,
  attention,
  accountPage,
  accountDetail,
  signalPage,
  authEventPage,
  activity,
  scorePage,
  trustedContext: accountDetail.trustedContexts[0]!,
  responseDetail,
  responsePage,
  restrictionPage,
  settings,
  rules,
  updateAccount: {
    protected: true,
    reason: 'Shared finance mailbox; act manually only',
    expectedRowVersion: 3,
  },
  setOverride: {
    verdict: 'benign' as const,
    reason: 'User confirmed the trip to Frankfurt by phone',
    expiresInHours: 72,
  },
  clearOverride: { reason: 'Trip ended; return to normal scoring' },
  addTrustedContext: {
    kind: 'ip_cidr' as const,
    value: '198.51.100.0/24',
    reason: 'Head office egress',
    expiresInDays: 180,
  },
  requestResponse: {
    actionType: 'restrict_smtp_sending' as const,
    durationMinutes: 240,
    mode: 'reject' as const,
    reason: 'Impossible travel followed by an outbound burst',
  },
  approve: { reason: 'Confirmed with the user by phone' },
  reject: { reason: 'Travel confirmed; not a compromise' },
  cancel: { reason: 'Requested in error' },
  rollback: { reason: 'Password reset completed; lift the restriction' },
  updateSettings: {
    expectedRowVersion: 2,
    settings: {
      mode: 'monitor',
      notifications: { incidentMinSeverity: 'high', socEmails: ['soc@corp.example'] },
    },
  },
} as const;

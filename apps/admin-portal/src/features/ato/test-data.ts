import type { ListItem, SuccessBody } from '@/lib/api/types';

/** Test builders of the account takeover and incident pages (typed against schema.gen.ts). */

export const ACCOUNT_ID = '01933c3a-1b2c-7d4e-8f00-0000000a7001';
export const CONNECTOR_ACCOUNT_ID = '01933c3a-1b2c-7d4e-8f00-0000000a7002';
export const INCIDENT_ID = '01933c3a-1b2c-7d4e-8f00-0000000a7101';
export const RESPONSE_ID = '01933c3a-1b2c-7d4e-8f00-0000000a7201';
export const RESTRICTION_ID = '01933c3a-1b2c-7d4e-8f00-0000000a7301';
export const CONTEXT_ID = '01933c3a-1b2c-7d4e-8f00-0000000a7401';
export const MESSAGE_ID = '01933c3a-1b2c-7d4e-8f00-0000000a7501';
export const OTHER_USER_ID = '01933c3a-1b2c-7d4e-8f00-0000000a7601';
/** `makeMe().user.id` of the test kit. */
export const ME_ID = '01930000-0000-7000-8000-000000000101';

type Overview = SuccessBody<'AtoOverviewController_overview_v1'>;
type Account = ListItem<'AtoAccountsController_list_v1'>;
type Detail = SuccessBody<'AtoAccountsController_get_v1'>;
type Signal = ListItem<'AtoAccountsController_signals_v1'>;
type AuthEvent = ListItem<'AtoAccountsController_authEvents_v1'>;
type Response = SuccessBody<'AtoResponsesController_get_v1'>;
type Restriction = ListItem<'AtoRestrictionsController_list_v1'>;
type Settings = SuccessBody<'AtoSettingsController_get_v1'>;
type Rules = SuccessBody<'AtoRulesController_list_v1'>;
type Incident = SuccessBody<'IncidentsController_get_v1'>;
type IncidentSummary = ListItem<'IncidentsController_list_v1'>;

const T = '2026-11-18T09:00:00.000Z';

export const CAPABILITIES: Detail['capabilities'] = {
  status: 'known',
  updatedAt: T,
  geoipCity: 'unavailable',
  geoipAsn: 'unavailable',
  geoipAnonymous: 'unavailable',
  dnsbl: 'available',
  breachIntel: 'unavailable',
  becObservations: 'available',
  providers: [],
};

export function overview(overrides: Partial<Overview> = {}): Overview {
  return {
    generatedAt: T,
    range: '7d',
    from: '2026-11-11T09:00:00.000Z',
    to: T,
    monitoring: { featureEnabled: true, mode: 'monitor', learning: false, learningEndsAt: null },
    accounts: {
      monitored: 12,
      byKind: { mailbox: 9, gateway_user: 2, smtp_connector: 1 },
      highRisk: 2,
      criticalRisk: 1,
    },
    incidents: {
      active: 2,
      activeBySeverity: { low: 0, medium: 0, high: 1, critical: 1 },
      critical: 1,
      openedInRange: 3,
      trend: [
        { bucketStart: '2026-11-17T00:00:00.000Z', low: 0, medium: 1, high: 0, critical: 0 },
        { bucketStart: '2026-11-18T00:00:00.000Z', low: 0, medium: 0, high: 1, critical: 1 },
      ],
      resolvedInRange: { remediated: 0, falsePositive: 1, other: 0 },
    },
    logins: { failedInRange: 17, suspiciousInRange: 4 },
    outbound: { suspiciousInRange: 3, restrictedAccounts: 1, policyHeldInRange: 5 },
    geography: {
      available: false,
      reason: 'geoip_unavailable',
      topCountries: [],
      impossibleTravelInRange: 0,
    },
    responses: { pendingApproval: 2, executedInRange: 6, failedInRange: 0 },
    attention: { criticalIncidents: 1, pendingApprovals: 2 },
    ...overrides,
  };
}

export function account(overrides: Partial<Account> = {}): Account {
  return {
    id: ACCOUNT_ID,
    kind: 'mailbox',
    address: 'finance@alpha.example.test',
    displayName: null,
    domainId: null,
    status: 'active',
    riskScore: 90,
    riskLevel: 'critical',
    riskUpdatedAt: T,
    lastSignalAt: T,
    firstSeenAt: '2026-09-01T00:00:00.000Z',
    lastSeenAt: T,
    protected: false,
    activeIncident: { id: INCIDENT_ID, severity: 'critical', status: 'open' },
    override: null,
    ...overrides,
  };
}

export function accountDetail(overrides: Partial<Detail> = {}): Detail {
  return {
    ...account(),
    rowVersion: 3,
    explanation: {
      text: 'Phishing sent from the account +45, Outbound volume spike +25',
      structured: {
        version: 'ato-score/1',
        top: [
          {
            code: 'ato.content.phishing_sent',
            category: 'outbound_content',
            strength: 'strong',
            weight: 45,
            multiplierPermille: 1000,
            decayPermille: 1000,
            contribution: 45,
          },
          {
            code: 'ato.outbound.volume_spike',
            category: 'outbound_behaviour',
            strength: 'moderate',
            weight: 25,
            multiplierPermille: 1000,
            decayPermille: 1000,
            contribution: 25,
          },
        ],
      },
    },
    overrideDetail: null,
    protection: { protected: false, reason: null, at: null },
    restrictions: [],
    baseline: {
      version: 'ato-baseline/1',
      mature: true,
      eventCount: 300,
      activeDays: 20,
      windowStart: '2026-10-20T00:00:00.000Z',
      windowEnd: '2026-11-17T00:00:00.000Z',
      rebuiltAt: T,
      timeZone: 'UTC',
      prefixes: [{ prefix: '198.51.100.0/24', count: 280 }],
      countries: [],
      asns: [],
      devices: [{ deviceHash: 'd3v1c3example', count: 250 }],
      channels: ['portal'],
      hourHistogram: Array.from({ length: 24 }, () => 2),
      messageHourHistogram: Array.from({ length: 24 }, () => 1),
      volume: {
        medianDailyMessages: 40,
        maxDailyMessages: 90,
        medianDailyRecipients: 60,
        maxHourlyMessages: 15,
      },
    },
    trustedContexts: [
      {
        id: CONTEXT_ID,
        kind: 'ip_cidr',
        value: '198.51.100.0/24',
        reason: 'Head office',
        source: 'analyst',
        incidentId: null,
        createdAt: T,
        expiresAt: '2027-01-01T00:00:00.000Z',
      },
    ],
    linkedAccounts: [],
    identities: [],
    capabilities: CAPABILITIES,
    ...overrides,
  };
}

export function signal(overrides: Partial<Signal> = {}): Signal {
  return {
    id: 'a1b2c3d4e5f6a7b8c9d0',
    ruleCode: 'ato.content.phishing_sent',
    title: 'Phishing sent from the account',
    category: 'outbound_content',
    strength: 'strong',
    weight: 45,
    status: 'active',
    occurrences: 2,
    detectedAt: T,
    firstOccurredAt: T,
    lastOccurredAt: T,
    explanation: 'An outbound message carried phishing indicators (url.phishing_high_confidence)',
    evidence: {},
    sourceKind: 'message',
    incidentId: INCIDENT_ID,
    rulesVersion: 'ato-rules/1',
    dismissedAt: null,
    dismissReason: null,
    ...overrides,
  };
}

export function authEvent(overrides: Partial<AuthEvent> = {}): AuthEvent {
  return {
    id: 'b1b2c3d4e5f6a7b8c9d0',
    occurredAt: T,
    lastOccurredAt: T,
    source: 'portal_login',
    channel: 'portal',
    outcome: 'failure',
    failureCode: 'bad_credentials',
    ipAddress: '203.0.113.77',
    ipPrefix: '203.0.113.0/24',
    geo: {
      status: 'unavailable',
      countryCode: null,
      region: null,
      city: null,
      latitude: null,
      longitude: null,
      accuracyKm: null,
    },
    asn: null,
    asnOrg: null,
    anonymizerFlags: null,
    reputation: null,
    device: { hash: 'd3v1c3example', label: 'Firefox on Linux' },
    mechanism: null,
    attemptCount: 1,
    ...overrides,
  };
}

export function response(overrides: Partial<Response> = {}): Response {
  return {
    id: RESPONSE_ID,
    actionType: 'restrict_smtp_sending',
    provider: 'gateway',
    impact: 'high',
    status: 'pending_approval',
    requiresApproval: true,
    authorization: 'manual',
    incidentId: INCIDENT_ID,
    account: { id: ACCOUNT_ID, kind: 'mailbox' },
    target: { scope: 'mailbox', connectorId: null, cidr: null },
    params: { durationMinutes: 240, mode: 'reject', description: null },
    requestedBy: { type: 'user', id: OTHER_USER_ID },
    requestReason: 'Stop the phishing run',
    approvedBy: null,
    decidedAt: null,
    decisionReason: null,
    approvalExpiresAt: '2026-11-19T09:00:00.000Z',
    executedAt: null,
    completedAt: null,
    effectiveUntil: null,
    providerReference: null,
    providerStatus: null,
    resultCode: null,
    attemptCount: 0,
    rollbackReason: null,
    canDecide: true,
    canRollback: false,
    createdAt: T,
    updatedAt: T,
    attempts: [],
    restriction: null,
    ...overrides,
  };
}

export function summaryOf(r: Response): ListItem<'AtoResponsesController_list_v1'> {
  const { attempts: _a, restriction: _r, ...rest } = r;
  return rest;
}

export function restriction(overrides: Partial<Restriction> = {}): Restriction {
  return {
    id: RESTRICTION_ID,
    kind: 'send_block',
    scope: 'mailbox',
    connectorId: null,
    connectorName: null,
    mailboxAddress: 'finance@alpha.example.test',
    ipCidr: null,
    mode: 'reject',
    status: 'active',
    reasonCode: 'restrict_smtp_sending',
    responseId: RESPONSE_ID,
    startsAt: T,
    expiresAt: '2026-11-18T13:00:00.000Z',
    liftedAt: null,
    liftReason: null,
    ...overrides,
  };
}

export function settings(overrides: Partial<Settings> = {}): Settings {
  return {
    featureEnabled: true,
    version: 2,
    rowVersion: 2,
    schemaVersion: 'ato-settings/1',
    stored: { mode: 'monitor', scoring: { bands: { medium: 30 } } },
    effective: {
      mode: 'monitor',
      learningDays: 14,
      scoring: {
        bands: { medium: 30, high: 50, critical: 75 },
        incidentThreshold: 50,
        weakOnlyCap: 45,
        strongFloor: 60,
        incidentReopenCooldownMinutes: 60,
        categoryMultipliers: {},
        halfLifeMinutes: {},
      },
      ipReputation: {
        useLocalFeed: true,
        useDnsbl: true,
        trustedNetworks: [],
        blockedNetworks: [],
      },
      notifications: {
        incidentMinSeverity: 'high',
        throttleMinutes: 15,
        digest: { daily: true, weekly: true, hourLocal: 8 },
        socEmails: [],
        includeOrganizationContact: true,
      },
      automation: {
        maxAutomaticPerHour: 10,
        restrict_smtp_sending: { mode: 'recommend', minLevel: 'critical', durationMinutes: 240 },
      },
      restrictions: { defaultMode: 'reject', defaultDurationMinutes: 240 },
    },
    storedInvalid: false,
    learning: { active: false, startedAt: null, endsAt: null },
    bounds: {
      band: { min: 10, max: 95 },
      learningDays: { min: 0, max: 60 },
      durationMinutes: { min: 15, max: 10080 },
    },
    capabilities: CAPABILITIES,
    sources: [{ source: 'portal_login', lastEventAt: T }],
    identityProviders: [
      { provider: 'microsoft_entra', integrations: [] },
      { provider: 'google_workspace', integrations: [] },
    ],
    policy: { atoFieldsInUse: false },
    automation: {
      platformEnabled: true,
      platformMaxPerHour: 10,
      approvalTtlHours: 24,
      maxActiveRestrictions: 500,
    },
    updatedAt: T,
    ...overrides,
  };
}

export const RULES: Rules = {
  rulesVersion: 'ato-rules/1',
  capabilities: CAPABILITIES,
  data: [
    {
      id: 'A1',
      code: 'ato.auth.bruteforce',
      title: 'Repeated failed sign-ins',
      category: 'authentication',
      strength: 'moderate',
      kinds: ['mailbox'],
      sources: ['portal_login'],
      correlation: false,
      baselineRelative: false,
      defaultWeight: 20,
      effective: { enabled: true, weight: 20, params: { failures: 10 } },
      params: [{ name: 'failures', default: 10, min: 3, max: 1000 }],
      capabilities: [],
      availability: { available: true, reason: null, missing: [] },
      explanation: '{failures} failed sign-ins',
    },
    {
      id: 'G2',
      code: 'ato.geo.impossible_travel',
      title: 'Impossible travel',
      category: 'geography',
      strength: 'moderate',
      kinds: ['mailbox'],
      sources: ['portal_login'],
      correlation: false,
      baselineRelative: false,
      defaultWeight: 30,
      effective: { enabled: true, weight: 30, params: {} },
      params: [],
      capabilities: ['geoip_city'],
      availability: { available: false, reason: 'capability_unavailable', missing: ['geoip_city'] },
      explanation: 'Impossible travel',
    },
    {
      id: 'P1',
      code: 'ato.content.phishing_sent',
      title: 'Phishing sent from the account',
      category: 'outbound_content',
      strength: 'strong',
      kinds: ['mailbox'],
      sources: ['outbound_message'],
      correlation: false,
      baselineRelative: false,
      defaultWeight: 45,
      effective: { enabled: true, weight: 45, params: {} },
      params: [],
      capabilities: [],
      availability: { available: true, reason: null, missing: [] },
      explanation: 'Phishing',
    },
  ],
};

export function incident(overrides: Partial<Incident> = {}): Incident {
  return {
    id: INCIDENT_ID,
    category: 'account_takeover',
    subject: { type: 'ato_account', id: ACCOUNT_ID, display: 'finance@alpha.example.test' },
    origin: 'detection',
    status: 'open',
    severity: 'critical',
    titleCode: 'ato.content.phishing_sent',
    reasonCodes: ['ato.content.phishing_sent', 'ato.outbound.volume_spike'],
    detectedAt: T,
    lastEvidenceAt: T,
    evidenceCount: 3,
    assigneeId: null,
    escalatedAt: null,
    resolvedAt: null,
    resolutionCode: null,
    createdAt: T,
    updatedAt: T,
    rowVersion: 4,
    detectorVersion: 'ato-rules/1',
    firstEvidenceAt: T,
    assignedAt: null,
    confirmedAt: null,
    mitigatedAt: null,
    resolution: null,
    createdBy: { type: 'system', id: null },
    canManage: true,
    allowedTransitions: [
      { to: 'investigating', resolutionCodes: [], noteRequired: false },
      { to: 'confirmed', resolutionCodes: [], noteRequired: true },
      {
        to: 'false_positive',
        resolutionCodes: ['false_positive', 'benign_activity', 'duplicate'],
        noteRequired: true,
      },
      {
        to: 'resolved',
        resolutionCodes: ['remediated', 'benign_activity', 'duplicate', 'other'],
        noteRequired: true,
      },
    ],
    evidence: { ato_signal: 2, message: 1 },
    detail: {
      account: {
        id: ACCOUNT_ID,
        kind: 'mailbox',
        address: 'finance@alpha.example.test',
        userId: null,
        connectorId: null,
        riskScore: 90,
        riskLevel: 'critical',
        protected: false,
      },
      riskScoreAtOpen: 70,
      peakRiskScore: 90,
      detectionReason: {
        codes: ['ato.content.phishing_sent'],
        versions: { rules: 'ato-rules/1', scorer: 'ato-score/1', settings: 2 },
      },
      detectionReasonText: ['Phishing sent from the account +45', 'Outbound volume spike +25'],
      recommendedActions: [
        {
          actionType: 'restrict_smtp_sending',
          availability: 'available',
          impact: 'high',
          target: { scope: 'mailbox' },
          reason: 'ato.content.phishing_sent',
        },
        {
          actionType: 'revoke_sessions',
          availability: 'requires_provider',
          impact: 'medium',
          target: null,
          reason: 'ato.content.phishing_sent',
        },
        {
          actionType: 'policy_hold_outbound',
          availability: 'policy',
          impact: null,
          target: null,
          reason: 'ato.content.phishing_sent',
          preset: 'outbound_high_risk_account',
        },
      ],
      relatedIps: [
        { ip: '203.0.113.77', country: null, asn: null, reputation: 'malicious', count: 12 },
      ],
      geoSummary: null,
      deviceSummary: { devices: ['Firefox on Linux'] },
      counts: { signals: 2, authEvents: 1, messages: 1, findings: 1 },
      responses: { total: 1, pendingApproval: 1 },
    },
    ...overrides,
  };
}

export function incidentSummary(overrides: Partial<IncidentSummary> = {}): IncidentSummary {
  const {
    rowVersion: _rv,
    detectorVersion: _dv,
    firstEvidenceAt: _f,
    assignedAt: _a,
    confirmedAt: _c,
    mitigatedAt: _m,
    resolution: _r,
    createdBy: _cb,
    canManage: _cm,
    allowedTransitions: _t,
    evidence: _e,
    detail: _d,
    ...summary
  } = incident();
  return { ...summary, ...overrides };
}

export const page = <T>(data: T[], nextCursor: string | null = null) => ({ data, nextCursor });

/** A `GET /auth/me` override with an MFA-authenticated session. */
export const MFA_SESSION = {
  session: { id: '01930000-0000-7000-8000-000000000501', mfaAuthenticated: true },
};

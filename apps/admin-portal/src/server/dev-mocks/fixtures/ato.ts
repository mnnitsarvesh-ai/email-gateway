import 'server-only';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { fixtureAnchor, paginate, stableUuid } from '../generator';
import {
  apiError,
  noContent,
  ok,
  type FixtureHandler,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { fixtureGuard } from './messages';
import { resolveFixturePrincipal } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the account takeover pages (step 8.4 §6, §5.1): all 26 `ato` operations over an
 * in-memory state per organization on globalThis (shared with `incidents.ts`, which serves the 8
 * generic incident operations). The rules the pages rely on are kept: permissions, users-only and
 * MFA routes (`403 mfa_required`), four eyes (`403 ato_approval_self`), CAS on account protection
 * and settings (`409`), required Idempotency-Key with replays, one active response per type
 * (`409 ato_response_active`), restrictions applied on approval and lifted on roll-back. Every
 * address is a reserved example name, every IP a documentation range; nothing is real.
 */

export const ATO_OPERATIONS = [
  'AtoOverviewController_overview_v1',
  'AtoOverviewController_attention_v1',
  'AtoAccountsController_list_v1',
  'AtoAccountsController_get_v1',
  'AtoAccountsController_update_v1',
  'AtoAccountsController_signals_v1',
  'AtoAccountsController_authEvents_v1',
  'AtoAccountsController_activity_v1',
  'AtoAccountsController_scoreHistory_v1',
  'AtoAccountsController_setOverride_v1',
  'AtoAccountsController_clearOverride_v1',
  'AtoAccountsController_addTrustedContext_v1',
  'AtoAccountsController_removeTrustedContext_v1',
  'AtoIncidentEvidenceController_signals_v1',
  'AtoIncidentEvidenceController_authEvents_v1',
  'AtoResponsesController_request_v1',
  'AtoResponsesController_list_v1',
  'AtoResponsesController_get_v1',
  'AtoResponsesController_approve_v1',
  'AtoResponsesController_reject_v1',
  'AtoResponsesController_cancel_v1',
  'AtoResponsesController_rollback_v1',
  'AtoRestrictionsController_list_v1',
  'AtoSettingsController_get_v1',
  'AtoSettingsController_update_v1',
  'AtoRulesController_list_v1',
] as const;

export type AccountDetail = SuccessBody<'AtoAccountsController_get_v1'>;
export type Signal = ListItem<'AtoAccountsController_signals_v1'>;
export type AuthEvent = ListItem<'AtoAccountsController_authEvents_v1'>;
export type ScorePoint = ListItem<'AtoAccountsController_scoreHistory_v1'>;
export type ActivityDay = SuccessBody<'AtoAccountsController_activity_v1'>['days'][number];
export type Response = SuccessBody<'AtoResponsesController_get_v1'>;
export type Restriction = ListItem<'AtoRestrictionsController_list_v1'>;
export type Settings = SuccessBody<'AtoSettingsController_get_v1'>;
export type Rule = SuccessBody<'AtoRulesController_list_v1'>['data'][number];
export type IncidentDetail = SuccessBody<'IncidentsController_get_v1'>;
export type TimelineEntry = ListItem<'IncidentsController_timeline_v1'>;
export type IncidentMessage = ListItem<'IncidentsController_messages_v1'>;

export interface IncidentRecord {
  incident: IncidentDetail;
  timeline: TimelineEntry[];
  messages: IncidentMessage[];
  signalIds: string[];
  authEventIds: string[];
}

export interface OrgAto {
  accounts: Map<string, AccountDetail>;
  signals: Map<string, Signal[]>;
  authEvents: Map<string, AuthEvent[]>;
  scores: Map<string, ScorePoint[]>;
  activity: Map<string, ActivityDay[]>;
  incidents: Map<string, IncidentRecord>;
  responses: Map<string, Response & { requesterUserId: string | null }>;
  restrictions: Map<string, Restriction>;
  settings: Settings;
  idempotency: Map<string, { fingerprint: string; response: FixtureResponse }>;
}

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const iso = (ms: number) => new Date(ms).toISOString();

const CAPABILITIES: AccountDetail['capabilities'] = {
  status: 'known',
  updatedAt: iso(fixtureAnchor() - 2 * MIN),
  // Dev mode mirrors a deployment without operator GeoIP data (PO2): geography is unavailable.
  geoipCity: 'unavailable',
  geoipAsn: 'unavailable',
  geoipAnonymous: 'unavailable',
  dnsbl: 'available',
  breachIntel: 'unavailable',
  becObservations: 'available',
  providers: [],
};

export const RULES: Rule[] = [
  rule('A1', 'ato.auth.bruteforce', 'Repeated failed sign-ins', 'authentication', 'moderate', 20, [
    { name: 'failures', default: 10, min: 3, max: 1000 },
    { name: 'windowMinutes', default: 15, min: 5, max: 60 },
  ]),
  rule(
    'A2',
    'ato.auth.success_after_failures',
    'Successful sign-in after failures',
    'authentication',
    'moderate',
    30,
    [{ name: 'failures', default: 5, min: 2, max: 1000 }],
  ),
  rule(
    'C1',
    'ato.access.new_ip_prefix',
    'Sign-in from a new network',
    'access_context',
    'weak',
    8,
    [],
  ),
  rule(
    'C3',
    'ato.access.new_device',
    'Sign-in from a new device',
    'access_context',
    'weak',
    10,
    [],
  ),
  rule(
    'G1',
    'ato.geo.new_country',
    'Sign-in from a new country',
    'geography',
    'weak',
    12,
    [],
    ['geoip_city'],
  ),
  rule(
    'G2',
    'ato.geo.impossible_travel',
    'Impossible travel',
    'geography',
    'moderate',
    30,
    [],
    ['geoip_city'],
  ),
  rule(
    'T1',
    'ato.ti.malicious_ip_success',
    'Successful sign-in from a known malicious address',
    'threat_intel',
    'strong',
    45,
    [],
  ),
  rule(
    'K1',
    'ato.account.refresh_token_reuse',
    'Refresh token reused',
    'account_change',
    'strong',
    50,
    [],
  ),
  rule(
    'O1',
    'ato.outbound.volume_spike',
    'Outbound volume spike',
    'outbound_behaviour',
    'moderate',
    25,
    [{ name: 'immaturePerHour', default: 200, min: 10, max: 100000 }],
  ),
  rule(
    'P1',
    'ato.content.phishing_sent',
    'Phishing sent from the account',
    'outbound_content',
    'strong',
    45,
    [],
  ),
  rule(
    'M1',
    'ato.mailbox.external_forwarding',
    'External forwarding added',
    'mailbox_configuration',
    'strong',
    45,
    [],
    ['provider:mailbox_audit'],
  ),
  rule(
    'X1',
    'ato.correlation.login_then_outbound',
    'Suspicious sign-in followed by abnormal sending',
    'correlation',
    'strong',
    40,
    [],
  ),
];

function rule(
  id: string,
  code: string,
  title: string,
  category: Rule['category'],
  strength: Rule['strength'],
  weight: number,
  params: Rule['params'],
  capabilities: string[] = [],
): Rule {
  const missing = capabilities.filter((c) => c.startsWith('provider') || c === 'geoip_city');
  return {
    id,
    code,
    title,
    category,
    strength,
    kinds: ['mailbox', 'gateway_user', 'smtp_connector'],
    sources: [],
    correlation: category === 'correlation',
    baselineRelative: strength === 'weak',
    defaultWeight: weight,
    effective: {
      enabled: true,
      weight,
      params: Object.fromEntries(params.map((p) => [p.name, p.default])),
    },
    params,
    capabilities,
    availability: {
      available: missing.length === 0,
      reason: missing.length === 0 ? null : 'capability_unavailable',
      missing,
    },
    explanation: `${title} (example explanation)`,
  };
}

export const ruleTitle = (code: string) => RULES.find((r) => r.code === code)?.title ?? code;

function baseSettings(): Settings {
  return {
    featureEnabled: true,
    version: 0,
    rowVersion: 0,
    schemaVersion: 'ato-settings/1',
    stored: {},
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
      baselines: { windowDays: 28, minActiveDays: 7, minEvents: 30, volumeK: 6 },
      geo: { impossibleTravelKmh: 900, minDistanceKm: 500, maxAccuracyRadiusKm: 500 },
      notifications: {
        incidentMinSeverity: 'high',
        throttleMinutes: 15,
        digest: { daily: true, weekly: true, hourLocal: 8 },
        socEmails: [],
        includeOrganizationContact: true,
      },
      automation: { maxAutomaticPerHour: 10 },
      restrictions: { defaultMode: 'reject', defaultDurationMinutes: 240 },
    },
    storedInvalid: false,
    learning: {
      active: false,
      startedAt: iso(fixtureAnchor() - 40 * DAY),
      endsAt: iso(fixtureAnchor() - 26 * DAY),
    },
    bounds: {
      learningDays: { min: 0, max: 60 },
      band: { min: 10, max: 95 },
      incidentThreshold: { min: 30, max: 90 },
      weakOnlyCap: { min: 20, max: 89 },
      strongFloor: { min: 40, max: 95 },
      incidentReopenCooldownMinutes: { min: 0, max: 10080 },
      categoryMultiplierPermille: { min: 500, max: 2000 },
      halfLifeMinutes: { min: 60, max: 43200 },
      ruleWeight: { min: 0, max: 100 },
      windowDays: { min: 7, max: 90 },
      minActiveDays: { min: 1, max: 30 },
      minEvents: { min: 1, max: 10000 },
      volumeK: { min: 2, max: 20 },
      impossibleTravelKmh: { min: 300, max: 2000 },
      minDistanceKm: { min: 100, max: 5000 },
      maxAccuracyRadiusKm: { min: 10, max: 1000 },
      throttleMinutes: { min: 1, max: 1440 },
      digestHourLocal: { min: 0, max: 23 },
      maxAutomaticPerHour: { min: 0, max: 100 },
      durationMinutes: { min: 15, max: 10080 },
    },
    capabilities: CAPABILITIES,
    sources: [
      { source: 'portal_login', lastEventAt: iso(fixtureAnchor() - 5 * MIN) },
      { source: 'account_change', lastEventAt: iso(fixtureAnchor() - 3 * HOUR) },
      { source: 'smtp_auth', lastEventAt: iso(fixtureAnchor() - 2 * MIN) },
      { source: 'smtp_submission', lastEventAt: iso(fixtureAnchor() - 2 * MIN) },
      { source: 'outbound_message', lastEventAt: iso(fixtureAnchor() - MIN) },
    ],
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
    updatedAt: null,
  };
}

const LEVEL = (score: number): AccountDetail['riskLevel'] =>
  score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 30 ? 'medium' : 'low';

interface Seed {
  key: string;
  kind: AccountDetail['kind'];
  address: string | null;
  displayName: string | null;
  score: number;
  signals: Array<{ code: string; minutesAgo: number; weight: number; status?: Signal['status'] }>;
}

const SEEDS: Seed[] = [
  {
    key: 'finance',
    kind: 'mailbox',
    address: 'finance@alpha.example.test',
    displayName: null,
    score: 90,
    signals: [
      { code: 'ato.content.phishing_sent', minutesAgo: 40, weight: 45 },
      { code: 'ato.outbound.volume_spike', minutesAgo: 55, weight: 25 },
      { code: 'ato.correlation.login_then_outbound', minutesAgo: 35, weight: 40 },
    ],
  },
  {
    key: 'relay',
    kind: 'smtp_connector',
    address: null,
    displayName: 'Branch office relay',
    score: 65,
    signals: [
      { code: 'ato.auth.success_after_failures', minutesAgo: 120, weight: 30 },
      { code: 'ato.ti.malicious_ip_success', minutesAgo: 118, weight: 45 },
    ],
  },
  {
    key: 'admin',
    kind: 'gateway_user',
    address: 'it.admin@alpha.example.test',
    displayName: 'IT Admin',
    score: 42,
    signals: [
      { code: 'ato.auth.bruteforce', minutesAgo: 600, weight: 20 },
      { code: 'ato.access.new_device', minutesAgo: 580, weight: 10 },
    ],
  },
  {
    key: 'sales',
    kind: 'mailbox',
    address: 'sales@alpha.example.test',
    displayName: null,
    score: 18,
    signals: [{ code: 'ato.access.new_ip_prefix', minutesAgo: 1500, weight: 8 }],
  },
  ...Array.from({ length: 8 }, (_, i) => ({
    key: `user${i}`,
    kind: 'mailbox' as const,
    address: `user${i + 1}@alpha.example.test`,
    displayName: null,
    score: (i * 3) % 12,
    signals: [],
  })),
];

function buildOrg(organizationId: string): OrgAto {
  const anchor = fixtureAnchor();
  const id = (name: string) => stableUuid(`ato:${organizationId}:${name}`);
  const org: OrgAto = {
    accounts: new Map(),
    signals: new Map(),
    authEvents: new Map(),
    scores: new Map(),
    activity: new Map(),
    incidents: new Map(),
    responses: new Map(),
    restrictions: new Map(),
    settings: baseSettings(),
    idempotency: new Map(),
  };
  for (const seed of SEEDS) {
    const accountId = id(`account:${seed.key}`);
    const level = LEVEL(seed.score);
    const signals: Signal[] = seed.signals.map((s, i) => ({
      id: id(`signal:${seed.key}:${i}`).replace(/-/g, '').slice(0, 20),
      ruleCode: s.code,
      title: ruleTitle(s.code),
      category: RULES.find((r) => r.code === s.code)?.category ?? 'authentication',
      strength: RULES.find((r) => r.code === s.code)?.strength ?? 'weak',
      weight: s.weight,
      status: s.status ?? 'active',
      occurrences: 1,
      detectedAt: iso(anchor - s.minutesAgo * MIN),
      firstOccurredAt: iso(anchor - s.minutesAgo * MIN),
      lastOccurredAt: iso(anchor - s.minutesAgo * MIN),
      explanation: `${ruleTitle(s.code)} (example evidence)`,
      evidence: { example: true },
      sourceKind: 'event',
      incidentId: null,
      rulesVersion: 'ato-rules/1',
      dismissedAt: null,
      dismissReason: null,
    }));
    const lastSignal = signals.reduce<string | null>(
      (latest, s) => (!latest || s.detectedAt > latest ? s.detectedAt : latest),
      null,
    );
    const account: AccountDetail = {
      id: accountId,
      kind: seed.kind,
      address: seed.address,
      displayName: seed.displayName,
      domainId: null,
      status: 'active',
      riskScore: seed.score,
      riskLevel: level,
      riskUpdatedAt: lastSignal,
      lastSignalAt: lastSignal,
      firstSeenAt: iso(anchor - 60 * DAY),
      lastSeenAt: iso(anchor - 10 * MIN),
      protected: false,
      activeIncident: null,
      override: null,
      rowVersion: 1,
      explanation: {
        text: signals.length > 0 ? signals.map((s) => `${s.title} +${s.weight}`).join(', ') : null,
        structured:
          signals.length > 0
            ? {
                version: 'ato-score/1',
                score: seed.score,
                level,
                top: signals.map((s) => ({
                  code: s.ruleCode,
                  category: s.category,
                  strength: s.strength,
                  weight: s.weight,
                  multiplierPermille: 1000,
                  decayPermille: 1000,
                  contribution: s.weight,
                })),
              }
            : null,
      },
      overrideDetail: null,
      protection: { protected: false, reason: null, at: null },
      restrictions: [],
      baseline: {
        version: 'ato-baseline/1',
        mature: true,
        eventCount: 340,
        activeDays: 26,
        windowStart: iso(anchor - 28 * DAY),
        windowEnd: iso(anchor - DAY),
        rebuiltAt: iso(anchor - 6 * HOUR),
        timeZone: 'UTC',
        prefixes: [
          { prefix: '198.51.100.0/24', count: 310 },
          { prefix: '2001:db8:10::/48', count: 30 },
        ],
        countries: [],
        asns: [],
        devices: [{ deviceHash: 'd3v1c3example', count: 300 }],
        channels: seed.kind === 'smtp_connector' ? ['smtp'] : ['portal'],
        hourHistogram: Array.from({ length: 24 }, (_, h) => (h >= 8 && h <= 18 ? 20 : 1)),
        messageHourHistogram: Array.from({ length: 24 }, (_, h) => (h >= 8 && h <= 18 ? 12 : 0)),
        volume: {
          medianDailyMessages: 40,
          maxDailyMessages: 90,
          medianDailyRecipients: 60,
          maxHourlyMessages: 15,
        },
      },
      trustedContexts: [],
      linkedAccounts: [],
      identities: [],
      capabilities: CAPABILITIES,
    };
    org.accounts.set(accountId, account);
    org.signals.set(accountId, signals);
    org.authEvents.set(
      accountId,
      Array.from({ length: 6 }, (_, i) => ({
        id: id(`auth:${seed.key}:${i}`).replace(/-/g, '').slice(0, 20),
        occurredAt: iso(anchor - (i * 90 + 5) * MIN),
        lastOccurredAt: iso(anchor - (i * 90 + 5) * MIN),
        source: seed.kind === 'smtp_connector' ? 'smtp_auth' : 'portal_login',
        channel: seed.kind === 'smtp_connector' ? 'smtp' : 'portal',
        outcome: i % 3 === 0 && seed.score >= 40 ? 'failure' : 'success',
        failureCode: i % 3 === 0 && seed.score >= 40 ? 'bad_credentials' : null,
        ipAddress: i % 2 === 0 ? '198.51.100.24' : '203.0.113.77',
        ipPrefix: i % 2 === 0 ? '198.51.100.0/24' : '203.0.113.0/24',
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
        device:
          seed.kind === 'smtp_connector'
            ? null
            : { hash: 'd3v1c3example', label: 'Firefox on Linux' },
        mechanism: seed.kind === 'smtp_connector' ? 'PLAIN' : null,
        attemptCount: seed.kind === 'smtp_connector' ? 12 : 1,
      })),
    );
    org.scores.set(
      accountId,
      seed.score > 0
        ? [
            {
              id: id(`score:${seed.key}:1`).replace(/-/g, '').slice(0, 20),
              computedAt: lastSignal ?? iso(anchor - HOUR),
              score: seed.score,
              level,
              previousScore: Math.max(0, seed.score - 30),
              previousLevel: LEVEL(Math.max(0, seed.score - 30)),
              trigger: 'signal',
              explanation: null,
              scorerVersion: 'ato-score/1',
              rulesVersion: 'ato-rules/1',
              settingsVersion: 0,
            },
          ]
        : [],
    );
    org.activity.set(
      accountId,
      seed.kind === 'gateway_user'
        ? []
        : Array.from({ length: 14 }, (_, d) => ({
            day: iso(anchor - (anchor % DAY) - (13 - d) * DAY),
            authSuccess: 4,
            authFailure: 0,
            messages: d === 13 && seed.score >= 60 ? 420 : 30 + d,
            recipients: d === 13 && seed.score >= 60 ? 900 : 45,
            externalRecipients: d === 13 && seed.score >= 60 ? 850 : 20,
            internalRecipients: 25,
            attachments: 3,
            findings: d === 13 && seed.score >= 60 ? 12 : 0,
            maxHourMessages: d === 13 && seed.score >= 60 ? 300 : 8,
            topRecipientDomains: [
              { domain: 'partner.example', count: 12 },
              { domain: 'customer.example', count: 8 },
            ],
            content: {},
          })),
    );
  }
  return org;
}

const globalState = globalThis as typeof globalThis & { __egDevFixtureAto?: Map<string, OrgAto> };

type Principal = NonNullable<ReturnType<typeof resolveFixturePrincipal>>;

export function principalOf(request: FixtureRequest): Principal {
  const principal = resolveFixturePrincipal(request.token);
  if (!principal) throw new Error('fixture principal missing after the guard');
  return principal;
}

/** The ATO state of the caller's organization (built on first use; incidents seeded once). */
export function atoOrgOf(request: FixtureRequest): OrgAto {
  globalState.__egDevFixtureAto ??= new Map();
  const id = principalOf(request).organizationId;
  let org = globalState.__egDevFixtureAto.get(id);
  if (!org) {
    org = buildOrg(id);
    globalState.__egDevFixtureAto.set(id, org);
    seedIncidents(org, id);
  }
  return org;
}

/** Resets the in-memory ATO state (tests). */
export function resetAtoFixtures(): void {
  globalState.__egDevFixtureAto = new Map();
}

// ---- incidents seeding (shared with incidents.ts) -------------------------------------------

export const TRANSITIONS: Record<string, string[]> = {
  open: ['investigating', 'confirmed', 'false_positive', 'resolved'],
  investigating: ['confirmed', 'false_positive', 'resolved'],
  confirmed: ['mitigated', 'resolved'],
  mitigated: ['resolved', 'confirmed'],
  false_positive: [],
  resolved: [],
};

export const RESOLUTIONS: Record<
  string,
  IncidentDetail['allowedTransitions'][number]['resolutionCodes']
> = {
  false_positive: ['false_positive', 'benign_activity', 'duplicate'],
  resolved: ['remediated', 'benign_activity', 'duplicate', 'other'],
};

function seedIncidents(org: OrgAto, organizationId: string): void {
  const anchor = fixtureAnchor();
  const seeds: Array<{
    key: string;
    severity: IncidentDetail['severity'];
    status: IncidentDetail['status'];
  }> = [
    { key: 'finance', severity: 'critical', status: 'open' },
    { key: 'relay', severity: 'high', status: 'investigating' },
    { key: 'sales', severity: 'medium', status: 'resolved' },
  ];
  for (const seed of seeds) {
    const accountId = stableUuid(`ato:${organizationId}:account:${seed.key}`);
    const account = org.accounts.get(accountId);
    if (!account) continue;
    const incidentId = stableUuid(`ato:${organizationId}:incident:${seed.key}`);
    const signals = org.signals.get(accountId) ?? [];
    for (const s of signals) s.incidentId = incidentId;
    const detected = signals[0]?.detectedAt ?? iso(anchor - 2 * DAY);
    const closed = seed.status === 'resolved';
    const incident: IncidentDetail = {
      id: incidentId,
      category: 'account_takeover',
      subject: {
        type: 'ato_account',
        id: accountId,
        display: account.address ?? account.displayName,
      },
      origin: 'detection',
      status: seed.status,
      severity: seed.severity,
      titleCode: signals[0]?.ruleCode ?? null,
      reasonCodes: signals.map((s) => s.ruleCode),
      detectedAt: detected,
      lastEvidenceAt: detected,
      evidenceCount: signals.length,
      assigneeId: null,
      escalatedAt: null,
      resolvedAt: closed ? iso(anchor - DAY) : null,
      resolutionCode: closed ? 'benign_activity' : null,
      createdAt: detected,
      updatedAt: detected,
      rowVersion: 1,
      detectorVersion: 'ato-rules/1',
      firstEvidenceAt: detected,
      assignedAt: null,
      confirmedAt: null,
      mitigatedAt: null,
      resolution: closed
        ? {
            code: 'benign_activity',
            note: 'Expected travel of the sales team (example).',
            resolvedAt: iso(anchor - DAY),
          }
        : null,
      createdBy: { type: 'system', id: null },
      canManage: true,
      allowedTransitions: [],
      evidence: {
        ato_signal: signals.length,
        ato_auth_event: 2,
        message: seed.key === 'finance' ? 2 : 0,
      },
      detail: {
        account: {
          id: accountId,
          kind: account.kind,
          address: account.address,
          userId: null,
          connectorId: null,
          riskScore: account.riskScore,
          riskLevel: account.riskLevel,
          protected: account.protected,
        },
        riskScoreAtOpen: account.riskScore,
        peakRiskScore: account.riskScore,
        detectionReason: {
          codes: signals.map((s) => s.ruleCode),
          contributions: [],
          versions: { rules: 'ato-rules/1', scorer: 'ato-score/1', settings: 0 },
        },
        detectionReasonText: signals.map((s) => `${s.title} +${s.weight}`),
        recommendedActions:
          account.kind === 'mailbox'
            ? [
                {
                  actionType: 'restrict_smtp_sending',
                  availability: 'available',
                  impact: 'high',
                  target: { scope: 'mailbox', accountPublicId: accountId },
                  reason: signals[0]?.ruleCode ?? 'level',
                },
                {
                  actionType: 'revoke_sessions',
                  availability: 'requires_provider',
                  impact: 'medium',
                  target: null,
                  reason: signals[0]?.ruleCode ?? 'level',
                },
                {
                  actionType: 'policy_hold_outbound',
                  availability: 'policy',
                  impact: null,
                  target: null,
                  reason: signals[0]?.ruleCode ?? 'level',
                  preset: 'outbound_high_risk_account',
                },
                {
                  actionType: 'alert_tenant_admins',
                  availability: 'available',
                  impact: 'low',
                  target: { scope: 'account', accountPublicId: accountId },
                  reason: 'level',
                },
              ]
            : [
                {
                  actionType: 'block_smtp_auth',
                  availability: 'available',
                  impact: 'medium',
                  target: {
                    scope: 'connector_ip',
                    accountPublicId: accountId,
                    cidr: '203.0.113.77/32',
                  },
                  reason: signals[0]?.ruleCode ?? 'level',
                },
                {
                  actionType: 'record_manual_action',
                  availability: 'manual',
                  impact: 'low',
                  target: null,
                  reason: 'level',
                  manual: 'rotate_connector_secret',
                },
              ],
        relatedIps: [
          {
            ip: '203.0.113.77',
            country: null,
            asn: null,
            reputation: seed.key === 'relay' ? 'malicious' : null,
            count: 14,
          },
        ],
        geoSummary: null,
        deviceSummary: account.kind === 'smtp_connector' ? null : { devices: ['Firefox on Linux'] },
        counts: {
          signals: signals.length,
          authEvents: 2,
          messages: seed.key === 'finance' ? 2 : 0,
          findings: seed.key === 'finance' ? 2 : 0,
        },
        responses: { total: 0, pendingApproval: 0, byStatus: {} },
      },
    };
    if (!closed)
      account.activeIncident = { id: incidentId, severity: seed.severity, status: seed.status };
    org.incidents.set(incidentId, {
      incident,
      timeline: [
        {
          id: stableUuid(`ato:${organizationId}:tl:${seed.key}:0`).replace(/-/g, '').slice(0, 20),
          at: detected,
          type: 'created',
          actor: { type: 'system', id: null },
          fromStatus: null,
          toStatus: 'open',
          fromSeverity: null,
          toSeverity: seed.severity,
          note: null,
          details: null,
        },
      ],
      messages:
        seed.key === 'finance'
          ? [0, 1].map((n) => ({
              id: stableUuid(`ato:${organizationId}:msg:${n}`),
              receivedAt: iso(anchor - (40 + n * 5) * MIN),
              direction: 'outbound' as const,
              finalVerdict: 'phishing',
              finalAction: 'quarantine',
              riskScore: 880,
              riskLevel: 'critical',
              recipientCount: 40,
              externalDomainCount: 31,
              findingCodes: ['url.phishing_high_confidence'],
            }))
          : [],
      signalIds: signals.map((s) => s.id),
      authEventIds: (org.authEvents.get(accountId) ?? []).slice(0, 2).map((e) => e.id),
    });
  }
  // One pending approval requested by the system (automation guard), so a dev user can approve.
  const finance = stableUuid(`ato:${organizationId}:account:finance`);
  const incidentId = stableUuid(`ato:${organizationId}:incident:finance`);
  const responseId = stableUuid(`ato:${organizationId}:response:seed`);
  org.responses.set(responseId, {
    ...newResponse({
      id: responseId,
      actionType: 'restrict_smtp_sending',
      impact: 'high',
      incidentId,
      accountId: finance,
      accountKind: 'mailbox',
      requestedBy: { type: 'system', id: null },
      reason: 'Automation guard: tenant in monitor mode (example)',
      durationMinutes: 240,
      mode: 'reject',
      at: anchor - 30 * MIN,
    }),
    requesterUserId: null,
  });
}

export function newResponse(input: {
  id: string;
  actionType: Response['actionType'];
  impact: Response['impact'];
  incidentId: string | null;
  accountId: string;
  accountKind: Response['account']['kind'];
  requestedBy: Response['requestedBy'];
  reason: string | null;
  durationMinutes?: number | null;
  mode?: 'reject' | 'defer' | null;
  description?: string | null;
  scope?: Response['target']['scope'];
  cidr?: string | null;
  at: number;
}): Response {
  const provider = [
    'revoke_sessions',
    'require_mfa',
    'require_password_reset',
    'suspend_account',
    'remove_forwarding_rule',
    'revoke_oauth_grant',
  ].includes(input.actionType)
    ? 'provider'
    : input.actionType === 'record_manual_action'
      ? 'manual'
      : 'gateway';
  const requiresApproval = input.impact !== 'low';
  return {
    id: input.id,
    actionType: input.actionType,
    provider,
    impact: input.impact,
    status: 'pending_approval',
    requiresApproval,
    authorization: input.requestedBy.type === 'system' ? 'automation_policy' : 'manual',
    incidentId: input.incidentId,
    account: { id: input.accountId, kind: input.accountKind },
    target: {
      scope:
        input.scope ??
        (input.accountKind === 'smtp_connector'
          ? 'connector'
          : input.accountKind === 'mailbox'
            ? 'mailbox'
            : 'account'),
      connectorId: null,
      cidr: input.cidr ?? null,
    },
    params: {
      durationMinutes: input.durationMinutes ?? null,
      mode: input.mode ?? null,
      description: input.description ?? null,
    },
    requestedBy: input.requestedBy,
    requestReason: input.reason,
    approvedBy: null,
    decidedAt: null,
    decisionReason: null,
    approvalExpiresAt: requiresApproval ? iso(input.at + 24 * HOUR) : null,
    executedAt: null,
    completedAt: null,
    effectiveUntil: null,
    providerReference: null,
    providerStatus: null,
    resultCode: null,
    attemptCount: 0,
    rollbackReason: null,
    canDecide: false,
    canRollback: false,
    createdAt: iso(input.at),
    updatedAt: iso(input.at),
    attempts: [],
    restriction: null,
  };
}

// ---- helpers ---------------------------------------------------------------------------------

function route(handler: (request: FixtureRequest, org: OrgAto) => FixtureResponse): FixtureHandler {
  return (request) => fixtureGuard(request) ?? handler(request, atoOrgOf(request));
}

export function mfa(request: FixtureRequest): FixtureResponse | null {
  return principalOf(request).mfaAuthenticated
    ? null
    : apiError(403, 'mfa_required', 'This action requires a session signed in with MFA');
}

export function idempotent(
  request: FixtureRequest,
  org: OrgAto,
  handler: () => FixtureResponse,
): FixtureResponse {
  const key = request.headers.get('idempotency-key');
  if (!key)
    return apiError(400, 'idempotency_key_required', 'The Idempotency-Key header is required');
  const scoped = `${principalOf(request).userId}:${key}`;
  const fingerprint = JSON.stringify([request.operationId, request.params, request.body]);
  const stored = org.idempotency.get(scoped);
  if (stored) {
    if (stored.fingerprint !== fingerprint) {
      return apiError(
        422,
        'idempotency_key_reused',
        'The Idempotency-Key was used for another request',
      );
    }
    return {
      ...stored.response,
      headers: { ...(stored.response.headers ?? {}), 'idempotency-replayed': 'true' },
    };
  }
  const response = handler();
  if (response.status >= 200 && response.status < 300)
    org.idempotency.set(scoped, { fingerprint, response });
  return response;
}

export function bodyOf(request: FixtureRequest): Record<string, unknown> {
  return request.body && typeof request.body === 'object'
    ? (request.body as Record<string, unknown>)
    : {};
}

function reasonOf(
  body: Record<string, unknown>,
  min: number,
  max: number,
  required = true,
): string | null | FixtureResponse {
  const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
  if (!reason && !required) return null;
  if (reason.length < min || reason.length > max) {
    return apiError(400, 'validation_failed', [`reason: must be ${min}-${max} characters`]);
  }
  return reason;
}

const isResponse = (v: unknown): v is FixtureResponse =>
  typeof v === 'object' && v !== null && 'status' in v && typeof v.status === 'number';

function summaryOf(a: AccountDetail): ListItem<'AtoAccountsController_list_v1'> {
  return {
    id: a.id,
    kind: a.kind,
    address: a.address,
    displayName: a.displayName,
    domainId: a.domainId,
    status: a.status,
    riskScore: a.riskScore,
    riskLevel: a.riskLevel,
    riskUpdatedAt: a.riskUpdatedAt,
    lastSignalAt: a.lastSignalAt,
    firstSeenAt: a.firstSeenAt,
    lastSeenAt: a.lastSeenAt,
    protected: a.protected,
    activeIncident: a.activeIncident,
    override: a.override,
  };
}

const list = (query: URLSearchParams, key: string) =>
  (query.get(key) ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);

/** The caller's view of a response (`canDecide`, `canRollback`). */
export function viewOf(
  request: FixtureRequest,
  response: Response & { requesterUserId: string | null },
): Response {
  const principal = principalOf(request);
  const respond = principal.permissions.includes('ato:respond');
  const { requesterUserId, ...rest } = response;
  return {
    ...rest,
    canDecide:
      respond && response.status === 'pending_approval' && requesterUserId !== principal.userId,
    canRollback:
      respond &&
      response.status === 'succeeded' &&
      ['restrict_smtp_sending', 'block_smtp_auth'].includes(response.actionType),
  };
}

function scoreAccount(account: AccountDetail, org: OrgAto): void {
  const active = (org.signals.get(account.id) ?? []).filter((s) => s.status === 'active');
  let score = Math.min(
    100,
    active.reduce((sum, s) => sum + s.weight, 0),
  );
  if (account.override?.verdict === 'compromised') score = Math.max(score, 90);
  if (account.override?.verdict === 'benign') score = Math.min(score, 29);
  account.riskScore = score;
  account.riskLevel = LEVEL(score);
  account.riskUpdatedAt = new Date().toISOString();
}

export function applyRestriction(org: OrgAto, response: Response): void {
  const account = org.accounts.get(response.account.id);
  const now = Date.now();
  const restriction: Restriction = {
    id: stableUuid(`restriction:${response.id}`),
    kind: response.actionType === 'block_smtp_auth' ? 'auth_block' : 'send_block',
    scope:
      response.target.scope === 'connector_ip'
        ? 'connector_ip'
        : response.target.scope === 'connector'
          ? 'connector'
          : 'mailbox',
    connectorId: null,
    connectorName: account?.kind === 'smtp_connector' ? account.displayName : null,
    mailboxAddress: account?.kind === 'mailbox' ? account.address : null,
    ipCidr: response.target.cidr,
    mode: response.params.mode ?? 'reject',
    status: 'active',
    reasonCode: response.actionType,
    responseId: response.id,
    startsAt: iso(now),
    expiresAt: iso(now + (response.params.durationMinutes ?? 240) * MIN),
    liftedAt: null,
    liftReason: null,
  };
  org.restrictions.set(restriction.id, restriction);
  if (account) account.restrictions = [...account.restrictions, restriction];
  response.restriction = restriction;
  response.effectiveUntil = restriction.expiresAt;
}

// ---- handlers --------------------------------------------------------------------------------

function overview(request: FixtureRequest, org: OrgAto): FixtureResponse {
  const range = (request.query.get('range') ?? '7d') as '24h' | '7d' | '30d';
  const now = fixtureAnchor();
  const span = range === '24h' ? DAY : range === '7d' ? 7 * DAY : 30 * DAY;
  const accounts = [...org.accounts.values()];
  const incidents = [...org.incidents.values()].map((r) => r.incident);
  const active = incidents.filter((i) =>
    ['open', 'investigating', 'confirmed', 'mitigated'].includes(i.status),
  );
  const by = (sev: string) => active.filter((i) => i.severity === sev).length;
  const pending = [...org.responses.values()].filter((r) => r.status === 'pending_approval').length;
  const buckets = range === '24h' ? 24 : range === '7d' ? 7 : 30;
  const step = span / buckets;
  return ok('AtoOverviewController_overview_v1', {
    generatedAt: iso(now),
    range,
    from: iso(now - span),
    to: iso(now),
    monitoring: {
      featureEnabled: org.settings.featureEnabled,
      mode: 'monitor',
      learning: false,
      learningEndsAt: null,
    },
    accounts: {
      monitored: accounts.length,
      byKind: {
        mailbox: accounts.filter((a) => a.kind === 'mailbox').length,
        gateway_user: accounts.filter((a) => a.kind === 'gateway_user').length,
        smtp_connector: accounts.filter((a) => a.kind === 'smtp_connector').length,
      },
      highRisk: accounts.filter((a) => a.riskLevel === 'high' || a.riskLevel === 'critical').length,
      criticalRisk: accounts.filter((a) => a.riskLevel === 'critical').length,
    },
    incidents: {
      active: active.length,
      activeBySeverity: {
        low: by('low'),
        medium: by('medium'),
        high: by('high'),
        critical: by('critical'),
      },
      critical: by('critical'),
      openedInRange: incidents.filter((i) => Date.parse(i.detectedAt) >= now - span).length,
      trend: Array.from({ length: buckets }, (_, b) => {
        const start = now - span + b * step;
        const inBucket = incidents.filter((i) => {
          const t = Date.parse(i.detectedAt);
          return t >= start && t < start + step;
        });
        const count = (sev: string) => inBucket.filter((i) => i.severity === sev).length;
        return {
          bucketStart: iso(start),
          low: count('low'),
          medium: count('medium'),
          high: count('high'),
          critical: count('critical'),
        };
      }),
      resolvedInRange: {
        remediated: incidents.filter((i) => i.resolutionCode === 'remediated').length,
        falsePositive: incidents.filter((i) => i.status === 'false_positive').length,
        other: incidents.filter((i) => i.status === 'resolved' && i.resolutionCode !== 'remediated')
          .length,
      },
    },
    logins: { failedInRange: 7, suspiciousInRange: 4 },
    outbound: {
      suspiciousInRange: 3,
      restrictedAccounts: [...org.restrictions.values()].filter((r) => r.status === 'active')
        .length,
      policyHeldInRange: 0,
    },
    geography: {
      available: false,
      reason: 'geoip_unavailable',
      topCountries: [],
      impossibleTravelInRange: 0,
    },
    responses: {
      pendingApproval: pending,
      executedInRange: [...org.responses.values()].filter((r) => r.status === 'succeeded').length,
      failedInRange: 0,
    },
    attention: { criticalIncidents: by('critical'), pendingApprovals: pending },
  });
}

function accountOr404(org: OrgAto, id: string | undefined): AccountDetail | FixtureResponse {
  const account = id ? org.accounts.get(id) : undefined;
  return account ?? apiError(404, 'ato_account_not_found', 'Account not found');
}

export const fixtures: FixtureHandlers = {
  AtoOverviewController_overview_v1: route(overview),

  AtoOverviewController_attention_v1: route((_request, org) => {
    const critical = [...org.incidents.values()].filter(
      (r) =>
        r.incident.severity === 'critical' &&
        ['open', 'investigating', 'confirmed', 'mitigated'].includes(r.incident.status),
    ).length;
    const pending = [...org.responses.values()].filter(
      (r) => r.status === 'pending_approval',
    ).length;
    return ok('AtoOverviewController_attention_v1', {
      criticalIncidents: critical,
      pendingApprovals: pending,
    });
  }),

  AtoAccountsController_list_v1: route((request, org) => {
    const q = request.query;
    const kinds = list(q, 'kind');
    const levels = list(q, 'level');
    const minScore = q.get('minScore') ? Number(q.get('minScore')) : null;
    const prefix = (q.get('q') ?? '').toLowerCase();
    if (prefix && prefix.length < 2)
      return apiError(400, 'validation_failed', ['q: at least 2 characters']);
    const sort = q.get('sort') ?? '-riskScore';
    let rows = [...org.accounts.values()].filter(
      (a) =>
        (kinds.length === 0 || kinds.includes(a.kind)) &&
        (levels.length === 0 || levels.includes(a.riskLevel)) &&
        (minScore === null || a.riskScore >= minScore) &&
        (q.get('hasActiveIncident') === null ||
          (a.activeIncident !== null) === (q.get('hasActiveIncident') === 'true')) &&
        (q.get('protected') === null || a.protected === (q.get('protected') === 'true')) &&
        (!prefix || (a.address ?? '').toLowerCase().startsWith(prefix)),
    );
    rows =
      sort === 'address'
        ? rows
            .filter((a) => a.address)
            .sort((x, y) => (x.address ?? '').localeCompare(y.address ?? ''))
        : sort === '-lastSignalAt'
          ? rows
              .filter((a) => a.lastSignalAt)
              .sort((x, y) => (y.lastSignalAt ?? '').localeCompare(x.lastSignalAt ?? ''))
          : rows.sort((x, y) => y.riskScore - x.riskScore || x.id.localeCompare(y.id));
    return { status: 200, body: paginate(rows.map(summaryOf), q) };
  }),

  AtoAccountsController_get_v1: route((request, org) => {
    const account = accountOr404(org, request.params.accountId);
    return isResponse(account) ? account : ok('AtoAccountsController_get_v1', account);
  }),

  AtoAccountsController_update_v1: route((request, org) => {
    const account = accountOr404(org, request.params.accountId);
    if (isResponse(account)) return account;
    return idempotent(request, org, () => {
      const body = bodyOf(request);
      if (body.expectedRowVersion !== account.rowVersion) {
        return apiError(409, 'ato_account_conflict', 'The account changed');
      }
      account.protected = body.protected === true;
      account.protection = {
        protected: account.protected,
        reason: typeof body.reason === 'string' ? body.reason : null,
        at: new Date().toISOString(),
      };
      account.rowVersion += 1;
      return ok('AtoAccountsController_update_v1', account);
    });
  }),

  AtoAccountsController_signals_v1: route((request, org) => {
    if (!org.accounts.has(request.params.accountId ?? ''))
      return apiError(404, 'ato_account_not_found', 'Account not found');
    const categories = list(request.query, 'category');
    const status = request.query.get('status');
    const rows = (org.signals.get(request.params.accountId ?? '') ?? [])
      .filter(
        (s) =>
          (categories.length === 0 || categories.includes(s.category)) &&
          (!status || s.status === status),
      )
      .sort((a, b) => b.detectedAt.localeCompare(a.detectedAt));
    return { status: 200, body: paginate(rows, request.query) };
  }),

  AtoAccountsController_authEvents_v1: route((request, org) => {
    if (!org.accounts.has(request.params.accountId ?? ''))
      return apiError(404, 'ato_account_not_found', 'Account not found');
    const outcomes = list(request.query, 'outcome');
    const rows = (org.authEvents.get(request.params.accountId ?? '') ?? []).filter(
      (e) => outcomes.length === 0 || outcomes.includes(e.outcome),
    );
    return { status: 200, body: paginate(rows, request.query) };
  }),

  AtoAccountsController_activity_v1: route((request, org) => {
    const id = request.params.accountId ?? '';
    if (!org.accounts.has(id)) return apiError(404, 'ato_account_not_found', 'Account not found');
    const now = fixtureAnchor();
    return ok('AtoAccountsController_activity_v1', {
      account: id,
      from: request.query.get('from') ?? iso(now - 30 * DAY),
      to: request.query.get('to') ?? iso(now),
      days: org.activity.get(id) ?? [],
    });
  }),

  AtoAccountsController_scoreHistory_v1: route((request, org) => {
    const id = request.params.accountId ?? '';
    if (!org.accounts.has(id)) return apiError(404, 'ato_account_not_found', 'Account not found');
    return { status: 200, body: paginate(org.scores.get(id) ?? [], request.query) };
  }),

  AtoAccountsController_setOverride_v1: route((request, org) => {
    const account = accountOr404(org, request.params.accountId);
    if (isResponse(account)) return account;
    return idempotent(request, org, () => {
      const body = bodyOf(request);
      const reason = reasonOf(body, 10, 1000);
      if (isResponse(reason)) return reason;
      const verdict = body.verdict === 'compromised' ? 'compromised' : 'benign';
      const hours = Number(body.expiresInHours);
      if (!Number.isInteger(hours) || hours < 1 || hours > 720) {
        return apiError(400, 'validation_failed', ['expiresInHours: 1-720']);
      }
      const now = Date.now();
      account.override = { verdict, expiresAt: iso(now + hours * HOUR) };
      account.overrideDetail = {
        id: stableUuid(`override:${account.id}:${now}`),
        verdict,
        reason: reason ?? '',
        expiresAt: iso(now + hours * HOUR),
        createdAt: iso(now),
        contradictedAt: null,
      };
      scoreAccount(account, org);
      return ok('AtoAccountsController_setOverride_v1', account);
    });
  }),

  AtoAccountsController_clearOverride_v1: route((request, org) => {
    const account = accountOr404(org, request.params.accountId);
    if (isResponse(account)) return account;
    return idempotent(request, org, () => {
      const reason = reasonOf(bodyOf(request), 10, 1000);
      if (isResponse(reason)) return reason;
      if (!account.override) return apiError(404, 'ato_override_not_found', 'No active override');
      account.override = null;
      account.overrideDetail = null;
      scoreAccount(account, org);
      return ok('AtoAccountsController_clearOverride_v1', account);
    });
  }),

  AtoAccountsController_addTrustedContext_v1: route((request, org) => {
    const account = accountOr404(org, request.params.accountId);
    if (isResponse(account)) return account;
    return idempotent(request, org, () => {
      const body = bodyOf(request);
      const value = typeof body.value === 'string' ? body.value.trim() : '';
      const kind = body.kind as AccountDetail['trustedContexts'][number]['kind'];
      const days = Number(body.expiresInDays);
      const valid =
        value.length > 0 &&
        Number.isInteger(days) &&
        days >= 1 &&
        days <= 365 &&
        (kind !== 'ip_cidr' || /^[0-9a-f:.]+\/\d{1,3}$/i.test(value)) &&
        (kind !== 'country' || /^[A-Za-z]{2}$/.test(value)) &&
        (kind !== 'asn' || /^\d{1,10}$/.test(value));
      if (!valid) return apiError(422, 'ato_trusted_context_invalid', 'Invalid trusted context');
      const now = Date.now();
      const context = {
        id: stableUuid(`ctx:${account.id}:${value}:${now}`),
        kind,
        value: kind === 'country' ? value.toUpperCase() : value,
        reason: typeof body.reason === 'string' ? body.reason : '',
        source: 'analyst' as const,
        incidentId: null,
        createdAt: iso(now),
        expiresAt: iso(now + days * DAY),
      };
      account.trustedContexts = [...account.trustedContexts, context];
      return ok('AtoAccountsController_addTrustedContext_v1', context, 201);
    });
  }),

  AtoAccountsController_removeTrustedContext_v1: route((request, org) => {
    const account = accountOr404(org, request.params.accountId);
    if (isResponse(account)) return account;
    return idempotent(request, org, () => {
      const before = account.trustedContexts.length;
      account.trustedContexts = account.trustedContexts.filter(
        (c) => c.id !== request.params.contextId,
      );
      return before === account.trustedContexts.length
        ? apiError(404, 'ato_trusted_context_not_found', 'Trusted context not found')
        : noContent();
    });
  }),

  AtoIncidentEvidenceController_signals_v1: route((request, org) => {
    const record = org.incidents.get(request.params.incidentId ?? '');
    if (!record) return apiError(404, 'incident_not_found', 'Incident not found');
    const all = [...org.signals.values()].flat().filter((s) => record.signalIds.includes(s.id));
    return { status: 200, body: paginate(all, request.query) };
  }),

  AtoIncidentEvidenceController_authEvents_v1: route((request, org) => {
    const record = org.incidents.get(request.params.incidentId ?? '');
    if (!record) return apiError(404, 'incident_not_found', 'Incident not found');
    const all = [...org.authEvents.values()]
      .flat()
      .filter((e) => record.authEventIds.includes(e.id));
    return { status: 200, body: paginate(all, request.query) };
  }),

  AtoResponsesController_request_v1: route((request, org) => {
    const record = org.incidents.get(request.params.incidentId ?? '');
    if (!record) return apiError(404, 'incident_not_found', 'Incident not found');
    return idempotent(request, org, () => {
      const body = bodyOf(request);
      const reason = reasonOf(body, 10, 1000);
      if (isResponse(reason)) return reason;
      const actionType = body.actionType as Response['actionType'];
      const accountId = (record.incident.detail as { account?: { id?: string } }).account?.id ?? '';
      const account = org.accounts.get(accountId);
      if (!account) return apiError(404, 'ato_account_not_found', 'Account not found');
      const duplicate = [...org.responses.values()].find(
        (r) =>
          r.incidentId === record.incident.id &&
          r.actionType === actionType &&
          ['pending_approval', 'approved', 'executing'].includes(r.status),
      );
      if (duplicate)
        return apiError(409, 'ato_response_active', 'A response of this type is active', {
          responseId: duplicate.id,
        });
      const impact: Response['impact'] = [
        'restrict_smtp_sending',
        'block_smtp_auth',
        'require_password_reset',
        'suspend_account',
      ].includes(actionType)
        ? 'high'
        : [
              'revoke_sessions',
              'require_mfa',
              'remove_forwarding_rule',
              'revoke_oauth_grant',
            ].includes(actionType)
          ? 'medium'
          : 'low';
      const principal = principalOf(request);
      const target = body.target as
        { scope?: Response['target']['scope']; cidr?: string } | undefined;
      const response = {
        ...newResponse({
          id: crypto.randomUUID(),
          actionType,
          impact,
          incidentId: record.incident.id,
          accountId,
          accountKind: account.kind,
          requestedBy: { type: 'user', id: principal.userId },
          reason,
          durationMinutes: typeof body.durationMinutes === 'number' ? body.durationMinutes : null,
          mode: body.mode === 'defer' ? 'defer' : body.mode === 'reject' ? 'reject' : null,
          description: typeof body.description === 'string' ? body.description : null,
          scope: target?.scope,
          cidr: target?.cidr ?? null,
          at: Date.now(),
        }),
        requesterUserId: principal.userId,
      };
      if (response.provider === 'provider') {
        response.status = 'unsupported';
        response.providerStatus = 'unsupported';
        response.resultCode = 'no_provider_adapter';
      } else if (actionType === 'record_manual_action') {
        response.status = 'attested';
        response.completedAt = response.createdAt;
      } else if (impact === 'low') {
        response.status = 'succeeded';
        response.providerStatus = 'unconfirmed';
        response.resultCode = 'queued_for_delivery';
        response.completedAt = response.createdAt;
      }
      org.responses.set(response.id, response);
      return ok('AtoResponsesController_request_v1', viewOf(request, response), 201);
    });
  }),

  AtoResponsesController_list_v1: route((request, org) => {
    const statuses = list(request.query, 'status');
    const types = list(request.query, 'actionType');
    const incidentId = request.query.get('incidentId');
    const accountId = request.query.get('accountId');
    const rows = [...org.responses.values()]
      .filter(
        (r) =>
          (statuses.length === 0 || statuses.includes(r.status)) &&
          (types.length === 0 || types.includes(r.actionType)) &&
          (!incidentId || r.incidentId === incidentId) &&
          (!accountId || r.account.id === accountId),
      )
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((r) => {
        const { attempts: _a, restriction: _r, ...summary } = viewOf(request, r);
        return summary;
      });
    return { status: 200, body: paginate(rows, request.query) };
  }),

  AtoResponsesController_get_v1: route((request, org) => {
    const response = org.responses.get(request.params.responseId ?? '');
    return response
      ? ok('AtoResponsesController_get_v1', viewOf(request, response))
      : apiError(404, 'ato_response_not_found', 'Response not found');
  }),

  AtoResponsesController_approve_v1: route((request, org) => {
    const response = org.responses.get(request.params.responseId ?? '');
    if (!response) return apiError(404, 'ato_response_not_found', 'Response not found');
    return (
      mfa(request) ??
      idempotent(request, org, () => {
        if (response.status !== 'pending_approval')
          return apiError(409, 'ato_response_state', 'Not pending');
        if (response.requesterUserId === principalOf(request).userId) {
          return apiError(403, 'ato_approval_self', 'The requester cannot approve');
        }
        const now = Date.now();
        response.approvedBy = principalOf(request).userId;
        response.decidedAt = iso(now);
        response.decisionReason =
          typeof bodyOf(request).reason === 'string' ? (bodyOf(request).reason as string) : null;
        response.status = 'succeeded';
        response.providerStatus = 'applied';
        response.executedAt = iso(now);
        response.completedAt = iso(now);
        response.updatedAt = iso(now);
        if (['restrict_smtp_sending', 'block_smtp_auth'].includes(response.actionType))
          applyRestriction(org, response);
        return ok('AtoResponsesController_approve_v1', viewOf(request, response));
      })
    );
  }),

  AtoResponsesController_reject_v1: route((request, org) => {
    const response = org.responses.get(request.params.responseId ?? '');
    if (!response) return apiError(404, 'ato_response_not_found', 'Response not found');
    return idempotent(request, org, () => {
      const reason = reasonOf(bodyOf(request), 10, 1000);
      if (isResponse(reason)) return reason;
      if (response.status !== 'pending_approval')
        return apiError(409, 'ato_response_state', 'Not pending');
      response.status = 'rejected';
      response.decidedAt = new Date().toISOString();
      response.decisionReason = reason;
      return ok('AtoResponsesController_reject_v1', viewOf(request, response));
    });
  }),

  AtoResponsesController_cancel_v1: route((request, org) => {
    const response = org.responses.get(request.params.responseId ?? '');
    if (!response) return apiError(404, 'ato_response_not_found', 'Response not found');
    return idempotent(request, org, () => {
      if (response.status !== 'pending_approval')
        return apiError(409, 'ato_response_state', 'Not pending');
      response.status = 'cancelled';
      response.decidedAt = new Date().toISOString();
      return ok('AtoResponsesController_cancel_v1', viewOf(request, response));
    });
  }),

  AtoResponsesController_rollback_v1: route((request, org) => {
    const response = org.responses.get(request.params.responseId ?? '');
    if (!response) return apiError(404, 'ato_response_not_found', 'Response not found');
    return (
      mfa(request) ??
      idempotent(request, org, () => {
        const reason = reasonOf(bodyOf(request), 10, 1000);
        if (isResponse(reason)) return reason;
        if (response.status !== 'succeeded' || !response.restriction) {
          return apiError(422, 'ato_rollback_unsupported', 'This response cannot be rolled back');
        }
        const now = new Date().toISOString();
        const restriction = org.restrictions.get(response.restriction.id);
        if (restriction) {
          restriction.status = 'lifted';
          restriction.liftedAt = now;
          restriction.liftReason = 'rollback';
          const account = org.accounts.get(response.account.id);
          if (account)
            account.restrictions = account.restrictions.map((r) =>
              r.id === restriction.id ? restriction : r,
            );
          response.restriction = restriction;
        }
        response.status = 'rolled_back';
        response.rollbackReason = reason;
        response.updatedAt = now;
        return ok('AtoResponsesController_rollback_v1', viewOf(request, response));
      })
    );
  }),

  AtoRestrictionsController_list_v1: route((request, org) => {
    const status = list(request.query, 'status');
    const kind = list(request.query, 'kind');
    const rows = [...org.restrictions.values()].filter(
      (r) =>
        (status.length === 0 || status.includes(r.status)) &&
        (kind.length === 0 || kind.includes(r.kind)),
    );
    return { status: 200, body: paginate(rows, request.query) };
  }),

  AtoSettingsController_get_v1: route((_request, org) =>
    ok('AtoSettingsController_get_v1', org.settings),
  ),

  AtoSettingsController_update_v1: route((request, org) =>
    idempotent(request, org, () => {
      const body = bodyOf(request);
      if (body.expectedRowVersion !== org.settings.rowVersion) {
        return apiError(409, 'ato_settings_conflict', 'Settings changed by someone else', {
          currentRowVersion: org.settings.rowVersion,
        });
      }
      const settings = (body.settings ?? {}) as Record<string, unknown>;
      const scoring = (settings.scoring ?? {}) as { bands?: Record<string, number> };
      const bands = scoring.bands ?? {};
      if (bands.medium !== undefined && bands.high !== undefined && !(bands.medium < bands.high)) {
        return apiError(400, 'ato_settings_invalid', 'Invalid ATO settings', {
          issues: [
            { path: 'scoring.bands', message: 'Bands must be ordered: medium < high < critical' },
          ],
        });
      }
      org.settings = {
        ...org.settings,
        stored: settings,
        version: org.settings.version + 1,
        rowVersion: org.settings.rowVersion + 1,
        updatedAt: new Date().toISOString(),
      };
      return ok('AtoSettingsController_update_v1', org.settings);
    }),
  ),

  AtoRulesController_list_v1: route(() =>
    ok('AtoRulesController_list_v1', {
      rulesVersion: 'ato-rules/1',
      capabilities: CAPABILITIES,
      data: RULES,
    }),
  ),
};

import 'server-only';
import type { OperationId, RequestBody, SuccessBody } from '@/lib/api/types';
import { SeededRandom, paginate, stableUuid } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import {
  DAY,
  HOUR,
  MINUTE,
  findDomain,
  guarded,
  idempotent,
  isoAgo,
  refreshDomainModes,
} from './domains';
import {
  effectiveMode,
  entitledPlan,
  liveDomains,
  organizationModeView,
  planOf,
  setOrganizationMode,
} from './protection-modes';
import { MAILBOX_PROFILE, providerConnectionsOf } from './provider-connections';
import {
  addMailboxEntry,
  registerMailboxHooks,
  releaseMailboxEntry,
  runQuarantineExecutor,
  updateMailboxEntry,
} from './quarantine';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of API-mode protection (step API-1 WP6, design D2, D10–D12): the organization and
 * domain protection modes (entitlement, MX conflict, inherit, unchanged = no change), and the 11
 * `/api-mode` operations over the 8.2 connections of the provider-connections fixture (grant
 * status from there), with mailboxes, detections, health checks, counters and the setup guide.
 * Step API-2 (WP6, R12, R13): the 9 remediation operations — policy with CAS, presets and
 * domain overrides; the history with a worker that completes a queued action about 8 seconds
 * later; manual remediate, restore (delegated to the quarantine fixture's release for mailbox
 * entries) and retry — plus the remediation fields of detections, connections and the overview
 * and the mailbox-located quarantine entries of remediated detections.
 * Synthetic only (`*.example.test`), per organization, deterministic, cursor pagination; never a
 * cursor, subscription id, provider message id or client state in a view.
 */

export const API_MODE_OPERATIONS: readonly OperationId[] = [
  'ProtectionModeController_getOrganization_v1',
  'ProtectionModeController_putOrganization_v1',
  'ProtectionModeController_putDomain_v1',
  'ApiModeController_overview_v1',
  'ApiModeController_listConnections_v1',
  'ApiModeController_getConnection_v1',
  'ApiModeController_setupGuide_v1',
  'ApiModeController_updateSettings_v1',
  'ApiModeController_inventorySync_v1',
  'ApiModeController_listMailboxes_v1',
  'ApiModeController_getMailbox_v1',
  'ApiModeController_resyncMailbox_v1',
  'ApiModeController_listDetections_v1',
  'ApiModeController_getDetection_v1',
];

/** Step API-2 (R13): the 9 remediation operations. */
export const API_MODE_REMEDIATION_OPERATIONS: readonly OperationId[] = [
  'ApiModeRemediationController_getPolicy_v1',
  'ApiModeRemediationController_putPolicy_v1',
  'ApiModeRemediationController_putDomainPolicy_v1',
  'ApiModeRemediationController_deleteDomainPolicy_v1',
  'ApiModeRemediationController_list_v1',
  'ApiModeRemediationController_detail_v1',
  'ApiModeRemediationController_retry_v1',
  'ApiModeRemediationController_remediate_v1',
  'ApiModeRemediationController_restore_v1',
];

type ConnectionView = SuccessBody<'ApiModeController_getConnection_v1'>;
type ConnectionRow = SuccessBody<'ApiModeController_listConnections_v1'>['data'][number];
type Mailbox = SuccessBody<'ApiModeController_getMailbox_v1'>;
type Detection = SuccessBody<'ApiModeController_getDetection_v1'>;
type Health = ConnectionRow['health']['status'];
type PolicyView = SuccessBody<'ApiModeRemediationController_getPolicy_v1'>;
type PolicyDocument = PolicyView['organization']['document'];
type PolicyMode = PolicyView['organization']['mode'];
type Action = SuccessBody<'ApiModeRemediationController_detail_v1'>;
type ActionRow = SuccessBody<'ApiModeRemediationController_list_v1'>['data'][number];
type Summary = SuccessBody<'ApiModeController_overview_v1'>['remediation'];

interface PolicyRow {
  id: string;
  mode: PolicyMode;
  document: PolicyDocument;
  rowVersion: number;
  updatedAt: string;
  /** Step API-4 B7: the detect-only period (null = none). */
  detectOnly?: { until: string; then: 'remind' | 'enforce'; startedAt: string } | null;
}

type EffectiveMapping = PolicyView['organization']['effectivePolicyMapping'];
const DEFAULT_MAPPING: EffectiveMapping = {
  quarantine: 'move_quarantine',
  require_approval: 'move_quarantine',
  reject: 'move_quarantine',
  allow_tagged: 'tag',
};
const MAPPING_KEYS = ['quarantine', 'require_approval', 'reject', 'allow_tagged'] as const;
const MAPPING_ACTIONS = new Set(['move_quarantine', 'move_junk', 'soft_delete', 'tag', 'none']);

/** Step API-4 A4.2: the effective mapping (missing keys take their default). */
export function effectiveMappingOf(document: PolicyDocument): EffectiveMapping {
  return { ...DEFAULT_MAPPING, ...(document.policyMapping ?? {}) };
}

/** Step API-4 B7: the detect-only view of a policy row (`simulatedSinceStart` from the actions). */
function detectOnlyView(organizationId: string, row: PolicyRow | null, domainId: string | null) {
  if (!row || row.mode !== 'detect_only' || !row.detectOnly) return null;
  const started = Date.parse(row.detectOnly.startedAt);
  const org = orgState(organizationId);
  const domainOf = (mailboxId: string) =>
    org.mailboxes.find((m) => m.id === mailboxId)?.domain?.id ?? null;
  const simulated = org.actions.filter(
    (a) =>
      a.status === 'simulated' &&
      Date.parse(a.createdAt) >= started &&
      (domainId === null || domainOf(a.mailbox.id) === domainId),
  ).length;
  return {
    until: row.detectOnly.until,
    then: row.detectOnly.then,
    startedAt: row.detectOnly.startedAt,
    ended: Date.parse(row.detectOnly.until) <= Date.now(),
    simulatedSinceStart: Math.min(simulated, 10_000),
  };
}

interface ApiConnectionState {
  apiConnectionId: string;
  feedsEnabled: boolean;
  feedMode: 'poll' | 'notify';
  feedsEnabledAt: string | null;
  inventoryStatus: ConnectionRow['inventoryStatus'];
  inventorySyncedAt: string | null;
  inventoryRequestedAt: string | null;
  health: Health;
  healthChangedAt: string | null;
  throttledUntil: string | null;
  remediationPaused: boolean;
  remediationPausedAt: string | null;
  rowVersion: number;
}

interface OrgApiState {
  connections: Map<string, ApiConnectionState>;
  mailboxes: Mailbox[];
  detections: Detection[];
  /** Step API-2: the organization policy row (null = the platform default P1). */
  policy: PolicyRow | null;
  domainPolicies: Map<string, PolicyRow & { domainName: string }>;
  /** Remediation actions, newest first. */
  actions: Action[];
}

interface ApiModeFixtureState {
  orgs: Map<string, OrgApiState>;
  idempotency: Map<string, FixtureResponse>;
}

const store = globalThis as typeof globalThis & { __egDevFixtureApiMode?: ApiModeFixtureState };

// ---- step API-2 policy documents (R2.3; the same rule ids as the platform default) ------------

const P1: PolicyDocument = {
  v: 1,
  rules: [
    {
      id: 'p1-high-confidence-malware-phishing-hb',
      when: { verdicts: ['malware', 'phishing'], hardBlock: true },
      action: 'move_quarantine',
    },
    {
      id: 'p1-high-confidence-malware-phishing',
      when: { verdicts: ['malware', 'phishing'], minLevel: 'critical' },
      action: 'move_quarantine',
    },
    { id: 'p1-other-malware-phishing', when: { verdicts: ['malware', 'phishing'] }, action: 'tag' },
    { id: 'p1-suspicious', when: { verdicts: ['suspicious', 'bec'] }, action: 'tag' },
  ],
};
const STRICT: PolicyDocument = {
  v: 1,
  rules: [
    ...P1.rules,
    { id: 'strict-spam-junk', when: { verdicts: ['spam'] }, action: 'move_junk' },
  ],
};
const PRESETS: PolicyView['presets'] = {
  p1: { mode: 'enforce', document: P1 },
  detectOnlyStart: { mode: 'detect_only', document: P1 },
  strict: { mode: 'enforce', document: STRICT },
};
/** `API_MODE_HARD_DELETE_ENABLED` of the fixture platform (off, as the platform default). */
const HARD_DELETE_AVAILABLE = false;
const WORKER_DELAY_MS = 8_000;
const sha = (seed: string) =>
  Array.from({ length: 8 }, (_, i) => stableUuid(`${seed}:${i}`).replace(/-/g, '').slice(0, 8))
    .join('')
    .slice(0, 64);
const state: ApiModeFixtureState = (store.__egDevFixtureApiMode ??= {
  orgs: new Map(),
  idempotency: new Map(),
});

export function resetApiModeFixtures(): void {
  state.orgs.clear();
  state.idempotency.clear();
}

const VERDICTS: Detection['verdict'][] = [
  'clean',
  'clean',
  'spam',
  'clean',
  'phishing',
  'clean',
  'malware',
  'suspicious',
  'clean',
  'bulk',
];

/** Step API-4 A12: the policy evaluation view of a detect row (content-free; synthetic). */
function policyEvaluationOf(
  disposition: Detection['policyDisposition'] & string,
  source: 'tenant_rule' | 'platform_default' | 'floor',
  ruleRef: string | null,
  at: string,
  outbound = false,
): NonNullable<Detection['policy']> {
  const type =
    disposition === 'reject'
      ? 'REJECT'
      : disposition === 'quarantine'
        ? 'QUARANTINE'
        : disposition === 'require_approval'
          ? 'REQUIRE_APPROVAL'
          : 'ALLOW';
  const reason = outbound
    ? 'outbound_already_sent'
    : type === 'ALLOW'
      ? 'already_delivered'
      : 'mapped_to_mailbox_action';
  const status = outbound ? 'not_applicable' : type === 'ALLOW' ? 'recorded' : 'requested';
  return {
    evaluationId: stableUuid(`evaluation:${at}:${disposition}`).replace(/-/g, '').slice(0, 20),
    evaluationMode: 'detect',
    disposition,
    decisionSource: source,
    decisiveRuleRef: ruleRef,
    overrideApplied: false,
    matchedRules: ruleRef ? [{ ruleRef, actions: [type] }] : [],
    actions: [{ type, status, reason }],
    explanation:
      source === 'floor'
        ? 'The DLP floor decided: a blocking DLP match is never allowed.'
        : ruleRef
          ? `Rule ${ruleRef} matched and decided ${disposition}.`
          : 'No rule matched; the platform default allowed the message.',
    postDelivery:
      type === 'REJECT'
        ? [
            { type: 'REJECT', status, reason },
            {
              type: 'SENDER_NOTICE',
              status: 'not_applicable',
              reason: outbound ? 'outbound_already_sent' : 'post_delivery_no_bounce',
            },
          ]
        : [{ type, status, reason }],
    evaluatedAt: at,
  };
}

/** Step API-4: the policy columns of a seeded copy (variety for the list and its filters). */
function policyFieldsOf(
  i: number,
  verdict: Detection['verdict'],
  tooLarge: boolean,
  inline: boolean,
  at: string,
): Pick<
  Detection,
  'policyState' | 'policyDisposition' | 'policyTagged' | 'dlpAction' | 'policy' | 'dlp'
> {
  if (tooLarge)
    return {
      policyState: 'not_applicable',
      policyDisposition: null,
      policyTagged: false,
      dlpAction: null,
      policy: null,
      dlp: null,
    };
  if (inline)
    return {
      policyState: 'inline',
      policyDisposition: 'allow',
      policyTagged: false,
      dlpAction: null,
      policy: null,
      dlp: null,
    };
  const rule = 'pol-0193f000-block-list#3/blocked-senders';
  if (i % 7 === 3)
    return {
      policyState: 'evaluated',
      policyDisposition: 'reject',
      policyTagged: false,
      dlpAction: 'block',
      policy: policyEvaluationOf('reject', 'floor', null, at),
      dlp: { action: 'block', verdict: 'violation', categories: ['payment_card'] },
    };
  const disposition: Detection['policyDisposition'] =
    verdict === 'phishing' || verdict === 'malware'
      ? 'quarantine'
      : i % 13 === 2
        ? 'require_approval'
        : 'allow';
  return {
    policyState: 'evaluated',
    policyDisposition: disposition,
    policyTagged: verdict === 'spam' || verdict === 'suspicious',
    dlpAction: null,
    policy: policyEvaluationOf(
      disposition,
      disposition === 'allow' ? 'platform_default' : 'tenant_rule',
      disposition === 'allow' ? null : rule,
      at,
    ),
    dlp: null,
  };
}

/** API-mode domains of the organization (effective api or hybrid, live). */
function apiDomains(organizationId: string) {
  return liveDomains(organizationId).filter(
    (d) => effectiveMode(organizationId, d.configured) !== 'inline',
  );
}

function seedOrg(organizationId: string): OrgApiState {
  const random = new SeededRandom(`${organizationId}:api-mode`);
  const connections = providerConnectionsOf(organizationId);
  const org: OrgApiState = {
    connections: new Map(),
    mailboxes: [],
    detections: [],
    policy: null,
    domainPolicies: new Map(),
    actions: [],
  };
  connections.forEach((c, index) => {
    const grant = c.grants.find((g) => g.profile === MAILBOX_PROFILE[c.provider]);
    const active = grant?.status === 'active';
    org.connections.set(c.id, {
      apiConnectionId: stableUuid(`${c.id}:api-mode`),
      feedsEnabled: active && index === 0,
      feedMode: 'poll',
      feedsEnabledAt: active && index === 0 ? isoAgo(5 * DAY) : null,
      inventoryStatus: active ? 'ok' : 'never',
      inventorySyncedAt: active ? isoAgo(2 * HOUR) : null,
      inventoryRequestedAt: null,
      health: active ? 'degraded' : 'unknown',
      healthChangedAt: active ? isoAgo(DAY) : null,
      throttledUntil: null,
      remediationPaused: false,
      remediationPausedAt: null,
      rowVersion: 3,
    });
  });
  const first = connections[0];
  const domains = apiDomains(organizationId);
  if (first && domains.length > 0) {
    const people = ['ana', 'ben', 'chen', 'dana', 'eli', 'fay', 'gus', 'hana', 'ivo', 'jo'];
    org.mailboxes = people.map((person, i) => {
      const domain = domains[i % domains.length]!;
      const coverage: Mailbox['coverage'] = i === 7 ? 'gap' : i === 9 ? 'out_of_scope' : 'covered';
      return {
        id: stableUuid(`${organizationId}:mailbox:${i}`),
        connectionId: first.id,
        address: `${person}@${domain.name}`,
        domain: { id: domain.id, name: domain.name },
        status: i === 9 ? 'disabled' : 'active',
        coverage,
        coverageChangedAt: isoAgo((i + 1) * HOUR),
        feedStatus: i === 7 ? 'error' : i === 9 ? 'off' : 'active',
        journalLastSeenAt: i % 3 === 0 ? isoAgo(i * 10 * MINUTE + MINUTE) : null,
        lastSyncAt: i === 9 ? null : isoAgo(3 * MINUTE),
        lastErrorCode: i === 7 ? 'rate_budget' : null,
        aliases: i === 0 ? [`a.${person}@${domain.name}`] : [],
        feedStartedAt: isoAgo(5 * DAY),
        notifications: { subscribed: false, expiresAt: null },
        lastChangeAt: isoAgo(20 * MINUTE),
        lastGapAt: null,
        consecutiveFailures: i === 7 ? 3 : 0,
        recentDetections: [],
      };
    });
    org.detections = Array.from({ length: 36 }, (_, i) => {
      const mailbox = org.mailboxes[i % 9]!;
      const receivedAt = isoAgo(i * 47 * MINUTE + random.int(1, 30) * MINUTE);
      const verdict = VERDICTS[i % VERDICTS.length] ?? 'clean';
      const lag = random.int(20, 900) * 1000;
      const source: Detection['source'] = i % 4 === 0 ? 'graph' : 'journal';
      return {
        id: stableUuid(`${organizationId}:detection:${i}`),
        mailboxId: mailbox.id,
        mailboxAddress: mailbox.address,
        connectionId: first.id,
        source,
        seenJournal: source === 'journal' || i % 8 === 0,
        seenApi: source === 'graph',
        status: i === 5 ? 'too_large' : 'scanned',
        verdict: i === 5 ? null : verdict,
        riskScore: i === 5 ? null : verdict === 'clean' ? random.int(0, 120) : random.int(400, 980),
        verdictAuthority: i % 11 === 0 ? 'inline' : 'copy',
        receivedAt,
        providerDeliveredAt: new Date(Date.parse(receivedAt) - lag / 2).toISOString(),
        verdictAt: i === 5 ? null : new Date(Date.parse(receivedAt) + lag / 2).toISOString(),
        lagMs: i === 5 ? null : lag,
        subject: null,
        subjectMasked: true,
        headerFrom: `s•••@sender-${i % 6}.example.test`,
        direction: i % 9 === 4 ? 'internal' : 'inbound',
        verdictRevision: i === 6 ? 1 : 0,
        clawbacks: [],
        deliveredBasis: source === 'graph' ? 'graph_received' : 'received_header',
        reasonCodes: verdict === 'clean' ? [] : ['url.reputation_malicious', 'auth.dmarc_fail'],
        remediationState: 'none',
        remediationAction: null,
        remediationId: null,
        quarantineEntryId: null,
        ...policyFieldsOf(i, verdict, i === 5, i % 11 === 0, receivedAt),
      };
    });
    // Step API-4 A6: two outbound DLP detections on a sender's mailbox (never remediated).
    for (const n of [0, 1]) {
      const mailbox = org.mailboxes[n + 1]!;
      const receivedAt = isoAgo((n * 5 + 3) * HOUR);
      const action = n === 0 ? 'block' : 'quarantine';
      org.detections.push({
        id: stableUuid(`${organizationId}:detection:outbound:${n}`),
        mailboxId: mailbox.id,
        mailboxAddress: mailbox.address,
        connectionId: first.id,
        source: 'journal',
        seenJournal: true,
        seenApi: false,
        status: 'scanned',
        verdict: 'dlp_violation',
        riskScore: 640,
        verdictAuthority: 'copy',
        receivedAt,
        providerDeliveredAt: null,
        verdictAt: receivedAt,
        lagMs: null,
        subject: null,
        subjectMasked: true,
        headerFrom: mailbox.address,
        direction: 'outbound',
        verdictRevision: 0,
        clawbacks: [],
        deliveredBasis: 'ingest',
        reasonCodes: ['dlp.payment_card'],
        remediationState: 'skipped',
        remediationAction: null,
        remediationId: null,
        quarantineEntryId: null,
        policyState: 'evaluated',
        policyDisposition: action === 'block' ? 'reject' : 'quarantine',
        policyTagged: false,
        dlpAction: action,
        policy: policyEvaluationOf(
          action === 'block' ? 'reject' : 'quarantine',
          'floor',
          null,
          receivedAt,
          true,
        ),
        dlp: { action, verdict: 'violation', categories: ['payment_card'] },
      });
    }
    org.detections.forEach((d, i) => SEARCH_KEYS.set(d.id, searchKeysOf(i)));
    seedRemediations(organizationId, org, first);
    for (const mailbox of org.mailboxes)
      mailbox.recentDetections = org.detections
        .filter((d) => d.mailboxId === mailbox.id)
        .slice(0, 20)
        .map(({ deliveredBasis: _b, reasonCodes: _r, policy: _p, dlp: _d, ...rest }) => rest);
  }
  return org;
}

function orgState(organizationId: string): OrgApiState {
  let org = state.orgs.get(organizationId);
  if (!org) {
    org = seedOrg(organizationId);
    state.orgs.set(organizationId, org);
  }
  // Connections created after the seed get their defaults lazily (as the api does).
  for (const c of providerConnectionsOf(organizationId)) {
    if (!org.connections.has(c.id))
      org.connections.set(c.id, {
        apiConnectionId: stableUuid(`${c.id}:api-mode`),
        feedsEnabled: false,
        feedMode: 'poll',
        feedsEnabledAt: null,
        inventoryStatus: 'never',
        inventorySyncedAt: null,
        inventoryRequestedAt: null,
        health: 'unknown',
        healthChangedAt: null,
        throttledUntil: null,
        remediationPaused: false,
        remediationPausedAt: null,
        rowVersion: 1,
      });
  }
  runWorker(org);
  runQuarantineExecutor();
  return org;
}

function coverageOf(mailboxes: readonly Mailbox[], total: number | null) {
  const active = mailboxes.filter((m) => m.status === 'active');
  const covered = active.filter((m) => m.coverage === 'covered').length;
  const gap = active.filter((m) => m.coverage === 'gap').length;
  return {
    covered,
    gap,
    total,
    percent:
      total === null || covered + gap === 0
        ? null
        : Math.floor((covered / (covered + gap)) * 1000) / 10,
  };
}

function failingChecksOf(health: Health): string[] {
  return health === 'degraded'
    ? ['coverage.percent', 'feeds.errors']
    : health === 'failing'
      ? ['mailbox_access.grant']
      : [];
}

function rowOf(organizationId: string, connectionId: string): ConnectionRow | null {
  const connection = providerConnectionsOf(organizationId).find((c) => c.id === connectionId);
  if (!connection) return null;
  const s = orgState(organizationId).connections.get(connection.id)!;
  const grant = connection.grants.find(
    (g) => g.profile === MAILBOX_PROFILE[connection.provider] && g.status !== 'revoked',
  );
  const mailboxes = orgState(organizationId).mailboxes.filter(
    (m) => m.connectionId === connection.id,
  );
  return {
    id: connection.id,
    apiConnectionId: s.apiConnectionId,
    displayName: connection.displayName,
    provider: connection.provider,
    status: connection.status,
    bound: connection.tenantId !== null,
    feedsEnabled: s.feedsEnabled,
    feedMode: s.feedMode,
    feedsEnabledAt: s.feedsEnabledAt,
    inventoryStatus: s.inventoryStatus,
    inventorySyncedAt: s.inventorySyncedAt,
    inventoryRequestedAt: s.inventoryRequestedAt,
    mailboxesTotal:
      s.inventoryStatus === 'ok' ? mailboxes.filter((m) => m.status === 'active').length : null,
    health: { status: s.health, changedAt: s.healthChangedAt },
    throttledUntil: s.throttledUntil,
    lastErrorCode: null,
    remediationPaused: s.remediationPaused,
    remediationPausedAt: s.remediationPausedAt,
    grant: grant
      ? { profile: grant.profile, status: grant.status, authMethod: grant.authMethod }
      : null,
    journalSources:
      connection.provider === 'microsoft_365'
        ? [
            {
              id: stableUuid(`${connection.id}:journal-source`),
              displayName: 'Exchange journal rule (fixture)',
              kind: 'm365_journal',
              status: 'active',
              health: 'healthy',
              verified: true,
            },
          ]
        : [],
    rowVersion: s.rowVersion,
  };
}

function lagOf(seed: number) {
  return {
    p50Seconds1h: 45 + (seed % 3) * 15,
    p95Seconds1h: 240 + (seed % 5) * 60,
    p50Seconds24h: 60,
    p95Seconds24h: 420,
  };
}

function detailOf(organizationId: string, row: ConnectionRow): ConnectionView {
  const mailboxes = orgState(organizationId).mailboxes.filter((m) => m.connectionId === row.id);
  const grantActive = row.grant?.status === 'active';
  const journalOk = row.journalSources.some((j) => j.verified);
  const domains = apiDomains(organizationId).length > 0;
  const step = (
    name: ConnectionView['wizard']['steps'][number]['step'],
    status: ConnectionView['wizard']['steps'][number]['status'],
    blockers: string[] = [],
  ) => ({ step: name, status, blockers });
  const steps = [
    domains ? step('domains', 'done') : step('domains', 'not_started', ['no_api_mode_domain']),
    row.status === 'active' && row.bound
      ? step('connection', 'done')
      : step('connection', 'in_progress', [
          row.bound ? 'connection_not_active' : 'connection_not_bound',
        ]),
    journalOk
      ? step('journal', 'done')
      : step('journal', 'not_started', ['journal_source_missing']),
    grantActive
      ? step('mailbox_access', 'done')
      : step('mailbox_access', 'not_started', ['grant_missing']),
    !row.feedsEnabled
      ? step('feeds', 'skipped')
      : grantActive
        ? step('feeds', 'done')
        : step('feeds', 'blocked', ['mailbox_access']),
    row.health.status === 'healthy' || row.health.status === 'degraded'
      ? step('monitor', 'done')
      : step('monitor', 'in_progress', ['health_unknown']),
  ];
  const next = steps.find(
    (s) => s.status !== 'done' && s.status !== 'skipped' && s.status !== 'blocked',
  );
  const actions: Record<string, string> = {
    domains: 'set_domain_api_mode',
    connection: 'bind_connection',
    journal: 'configure_journal',
    mailbox_access: 'grant_mailbox_access',
    feeds: 'wait_for_feeds',
    monitor: 'review_health',
  };
  return {
    ...row,
    coverage: coverageOf(mailboxes, row.mailboxesTotal),
    wizard: {
      steps,
      nextAction: next ? { step: next.step, action: actions[next.step] ?? next.step } : null,
    },
    healthChecks:
      row.health.status === 'unknown'
        ? []
        : [
            { code: 'connection.active', status: 'pass', evidence: null },
            { code: 'intake.present', status: 'pass', evidence: 'journal source verified' },
            {
              code: 'coverage.percent',
              status: row.health.status === 'degraded' ? 'warn' : 'pass',
              evidence: 'covered 8 of 9 active mailboxes',
            },
            {
              code: 'feeds.errors',
              status: row.health.status === 'degraded' ? 'warn' : 'pass',
              evidence: '1 of 9 feed mailboxes in error',
            },
            { code: 'lag.p95_1h', status: 'pass', evidence: 'p95 300 s' },
          ],
    counters: Array.from({ length: 7 }, (_, i) => ({
      day: isoAgo(i * DAY).slice(0, 10),
      journalCopies: 40 + i * 3,
      feedCopies: row.feedsEnabled ? 12 + i : 0,
      duplicates: row.feedsEnabled ? 30 : 0,
      skippedInternal: 2,
      tooLarge: i === 0 ? 1 : 0,
      providerRequests: row.feedsEnabled ? 900 : 0,
      throttled429: i === 1 ? 2 : 0,
      throttled503: 0,
      providerErrors: 0,
      cursorResets: 0,
      lagCount: 50,
      lagP95Seconds: 300,
    })),
    remediation: summaryOf(organizationId, row.id),
  };
}

const connectionNotFound = () =>
  apiError(404, 'api_mode_connection_not_found', 'API-mode connection not found');

function keyed(request: FixtureRequest, run: () => FixtureResponse): FixtureResponse {
  return idempotent(state.idempotency, request, run);
}

function reasonInvalid(reason: unknown): FixtureResponse | null {
  const text = typeof reason === 'string' ? reason.trim() : '';
  return text.length < 1 || text.length > 500
    ? apiError(400, 'validation_failed', ['reason: 1 to 500 characters'])
    : null;
}

const MODES = new Set(['inline', 'api', 'hybrid']);

function guideOf(row: ConnectionRow): SuccessBody<'ApiModeController_setupGuide_v1'> {
  const m365 = row.provider === 'microsoft_365';
  const permissions = m365
    ? ['Mail.ReadWrite', 'User.Read.All']
    : [
        'https://www.googleapis.com/auth/gmail.modify',
        'https://www.googleapis.com/auth/admin.directory.user.readonly',
      ];
  return {
    schema: 'api-mode-guide/1',
    provider: row.provider,
    connection: { id: row.id, displayName: row.displayName },
    notice:
      'Written for this connection (fixture). Nothing in this guide changes mail flow: the MX records stay with your provider.',
    sections: [
      {
        id: 'overview',
        number: 1,
        title: 'How API mode works',
        paragraphs: [
          'The gateway scans a copy of each delivered message: the journal copy, or the message read from the mailbox when no copy was seen.',
        ],
        steps: [],
      },
      {
        id: 'mailbox-access',
        number: 2,
        title: m365 ? 'Grant mailbox access' : 'Authorize domain-wide delegation',
        paragraphs: ['Grant exactly these permissions to the gateway mailbox app.'],
        steps: [
          {
            id: 'mailbox-access-grant',
            title: m365 ? 'Admin consent' : 'Delegation',
            paragraphs: ['Use the connection page’s mailbox access card.'],
            values: [{ label: 'Permissions', value: permissions.join(', ') }],
          },
        ],
      },
      {
        id: 'revoke',
        number: 3,
        title: 'Revoke',
        paragraphs: [
          'Revoke on the connection page, then remove the app or delegation at the provider.',
        ],
        steps: [],
      },
    ],
    attestations: [],
    permissions,
    generatedAt: new Date().toISOString(),
  };
}

function guideMarkdown(guide: SuccessBody<'ApiModeController_setupGuide_v1'>): string {
  return [
    `# API-mode setup: ${guide.connection.displayName}`,
    '',
    guide.notice,
    '',
    ...guide.sections.flatMap((s) => [`## ${s.number}. ${s.title}`, '', ...s.paragraphs, '']),
  ].join('\n');
}

function isPlatform(permissions: readonly string[]): boolean {
  return permissions.includes('platform:organizations');
}

// ---- step API-2: remediation (R2, R5, R9, R12, R13) -------------------------------------------

const ENTRY_ACTIONS = new Set(['move_quarantine', 'move_junk', 'soft_delete']);
const CONTAINER_OF: Record<string, 'quarantine_folder' | 'junk' | 'deleted_items'> = {
  move_quarantine: 'quarantine_folder',
  move_junk: 'junk',
  soft_delete: 'deleted_items',
};
const REASON_OF_VERDICT: Record<
  string,
  'malware' | 'phishing' | 'spam' | 'bulk' | 'bec' | 'dlp' | 'suspicious' | 'policy'
> = {
  malware: 'malware',
  phishing: 'phishing',
  spam: 'spam',
  bulk: 'bulk',
  bec: 'bec',
  dlp_violation: 'dlp',
  suspicious: 'suspicious',
};

function listView(action: Action): ActionRow {
  return {
    id: action.id,
    action: action.action,
    trigger: action.trigger,
    status: action.status,
    reasonCode: action.reasonCode,
    attempts: action.attempts,
    lastErrorCode: action.lastErrorCode,
    generation: action.generation,
    mailbox: action.mailbox,
    connectionId: action.connectionId,
    detectionId: action.detectionId,
    quarantineEntryId: action.quarantineEntryId,
    createdAt: action.createdAt,
    nextAttemptAt: action.nextAttemptAt,
    completedAt: action.completedAt,
    latencyMs: action.latencyMs,
    clawbackId: action.clawbackId,
  };
}

function newAction(
  detection: Detection,
  input: {
    seed: string;
    action: Action['action'];
    trigger: Action['trigger'];
    status: Action['status'];
    at: string;
    reason?: string | null;
    userId?: string | null;
    ruleId?: string | null;
    clawbackId?: string | null;
  },
): Action {
  const completed = input.status === 'succeeded' || input.status === 'failed';
  const completedAt = completed ? new Date(Date.parse(input.at) + 4_000).toISOString() : null;
  return {
    id: stableUuid(`remediation:${input.seed}`),
    action: input.action,
    trigger: input.trigger,
    status: input.status,
    reasonCode: input.status === 'failed' ? 'provider_unavailable' : null,
    attempts: input.status === 'failed' ? 8 : completed ? 1 : 0,
    lastErrorCode: input.status === 'failed' ? 'provider_unavailable' : null,
    generation: 0,
    mailbox: { id: detection.mailboxId, address: detection.mailboxAddress },
    connectionId: detection.connectionId,
    detectionId: detection.id,
    quarantineEntryId: null,
    createdAt: input.at,
    nextAttemptAt: input.status === 'pending' ? input.at : null,
    completedAt,
    latencyMs: completedAt ? 4_000 : null,
    decision:
      input.trigger === 'policy'
        ? {
            v: 1,
            policy: {
              scope: 'platform_default',
              publicId: null,
              rowVersion: null,
              sha256: sha('p1'),
            },
            mode: 'enforce',
            ruleId: input.ruleId ?? null,
            inputs: {
              verdict: detection.verdict,
              riskScore: detection.riskScore,
              level: (detection.riskScore ?? 0) >= 900 ? 'critical' : 'high',
              hardBlocks: detection.verdict === 'malware' ? ['hb.malware_attachment'] : [],
              verdictAuthority: detection.verdictAuthority,
            },
            policyOutcome: null,
            notes: [],
          }
        : { requestedAction: input.action, reason: input.reason ?? null },
    requestedBy:
      input.trigger === 'policy' || input.trigger === 'system' || input.trigger === 'clawback'
        ? { type: 'system', userId: null }
        : { type: 'user', userId: input.userId ?? null },
    requestReason: input.reason ?? null,
    locateAttempts: completed ? 1 : 0,
    lastHttpStatus: input.status === 'failed' ? 503 : null,
    providerRefs: completed
      ? {
          container: input.status === 'failed' ? null : (CONTAINER_OF[input.action] ?? null),
          before: input.status === 'failed' ? 0 : 1,
          after: input.status === 'succeeded' && input.action !== 'tag' ? 1 : 0,
        }
      : null,
    reverses: null,
    reversedBy: null,
    releaseId: null,
    verdictAt: detection.verdictAt,
    startedAt: completed ? new Date(Date.parse(input.at) + 1_000).toISOString() : null,
    updatedAt: completedAt ?? input.at,
    clawbackId: input.clawbackId ?? null,
  };
}

/** The mailbox entry a succeeded entry-creating action leaves (R9.1). */
function createEntryFor(detection: Detection, action: Action): void {
  if (!ENTRY_ACTIONS.has(action.action)) return;
  const at = action.completedAt ?? new Date().toISOString();
  const entryId = addMailboxEntry({
    key: `${detection.id}:${action.generation}`,
    messageId: stableUuid(`copy-message:${detection.id}`),
    generation: action.generation,
    recipient: detection.mailboxAddress,
    reason: REASON_OF_VERDICT[detection.verdict ?? ''] ?? 'policy',
    riskScore: detection.riskScore,
    hardBlocks: detection.verdict === 'malware' ? ['hb.malware_attachment'] : [],
    receivedAt: detection.receivedAt,
    quarantinedAt: at,
    ruleId:
      action.decision && 'ruleId' in action.decision && action.decision.ruleId
        ? action.decision.ruleId
        : 'manual',
    location: {
      container: CONTAINER_OF[action.action]!,
      mailboxAddress: detection.mailboxAddress,
      provider: 'microsoft_365',
      connectionId: detection.connectionId,
      detectionId: detection.id,
      remediationId: action.id,
      remediationStatus: 'succeeded',
    },
  });
  action.quarantineEntryId = entryId;
  detection.quarantineEntryId = entryId;
}

function applyToDetection(detection: Detection, action: Action): void {
  detection.remediationId = action.id;
  if (action.action === 'restore_inbox' || action.action === 'remove_tag') {
    detection.remediationState =
      action.status === 'succeeded'
        ? 'restored'
        : action.status === 'pending'
          ? 'pending'
          : 'remediated';
    return;
  }
  detection.remediationAction = action.action;
  detection.remediationState =
    action.status === 'succeeded'
      ? 'remediated'
      : action.status === 'failed'
        ? 'failed'
        : action.status === 'skipped'
          ? 'skipped'
          : action.status === 'simulated'
            ? 'simulated'
            : 'pending';
}

/** P1 outcomes of the seeded copies (R2.3) with one failure and one inline-authority skip. */
function seedRemediations(organizationId: string, org: OrgApiState, first: { id: string }): void {
  void first;
  org.detections.forEach((detection, i) => {
    if (detection.status !== 'scanned' || !detection.verdict) return;
    const verdict = detection.verdict;
    if (verdict === 'clean' || verdict === 'unknown' || verdict === 'spam' || verdict === 'bulk')
      return;
    const at = detection.verdictAt ?? detection.receivedAt;
    const seed = `${organizationId}:policy:${i}`;
    let action: Action;
    if (detection.verdictAuthority === 'inline') {
      action = newAction(detection, {
        seed,
        action: 'move_quarantine',
        trigger: 'policy',
        status: 'skipped',
        at,
        ruleId: 'p1-high-confidence-malware-phishing',
      });
      action.reasonCode = 'inline_authority';
    } else if (verdict === 'malware') {
      action = newAction(detection, {
        seed,
        action: 'move_quarantine',
        trigger: 'policy',
        status: 'succeeded',
        at,
        ruleId: 'p1-high-confidence-malware-phishing-hb',
      });
    } else if (verdict === 'phishing') {
      action = newAction(detection, {
        seed,
        action: 'move_quarantine',
        trigger: 'policy',
        status: i === 4 ? 'failed' : 'succeeded',
        at,
        ruleId: 'p1-high-confidence-malware-phishing',
      });
    } else {
      action = newAction(detection, {
        seed,
        action: 'tag',
        trigger: 'policy',
        status: 'succeeded',
        at,
        ruleId: 'p1-suspicious',
      });
    }
    org.actions.push(action);
    if (action.status === 'succeeded') createEntryFor(detection, action);
    applyToDetection(detection, action);
  });
  org.actions.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/** The remediate role: a queued action completes about 8 seconds after it was requested. */
function runWorker(org: OrgApiState, now = Date.now()): void {
  for (const action of org.actions) {
    if (
      action.status !== 'pending' ||
      now - Date.parse(action.nextAttemptAt ?? action.createdAt) < WORKER_DELAY_MS
    )
      continue;
    // Release restores complete with the quarantine release (fixture executor, `restored`).
    if (action.action === 'restore_inbox' && action.releaseId) continue;
    action.status = 'succeeded';
    action.attempts += 1;
    action.locateAttempts = Math.max(action.locateAttempts, 1);
    action.completedAt = new Date(now).toISOString();
    action.updatedAt = action.completedAt;
    action.startedAt = new Date(now - 1_000).toISOString();
    action.nextAttemptAt = null;
    action.latencyMs = now - Date.parse(action.createdAt);
    action.providerRefs = {
      container:
        action.action === 'restore_inbox' ? 'inbox' : (CONTAINER_OF[action.action] ?? null),
      before: 1,
      after: action.action === 'tag' || action.action === 'remove_tag' ? 0 : 1,
    };
    const detection = org.detections.find((d) => d.id === action.detectionId);
    if (!detection) continue;
    if (action.action === 'remove_tag' || action.action === 'restore_inbox') {
      const reversed = org.actions.find((a) => a.id === action.reverses);
      if (reversed) reversed.reversedBy = action.id;
    } else {
      createEntryFor(detection, action);
    }
    applyToDetection(detection, action);
  }
}

registerMailboxHooks({
  seed: (organizationId) => void orgState(organizationId),
  queued: (entryId, releaseId, trigger) => {
    for (const org of state.orgs.values()) {
      const detection = org.detections.find((d) => d.quarantineEntryId === entryId);
      if (!detection) continue;
      const remediation = org.actions.find((a) => a.id === detection.remediationId);
      const action = newAction(detection, {
        seed: `${releaseId}:restore`,
        action: 'restore_inbox',
        trigger,
        status: 'pending',
        at: new Date().toISOString(),
      });
      action.reverses = remediation?.id ?? null;
      action.releaseId = releaseId;
      action.quarantineEntryId = entryId;
      org.actions.unshift(action);
      updateMailboxEntry(entryId, { remediationId: action.id, remediationStatus: 'pending' });
      return;
    }
  },
  restored: (entryId) => {
    for (const org of state.orgs.values()) {
      const action = org.actions.find(
        (a) =>
          a.action === 'restore_inbox' && a.quarantineEntryId === entryId && a.status === 'pending',
      );
      if (!action) continue;
      const now = Date.now();
      action.status = 'succeeded';
      action.attempts = 1;
      action.completedAt = new Date(now).toISOString();
      action.updatedAt = action.completedAt;
      action.nextAttemptAt = null;
      action.latencyMs = now - Date.parse(action.createdAt);
      action.providerRefs = { container: 'inbox', before: 1, after: 1 };
      const reversed = org.actions.find((a) => a.id === action.reverses);
      if (reversed) reversed.reversedBy = action.id;
      updateMailboxEntry(entryId, { remediationStatus: 'succeeded' });
      const detection = org.detections.find((d) => d.id === action.detectionId);
      if (detection) {
        detection.remediationId = action.id;
        detection.remediationState = 'restored';
      }
      return;
    }
  },
});

/** The overview and connection `remediation` block from the fixture actions (R13). */
function summaryOf(organizationId: string, connectionId: string | null): Summary {
  const org = orgState(organizationId);
  const now = Date.now();
  const actions = org.actions.filter((a) => !connectionId || a.connectionId === connectionId);
  const within = (a: Action, ms: number) => Date.parse(a.completedAt ?? a.createdAt) >= now - ms;
  const reversal = (a: Action) => a.action === 'restore_inbox' || a.action === 'remove_tag';
  const count = (ms: number, status: Action['status'], reversals = false) =>
    actions.filter((a) => a.status === status && reversal(a) === reversals && within(a, ms)).length;
  const pending = actions.filter((a) => a.status === 'pending');
  const oldest = pending.reduce<number | null>(
    (min, a) => (min === null ? Date.parse(a.createdAt) : Math.min(min, Date.parse(a.createdAt))),
    null,
  );
  const latencies = actions
    .filter((a) => a.trigger === 'policy' && a.latencyMs !== null && within(a, DAY))
    .map((a) => a.latencyMs!);
  const connections = [...org.connections.entries()].filter(
    ([id]) => !connectionId || id === connectionId,
  );
  return {
    policyMode: org.policy?.mode ?? 'enforce',
    policySource: org.policy ? 'organization' : 'platform_default',
    paused: connections.some(([, c]) => c.remediationPaused),
    succeeded1h: count(HOUR, 'succeeded'),
    failed1h: count(HOUR, 'failed'),
    succeeded24h: count(DAY, 'succeeded'),
    failed24h: count(DAY, 'failed'),
    skipped24h: count(DAY, 'skipped'),
    simulated24h: count(DAY, 'simulated'),
    restores24h: count(DAY, 'succeeded', true),
    throttled24h: connectionId === null || connectionId === connections[0]?.[0] ? 1 : 0,
    backlog: {
      pending: pending.length,
      capped: false,
      oldestPendingAgeSeconds: oldest === null ? null : Math.floor((now - oldest) / 1000),
    },
    latencyAvgSeconds24h:
      latencies.length === 0
        ? null
        : Math.round(latencies.reduce((sum, ms) => sum + ms, 0) / latencies.length / 100) / 10,
    latencyMaxSeconds24h: latencies.length === 0 ? null : Math.max(...latencies) / 1000,
  };
}

const RULE_VERDICTS = new Set([
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
]);
const RULE_LEVELS = ['low', 'medium', 'high', 'critical'];
const RULE_ACTIONS = new Set([
  'move_quarantine',
  'move_junk',
  'tag',
  'soft_delete',
  'hard_delete',
  'none',
]);

/** The strict `api-remediation-policy/1` checks of the api (paths as `document.…`). */
function policyIssues(document: unknown): string[] {
  const issues: string[] = [];
  const doc = document as { v?: unknown; rules?: unknown } | null;
  if (!doc || typeof doc !== 'object' || doc.v !== 1) return ['document.v: must be 1'];
  const allowed = new Set(['v', 'rules', 'remediateScanFailures', 'policyMapping']);
  for (const key of Object.keys(doc))
    if (!allowed.has(key)) issues.push(`document.${key}: unrecognized key`);
  if (!Array.isArray(doc.rules) || doc.rules.length < 1 || doc.rules.length > 16)
    return [...issues, 'document.rules: 1 to 16 rules'];
  const ids = new Set<string>();
  doc.rules.forEach((raw: unknown, i: number) => {
    const rule = raw as { id?: unknown; when?: Record<string, unknown>; action?: unknown };
    const path = `document.rules.${i}`;
    if (typeof rule.id !== 'string' || !/^[a-z0-9_-]{1,48}$/.test(rule.id))
      issues.push(`${path}.id: 1-48 characters a-z, 0-9, - and _`);
    else if (ids.has(rule.id)) issues.push(`${path}.id: duplicate_rule_id`);
    else ids.add(rule.id);
    const when = rule.when ?? {};
    const verdicts = when.verdicts;
    if (
      !Array.isArray(verdicts) ||
      verdicts.length === 0 ||
      verdicts.some((v) => !RULE_VERDICTS.has(String(v)))
    )
      issues.push(`${path}.when.verdicts: 1-9 remediable verdicts`);
    if ('policyDispositions' in when)
      issues.push(`${path}.when.policyDispositions: use_policy_mapping`);
    const level = (value: unknown) =>
      value === undefined ? null : typeof value === 'string' ? RULE_LEVELS.indexOf(value) : -1;
    const min = level(when.minLevel);
    const max = level(when.maxLevel);
    if (min === -1 || max === -1) issues.push(`${path}.when: invalid level`);
    else if (min !== null && max !== null && max < min)
      issues.push(`${path}.when.maxLevel: below minLevel`);
    if (
      when.minScore !== undefined &&
      !(
        Number.isInteger(when.minScore) &&
        (when.minScore as number) >= 0 &&
        (when.minScore as number) <= 1000
      )
    )
      issues.push(`${path}.when.minScore: integer 0-1000`);
    if (!RULE_ACTIONS.has(String(rule.action))) issues.push(`${path}.action: invalid`);
  });
  return issues;
}

/** Shared body checks of the two policy PUTs: reason, mode, document, hard delete. */
function policyBodyError(body: Record<string, unknown>): FixtureResponse | null {
  const invalid = reasonInvalid(body.reason);
  if (invalid) return invalid;
  if (body.mode !== 'detect_only' && body.mode !== 'enforce')
    return apiError(400, 'validation_failed', ['mode: detect_only or enforce']);
  if (body.expectedRowVersion !== null && typeof body.expectedRowVersion !== 'number')
    return apiError(400, 'validation_failed', ['expectedRowVersion: a number or null']);
  const issues = policyIssues(body.document);
  // Step API-4 A4.2: the optional strict mapping (never hard delete).
  const mapping = (body.document as { policyMapping?: unknown } | null)?.policyMapping;
  if (mapping !== undefined) {
    if (typeof mapping !== 'object' || mapping === null)
      issues.push('document.policyMapping: an object');
    else
      for (const [key, value] of Object.entries(mapping)) {
        if (!(MAPPING_KEYS as readonly string[]).includes(key))
          issues.push(`document.policyMapping.${key}: unknown key`);
        else if (
          !MAPPING_ACTIONS.has(String(value)) ||
          (key === 'allow_tagged' && value !== 'tag' && value !== 'none')
        )
          issues.push(`document.policyMapping.${key}: invalid action`);
      }
  }
  if (issues.length > 0) return apiError(400, 'validation_failed', issues);
  // Step API-4 B7: a detect-only period only with mode detect_only, 1 h to 30 days ahead.
  if (body.detectOnly !== undefined && body.detectOnly !== null) {
    const d = body.detectOnly as { until?: unknown; then?: unknown };
    const until = typeof d.until === 'string' ? Date.parse(d.until) : NaN;
    const reason =
      body.mode !== 'detect_only'
        ? 'mode_not_detect_only'
        : Number.isNaN(until) || until < Date.now() + HOUR - MINUTE
          ? 'until_too_soon'
          : until > Date.now() + 30 * DAY + MINUTE
            ? 'until_too_late'
            : d.then !== 'remind' && d.then !== 'enforce'
              ? 'then_invalid'
              : null;
    if (reason)
      return apiError(422, 'api_mode_detect_only_invalid', 'Invalid detect-only period', {
        reason,
      });
  }
  const hardDelete = (body.document as PolicyDocument).rules
    .filter((r) => r.action === 'hard_delete')
    .map((r) => r.id);
  if (hardDelete.length > 0 && !HARD_DELETE_AVAILABLE)
    return apiError(
      422,
      'api_mode_hard_delete_disabled',
      'Hard delete is turned off on this platform',
      { ruleIds: hardDelete.join(',') },
    );
  return null;
}

/** B7: enforce clears the period; a new period restarts it; absent keeps it. */
function nextDetectOnly(
  previous: PolicyRow | null,
  body: Record<string, unknown>,
): PolicyRow['detectOnly'] {
  if (body.mode !== 'detect_only') return null;
  const d = body.detectOnly as { until: string; then: 'remind' | 'enforce' } | null | undefined;
  if (d === null) return null;
  if (d === undefined) return previous?.detectOnly ?? null;
  return { until: d.until, then: d.then, startedAt: new Date().toISOString() };
}

const policyConflict = (current: number | null) =>
  apiError(409, 'api_mode_remediation_policy_conflict', 'expectedRowVersion is not current', {
    currentRowVersion: current,
  });

const remediationNotFound = () =>
  apiError(404, 'api_mode_remediation_not_found', 'Remediation not found');
const detectionNotFound = () =>
  apiError(404, 'api_mode_detection_not_found', 'Detection not found');

function userOf(request: FixtureRequest): string {
  return stableUuid(`user:${request.token ?? 'unknown'}`);
}

// ---- step API-3: what the clawback fixture (api-mode-clawback.ts) needs from this state --------

/** Synthetic search keys of a seeded copy (the registry message's Message-ID, sender, …; C4.2). */
export interface CopySearchKeys {
  readonly messageId: string;
  readonly sender: string;
  readonly subject: string;
  readonly attachmentSha256: readonly string[];
  readonly urls: readonly string[];
}

const SEARCH_KEYS = new Map<string, CopySearchKeys>();

/** Copies of one campaign group (index mod 6) share their keys: a search finds several mailboxes. */
function searchKeysOf(index: number): CopySearchKeys {
  const g = index % 6;
  return {
    messageId: `<campaign-${g}@mail.sender-${g}.example.test>`,
    sender: `billing@sender-${g}.example.test`,
    subject: `Invoice ${1000 + g} overdue`,
    attachmentSha256: g % 2 === 0 ? [sha(`attachment:${g}`)] : [],
    urls: g % 3 === 0 ? [`https://login-${g}.phish.example.test/reset`] : [],
  };
}

export function copySearchKeys(detectionId: string): CopySearchKeys | null {
  return SEARCH_KEYS.get(detectionId) ?? null;
}

type OverviewBody = SuccessBody<'ApiModeController_overview_v1'>;
type OrgBlocks = Pick<OverviewBody, 'internal' | 'clawback' | 'reports'>;
type ConnectionBlocks = Pick<
  OverviewBody['connections'][number],
  'internal' | 'clawback' | 'reports'
>;
interface ClawbackHooks {
  overview: (organizationId: string, connectionId: null) => OrgBlocks;
  connection: (organizationId: string, connectionId: string) => ConnectionBlocks;
  /** Step API-4 A12: the two organization settings of the settings fixture. */
  policyEvaluationEnabled: (organizationId: string) => boolean;
  outboundDetectionEnabled: (organizationId: string) => boolean;
}
const EMPTY_REPORTS = {
  pendingTriage: 0,
  inReview: 0,
  received24h: 0,
  resolved24h: 0,
  oldestPendingAgeSeconds: null,
  reportMailboxes: 0,
};
const hookStore = globalThis as typeof globalThis & { __egDevFixtureClawbackHooks?: ClawbackHooks };

/** The clawback fixture provides the overview's internal, clawback and reports blocks (C13). */
export function registerClawbackHooks(hooks: ClawbackHooks): void {
  hookStore.__egDevFixtureClawbackHooks = hooks;
}

function clawbackHooks(): ClawbackHooks {
  return (
    hookStore.__egDevFixtureClawbackHooks ?? {
      overview: () => ({
        internal: { copies24h: 0, enabled: true },
        clawback: {
          active: 0,
          reviewRequired: 0,
          pendingApproval: 0,
          completed24h: 0,
          targetsSucceeded24h: 0,
          targetsFailed24h: 0,
          oldestActiveAgeSeconds: null,
        },
        reports: EMPTY_REPORTS,
      }),
      connection: () => ({
        internal: { copies24h: 0, enabled: true },
        clawback: { targetsQueued24h: 0, targetsSucceeded24h: 0, targetsFailed24h: 0 },
        reports: EMPTY_REPORTS,
      }),
      policyEvaluationEnabled: () => true,
      outboundDetectionEnabled: () => true,
    }
  );
}

/** The organization's API-mode rows (the worker has run, as on every read). */
export function apiModeStateOf(organizationId: string): {
  mailboxes: Mailbox[];
  detections: Detection[];
  actions: Action[];
  connectionIds: string[];
} {
  const org = orgState(organizationId);
  return {
    mailboxes: org.mailboxes,
    detections: org.detections,
    actions: org.actions,
    connectionIds: [...org.connections.keys()],
  };
}

/** Step API-4: the API-mode view of one 8.2 connection (null = unknown). */
export function apiModeConnectionRow(organizationId: string, connectionId: string) {
  return rowOf(organizationId, connectionId);
}

/** Step API-4 B7, B8, A10: the remediation policy that applies to a domain. */
export function effectiveRemediationOf(
  organizationId: string,
  domainId: string,
): {
  source: 'platform_default' | 'organization' | 'domain';
  mode: PolicyMode;
  presetKey: 'p1' | 'detectOnlyStart' | 'strict' | null;
  detectOnly: ReturnType<typeof detectOnlyView>;
} {
  const org = orgState(organizationId);
  const override = org.domainPolicies.get(domainId) ?? null;
  const row = override ?? org.policy;
  if (!row)
    return { source: 'platform_default', mode: 'enforce', presetKey: 'p1', detectOnly: null };
  const same = (doc: PolicyDocument) =>
    JSON.stringify(doc.rules) === JSON.stringify(row.document.rules);
  const presetKey =
    row.document.policyMapping !== undefined
      ? null
      : same(STRICT)
        ? 'strict'
        : same(P1)
          ? row.mode === 'detect_only'
            ? 'detectOnlyStart'
            : 'p1'
          : null;
  return {
    source: override ? 'domain' : 'organization',
    mode: row.mode,
    presetKey,
    detectOnly: detectOnlyView(organizationId, row, override ? domainId : null),
  };
}

/** Step API-4: the policy-evaluation and outbound settings of the organization. */
export function apiModeSettingsOf(organizationId: string): {
  policyEvaluationEnabled: boolean;
  outboundDetectionEnabled: boolean;
} {
  return {
    policyEvaluationEnabled: clawbackHooks().policyEvaluationEnabled(organizationId),
    outboundDetectionEnabled: clawbackHooks().outboundDetectionEnabled(organizationId),
  };
}

/** API-mode domains of the organization (report mailboxes added by address must be in one). */
export function apiModeDomainsOf(organizationId: string): Array<{ id: string; name: string }> {
  return apiDomains(organizationId).map((d) => ({ id: d.id, name: d.name }));
}

/**
 * A mailbox action queued for a clawback target (C5.4): the `remediate` role of this fixture
 * runs it like any other (about 8 s later) and the mailbox entry follows (R9.1).
 */
export function queueClawbackAction(
  organizationId: string,
  detection: Detection,
  input: {
    action: Action['action'];
    trigger: 'clawback' | 'purge' | 'admin' | 'release';
    clawbackId: string;
    userId: string | null;
    reason: string | null;
    reverses?: string | null;
  },
): Action {
  const org = orgState(organizationId);
  const action = newAction(detection, {
    seed: `${input.clawbackId}:${detection.id}:${input.action}:${Date.now()}`,
    action: input.action,
    trigger: input.trigger,
    status: 'pending',
    at: new Date().toISOString(),
    reason: input.reason,
    userId: input.userId,
    clawbackId: input.clawbackId,
  });
  action.reverses = input.reverses ?? null;
  org.actions.unshift(action);
  applyToDetection(detection, action);
  return action;
}

/** Cancels a pending clawback action (C5.6); the copy goes back to its earlier state. */
export function cancelClawbackAction(organizationId: string, actionId: string): void {
  const org = orgState(organizationId);
  const action = org.actions.find((a) => a.id === actionId);
  if (!action || action.status !== 'pending') return;
  action.status = 'cancelled';
  action.nextAttemptAt = null;
  action.updatedAt = new Date().toISOString();
  const detection = org.detections.find((d) => d.id === action.detectionId);
  if (!detection) return;
  const previous = org.actions.find(
    (a) =>
      a.detectionId === detection.id &&
      a.id !== action.id &&
      a.status === 'succeeded' &&
      a.action !== 'restore_inbox' &&
      a.action !== 'remove_tag',
  );
  detection.remediationState = previous ? 'remediated' : 'none';
  detection.remediationAction =
    previous && previous.action !== 'restore_inbox' && previous.action !== 'remove_tag'
      ? previous.action
      : null;
  detection.remediationId = previous?.id ?? null;
}

/** A discovered mailbox added by address (C9.1: no provider user id yet). */
export function addDiscoveredMailbox(
  organizationId: string,
  address: string,
  domain: { id: string; name: string },
): Mailbox {
  const org = orgState(organizationId);
  const connectionId = [...org.connections.keys()][0] ?? '';
  const mailbox: Mailbox = {
    id: stableUuid(`${organizationId}:mailbox:${address}`),
    connectionId,
    address,
    domain,
    status: 'discovered',
    coverage: 'gap',
    coverageChangedAt: new Date().toISOString(),
    feedStatus: 'off',
    journalLastSeenAt: null,
    lastSyncAt: null,
    lastErrorCode: null,
    aliases: [],
    feedStartedAt: null,
    notifications: { subscribed: false, expiresAt: null },
    lastChangeAt: null,
    lastGapAt: null,
    consecutiveFailures: 0,
    recentDetections: [],
  };
  org.mailboxes.push(mailbox);
  return mailbox;
}

export const fixtures: FixtureHandlers = {
  ProtectionModeController_getOrganization_v1: guarded(
    'ProtectionModeController_getOrganization_v1',
    (request, p) => {
      const id = request.params.id ?? '';
      if (id !== p.organizationId && !isPlatform(p.permissions))
        return apiError(404, 'organization_not_found', 'Organization not found');
      return ok(
        'ProtectionModeController_getOrganization_v1',
        organizationModeView(id, planOf(id)),
      );
    },
  ),
  ProtectionModeController_putOrganization_v1: guarded(
    'ProtectionModeController_putOrganization_v1',
    (request, p) =>
      keyed(request, () => {
        const id = request.params.id ?? '';
        if (id !== p.organizationId && !isPlatform(p.permissions))
          return apiError(404, 'organization_not_found', 'Organization not found');
        const body = (request.body ?? {}) as Partial<
          RequestBody<'ProtectionModeController_putOrganization_v1'>
        >;
        if (!body.mode || !MODES.has(body.mode))
          return apiError(400, 'validation_failed', ['mode: inline, api or hybrid']);
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        const mode = body.mode;
        if (mode !== 'inline' && !entitledPlan(planOf(id)))
          return apiError(403, 'api_mode_not_enabled', 'API-mode protection is not enabled');
        const inheriting = liveDomains(id).filter((d) => d.configured === null);
        const before = organizationModeView(id, planOf(id));
        if (mode === 'api' && before.mode !== 'api') {
          const conflicts = inheriting.filter((d) => d.mxPointsToGateway).slice(0, 20);
          if (conflicts.length > 0)
            return apiError(
              409,
              'protection_mode_mx_points_to_gateway',
              'The MX records of the domain still point to the gateway: choose hybrid, or move the MX records to the provider first',
              { domains: conflicts.map((d) => ({ id: d.id, name: d.name })) },
            );
        }
        const changed = before.mode !== mode;
        if (changed) {
          setOrganizationMode(id, mode);
          refreshDomainModes(id);
        }
        return ok('ProtectionModeController_putOrganization_v1', {
          ...organizationModeView(id, planOf(id)),
          organizationId: id,
          changed,
          inheritingDomains: inheriting.length,
        });
      }),
  ),
  ProtectionModeController_putDomain_v1: guarded(
    'ProtectionModeController_putDomain_v1',
    (request, p) =>
      keyed(request, () => {
        const entry = findDomain(p.organizationId, request.params.domainId);
        if (!entry) return apiError(404, 'domain_not_found', 'Domain not found');
        const body = (request.body ?? {}) as Partial<
          RequestBody<'ProtectionModeController_putDomain_v1'>
        >;
        if (!body.mode || (!MODES.has(body.mode) && body.mode !== 'inherit'))
          return apiError(400, 'validation_failed', ['mode: inline, api, hybrid or inherit']);
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        const configured = body.mode === 'inherit' ? null : body.mode;
        const before = entry.domain.protectionMode;
        const effective = effectiveMode(p.organizationId, configured);
        if (effective !== 'inline' && !entitledPlan(planOf(p.organizationId)))
          return apiError(403, 'api_mode_not_enabled', 'API-mode protection is not enabled');
        if (effective === 'api' && before.effective !== 'api' && entry.checks.mx === 'valid')
          return apiError(
            409,
            'protection_mode_mx_points_to_gateway',
            'The MX records of the domain still point to the gateway: choose hybrid, or move the MX records to the provider first',
            { domains: [{ id: entry.domain.id, name: entry.domain.name }] },
          );
        const changed = before.configured !== configured;
        if (changed) {
          entry.domain = {
            ...entry.domain,
            protectionMode: { ...before, configured, changedAt: new Date().toISOString() },
          };
          refreshDomainModes(p.organizationId);
        }
        const current = findDomain(p.organizationId, request.params.domainId) ?? entry;
        return ok('ProtectionModeController_putDomain_v1', {
          domainId: current.domain.id,
          name: current.domain.name,
          protectionMode: current.domain.protectionMode,
          changed,
        });
      }),
  ),
  ApiModeController_overview_v1: guarded('ApiModeController_overview_v1', (_request, p) => {
    const org = orgState(p.organizationId);
    const view = organizationModeView(p.organizationId, planOf(p.organizationId));
    const rows = providerConnectionsOf(p.organizationId)
      .map((c) => rowOf(p.organizationId, c.id))
      .filter((r): r is ConnectionRow => r !== null);
    const byHealth = { unknown: 0, healthy: 0, degraded: 0, failing: 0 };
    for (const r of rows) byHealth[r.health.status] += 1;
    const inventoried = rows.some((r) => r.inventoryStatus === 'ok');
    return ok('ApiModeController_overview_v1', {
      generatedAt: new Date().toISOString(),
      entitled: view.entitled,
      active: view.active,
      organizationMode: view.mode,
      domainsByEffectiveMode: view.domainsByEffectiveMode,
      coverage: coverageOf(
        org.mailboxes,
        inventoried ? org.mailboxes.filter((m) => m.status === 'active').length : null,
      ),
      connectionsByHealth: byHealth,
      lag: lagOf(0),
      throttling: { events1h: 0, events24h: 2 },
      copiesToday: org.detections.filter((d) => Date.parse(d.receivedAt) > Date.now() - DAY).length,
      remediation: summaryOf(p.organizationId, null),
      ...clawbackHooks().overview(p.organizationId, null),
      // Step API-4 A12: policy evaluation, outbound detections and the mailbox scope.
      policy: {
        enabled: clawbackHooks().policyEvaluationEnabled(p.organizationId),
        evaluated24h: org.detections.filter(
          (d) => d.policyState === 'evaluated' && Date.parse(d.receivedAt) > Date.now() - DAY,
        ).length,
        errors24h: org.detections.filter(
          (d) => d.policyState === 'failed' && Date.parse(d.receivedAt) > Date.now() - DAY,
        ).length,
      },
      outbound: {
        detections24h: org.detections.filter(
          (d) => d.direction === 'outbound' && Date.parse(d.receivedAt) > Date.now() - DAY,
        ).length,
        enabled: clawbackHooks().outboundDetectionEnabled(p.organizationId),
      },
      scope: { excluded: org.mailboxes.filter((m) => m.coverage === 'out_of_scope').length },
      connections: rows.map((r, i) => ({
        id: r.id,
        displayName: r.displayName,
        provider: r.provider,
        health: r.health.status,
        failingChecks: failingChecksOf(r.health.status),
        coverage: coverageOf(
          org.mailboxes.filter((m) => m.connectionId === r.id),
          r.mailboxesTotal,
        ),
        feedsEnabled: r.feedsEnabled,
        feedMode: r.feedMode,
        grantStatus: r.grant?.status ?? null,
        inventoryStatus: r.inventoryStatus,
        lag: lagOf(i),
        throttling: { events1h: 0, events24h: i === 0 ? 2 : 0 },
        copiesToday: i === 0 ? org.detections.length : 0,
        throttledUntil: r.throttledUntil,
        remediation: summaryOf(p.organizationId, r.id),
        ...clawbackHooks().connection(p.organizationId, r.id),
      })),
    });
  }),
  ApiModeController_listConnections_v1: guarded(
    'ApiModeController_listConnections_v1',
    (_request, p) =>
      ok('ApiModeController_listConnections_v1', {
        data: providerConnectionsOf(p.organizationId)
          .map((c) => rowOf(p.organizationId, c.id))
          .filter((r): r is ConnectionRow => r !== null),
      }),
  ),
  ApiModeController_getConnection_v1: guarded(
    'ApiModeController_getConnection_v1',
    (request, p) => {
      const row = rowOf(p.organizationId, request.params.connectionId ?? '');
      return row
        ? ok('ApiModeController_getConnection_v1', detailOf(p.organizationId, row))
        : connectionNotFound();
    },
  ),
  ApiModeController_setupGuide_v1: guarded('ApiModeController_setupGuide_v1', (request, p) => {
    const row = rowOf(p.organizationId, request.params.connectionId ?? '');
    if (!row) return connectionNotFound();
    const guide = guideOf(row);
    const markdown =
      request.query.get('format') === 'markdown' ||
      (request.headers.get('accept') ?? '').includes('text/markdown');
    if (!markdown) return ok('ApiModeController_setupGuide_v1', guide);
    return {
      status: 200,
      body: guideMarkdown(guide),
      headers: {
        'content-type': 'text/markdown; charset=utf-8',
        'content-disposition': `attachment; filename="api-mode-${row.provider.replace('_', '-')}-fixture.md"`,
      },
    };
  }),
  ApiModeController_updateSettings_v1: guarded(
    'ApiModeController_updateSettings_v1',
    (request, p) =>
      keyed(request, () => {
        const row = rowOf(p.organizationId, request.params.connectionId ?? '');
        if (!row) return connectionNotFound();
        const s = orgState(p.organizationId).connections.get(row.id)!;
        const body = (request.body ?? {}) as Partial<
          RequestBody<'ApiModeController_updateSettings_v1'>
        >;
        if (typeof body.feedsEnabled !== 'boolean' || typeof body.expectedRowVersion !== 'number')
          return apiError(400, 'validation_failed', [
            'feedsEnabled and expectedRowVersion required',
          ]);
        if (body.expectedRowVersion !== s.rowVersion)
          return apiError(409, 'api_mode_connection_conflict', 'The settings changed', {
            currentRowVersion: s.rowVersion,
          });
        const mode = body.feedMode ?? s.feedMode;
        if (body.feedsEnabled && row.grant?.status !== 'active')
          return apiError(
            409,
            'api_mode_mailbox_access_required',
            'Feeds need the active mailbox access grant',
          );
        if (mode === 'notify' && row.provider !== 'microsoft_365')
          return apiError(
            422,
            'api_mode_notifications_unavailable',
            'Change notifications exist for Microsoft 365 only',
            { reason: 'provider' },
          );
        if (body.feedsEnabled && !s.feedsEnabled) s.feedsEnabledAt = new Date().toISOString();
        if (!body.feedsEnabled) s.feedsEnabledAt = null;
        if (
          typeof body.remediationPaused === 'boolean' &&
          body.remediationPaused !== s.remediationPaused
        ) {
          s.remediationPaused = body.remediationPaused;
          s.remediationPausedAt = body.remediationPaused ? new Date().toISOString() : null;
        }
        s.feedsEnabled = body.feedsEnabled;
        s.feedMode = mode;
        s.rowVersion += 1;
        return ok('ApiModeController_updateSettings_v1', rowOf(p.organizationId, row.id)!);
      }),
  ),
  ApiModeController_inventorySync_v1: guarded('ApiModeController_inventorySync_v1', (request, p) =>
    keyed(request, () => {
      const row = rowOf(p.organizationId, request.params.connectionId ?? '');
      if (!row) return connectionNotFound();
      if (row.grant?.status !== 'active')
        return apiError(
          409,
          'api_mode_mailbox_access_required',
          'The inventory needs the active mailbox access grant',
        );
      const now = new Date().toISOString();
      orgState(p.organizationId).connections.get(row.id)!.inventoryRequestedAt = now;
      return ok(
        'ApiModeController_inventorySync_v1',
        { connectionId: row.id, inventoryRequestedAt: now, nextInventoryAt: now },
        202,
      );
    }),
  ),
  ApiModeController_listMailboxes_v1: guarded(
    'ApiModeController_listMailboxes_v1',
    (request, p) => {
      const q = request.query;
      const prefix = q.get('q')?.toLowerCase();
      const rows = orgState(p.organizationId)
        .mailboxes.filter(
          (m) =>
            (!q.get('connectionId') || m.connectionId === q.get('connectionId')) &&
            (!q.get('coverage') || m.coverage === q.get('coverage')) &&
            (!q.get('feedStatus') || m.feedStatus === q.get('feedStatus')) &&
            (!q.get('status') || m.status === q.get('status')) &&
            (!q.get('domainId') || m.domain?.id === q.get('domainId')) &&
            (!prefix || m.address.startsWith(prefix)),
        )
        .map(
          ({
            aliases: _a,
            feedStartedAt: _f,
            notifications: _n,
            lastChangeAt: _c,
            lastGapAt: _g,
            consecutiveFailures: _x,
            recentDetections: _r,
            ...row
          }) => row,
        );
      return { status: 200, body: paginate(rows, q) };
    },
  ),
  ApiModeController_getMailbox_v1: guarded('ApiModeController_getMailbox_v1', (request, p) => {
    const mailbox = orgState(p.organizationId).mailboxes.find(
      (m) => m.id === request.params.mailboxId,
    );
    return mailbox
      ? ok('ApiModeController_getMailbox_v1', mailbox)
      : apiError(404, 'api_mode_mailbox_not_found', 'Mailbox not found');
  }),
  ApiModeController_resyncMailbox_v1: guarded('ApiModeController_resyncMailbox_v1', (request, p) =>
    keyed(request, () => {
      const mailbox = orgState(p.organizationId).mailboxes.find(
        (m) => m.id === request.params.mailboxId,
      );
      if (!mailbox) return apiError(404, 'api_mode_mailbox_not_found', 'Mailbox not found');
      const row = rowOf(p.organizationId, mailbox.connectionId);
      if (row?.grant?.status !== 'active')
        return apiError(
          409,
          'api_mode_mailbox_access_required',
          'Resync needs the active mailbox access grant',
        );
      const now = new Date().toISOString();
      mailbox.feedStatus = 'pending';
      return ok(
        'ApiModeController_resyncMailbox_v1',
        { mailboxId: mailbox.id, syncRequestedAt: now },
        202,
      );
    }),
  ),
  ApiModeController_listDetections_v1: guarded(
    'ApiModeController_listDetections_v1',
    (request, p) => {
      const q = request.query;
      const from = q.get('from') ? Date.parse(q.get('from')!) : Date.now() - 7 * DAY;
      const to = q.get('to') ? Date.parse(q.get('to')!) : Date.now() + HOUR;
      if (to - from > 31 * DAY)
        return apiError(400, 'validation_failed', ['to: range longer than 31 days']);
      const rows = orgState(p.organizationId)
        .detections.filter((d) => {
          const at = Date.parse(d.receivedAt);
          return (
            at >= from &&
            at < to &&
            (!q.get('verdict') || d.verdict === q.get('verdict')) &&
            (!q.get('status') || d.status === q.get('status')) &&
            (!q.get('source') || d.source === q.get('source')) &&
            (!q.get('mailboxId') || d.mailboxId === q.get('mailboxId')) &&
            (!q.get('connectionId') || d.connectionId === q.get('connectionId')) &&
            (!q.get('remediationState') ||
              (q.get('remediationState') ?? '').split(',').includes(d.remediationState)) &&
            (!q.get('direction') || (q.get('direction') ?? '').split(',').includes(d.direction)) &&
            (!q.get('policyDisposition') ||
              (q.get('policyDisposition') ?? '')
                .split(',')
                .includes(String(d.policyDisposition))) &&
            (!q.get('dlpAction') ||
              (q.get('dlpAction') ?? '').split(',').includes(String(d.dlpAction)))
          );
        })
        .map(({ deliveredBasis: _b, reasonCodes: _r, policy: _p, dlp: _d, ...row }) => row);
      return { status: 200, body: paginate(rows, q) };
    },
  ),
  ApiModeController_getDetection_v1: guarded('ApiModeController_getDetection_v1', (request, p) => {
    const detection = orgState(p.organizationId).detections.find(
      (d) => d.id === request.params.detectionId,
    );
    return detection
      ? ok('ApiModeController_getDetection_v1', detection)
      : apiError(404, 'api_mode_detection_not_found', 'Detection not found');
  }),
  // ---- step API-2 (R13) ------------------------------------------------------------------------
  ApiModeRemediationController_getPolicy_v1: guarded(
    'ApiModeRemediationController_getPolicy_v1',
    (_request, p) => {
      const org = orgState(p.organizationId);
      return ok('ApiModeRemediationController_getPolicy_v1', {
        organization: org.policy
          ? {
              source: 'organization',
              id: org.policy.id,
              mode: org.policy.mode,
              document: org.policy.document,
              sha256: sha(`${org.policy.id}:${org.policy.rowVersion}`),
              rowVersion: org.policy.rowVersion,
              updatedAt: org.policy.updatedAt,
              effectivePolicyMapping: effectiveMappingOf(org.policy.document),
              detectOnly: detectOnlyView(p.organizationId, org.policy, null),
            }
          : {
              source: 'platform_default',
              id: null,
              mode: 'enforce',
              document: P1,
              sha256: sha('p1'),
              rowVersion: null,
              updatedAt: null,
              effectivePolicyMapping: effectiveMappingOf(P1),
              detectOnly: null,
            },
        domains: [...org.domainPolicies.entries()].map(([domainId, row]) => ({
          id: row.id,
          domainId,
          domainName: row.domainName,
          mode: row.mode,
          document: row.document,
          sha256: sha(`${row.id}:${row.rowVersion}`),
          rowVersion: row.rowVersion,
          updatedAt: row.updatedAt,
          effectivePolicyMapping: effectiveMappingOf(row.document),
          detectOnly: detectOnlyView(p.organizationId, row, domainId),
        })),
        presets: PRESETS,
        hardDeleteAvailable: HARD_DELETE_AVAILABLE,
      });
    },
  ),
  ApiModeRemediationController_putPolicy_v1: guarded(
    'ApiModeRemediationController_putPolicy_v1',
    (request, p) =>
      keyed(request, () => {
        const org = orgState(p.organizationId);
        const body = (request.body ?? {}) as Record<string, unknown>;
        const invalid = policyBodyError(body);
        if (invalid) return invalid;
        const current = org.policy?.rowVersion ?? null;
        if (body.expectedRowVersion !== current) return policyConflict(current);
        const created = org.policy === null;
        org.policy = {
          id: org.policy?.id ?? stableUuid(`${p.organizationId}:remediation-policy`),
          mode: body.mode as PolicyMode,
          document: body.document as PolicyDocument,
          rowVersion: (current ?? 0) + 1,
          updatedAt: new Date().toISOString(),
          detectOnly: nextDetectOnly(org.policy, body),
        };
        return ok('ApiModeRemediationController_putPolicy_v1', {
          scope: 'organization',
          id: org.policy.id,
          domainId: null,
          mode: org.policy.mode,
          document: org.policy.document,
          sha256: sha(`${org.policy.id}:${org.policy.rowVersion}`),
          rowVersion: org.policy.rowVersion,
          updatedAt: org.policy.updatedAt,
          effectivePolicyMapping: effectiveMappingOf(org.policy.document),
          detectOnly: detectOnlyView(p.organizationId, org.policy, null),
          created,
        });
      }),
  ),
  ApiModeRemediationController_putDomainPolicy_v1: guarded(
    'ApiModeRemediationController_putDomainPolicy_v1',
    (request, p) =>
      keyed(request, () => {
        const domain = findDomain(p.organizationId, request.params.domainId);
        if (!domain) return apiError(404, 'domain_not_found', 'Domain not found');
        const org = orgState(p.organizationId);
        const body = (request.body ?? {}) as Record<string, unknown>;
        const invalid = policyBodyError(body);
        if (invalid) return invalid;
        const existing = org.domainPolicies.get(domain.domain.id);
        const current = existing?.rowVersion ?? null;
        if (body.expectedRowVersion !== current) return policyConflict(current);
        const row = {
          id: existing?.id ?? stableUuid(`${domain.domain.id}:remediation-policy`),
          domainName: domain.domain.name,
          mode: body.mode as PolicyMode,
          document: body.document as PolicyDocument,
          rowVersion: (current ?? 0) + 1,
          updatedAt: new Date().toISOString(),
          detectOnly: nextDetectOnly(existing ?? null, body),
        };
        org.domainPolicies.set(domain.domain.id, row);
        return ok('ApiModeRemediationController_putDomainPolicy_v1', {
          scope: 'domain',
          id: row.id,
          domainId: domain.domain.id,
          mode: row.mode,
          document: row.document,
          sha256: sha(`${row.id}:${row.rowVersion}`),
          rowVersion: row.rowVersion,
          updatedAt: row.updatedAt,
          effectivePolicyMapping: effectiveMappingOf(row.document),
          detectOnly: detectOnlyView(p.organizationId, row, domain.domain.id),
          created: existing === undefined,
        });
      }),
  ),
  ApiModeRemediationController_deleteDomainPolicy_v1: guarded(
    'ApiModeRemediationController_deleteDomainPolicy_v1',
    (request, p) =>
      keyed(request, () => {
        const domain = findDomain(p.organizationId, request.params.domainId);
        if (!domain) return apiError(404, 'domain_not_found', 'Domain not found');
        orgState(p.organizationId).domainPolicies.delete(domain.domain.id);
        return { status: 204 };
      }),
  ),
  ApiModeRemediationController_list_v1: guarded(
    'ApiModeRemediationController_list_v1',
    (request, p) => {
      const q = request.query;
      const from = q.get('from') ? Date.parse(q.get('from')!) : Date.now() - 7 * DAY;
      const to = q.get('to') ? Date.parse(q.get('to')!) : Date.now() + HOUR;
      if (to - from > 31 * DAY)
        return apiError(400, 'validation_failed', ['to: range longer than 31 days']);
      const inList = (name: string, value: string | null) =>
        !q.get(name) || (q.get(name) ?? '').split(',').includes(value ?? '');
      const rows = orgState(p.organizationId)
        .actions.filter((a) => {
          const at = Date.parse(a.createdAt);
          return (
            at >= from &&
            at < to &&
            inList('status', a.status) &&
            inList('action', a.action) &&
            inList('trigger', a.trigger) &&
            inList('mailboxId', a.mailbox.id) &&
            inList('connectionId', a.connectionId) &&
            inList('detectionId', a.detectionId)
          );
        })
        .map(listView);
      return { status: 200, body: paginate(rows, q) };
    },
  ),
  ApiModeRemediationController_detail_v1: guarded(
    'ApiModeRemediationController_detail_v1',
    (request, p) => {
      const action = orgState(p.organizationId).actions.find(
        (a) => a.id === request.params.remediationId,
      );
      return action ? ok('ApiModeRemediationController_detail_v1', action) : remediationNotFound();
    },
  ),
  ApiModeRemediationController_retry_v1: guarded(
    'ApiModeRemediationController_retry_v1',
    (request, p) =>
      keyed(request, () => {
        const org = orgState(p.organizationId);
        const action = org.actions.find((a) => a.id === request.params.remediationId);
        if (!action) return remediationNotFound();
        if (action.status !== 'failed')
          return apiError(409, 'api_mode_remediation_not_retryable', 'Only failed actions', {
            cause: action.status,
          });
        if (action.action === 'restore_inbox' && action.quarantineEntryId)
          return apiError(409, 'api_mode_remediation_not_retryable', 'Release the entry again', {
            cause: 'use_quarantine_release',
          });
        if (org.actions.some((a) => a.detectionId === action.detectionId && a.status === 'pending'))
          return apiError(409, 'api_mode_remediation_in_progress', 'An action is pending');
        const now = new Date().toISOString();
        Object.assign(action, {
          status: 'pending',
          attempts: 0,
          locateAttempts: 0,
          lastErrorCode: null,
          lastHttpStatus: null,
          reasonCode: null,
          nextAttemptAt: now,
          completedAt: null,
          latencyMs: null,
          updatedAt: now,
        } satisfies Partial<Action>);
        const detection = org.detections.find((d) => d.id === action.detectionId);
        if (detection) applyToDetection(detection, action);
        return ok('ApiModeRemediationController_retry_v1', listView(action), 202);
      }),
  ),
  ApiModeRemediationController_remediate_v1: guarded(
    'ApiModeRemediationController_remediate_v1',
    (request, p) =>
      keyed(request, () => {
        const org = orgState(p.organizationId);
        const detection = org.detections.find((d) => d.id === request.params.detectionId);
        if (!detection) return detectionNotFound();
        const body = (request.body ?? {}) as Record<string, unknown>;
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        if (body.action === 'hard_delete')
          return apiError(422, 'api_mode_hard_delete_not_manual', 'Hard delete is never manual');
        if (!['move_quarantine', 'move_junk', 'tag', 'soft_delete'].includes(String(body.action)))
          return apiError(400, 'validation_failed', ['action: a manual mailbox action']);
        if (detection.status !== 'scanned' && detection.status !== 'scan_failed')
          return apiError(409, 'api_mode_detection_not_remediable', 'Not scanned', {
            status: detection.status,
          });
        if (rowOf(p.organizationId, detection.connectionId)?.grant?.status !== 'active')
          return apiError(409, 'api_mode_mailbox_access_required', 'Mailbox access required');
        if (org.actions.some((a) => a.detectionId === detection.id && a.status === 'pending'))
          return apiError(409, 'api_mode_remediation_in_progress', 'An action is pending');
        if (
          detection.remediationState === 'remediated' &&
          detection.remediationAction === body.action
        )
          return apiError(409, 'api_mode_remediation_already_applied', 'Already applied', {
            action: String(body.action),
          });
        const action = newAction(detection, {
          seed: `${detection.id}:admin:${Date.now()}`,
          action: body.action as Action['action'],
          trigger: 'admin',
          status: 'pending',
          at: new Date().toISOString(),
          reason: String(body.reason).trim(),
          userId: userOf(request),
        });
        org.actions.unshift(action);
        applyToDetection(detection, action);
        return ok(
          'ApiModeRemediationController_remediate_v1',
          { detectionId: detection.id, remediation: listView(action) },
          202,
        );
      }),
  ),
  ApiModeRemediationController_restore_v1: guarded(
    'ApiModeRemediationController_restore_v1',
    (request, p) =>
      keyed(request, () => {
        const org = orgState(p.organizationId);
        const detection = org.detections.find((d) => d.id === request.params.detectionId);
        if (!detection) return detectionNotFound();
        const body = (request.body ?? {}) as Record<string, unknown>;
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        if (detection.remediationState !== 'remediated')
          return apiError(409, 'api_mode_nothing_to_restore', 'Nothing to restore', {
            remediationState: detection.remediationState,
          });
        if (detection.remediationAction === 'hard_delete')
          return apiError(409, 'api_mode_restore_not_possible', 'Cannot be restored', {
            cause: 'hard_delete',
          });
        const reason = String(body.reason).trim();
        if (detection.remediationAction === 'tag') {
          const action = newAction(detection, {
            seed: `${detection.id}:remove-tag:${Date.now()}`,
            action: 'remove_tag',
            trigger: 'admin',
            status: 'pending',
            at: new Date().toISOString(),
            reason,
            userId: userOf(request),
          });
          action.reverses = detection.remediationId;
          org.actions.unshift(action);
          applyToDetection(detection, action);
          return ok(
            'ApiModeRemediationController_restore_v1',
            {
              detectionId: detection.id,
              via: 'mailbox_action',
              remediation: listView(action),
              release: null,
            },
            202,
          );
        }
        if (!p.permissions.includes('quarantine:release'))
          return apiError(403, 'quarantine_permission_required', 'quarantine:release required');
        if (!detection.quarantineEntryId)
          return apiError(409, 'api_mode_restore_not_possible', 'Cannot be restored', {
            cause: 'entry_missing',
          });
        const released = releaseMailboxEntry(detection.quarantineEntryId, request, reason);
        if (released.status >= 300) return released;
        return ok(
          'ApiModeRemediationController_restore_v1',
          {
            detectionId: detection.id,
            via: 'quarantine_release',
            remediation: null,
            release: released.body as NonNullable<
              SuccessBody<'ApiModeRemediationController_restore_v1'>['release']
            >,
          },
          202,
        );
      }),
  ),
};

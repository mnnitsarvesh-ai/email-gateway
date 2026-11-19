/**
 * Step 8.4 (§10.6): synthetic account takeover data of the e2e tenants, written through the
 * libraries' transactional stores (`AtoStore` / `IncidentStore` with the ATO category handler,
 * as the ato-worker's detect role and the api do): the feature `ato_detection` enabled for the
 * two e2e organizations only (D21), the learning period ended, mailbox accounts with auth events
 * and signals, rescored, and incidents opened by the store's incident policy.
 *
 * The plan below states each account's expected score, level and incident severity from the
 * D11 arithmetic of the design (fresh signals, default weights and settings), so the dashboard
 * spec compares the api's figures with values computed independently of the api. Addresses are
 * the tenants' own `.test` names; IPs are documentation ranges (RFC 5737). Nothing here is used
 * by production code.
 */
import { createHash, randomUUID } from 'node:crypto';
import {
  AtoStore,
  atoIncidentHandler,
  ruleByCode,
  type SignalCandidate,
} from '@email-gateway/ato-detection';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import { IncidentCategoryRegistry, IncidentStore } from '@email-gateway/security-incidents';

type Tx = Prisma.TransactionClient;

/** ATO and security-incident tables in delete order (cleanup.ts). */
export const ATO_TABLES = [
  'ato_response_action_logs',
  'ato_response_actions',
  'ato_smtp_restrictions',
  'ato_incident_details',
  'security_incident_links',
  'security_incident_events',
  'security_incidents',
  'ato_trusted_contexts',
  'ato_risk_overrides',
  'ato_risk_signals',
  'ato_risk_scores',
  'ato_auth_events',
  'ato_account_activity_daily',
  'ato_account_baselines',
  'ato_account_identities',
  'ato_provider_integrations',
  'ato_accounts',
  'ato_settings_versions',
  'ato_settings',
] as const;

/** Partitioned ATO tables and their partition columns (docs/database/partitioning.md). */
export const ATO_PARTITION_COLUMNS: Record<string, string> = {
  ato_auth_events: 'occurred_at',
  ato_account_activity_daily: 'day_start',
  ato_risk_signals: 'detected_at',
  ato_risk_scores: 'computed_at',
};

export interface AtoAccountPlan {
  key: string;
  local: string;
  codes: string[];
  /** Expected score, level and incident severity (D11 arithmetic, fresh signals, defaults). */
  score: number;
  level: 'low' | 'medium' | 'high' | 'critical';
  incident: 'high' | 'critical' | null;
  failures: number;
  successes: number;
}

/**
 * D11: P1 45 (strong) + O1 25 + X1 40 → 110 → 100 critical (strong floor 60 not needed);
 * P1 alone → 45, strong floor → 60 high (≥ incident threshold 50 → incident, severity high);
 * C1 alone (weak) → 8 low; no signal → 0 low.
 */
export const ALPHA_ATO_PLAN: readonly AtoAccountPlan[] = [
  {
    key: 'victim',
    local: 'ato-victim',
    codes: [
      'ato.content.phishing_sent',
      'ato.outbound.volume_spike',
      'ato.correlation.login_then_outbound',
    ],
    score: 100,
    level: 'critical',
    incident: 'critical',
    failures: 3,
    successes: 1,
  },
  {
    key: 'traveller',
    local: 'ato-traveller',
    codes: ['ato.content.phishing_sent'],
    score: 60,
    level: 'high',
    incident: 'high',
    failures: 0,
    successes: 1,
  },
  {
    key: 'quiet',
    local: 'ato-quiet',
    codes: ['ato.access.new_ip_prefix'],
    score: 8,
    level: 'low',
    incident: null,
    failures: 0,
    successes: 1,
  },
  {
    key: 'clean1',
    local: 'ato-clean1',
    codes: [],
    score: 0,
    level: 'low',
    incident: null,
    failures: 0,
    successes: 0,
  },
  {
    key: 'clean2',
    local: 'ato-clean2',
    codes: [],
    score: 0,
    level: 'low',
    incident: null,
    failures: 0,
    successes: 0,
  },
];

export const BETA_ATO_PLAN: readonly AtoAccountPlan[] = [
  {
    key: 'beta-victim',
    local: 'ato-beta-victim',
    codes: [
      'ato.content.phishing_sent',
      'ato.outbound.volume_spike',
      'ato.correlation.login_then_outbound',
    ],
    score: 100,
    level: 'critical',
    incident: 'critical',
    failures: 0,
    successes: 1,
  },
];

const LOGIN_CATEGORIES = new Set(['authentication', 'access_context', 'geography', 'threat_intel']);
const OUTBOUND_CATEGORIES = new Set(['outbound_behaviour', 'outbound_content']);

/** The dashboard figures of a plan, computed without the api (the spec compares them). */
export function expectAtoDashboard(plan: readonly AtoAccountPlan[]) {
  const category = (code: string) => ruleByCode(code)?.category ?? '';
  return {
    monitored: plan.length,
    highRisk: plan.filter((a) => a.level === 'high' || a.level === 'critical').length,
    criticalRisk: plan.filter((a) => a.level === 'critical').length,
    activeIncidents: plan.filter((a) => a.incident).length,
    criticalIncidents: plan.filter((a) => a.incident === 'critical').length,
    failedLogins: plan.reduce((n, a) => n + a.failures, 0),
    suspiciousLogins: plan.flatMap((a) => a.codes).filter((c) => LOGIN_CATEGORIES.has(category(c)))
      .length,
    suspiciousOutbound: plan
      .flatMap((a) => a.codes)
      .filter((c) => OUTBOUND_CATEGORIES.has(category(c))).length,
  };
}

export interface SeededAtoAccount {
  key: string;
  accountId: string;
  address: string;
  incidentId: string | null;
}

const hex64 = (label: string) => createHash('sha256').update(label).digest('hex');

function candidate(code: string): SignalCandidate {
  const rule = ruleByCode(code);
  if (!rule) throw new Error(`unknown ATO rule ${code}`);
  return {
    code,
    category: rule.category,
    strength: rule.strength,
    weight: rule.defaultWeight,
    dedupeKey: hex64(`${code}|${randomUUID()}`),
    dedupeWindowMinutes: 60,
    evidence: { count: 1 },
    sourceKind: 'window',
    sourceRef: null,
    messageRef: null,
    authEventRef: null,
    informational: false,
  };
}

/** The libraries' stores, wired as the ato-worker wires them (no automation is run here). */
function stores(): AtoStore {
  // eslint-disable-next-line prefer-const -- the two stores reference each other
  let store: AtoStore;
  const incidents = new IncidentStore({
    registry: new IncidentCategoryRegistry([atoIncidentHandler({ store: () => store })]),
  });
  store = new AtoStore({
    incidents,
    config: {
      approvalTtlHours: 24,
      automatedResponsesEnabled: true,
      maxAutomatedPerOrgPerHour: 10,
      maxActiveRestrictionsPerOrg: 500,
    },
  });
  return store;
}

async function seedOrganization(
  p: PrismaClient,
  store: AtoStore,
  organizationId: bigint,
  domain: string,
  plan: readonly AtoAccountPlan[],
): Promise<SeededAtoAccount[]> {
  await p.organizationFeature.upsert({
    where: { organizationId_featureKey: { organizationId, featureKey: 'ato_detection' } },
    create: { organizationId, featureKey: 'ato_detection', enabled: true },
    update: { enabled: true },
  });
  const tx = <T>(fn: (t: Tx) => Promise<T>) =>
    p.$transaction(fn, { timeout: 120_000, maxWait: 30_000 });
  await tx((t) => store.ensureSettings(t, organizationId));
  // The learning period has ended (baseline-relative signals count, D9).
  await p.atoSetting.update({
    where: { organizationId },
    data: { learningStartedAt: new Date(Date.now() - 60 * 86_400_000) },
  });
  const out: SeededAtoAccount[] = [];
  for (const [i, a] of plan.entries()) {
    const address = `${a.local}@${domain}`;
    const now = Date.now();
    const account = await tx((t) =>
      store.ensureAccount(t, {
        organizationId,
        subject: { kind: 'mailbox', address },
        at: new Date(now - 20 * 86_400_000),
      }),
    );
    const events: Array<{ id: bigint; occurredAt: Date }> = [];
    for (let n = 0; n < a.failures + a.successes; n += 1) {
      const outcome = n < a.failures ? 'failure' : 'success';
      const occurredAt = new Date(now - (30 - n) * 60_000 - i * 1000);
      const event = await tx((t) =>
        store.recordAuthEvent(t, {
          organizationId,
          accountId: account.id,
          source: 'portal_login',
          channel: 'portal',
          outcome,
          failureCode: outcome === 'failure' ? 'invalid_password' : null,
          occurredAt,
          ip: `203.0.113.${40 + i}`,
          ipPrefix: '203.0.113.0/24',
          geo: null,
          reputation: null,
          device: { hash: hex64(`device:${a.key}`).slice(0, 16), label: 'Firefox on Linux' },
          mechanism: null,
          sourceRef: null,
          dedupeKey: hex64(`${organizationId}|${a.key}|${n}|${randomUUID()}`),
        }),
      );
      events.push({ id: event.id, occurredAt: event.occurredAt });
    }
    let incidentId: string | null = null;
    if (a.codes.length > 0) {
      const result = await tx(async (t) => {
        const settings = await store.ensureSettings(t, organizationId);
        const [locked] = await store.lockAccounts(t, organizationId, [account.id]);
        const recorded = await store.recordSignals(t, {
          organizationId,
          account: locked!,
          candidates: a.codes.map(candidate),
          settingsVersion: settings.version,
          at: new Date(),
        });
        const rescore = await store.rescore(t, {
          organizationId,
          accountId: account.id,
          trigger: 'signal',
          settings,
        });
        const policy = await store.applyIncidentPolicy(t, {
          organizationId,
          accountId: account.id,
          rescore,
          settings,
          evidence: {
            signals: recorded.created.map((s) => ({ id: s.id, detectedAt: s.detectedAt })),
            authEvents: events,
            messages: [],
            codes: recorded.created.map((s) => s.ruleCode),
          },
          newStrongSignal: recorded.created.some((s) => s.strength === 'strong'),
          context: { hasAtoPolicyRule: false, providerActions: new Set<string>() },
        });
        return { rescore, policy };
      });
      if (result.rescore.result.score !== a.score) {
        throw new Error(
          `ATO seed ${a.key}: score ${result.rescore.result.score}, plan ${a.score} (D11 arithmetic)`,
        );
      }
      incidentId = result.policy.incident?.publicId ?? null;
      if (Boolean(incidentId) !== Boolean(a.incident)) {
        throw new Error(
          `ATO seed ${a.key}: incident ${incidentId ?? 'none'}, plan ${a.incident ?? 'none'}`,
        );
      }
    }
    out.push({ key: a.key, accountId: account.publicId, address, incidentId });
  }
  return out;
}

export interface AtoSeedResult {
  alpha: SeededAtoAccount[];
  beta: SeededAtoAccount[];
}

/** Seeds both e2e tenants (alpha: the plan above; beta: one critical incident, isolation target). */
export async function seedAto(
  p: PrismaClient,
  orgs: { alpha: { id: bigint; domain: string }; beta: { id: bigint; domain: string } },
): Promise<AtoSeedResult> {
  const store = stores();
  return {
    alpha: await seedOrganization(p, store, orgs.alpha.id, orgs.alpha.domain, ALPHA_ATO_PLAN),
    beta: await seedOrganization(p, store, orgs.beta.id, orgs.beta.domain, BETA_ATO_PLAN),
  };
}

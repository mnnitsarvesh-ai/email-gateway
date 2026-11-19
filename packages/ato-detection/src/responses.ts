/**
 * Responses (step 8.4 D13, ADR-0072): the catalogue with impact and rollback, the response state
 * machine, recommendations per account and incident, the automation decision with every guard
 * reason, and the dedupe hash of one non-terminal action per (incident, type, target).
 */
import { createHash } from 'node:crypto';
import {
  atoRiskLevelRank,
  type AtoAccountKind,
  type AtoRiskLevel,
} from '@email-gateway/security-contracts';
import type { ResponseImpact, ResponseStatus, SignalCategory, SignalStrength } from './taxonomy';

export const GATEWAY_ACTION_TYPES = [
  'alert_tenant_admins',
  'notify_soc',
  'escalate_investigation',
  'restrict_smtp_sending',
  'block_smtp_auth',
] as const;
export const PROVIDER_ACTION_TYPES = [
  'revoke_sessions',
  'require_mfa',
  'require_password_reset',
  'suspend_account',
  'remove_forwarding_rule',
  'revoke_oauth_grant',
] as const;
export type GatewayActionType = (typeof GATEWAY_ACTION_TYPES)[number];
export type ProviderActionType = (typeof PROVIDER_ACTION_TYPES)[number];

export const RESPONSE_ACTION_TYPES = [
  ...GATEWAY_ACTION_TYPES,
  'record_manual_action',
  ...PROVIDER_ACTION_TYPES,
] as const;
export type ResponseActionType = (typeof RESPONSE_ACTION_TYPES)[number];

export interface ResponseCatalogueEntry {
  type: ResponseActionType;
  /** `gateway` (inline), `manual` (attested) or `provider` (through the port, 8.5). */
  provider: 'gateway' | 'manual' | 'provider';
  impact: ResponseImpact;
  /** `none`, `lift` (gateway restriction) or `provider` (provider-dependent). */
  rollback: 'none' | 'lift' | 'provider';
}

/** `RESPONSE_CATALOGUE` (D13 table). `block_smtp_auth` is medium for a connector + IP scope. */
export const RESPONSE_CATALOGUE: Readonly<Record<ResponseActionType, ResponseCatalogueEntry>> =
  Object.freeze({
    alert_tenant_admins: {
      type: 'alert_tenant_admins',
      provider: 'gateway',
      impact: 'low',
      rollback: 'none',
    },
    notify_soc: { type: 'notify_soc', provider: 'gateway', impact: 'low', rollback: 'none' },
    escalate_investigation: {
      type: 'escalate_investigation',
      provider: 'gateway',
      impact: 'low',
      rollback: 'none',
    },
    restrict_smtp_sending: {
      type: 'restrict_smtp_sending',
      provider: 'gateway',
      impact: 'high',
      rollback: 'lift',
    },
    block_smtp_auth: {
      type: 'block_smtp_auth',
      provider: 'gateway',
      impact: 'high',
      rollback: 'lift',
    },
    record_manual_action: {
      type: 'record_manual_action',
      provider: 'manual',
      impact: 'low',
      rollback: 'none',
    },
    revoke_sessions: {
      type: 'revoke_sessions',
      provider: 'provider',
      impact: 'medium',
      rollback: 'none',
    },
    require_mfa: {
      type: 'require_mfa',
      provider: 'provider',
      impact: 'medium',
      rollback: 'provider',
    },
    require_password_reset: {
      type: 'require_password_reset',
      provider: 'provider',
      impact: 'high',
      rollback: 'none',
    },
    suspend_account: {
      type: 'suspend_account',
      provider: 'provider',
      impact: 'high',
      rollback: 'provider',
    },
    remove_forwarding_rule: {
      type: 'remove_forwarding_rule',
      provider: 'provider',
      impact: 'medium',
      rollback: 'provider',
    },
    revoke_oauth_grant: {
      type: 'revoke_oauth_grant',
      provider: 'provider',
      impact: 'medium',
      rollback: 'none',
    },
  });

export const isResponseActionType = (value: string): value is ResponseActionType =>
  (RESPONSE_ACTION_TYPES as readonly string[]).includes(value);

/** Action types that may be automated (every catalogue type except `record_manual_action`). */
export const AUTOMATABLE_ACTION_TYPES = RESPONSE_ACTION_TYPES.filter(
  (t): t is Exclude<ResponseActionType, 'record_manual_action'> => t !== 'record_manual_action',
);
export type AutomatableActionType = (typeof AUTOMATABLE_ACTION_TYPES)[number];

/** Target of a response (stored in `ato_response_actions.target`). */
export interface ResponseTarget {
  scope: 'mailbox' | 'connector' | 'connector_ip' | 'account';
  /** Public id of the ATO account. */
  accountPublicId: string;
  connectorId?: string | null;
  /** SHA-256 of the mailbox address (never the address itself). */
  mailboxSha256?: string | null;
  cidr?: string | null;
}

/** Impact of an action for a target (block_smtp_auth on connector + IP is medium, D13). */
export function impactFor(
  type: ResponseActionType,
  target: Pick<ResponseTarget, 'scope'>,
): ResponseImpact {
  if (type === 'block_smtp_auth' && target.scope === 'connector_ip') return 'medium';
  return RESPONSE_CATALOGUE[type].impact;
}

/** Whether the action (with its target) supports rollback. */
export function supportsRollback(type: ResponseActionType): boolean {
  return RESPONSE_CATALOGUE[type].rollback !== 'none';
}

/**
 * Response state machine (D13). `executing` only for provider actions awaiting confirmation;
 * `succeeded → rollback_requested` only when the type supports rollback.
 */
export const RESPONSE_TRANSITIONS: Readonly<Record<ResponseStatus, readonly ResponseStatus[]>> =
  Object.freeze({
    pending_approval: ['approved', 'rejected', 'expired', 'cancelled'],
    approved: ['succeeded', 'failed', 'executing', 'unsupported'],
    executing: ['succeeded', 'failed'],
    succeeded: ['rollback_requested'],
    rollback_requested: ['rolled_back', 'rollback_failed'],
    failed: [],
    rejected: [],
    cancelled: [],
    expired: [],
    unsupported: [],
    rolled_back: [],
    rollback_failed: [],
    attested: [],
  });

/** Non-terminal response states (the generated `active_marker` is 1 for them). */
export const ACTIVE_RESPONSE_STATUSES: readonly ResponseStatus[] = [
  'pending_approval',
  'approved',
  'executing',
  'rollback_requested',
];

/** States without an outgoing transition. */
export const isTerminalResponseStatus = (status: ResponseStatus): boolean =>
  RESPONSE_TRANSITIONS[status].length === 0;

/** States that complete a phase and emit `ato.response.completed.v1` (D2). */
export const COMPLETED_RESPONSE_STATUSES = [
  'succeeded',
  'failed',
  'unsupported',
  'rolled_back',
  'rollback_failed',
  'attested',
  'rejected',
  'cancelled',
  'expired',
] as const satisfies readonly ResponseStatus[];

/** Whether `from → to` is allowed for the action type. */
export function canTransitionResponse(
  from: ResponseStatus,
  to: ResponseStatus,
  type: ResponseActionType,
): boolean {
  if (!RESPONSE_TRANSITIONS[from].includes(to)) return false;
  if (to === 'rollback_requested' && !supportsRollback(type)) return false;
  if (to === 'executing' && RESPONSE_CATALOGUE[type].provider !== 'provider') return false;
  return true;
}

/**
 * `responseDedupeHash(incidentId, type, target)`: SHA-256 of `ato-response/1|incident|type|target`
 * (canonical target JSON), so one non-terminal action per (incident, type, target) exists.
 */
export function responseDedupeHash(
  incidentId: bigint | string | null,
  type: ResponseActionType,
  target: ResponseTarget,
): string {
  const canonical = JSON.stringify(
    Object.fromEntries(
      Object.entries(target)
        .filter(([, v]) => v !== undefined && v !== null)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
    ),
  );
  return createHash('sha256')
    .update(
      `ato-response/1|${incidentId === null ? '-' : incidentId.toString()}|${type}|${canonical}`,
      'utf8',
    )
    .digest('hex');
}

// ------------------------------------------------------------------ recommendations

export const RECOMMENDATION_AVAILABILITY = [
  'available',
  'requires_provider',
  'manual',
  'policy',
] as const;
export type RecommendationAvailability = (typeof RECOMMENDATION_AVAILABILITY)[number];

/** Manual follow-ups recommended as `record_manual_action` (existing administration routes). */
export const MANUAL_RECOMMENDATIONS = [
  'rotate_connector_secret',
  'revoke_portal_sessions',
  'reset_portal_mfa',
  'disable_portal_user',
] as const;
export type ManualRecommendation = (typeof MANUAL_RECOMMENDATIONS)[number];

/** Builder preset linked by the `policy` hint (D23). */
export const ATO_POLICY_PRESET = 'outbound_high_risk_account';

export interface Recommendation {
  actionType: ResponseActionType | 'policy_hold_outbound';
  availability: RecommendationAvailability;
  impact: ResponseImpact | null;
  target: ResponseTarget | null;
  /** Code of the reason (a contributing rule code or a level rule). */
  reason: string;
  manual?: ManualRecommendation;
  preset?: string;
}

export interface RecommendationAccount {
  kind: AtoAccountKind;
  publicId: string;
  level: AtoRiskLevel;
  connectorId: string | null;
  mailboxSha256: string | null;
}

export interface Contributor {
  code: string;
  category: SignalCategory;
  strength: SignalStrength;
  /** Client IP of an authentication anomaly (connector + IP block). */
  ip?: string | null;
}

/**
 * `recommendResponses` (D13): mailbox with outbound behaviour/content signals → restrict sending
 * (mailbox) + provider revoke sessions, password reset, remove forwarding (when M1/M2 fired), and the
 * `policy` hint when the tenant has no active rule over `ato.*`; connector with authentication
 * anomalies → block SMTP auth (connector + suspicious IP), with outbound abuse also restrict
 * sending and block auth (connector) and a manual secret rotation; gateway user → manual revoke
 * sessions, reset MFA, disable the user; always alert tenant admins; critical → escalate and
 * notify the SOC.
 */
export function recommendResponses(
  account: RecommendationAccount,
  contributors: readonly Contributor[],
  capabilities: { providerActions: ReadonlySet<string> },
  hasAtoPolicyRule: boolean,
): Recommendation[] {
  const out: Recommendation[] = [];
  const has = (cats: readonly SignalCategory[]) =>
    contributors.find((c) => cats.includes(c.category));
  const top = (cats: readonly SignalCategory[]) => has(cats)?.code ?? 'ato.level';
  const outbound = has(['outbound_behaviour', 'outbound_content']);
  const authAnomaly = has(['authentication', 'access_context', 'geography', 'threat_intel']);
  const base = { accountPublicId: account.publicId };
  const provider = (type: ProviderActionType, reason: string): Recommendation => ({
    actionType: type,
    availability: capabilities.providerActions.has(type) ? 'available' : 'requires_provider',
    impact: RESPONSE_CATALOGUE[type].impact,
    target: { scope: 'account', ...base },
    reason,
  });
  const manual = (m: ManualRecommendation, reason: string): Recommendation => ({
    actionType: 'record_manual_action',
    availability: 'manual',
    impact: 'low',
    target: { scope: 'account', ...base },
    reason,
    manual: m,
  });

  if (account.kind === 'mailbox') {
    if (outbound && account.mailboxSha256) {
      out.push({
        actionType: 'restrict_smtp_sending',
        availability: 'available',
        impact: 'high',
        target: { scope: 'mailbox', ...base, mailboxSha256: account.mailboxSha256 },
        reason: outbound.code,
      });
    }
    if (outbound || authAnomaly) {
      out.push(
        provider(
          'revoke_sessions',
          top([
            'outbound_behaviour',
            'outbound_content',
            'access_context',
            'geography',
            'threat_intel',
            'authentication',
          ]),
        ),
      );
      out.push(
        provider(
          'require_password_reset',
          top([
            'outbound_behaviour',
            'outbound_content',
            'access_context',
            'geography',
            'threat_intel',
            'authentication',
          ]),
        ),
      );
    }
    const forwarding = contributors.find(
      (c) =>
        c.code === 'ato.mailbox.external_forwarding' ||
        c.code === 'ato.mailbox.suspicious_inbox_rule',
    );
    if (forwarding) out.push(provider('remove_forwarding_rule', forwarding.code));
    if (outbound && !hasAtoPolicyRule) {
      out.push({
        actionType: 'policy_hold_outbound',
        availability: 'policy',
        impact: null,
        target: null,
        reason: outbound.code,
        preset: ATO_POLICY_PRESET,
      });
    }
  } else if (account.kind === 'smtp_connector' && account.connectorId) {
    const connector = { scope: 'connector' as const, ...base, connectorId: account.connectorId };
    if (authAnomaly) {
      const ip = contributors.find((c) => c.ip)?.ip ?? null;
      if (ip) {
        out.push({
          actionType: 'block_smtp_auth',
          availability: 'available',
          impact: 'medium',
          target: {
            ...connector,
            scope: 'connector_ip',
            cidr: ip.includes(':') ? `${ip}/128` : `${ip}/32`,
          },
          reason: authAnomaly.code,
        });
      }
    }
    if (outbound) {
      out.push({
        actionType: 'restrict_smtp_sending',
        availability: 'available',
        impact: 'high',
        target: connector,
        reason: outbound.code,
      });
      out.push({
        actionType: 'block_smtp_auth',
        availability: 'available',
        impact: 'high',
        target: connector,
        reason: outbound.code,
      });
    }
    if (authAnomaly || outbound) {
      out.push(manual('rotate_connector_secret', (outbound ?? authAnomaly)!.code));
    }
  } else if (account.kind === 'gateway_user') {
    const reason = contributors[0]?.code ?? 'ato.level';
    out.push(manual('revoke_portal_sessions', reason));
    out.push(manual('reset_portal_mfa', reason));
    out.push(manual('disable_portal_user', reason));
  }

  out.push({
    actionType: 'alert_tenant_admins',
    availability: 'available',
    impact: 'low',
    target: { scope: 'account', ...base },
    reason: 'ato.level',
  });
  if (account.level === 'critical') {
    out.push({
      actionType: 'escalate_investigation',
      availability: 'available',
      impact: 'low',
      target: { scope: 'account', ...base },
      reason: 'ato.level.critical',
    });
    out.push({
      actionType: 'notify_soc',
      availability: 'available',
      impact: 'low',
      target: { scope: 'account', ...base },
      reason: 'ato.level.critical',
    });
  }
  return out;
}

// ------------------------------------------------------------------ automation

export const AUTOMATION_MODES = ['off', 'recommend', 'automatic'] as const;
export type AutomationMode = (typeof AUTOMATION_MODES)[number];

/** Every reason an automatic medium/high action is not executed (counted per reason, D13). */
export const AUTOMATION_GUARD_REASONS = [
  'automation_off',
  'recommend_only',
  'globally_disabled',
  'tenant_monitor_mode',
  'level_below_minimum',
  'no_strong_signal',
  'single_category',
  'account_protected',
  'benign_override',
  'platform_organization',
  'tenant_hourly_cap',
  'platform_hourly_cap',
] as const;
export type AutomationGuardReason = (typeof AUTOMATION_GUARD_REASONS)[number];

export interface AutomationInput {
  impact: ResponseImpact;
  tenantMode: 'monitor' | 'enforce' | 'off';
  automation: { mode: AutomationMode; minLevel: 'high' | 'critical' };
  level: AtoRiskLevel;
  contributors: readonly Pick<Contributor, 'category' | 'strength'>[];
  account: { protected: boolean; benignOverride: boolean; platformOrganization: boolean };
  /** The organization's automatic medium/high actions in the last hour. */
  automaticLastHour: number;
  tenantMaxPerHour: number;
  platformMaxPerHour: number;
  /** `ATO_AUTOMATED_RESPONSES_ENABLED`. */
  globallyEnabled: boolean;
}

export type AutomationDecision =
  { automatic: true } | { automatic: false; reason: AutomationGuardReason };

/**
 * `automationDecision` (D13). Low-impact actions are automatic when their mode is `automatic`
 * (never for the platform organization's accounts beyond notifications: they are low impact).
 * A medium or high-impact action is automatic only when **all** hold: tenant mode `enforce`,
 * the type's mode `automatic`, level ≥ `minLevel`, a strong or correlation contributor **and**
 * contributors from ≥ 2 categories, the account not protected, no benign override, not the platform
 * organization, below the tenant and platform hourly caps, and automation globally enabled.
 */
export function automationDecision(input: AutomationInput): AutomationDecision {
  if (input.automation.mode === 'off') return { automatic: false, reason: 'automation_off' };
  if (input.automation.mode === 'recommend') return { automatic: false, reason: 'recommend_only' };
  if (input.impact === 'low') return { automatic: true };
  if (!input.globallyEnabled) return { automatic: false, reason: 'globally_disabled' };
  if (input.tenantMode !== 'enforce') return { automatic: false, reason: 'tenant_monitor_mode' };
  if (atoRiskLevelRank(input.level) < atoRiskLevelRank(input.automation.minLevel)) {
    return { automatic: false, reason: 'level_below_minimum' };
  }
  const strong = input.contributors.some(
    (c) => c.strength === 'strong' || c.category === 'correlation',
  );
  if (!strong) return { automatic: false, reason: 'no_strong_signal' };
  if (new Set(input.contributors.map((c) => c.category)).size < 2) {
    return { automatic: false, reason: 'single_category' };
  }
  if (input.account.protected) return { automatic: false, reason: 'account_protected' };
  if (input.account.benignOverride) return { automatic: false, reason: 'benign_override' };
  if (input.account.platformOrganization)
    return { automatic: false, reason: 'platform_organization' };
  if (input.automaticLastHour >= input.tenantMaxPerHour) {
    return { automatic: false, reason: 'tenant_hourly_cap' };
  }
  if (input.automaticLastHour >= input.platformMaxPerHour) {
    return { automatic: false, reason: 'platform_hourly_cap' };
  }
  return { automatic: true };
}

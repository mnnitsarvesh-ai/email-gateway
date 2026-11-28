import type { ProtectionModeValue } from '../../../tenancy/api-mode-status.service';

/**
 * Protection by mode (step API-4 A10; docs/plan/steps/38-api-mode-parity-onboarding.md): the
 * static capability matrix of the three protection modes and the per-domain coverage view with
 * its gap codes. Pure and table-tested; counts and codes only (never an address).
 */

export const CAPABILITY_SUPPORT = ['yes', 'no', 'partial'] as const;
export type CapabilitySupport = (typeof CAPABILITY_SUPPORT)[number];

/** The fixed capability codes of A10 (documented; the portal renders a text per code). */
export const PROTECTION_CAPABILITY_CODES = [
  'pre_delivery_blocking',
  'hold_for_review',
  'post_delivery_removal',
  'retroactive_clawback',
  'internal_mail',
  'outbound_dlp_enforce',
  'outbound_dlp_detect',
  'tenant_policies',
  'url_rewriting',
  'message_tagging',
  'user_reports',
  'alerts_webhooks',
] as const;
export type ProtectionCapabilityCode = (typeof PROTECTION_CAPABILITY_CODES)[number];

export interface ProtectionCapability {
  code: ProtectionCapabilityCode;
  inline: CapabilitySupport;
  api: CapabilitySupport;
  hybrid: CapabilitySupport;
  /** A note code explaining a `partial` / `no` cell (null = none). */
  noteCode: string | null;
}

/**
 * `PROTECTION_MODE_CAPABILITIES` (A10): what each mode covers. Inline decides before delivery;
 * API acts on delivered mail (detect mode, mailbox actions); hybrid is inline for mail through
 * the gateway plus the API side (inline decides first, P-I3).
 */
export const PROTECTION_MODE_CAPABILITIES: readonly Readonly<ProtectionCapability>[] =
  Object.freeze(
    (
      [
        ['pre_delivery_blocking', 'yes', 'no', 'yes', 'api_acts_after_delivery'],
        ['hold_for_review', 'yes', 'partial', 'yes', 'api_review_in_quarantine_folder'],
        ['post_delivery_removal', 'partial', 'yes', 'yes', 'inline_release_only'],
        ['retroactive_clawback', 'no', 'yes', 'yes', 'inline_needs_mailbox_access'],
        ['internal_mail', 'partial', 'yes', 'yes', 'inline_sees_relayed_internal_only'],
        ['outbound_dlp_enforce', 'yes', 'no', 'yes', 'api_outbound_already_sent'],
        ['outbound_dlp_detect', 'yes', 'yes', 'yes', null],
        ['tenant_policies', 'yes', 'partial', 'yes', 'api_post_delivery_actions_only'],
        ['url_rewriting', 'yes', 'no', 'yes', 'api_no_message_edits'],
        ['message_tagging', 'yes', 'yes', 'yes', 'inline_headers_api_category_label'],
        ['user_reports', 'no', 'yes', 'yes', 'reports_need_report_mailbox'],
        ['alerts_webhooks', 'yes', 'yes', 'yes', null],
      ] as const
    ).map(([code, inline, api, hybrid, noteCode]) =>
      Object.freeze({ code, inline, api, hybrid, noteCode }),
    ),
  );

/** Gap codes of a domain (A10). */
export const COVERAGE_GAP_CODES = [
  'inline_mx_not_at_gateway',
  'inline_not_active',
  'api_no_connection',
  'api_no_mailbox_access',
  'api_no_intake',
  'api_coverage_gaps',
  'api_mx_points_to_gateway',
  'api_detect_only',
  'api_policy_evaluation_off',
] as const;
export type CoverageGapCode = (typeof COVERAGE_GAP_CODES)[number];

export type MailboxAccess = 'active' | 'missing' | 'revoked';
export type JournalIntake = 'verified' | 'pending' | 'missing';
export type FeedIntake = 'active' | 'partial' | 'off';

/** The facts of one domain the coverage row is computed from. */
export interface DomainCoverageFacts {
  domainId: string;
  name: string;
  status: string;
  effectiveMode: ProtectionModeValue;
  inherited: boolean;
  inboundEnabled: boolean;
  outboundEnabled: boolean;
  /** The latest definitive MX observation points to the gateway; null = never observed. */
  mxPointsToGateway: boolean | null;
  connection: {
    id: string;
    provider: 'microsoft_365' | 'google_workspace';
    health: 'unknown' | 'healthy' | 'degraded' | 'failing';
    disabled: boolean;
    mailboxGrantStatus: string | null;
    journalSources: ReadonlyArray<{ status: string; verified: boolean }>;
    feedsEnabled: boolean;
  } | null;
  scopeKind: 'all' | 'departments' | 'mailboxes';
  mailboxes: {
    /** Non-deleted mailboxes of the domain (null = no inventory yet and none seen). */
    total: number | null;
    inScope: number;
    covered: number;
    gap: number;
    feedsActive: number;
  };
  remediation: {
    source: 'platform_default' | 'organization' | 'domain';
    mode: 'enforce' | 'detect_only';
    detectOnlyUntil: Date | null;
  };
  policyEvaluation: boolean;
  lastCopyAt: Date | null;
}

export const mailboxAccessOf = (grantStatus: string | null): MailboxAccess =>
  grantStatus === 'active' ? 'active' : grantStatus === 'revoked' ? 'revoked' : 'missing';

/** A journal source that verified and is not disabled counts; a pending one is `pending`. */
export function journalIntakeOf(
  sources: ReadonlyArray<{ status: string; verified: boolean }>,
): JournalIntake {
  if (sources.some((s) => s.verified && s.status !== 'disabled')) return 'verified';
  if (sources.some((s) => s.status === 'pending_verification')) return 'pending';
  return 'missing';
}

/** B1 intake rule: feeds count as active on ≥ 90 % of the in-scope mailboxes. */
export const FEEDS_ACTIVE_RATIO = 0.9;

export function feedIntakeOf(enabled: boolean, active: number, inScope: number): FeedIntake {
  if (!enabled) return 'off';
  if (inScope > 0 && active >= Math.ceil(inScope * FEEDS_ACTIVE_RATIO)) return 'active';
  return 'partial';
}

const appliesInline = (mode: ProtectionModeValue) => mode === 'inline' || mode === 'hybrid';
const appliesApi = (mode: ProtectionModeValue) => mode === 'api' || mode === 'hybrid';

/** One `items[]` row of `GET /api-mode/protection-coverage` (A10). */
export function domainCoverage(f: DomainCoverageFacts) {
  const gaps: CoverageGapCode[] = [];
  const inline = appliesInline(f.effectiveMode);
  const api = appliesApi(f.effectiveMode);
  if (inline) {
    if (f.mxPointsToGateway !== true) gaps.push('inline_mx_not_at_gateway');
    if (f.status !== 'active') gaps.push('inline_not_active');
  }
  let apiView = null;
  if (api) {
    const c = f.connection;
    const access = mailboxAccessOf(c?.mailboxGrantStatus ?? null);
    const journal = journalIntakeOf(c?.journalSources ?? []);
    const feeds = feedIntakeOf(
      c?.feedsEnabled ?? false,
      f.mailboxes.feedsActive,
      f.mailboxes.inScope,
    );
    if (c === null || c.disabled) gaps.push('api_no_connection');
    if (access !== 'active') gaps.push('api_no_mailbox_access');
    if (journal !== 'verified' && feeds === 'off') gaps.push('api_no_intake');
    if (f.mailboxes.gap > 0) gaps.push('api_coverage_gaps');
    if (f.effectiveMode === 'api' && f.mxPointsToGateway === true) {
      gaps.push('api_mx_points_to_gateway');
    }
    if (f.remediation.mode === 'detect_only') gaps.push('api_detect_only');
    if (!f.policyEvaluation) gaps.push('api_policy_evaluation_off');
    apiView = {
      applies: true as const,
      connection:
        c === null
          ? null
          : { id: c.id, provider: c.provider, health: c.health, mailboxAccess: access },
      intake: { journal, feeds },
      scope: f.scopeKind,
      mailboxes: {
        inScope: f.mailboxes.inScope,
        covered: f.mailboxes.covered,
        gap: f.mailboxes.gap,
        total: f.mailboxes.total,
      },
      remediation: {
        source: f.remediation.source,
        mode: f.remediation.mode,
        detectOnlyUntil: f.remediation.detectOnlyUntil?.toISOString() ?? null,
      },
      policyEvaluation: f.policyEvaluation,
      lastCopyAt: f.lastCopyAt?.toISOString() ?? null,
    };
  }
  return {
    domainId: f.domainId,
    name: f.name,
    status: f.status,
    effectiveMode: f.effectiveMode,
    inherited: f.inherited,
    inline: {
      applies: inline,
      inboundEnabled: f.inboundEnabled,
      outboundEnabled: f.outboundEnabled,
      mxPointsToGateway: f.mxPointsToGateway,
    },
    api: apiView,
    gaps,
  };
}
export type DomainCoverageView = ReturnType<typeof domainCoverage>;

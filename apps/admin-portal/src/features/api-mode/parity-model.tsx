import { ToneBadge } from '@/components/domain/tone-badge';
import type { SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { humanize } from '@/lib/format';

/**
 * Labels and badges of API-mode parity (step API-4, docs/plan/steps/38-api-mode-parity-
 * onboarding.md A4, A5, A10, A12, B7, B8): policy evaluation of copies (detect mode), DLP
 * actions, the policy lane of the remediation decision, the policy mapping, the detect-only
 * period, the protection-by-mode matrix and gap codes and the first-copy hints. Every value is
 * computed by the api; the portal never evaluates a policy (ADR-0063).
 */

export type DetectionDetail = SuccessBody<'ApiModeController_getDetection_v1'>;
export type PolicyEvaluation = NonNullable<DetectionDetail['policy']>;
export type DlpFacts = NonNullable<DetectionDetail['dlp']>;
export type PolicyState = DetectionDetail['policyState'];
export type PolicyDisposition = NonNullable<DetectionDetail['policyDisposition']>;
export type DlpAction = NonNullable<DetectionDetail['dlpAction']>;
export type PolicyView = SuccessBody<'ApiModeRemediationController_getPolicy_v1'>;
export type EffectivePolicyMapping = PolicyView['organization']['effectivePolicyMapping'];
export type PolicyMappingKey = keyof EffectivePolicyMapping;
export type DetectOnlyView = NonNullable<PolicyView['organization']['detectOnly']>;
export type DetectOnlyThen = DetectOnlyView['then'];
export type ProtectionCoverage = SuccessBody<'ApiModeOnboardingController_protectionCoverage_v1'>;
export type CoverageItem = ProtectionCoverage['items'][number];
export type Capability = ProtectionCoverage['capabilities'][number];
export type GapCode = CoverageItem['gaps'][number];
export type DomainOnboarding = SuccessBody<'ApiModeOnboardingController_domainOnboarding_v1'>;
export type OnboardingStepView = DomainOnboarding['steps'][number];
export type FirstCopyHint = DomainOnboarding['firstCopy']['hints'][number];
export type ScopeView = SuccessBody<'ApiModeOnboardingController_getScope_v1'>;
export type ScopeKind = ScopeView['kind'];

export const POLICY_STATES: readonly PolicyState[] = [
  'none',
  'evaluated',
  'inline',
  'disabled',
  'failed',
  'not_applicable',
];
export const POLICY_DISPOSITIONS: readonly PolicyDisposition[] = [
  'allow',
  'require_approval',
  'quarantine',
  'reject',
];
export const DLP_ACTIONS: readonly DlpAction[] = [
  'allow',
  'alert',
  'require_approval',
  'quarantine',
  'block',
];

export const POLICY_STATE_LABEL: Record<PolicyState, string> = {
  none: 'Not evaluated',
  evaluated: 'Evaluated',
  inline: 'Decided inline',
  disabled: 'Evaluation off',
  failed: 'Evaluation failed',
  not_applicable: 'Not applicable',
};

export const POLICY_STATE_TEXT: Record<PolicyState, string> = {
  none: 'Not evaluated (recorded before step API-4 or still pending).',
  evaluated: 'Your policies were evaluated on this copy in detect mode.',
  inline: 'The inline gateway already evaluated this message (Hybrid); shown for reference.',
  disabled: 'Policy evaluation of copies is turned off for the organization or the platform.',
  failed: 'The evaluation failed; the verdict rules alone decided the mailbox action.',
  not_applicable: 'Not evaluated: the copy could not be parsed, was too large or is a report.',
};

export const DISPOSITION_LABEL: Record<PolicyDisposition, string> = {
  allow: 'Allow',
  require_approval: 'Require approval',
  quarantine: 'Quarantine',
  reject: 'Reject',
};

const DISPOSITION_TONE: Record<PolicyDisposition, Tone> = {
  allow: 'success',
  require_approval: 'warning',
  quarantine: 'orange',
  reject: 'danger',
};

export const DLP_ACTION_LABEL: Record<DlpAction, string> = {
  allow: 'Allow',
  alert: 'Alert',
  require_approval: 'Require approval',
  quarantine: 'Quarantine',
  block: 'Block',
};

const DLP_TONE: Record<DlpAction, Tone> = {
  allow: 'success',
  alert: 'info',
  require_approval: 'warning',
  quarantine: 'orange',
  block: 'danger',
};

const STATE_TONE: Record<PolicyState, Tone> = {
  none: 'neutral',
  evaluated: 'info',
  inline: 'purple',
  disabled: 'neutral',
  failed: 'danger',
  not_applicable: 'neutral',
};

export function PolicyStateBadge({ state }: { state: PolicyState }) {
  return (
    <ToneBadge tone={STATE_TONE[state] ?? 'neutral'}>
      {POLICY_STATE_LABEL[state] ?? humanize(state)}
    </ToneBadge>
  );
}

export function DispositionBadge({
  disposition,
  tagged = false,
}: {
  disposition: PolicyDisposition | null;
  tagged?: boolean;
}) {
  if (disposition === null) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <ToneBadge tone={DISPOSITION_TONE[disposition] ?? 'neutral'}>
        {DISPOSITION_LABEL[disposition] ?? humanize(disposition)}
      </ToneBadge>
      {tagged ? <ToneBadge tone="info">Tagged</ToneBadge> : null}
    </span>
  );
}

export function DlpActionBadge({ action }: { action: DlpAction | null }) {
  if (action === null) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <ToneBadge tone={DLP_TONE[action] ?? 'neutral'}>
      DLP {DLP_ACTION_LABEL[action] ?? humanize(action)}
    </ToneBadge>
  );
}

/** Outbound detections are never remediated (P-I5): the message has already left. */
export const OUTBOUND_NOT_REMEDIABLE = 'Not remediable — already sent';

export const DECISION_SOURCE_LABEL: Record<string, string> = {
  tenant_rule: 'Your policy rule',
  platform_default: 'Platform default',
  floor: 'Platform floor (DLP or threat block)',
};

/** Post-delivery statuses and reasons of policy actions (A5). */
export const ACTION_STATUS_LABEL: Record<string, string> = {
  enforced: 'Enforced',
  requested: 'Requested',
  recorded: 'Recorded',
  not_applicable: 'Not applicable',
};

export const POST_DELIVERY_REASON_TEXT: Record<string, string> = {
  mapped_to_mailbox_action: 'Mapped to a mailbox action (policy mapping)',
  already_delivered: 'Already delivered',
  post_delivery_no_bounce: 'No bounce or sender notice after delivery',
  post_delivery_no_header_edit: 'No header, subject or banner edit after delivery',
  post_delivery_no_rewrite: 'No URL rewriting after delivery',
  archive_follows_journaling: 'Archiving follows the journaling settings',
  post_delivery_no_encrypt: 'No encryption after delivery',
  post_delivery_no_redirect: 'No redirect after delivery',
  outbound_already_sent: 'Outbound: the message has already been sent',
};

export function postDeliveryReasonText(reason: string | null | undefined): string | null {
  if (!reason) return null;
  return POST_DELIVERY_REASON_TEXT[reason] ?? humanize(reason);
}

// ---- policy mapping (A4.2) -----------------------------------------------------------------

export const POLICY_MAPPING_KEYS: readonly PolicyMappingKey[] = [
  'quarantine',
  'require_approval',
  'reject',
  'allow_tagged',
];

export const MAPPING_KEY_LABEL: Record<PolicyMappingKey, string> = {
  quarantine: 'Policy disposition Quarantine',
  require_approval: 'Policy disposition Require approval',
  reject: 'Policy disposition Reject',
  allow_tagged: 'Allowed with Tag or Warn',
};

export const MAPPING_KEY_HELP: Record<PolicyMappingKey, string> = {
  quarantine: 'A rule (or the DLP floor) quarantines the message.',
  require_approval: 'A rule holds the message for approval; a restore needs an approver.',
  reject: 'A rule rejects the message; no bounce is ever sent after delivery.',
  allow_tagged: 'The message is allowed but a TAG or WARN action applies.',
};

/** Mailbox actions of a disposition (`hard_delete` is never allowed, R-I2). */
export const MAPPING_ACTIONS = ['move_quarantine', 'move_junk', 'soft_delete', 'tag', 'none'];
export const TAGGED_MAPPING_ACTIONS = ['tag', 'none'];

/** The default mapping (API4-3): every blocking disposition to the quarantine folder. */
export const DEFAULT_POLICY_MAPPING: EffectivePolicyMapping = {
  quarantine: 'move_quarantine',
  require_approval: 'move_quarantine',
  reject: 'move_quarantine',
  allow_tagged: 'tag',
};

export function isDefaultMapping(mapping: EffectivePolicyMapping): boolean {
  return POLICY_MAPPING_KEYS.every((key) => mapping[key] === DEFAULT_POLICY_MAPPING[key]);
}

// ---- detect-only period (B7) ---------------------------------------------------------------

export const DETECT_ONLY_DEFAULT_DAYS = 7;
export const DETECT_ONLY_MAX_DAYS = 30;

export const DETECT_ONLY_THEN_LABEL: Record<DetectOnlyThen, string> = {
  remind: 'Remind me to switch to enforce',
  enforce: 'Switch to enforce automatically',
};

/** `until` of a period `days` from `now` (ISO, the api accepts now + 1 h … now + 30 d). */
export function detectOnlyUntil(days: number, now: number = Date.now()): string {
  return new Date(now + days * 86_400_000).toISOString();
}

export function simulatedHistoryHref(): string {
  return '/api-mode?tab=history&status=simulated';
}

// ---- protection by mode (A10) --------------------------------------------------------------

export const CAPABILITY_LABEL: Record<Capability['code'], string> = {
  pre_delivery_blocking: 'Block threats before delivery',
  hold_for_review: 'Hold messages for review before delivery',
  post_delivery_removal: 'Remove threats from mailboxes after delivery',
  retroactive_clawback: 'Retroactive clawback of late verdicts',
  internal_mail: 'Internal (east-west) mail',
  outbound_dlp_enforce: 'Outbound DLP enforcement (block before sending)',
  outbound_dlp_detect: 'Outbound DLP detection and alerts',
  tenant_policies: 'Your policies (rules, allow and block lists, DLP, BEC)',
  url_rewriting: 'URL rewriting',
  message_tagging: 'Message tagging',
  user_reports: 'User-reported phishing',
  alerts_webhooks: 'Alerts and webhooks',
};

/** Note codes of the static matrix (`PROTECTION_MODE_CAPABILITIES` of the api). */
export const CAPABILITY_NOTE_TEXT: Record<string, string> = {
  api_acts_after_delivery: 'API mode acts after delivery: threats are removed from the mailbox.',
  api_review_in_quarantine_folder:
    'API mode: a message held for review moves to the quarantine folder; a restore needs an approver.',
  inline_release_only:
    'Inline: delivered mail is not touched afterwards (quarantine releases only).',
  inline_needs_mailbox_access: 'Needs mailbox access, which only API and Hybrid mode use.',
  inline_sees_relayed_internal_only: 'Inline sees internal mail only when it is relayed.',
  api_outbound_already_sent:
    'API mode sees outbound mail after it was sent: detect and alert only.',
  api_post_delivery_actions_only:
    'API mode: policy dispositions map to mailbox actions; bounces, header edits and rewrites do not apply after delivery.',
  api_no_message_edits: 'API mode never edits a delivered message.',
  inline_headers_api_category_label:
    'Inline: a header or subject tag; API: a category (Microsoft 365) or label (Google Workspace).',
  reports_need_report_mailbox: 'Needs a report mailbox and mailbox access.',
};

export function capabilityNoteText(code: string | null): string | null {
  if (!code) return null;
  return CAPABILITY_NOTE_TEXT[code] ?? humanize(code);
}

export const SUPPORT_LABEL: Record<Capability['inline'], string> = {
  yes: 'Yes',
  partial: 'Partial',
  no: 'No',
};

const SUPPORT_TONE: Record<Capability['inline'], Tone> = {
  yes: 'success',
  partial: 'warning',
  no: 'neutral',
};

export function SupportBadge({ value }: { value: Capability['inline'] }) {
  return <ToneBadge tone={SUPPORT_TONE[value] ?? 'neutral'}>{SUPPORT_LABEL[value]}</ToneBadge>;
}

/** Gap codes (A10) with their text and the page that fixes them. */
export function gapInfo(
  code: GapCode,
  item: Pick<CoverageItem, 'domainId' | 'api'>,
): { text: string; href: string; fix: string } {
  const connection = item.api?.connection?.id;
  const domainPage = `/domains/${item.domainId}`;
  switch (code) {
    case 'inline_mx_not_at_gateway':
      return {
        text: 'The MX record does not point to the gateway yet',
        href: `${domainPage}?tab=dns`,
        fix: 'DNS records',
      };
    case 'inline_not_active':
      return {
        text: 'The domain is not active',
        href: `/domains/onboarding?domainId=${item.domainId}`,
        fix: 'Continue onboarding',
      };
    case 'api_no_connection':
      return {
        text: 'No Microsoft 365 or Google Workspace connection',
        href: `/domains/onboarding?domainId=${item.domainId}&step=connect`,
        fix: 'Connect mailboxes',
      };
    case 'api_no_mailbox_access':
      return {
        text: 'Mailbox access is not granted',
        href: connection
          ? `/integrations/providers/${connection}?tab=settings#mailbox-access`
          : '/integrations',
        fix: 'Grant mailbox access',
      };
    case 'api_no_intake':
      return {
        text: 'No journal copy or mailbox feeds',
        href: `/domains/onboarding?domainId=${item.domainId}&step=intake`,
        fix: 'Set up intake',
      };
    case 'api_coverage_gaps':
      return {
        text: 'Some in-scope mailboxes have no recent copy',
        href: '/api-mode?tab=mailboxes&coverage=gap',
        fix: 'Mailboxes with a gap',
      };
    case 'api_mx_points_to_gateway':
      return {
        text: 'API mode, but the MX record points to the gateway',
        href: domainPage,
        fix: 'Change the mode',
      };
    case 'api_detect_only':
      return {
        text: 'Remediation is in detect-only mode',
        href: '/api-mode?tab=remediation',
        fix: 'Remediation policy',
      };
    case 'api_policy_evaluation_off':
      return {
        text: 'Policy evaluation of copies is turned off',
        href: '/api-mode?tab=settings',
        fix: 'Settings',
      };
    default:
      return { text: humanize(code), href: domainPage, fix: 'Open the domain' };
  }
}

// ---- onboarding (B8) -----------------------------------------------------------------------

export const ONBOARDING_CODE_TEXT: Record<string, string> = {
  ownership_failed: 'ownership verification failed',
  ownership_pending: 'ownership is not verified yet',
  connection_missing: 'no provider connection is linked to the domain',
  connection_disabled: 'the provider connection is disconnected',
  connection_not_bound: 'the provider tenant is not bound yet',
  mailbox_access_missing: 'mailbox access is not granted',
  intake_missing: 'neither a journal copy nor mailbox feeds deliver copies',
  no_mailboxes_in_scope: 'no mailbox is in scope',
  domain_not_active: 'the domain is not active yet',
  verify_ownership: 'Publish the TXT record and check again',
  verify_through_provider: 'Verify automatically through your provider',
  restart_verification: 'Restart the verification',
  link_connection: 'Link the domain to a provider connection',
  complete_binding: 'Finish the provider connection (tenant binding)',
  grant_mailbox_access: 'Grant mailbox access',
  enable_connection: 'Connect the provider again',
  set_up_journal: 'Set up the journal copy',
  verify_journal_source: 'Send the first journal message to verify the source',
  enable_feeds: 'Turn on mailbox feeds',
  wait_for_feeds: 'Wait for the mailbox feeds to start',
  sync_inventory: 'Run a mailbox inventory sync',
  choose_mailboxes: 'Choose which mailboxes are protected',
  choose_action: 'Choose the threat action',
  activate_domain: 'Activate the domain',
  send_test_message: 'Send a test message',
};

export function onboardingCodeText(code: string): string {
  return ONBOARDING_CODE_TEXT[code] ?? humanize(code);
}

export const HINT_TEXT: Record<FirstCopyHint['code'], string> = {
  domain_not_active: 'The domain is not active yet: activate it on the review step.',
  mode_not_api: 'The domain is not in API or Hybrid mode.',
  connection_missing: 'No provider connection is linked to this domain.',
  connection_not_bound: 'The provider tenant is not bound yet: finish the connection.',
  mailbox_access_missing: 'Mailbox access is not granted: feeds cannot read new messages.',
  journal_source_missing: 'No journal copy source exists on the connection.',
  journal_source_unverified: 'The journal source has not received its first message yet.',
  journal_source_silent: 'The journal source is silent or failing.',
  journal_seen_no_domain_recipient:
    'The journal source receives messages, but none for this domain: check the journal rule’s scope.',
  feeds_disabled: 'Mailbox feeds are turned off and no journal copy arrives.',
  feeds_initializing: 'Mailbox feeds are still starting.',
  no_mailboxes_in_scope: 'No mailbox of this domain is in scope.',
  connection_throttled: 'The provider is throttling the connection.',
  copies_failing: 'Recent copies of the connection could not be scanned or parsed.',
  send_test_message: 'Send a test message to any mailbox of the domain.',
};

export function hintText(code: string): string {
  return HINT_TEXT[code as FirstCopyHint['code']] ?? humanize(code);
}

export const SCOPE_KIND_LABEL: Record<ScopeKind, string> = {
  all: 'All mailboxes',
  departments: 'Departments of the policy directory',
  mailboxes: 'Selected mailboxes',
};

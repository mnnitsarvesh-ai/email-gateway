import {
  Activity,
  BarChart3,
  BotMessageSquare,
  Briefcase,
  Building2,
  CreditCard,
  FileClock,
  FileSearch,
  Gavel,
  Globe,
  History,
  KeyRound,
  Layers,
  LayoutDashboard,
  Link2,
  Mail,
  MailCheck,
  Paperclip,
  Plug,
  Radar,
  ScrollText,
  Server,
  Settings,
  Settings2,
  ShieldAlert,
  ScanSearch,
  ShieldCheck,
  Siren,
  Sparkles,
  UserCheck,
  UserSearch,
  Users,
  Workflow,
  type LucideIcon,
} from 'lucide-react';
import { passesGate } from '@/lib/auth/permissions';
import type { OperationId } from '@/lib/api/types';

/**
 * The navigation model (design P11, single source). An item is visible when the user may
 * perform ANY operation of its gate; `<RouteGate>` guards the route with the same gate. Gates
 * follow the §1.3 "Gate" column of docs/plan/steps/20-admin-portal.md (asserted by a test).
 */
export type Gate = readonly OperationId[] | 'authenticated';

/**
 * The service profile of the acting organization (step 8.6 D13, ADR-0090), derived by the api
 * from the effective features and returned by `GET /auth/me` (`organization.serviceProfile`).
 */
export type ServiceProfile = 'gateway' | 'archive_only';

/** Items that exist only for organizations whose mail flows through the gateway (D13). */
const GATEWAY_ONLY: readonly ServiceProfile[] = ['gateway'];

export interface NavItem {
  readonly id: string;
  readonly label: string;
  readonly href: string;
  readonly icon: LucideIcon;
  readonly gate: Gate;
  /**
   * Gate of the routes below `href` when it differs from the item's own (step 8.1: an archived
   * message's details need `archive:read`, the search page `archive:search`).
   */
  readonly childGate?: Gate;
  /** A live badge rendered by the shell (step 8.4 D16: active critical incidents, approvals). */
  readonly badge?: 'ato-attention';
  /**
   * Service profiles the item exists for (step 8.6 D13; default: every profile). A hidden item's
   * routes show the "not available for this plan" state.
   */
  readonly profiles?: readonly ServiceProfile[];
  /**
   * Permissions the user must also hold, all of them (step 8.6: the Archive → Access audit page
   * reads the audit log with `audit:read` and is part of the archive audience, `archive:search`).
   */
  readonly requires?: readonly string[];
  /**
   * `false`: never the landing page of `/` (step AI-1: the AI assistant is an entry point to the
   * other pages, not a start page).
   */
  readonly landing?: false;
}

export interface NavSection {
  readonly id: string;
  readonly label: string;
  readonly items: readonly NavItem[];
}

export const NAVIGATION: readonly NavSection[] = [
  {
    id: 'overview',
    label: 'Overview',
    items: [
      {
        id: 'dashboard',
        profiles: GATEWAY_ONLY,
        label: 'Dashboard',
        href: '/dashboard',
        icon: LayoutDashboard,
        gate: ['ReportsController_traffic_v1'],
      },
      {
        id: 'reports',
        profiles: GATEWAY_ONLY,
        label: 'Reports',
        href: '/reports',
        icon: BarChart3,
        gate: ['ReportsController_traffic_v1'],
      },
      {
        // Step AI-1 (D14): the full-screen AI assistant (gateway and archive-only profiles); the
        // header's "Ask AI" panel uses the same gate plus `GET /assistant/status`.
        id: 'assistant',
        label: 'AI assistant',
        href: '/assistant',
        icon: Sparkles,
        gate: ['AssistantConversationsController_list_v1'],
        // Step AI-R (D9): the full-size report page below it reads one report.
        childGate: ['AssistantReportsController_get_v1'],
        landing: false,
      },
    ],
  },
  {
    id: 'mail',
    label: 'Mail',
    items: [
      {
        id: 'messages',
        profiles: GATEWAY_ONLY,
        label: 'Email explorer',
        href: '/messages',
        icon: Mail,
        gate: ['MessagesController_list_v1'],
      },
      {
        id: 'quarantine',
        profiles: GATEWAY_ONLY,
        label: 'Quarantine',
        href: '/quarantine',
        icon: ShieldAlert,
        gate: ['QuarantineEntriesController_search_v1', 'QuarantineSelfController_search_v1'],
      },
      {
        id: 'mail-servers',
        profiles: GATEWAY_ONLY,
        label: 'Mail servers',
        href: '/mail-servers',
        icon: Server,
        gate: [
          'DomainDestinationsController_get_v1',
          'SmtpConnectorsController_list_v1',
          'RecipientSuppressionsController_list_v1',
        ],
      },
    ],
  },
  {
    id: 'security',
    label: 'Security',
    items: [
      {
        // Step 8.4 D24: the generic, category-aware incident list (top-level; ATO is its first
        // category, ATP categories join the same page later).
        id: 'incidents',
        profiles: GATEWAY_ONLY,
        label: 'Incidents',
        href: '/incidents',
        icon: Siren,
        gate: ['IncidentsController_list_v1'],
        childGate: ['IncidentsController_get_v1'],
      },
      {
        id: 'policies',
        profiles: GATEWAY_ONLY,
        label: 'Policy management',
        href: '/policies',
        icon: ScrollText,
        gate: ['PolicyManagementController_list_v1'],
      },
      {
        id: 'policy-builder',
        profiles: GATEWAY_ONLY,
        label: 'Policy builder',
        href: '/policies/builder',
        icon: Workflow,
        gate: ['PolicyToolsController_catalog_v1'],
      },
      {
        id: 'threat-intelligence',
        profiles: GATEWAY_ONLY,
        label: 'Threat intelligence',
        href: '/threat-intelligence',
        icon: Radar,
        gate: ['ThreatIntelligenceController_lookup_v1', 'ThreatHashesController_list_v1'],
      },
      {
        id: 'url-protection',
        profiles: GATEWAY_ONLY,
        label: 'URL protection',
        href: '/url-protection',
        icon: Link2,
        gate: ['UrlProtectionController_clicks_v1', 'ReportsController_urlClicks_v1'],
      },
      {
        id: 'attachments',
        profiles: GATEWAY_ONLY,
        label: 'Attachment analysis',
        href: '/attachments',
        icon: Paperclip,
        gate: ['AttachmentsController_search_v1', 'AttachmentRescansController_list_v1'],
      },
      {
        // Step API-1 (D14): API-mode protection (coverage, mailboxes, detections, setup); the
        // write controls inside are gated per operation (remediation:write).
        id: 'api-mode',
        profiles: GATEWAY_ONLY,
        label: 'Mailbox protection',
        href: '/api-mode',
        icon: MailCheck,
        gate: ['ApiModeController_overview_v1'],
      },
      {
        // Step API-4 (A10, API4-15): what Inline, API and Hybrid cover and each domain's gaps.
        id: 'protection-by-mode',
        profiles: GATEWAY_ONLY,
        label: 'Protection by mode',
        href: '/protection-by-mode',
        icon: Layers,
        gate: ['ApiModeOnboardingController_protectionCoverage_v1'],
      },
    ],
  },
  {
    // Step 8.4 (§6, D18): account takeover detection.
    id: 'account-security',
    label: 'Account security',
    items: [
      {
        id: 'ato',
        label: 'ATO dashboard',
        href: '/ato',
        icon: Activity,
        gate: ['AtoOverviewController_overview_v1'],
        badge: 'ato-attention',
      },
      {
        id: 'ato-accounts',
        label: 'Accounts',
        href: '/ato/accounts',
        icon: UserSearch,
        gate: ['AtoAccountsController_list_v1'],
        childGate: ['AtoAccountsController_get_v1'],
      },
      {
        id: 'ato-responses',
        label: 'Responses',
        href: '/ato/responses',
        icon: UserCheck,
        gate: ['AtoResponsesController_list_v1'],
      },
      {
        id: 'ato-settings',
        label: 'ATO settings',
        href: '/ato/settings',
        icon: Settings2,
        gate: ['AtoSettingsController_get_v1'],
      },
      {
        // Step 8.5 (§7): identity-provider integrations of ATO detection.
        id: 'ato-providers',
        label: 'Identity providers',
        href: '/ato/providers',
        icon: KeyRound,
        gate: ['AtoProvidersController_list_v1'],
        childGate: ['AtoProvidersController_get_v1'],
      },
    ],
  },
  {
    // Step 8.6 (D14): the former "Compliance" section is the Archive: storage and use of archived
    // mail. What is journaled (capture) is configured in Settings → Journaling.
    id: 'archive',
    label: 'Archive',
    items: [
      {
        id: 'archive',
        label: 'Search',
        href: '/archive',
        icon: ScanSearch,
        gate: ['ArchiveMessagesController_list_v1'],
        childGate: ['ArchiveMessagesController_detail_v1'],
      },
      {
        id: 'retention',
        label: 'Retention and lock',
        href: '/archive/retention',
        icon: History,
        gate: ['ArchiveRetentionController_list_v1'],
      },
      {
        id: 'legal-holds',
        label: 'Legal holds',
        href: '/legal-holds',
        icon: Gavel,
        gate: ['LegalHoldsController_list_v1'],
      },
      {
        id: 'ediscovery',
        label: 'eDiscovery',
        href: '/ediscovery',
        icon: Briefcase,
        gate: ['EdiscoveryCasesController_list_v1'],
      },
      {
        // Step 8.6 (D14): the audit log rows of archive use (archive., ediscovery., legal_hold.,
        // rbac.archive_access) for the archive audience.
        id: 'access-audit',
        label: 'Access audit',
        href: '/archive/access-audit',
        icon: FileSearch,
        gate: ['AuditLogsController_search_v1'],
        requires: ['archive:search'],
      },
    ],
  },
  {
    id: 'directory',
    label: 'Directory',
    items: [
      {
        id: 'domains',
        label: 'Domains',
        href: '/domains',
        icon: Globe,
        gate: ['DomainsController_list_v1'],
      },
      {
        id: 'users',
        label: 'Users',
        href: '/users',
        icon: Users,
        gate: ['UsersController_list_v1'],
      },
      {
        id: 'roles',
        label: 'Roles and permissions',
        href: '/roles',
        icon: ShieldCheck,
        gate: ['RolesController_list_v1'],
      },
    ],
  },
  {
    id: 'administration',
    label: 'Administration',
    items: [
      {
        id: 'organizations',
        label: 'Organizations',
        href: '/organizations',
        icon: Building2,
        gate: ['OrganizationsController_list_v1'],
      },
      {
        id: 'integrations',
        label: 'Integrations',
        href: '/integrations',
        icon: Plug,
        gate: [
          'WebhooksController_list_v1',
          'ApiKeysController_list_v1',
          'SmtpConnectorsController_list_v1',
          'ProviderConnectionsController_list_v1',
        ],
      },
      {
        id: 'audit-logs',
        label: 'Audit logs',
        href: '/audit-logs',
        icon: FileClock,
        gate: ['AuditLogsController_search_v1'],
      },
      {
        // Step AI-6 (D1): tenant AI administration (usage per person, limits, data sharing, the
        // provider key, feedback) and the metadata-only conversation audit; tabs are gated one by
        // one inside the page, the item by any of the two entry operations.
        id: 'assistant-admin',
        label: 'AI administration',
        href: '/assistant/admin',
        icon: BotMessageSquare,
        gate: [
          'AssistantAdminController_usageByUser_v1',
          'AssistantAdminAuditController_conversations_v1',
        ],
        landing: false,
      },
      {
        id: 'billing',
        label: 'Usage and billing',
        href: '/billing',
        icon: CreditCard,
        gate: ['BillingController_plan_v1', 'UsageController_get_v1'],
      },
      {
        id: 'settings',
        label: 'Settings',
        href: '/settings',
        icon: Settings,
        gate: 'authenticated',
      },
    ],
  },
];

export const NAV_ITEMS: readonly NavItem[] = NAVIGATION.flatMap((section) => section.items);

/** Whether the item exists for the organization's service profile (step 8.6 D13). */
export function availableForProfile(item: NavItem, profile: ServiceProfile = 'gateway'): boolean {
  return !item.profiles || item.profiles.includes(profile);
}

/** Whether the user may see the item: its gate, its extra permissions and the profile. */
export function itemVisible(
  item: NavItem,
  granted: ReadonlySet<string>,
  profile: ServiceProfile = 'gateway',
): boolean {
  return (
    availableForProfile(item, profile) &&
    passesGate(item.gate, granted) &&
    (item.requires ?? []).every((permission) => granted.has(permission))
  );
}

/** Sections with only the items the user may see (empty sections dropped). */
export function visibleNavigation(
  permissions: readonly string[],
  profile: ServiceProfile = 'gateway',
): NavSection[] {
  const granted = new Set(permissions);
  return NAVIGATION.map((section) => ({
    ...section,
    items: section.items.filter((item) => itemVisible(item, granted, profile)),
  })).filter((section) => section.items.length > 0);
}

/** Settings → Journaling (step 8.6 D14): the capture half of the former archive settings. */
export const JOURNALING_SETTINGS_HREF = '/settings?tab=journaling';

/**
 * The first route the user may open (the `/` redirect); `/settings` is always allowed. An
 * archive-only organization lands on Archive search, or on Settings → Journaling for users
 * without archive access (step 8.6 D13).
 */
export function firstPermittedHref(
  permissions: readonly string[],
  profile: ServiceProfile = 'gateway',
): string {
  const granted = new Set(permissions);
  if (profile === 'archive_only') {
    const search = NAV_ITEMS.find((item) => item.id === 'archive');
    if (search && itemVisible(search, granted, profile)) return search.href;
    if (passesGate(['JournalingController_get_v1'], granted)) return JOURNALING_SETTINGS_HREF;
  }
  return (
    NAV_ITEMS.find((item) => item.landing !== false && itemVisible(item, granted, profile))?.href ??
    '/settings'
  );
}

/** Whether a route belongs to an item the organization's plan does not offer (D13). */
export function hiddenForProfile(pathname: string, profile: ServiceProfile = 'gateway'): boolean {
  const item = navItemForPath(pathname);
  return item !== null && !availableForProfile(item, profile);
}

/** Gate of the navigation item that owns a pathname (longest matching href). */
export function navItemForPath(pathname: string): NavItem | null {
  let best: NavItem | null = null;
  for (const item of NAV_ITEMS) {
    const matches = pathname === item.href || pathname.startsWith(`${item.href}/`);
    if (matches && (!best || item.href.length > best.href.length)) best = item;
  }
  return best;
}

/** The gate that guards a pathname: the owning item's, or its `childGate` below its href. */
export function gateForPath(pathname: string): Gate | null {
  const item = navItemForPath(pathname);
  if (!item) return null;
  return pathname !== item.href && item.childGate ? item.childGate : item.gate;
}

/** Plan references for the "arrives in step N" states (UnavailableState). */
export const PLAN_STEPS: Readonly<Record<string, string>> = {
  '7.2': 'Step 7.2: Email Explorer and Email Details (docs/plan/execution-plan.md)',
  '7.3': 'Step 7.3: Visual policy builder (docs/plan/execution-plan.md)',
  '8.1': 'Step 8.1: Journaling and compliance archiving (docs/plan/execution-plan.md)',
  '8.2': 'Step 8.2: M365 / Google Workspace connectors (docs/plan/execution-plan.md)',
  '8.3': 'Step 8.3: Deployment manager (docs/plan/execution-plan.md)',
  '8.5':
    'Step 8.5: Microsoft 365 / Google Workspace identity-provider adapters for account takeover (docs/plan/execution-plan.md)',
  '8.6':
    'Step 8.6: Journal-only intake and the Journaling / Archive split (docs/plan/execution-plan.md)',
};

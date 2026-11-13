import {
  BarChart3,
  Building2,
  CreditCard,
  FileClock,
  Globe,
  LayoutDashboard,
  Link2,
  Mail,
  Paperclip,
  Plug,
  Radar,
  ScrollText,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
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

export interface NavItem {
  readonly id: string;
  readonly label: string;
  readonly href: string;
  readonly icon: LucideIcon;
  readonly gate: Gate;
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
        label: 'Dashboard',
        href: '/dashboard',
        icon: LayoutDashboard,
        gate: ['ReportsController_traffic_v1'],
      },
      {
        id: 'reports',
        label: 'Reports',
        href: '/reports',
        icon: BarChart3,
        gate: ['ReportsController_traffic_v1'],
      },
    ],
  },
  {
    id: 'mail',
    label: 'Mail',
    items: [
      {
        id: 'messages',
        label: 'Email explorer',
        href: '/messages',
        icon: Mail,
        gate: ['MessagesController_list_v1'],
      },
      {
        id: 'quarantine',
        label: 'Quarantine',
        href: '/quarantine',
        icon: ShieldAlert,
        gate: ['QuarantineEntriesController_search_v1', 'QuarantineSelfController_search_v1'],
      },
      {
        id: 'mail-servers',
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
        id: 'policies',
        label: 'Policy management',
        href: '/policies',
        icon: ScrollText,
        gate: ['PolicyManagementController_list_v1'],
      },
      {
        id: 'policy-builder',
        label: 'Policy builder',
        href: '/policies/builder',
        icon: Workflow,
        gate: ['PolicyToolsController_catalog_v1'],
      },
      {
        id: 'threat-intelligence',
        label: 'Threat intelligence',
        href: '/threat-intelligence',
        icon: Radar,
        gate: ['ThreatIntelligenceController_lookup_v1', 'ThreatHashesController_list_v1'],
      },
      {
        id: 'url-protection',
        label: 'URL protection',
        href: '/url-protection',
        icon: Link2,
        gate: ['UrlProtectionController_clicks_v1', 'ReportsController_urlClicks_v1'],
      },
      {
        id: 'attachments',
        label: 'Attachment analysis',
        href: '/attachments',
        icon: Paperclip,
        gate: ['AttachmentsController_search_v1', 'AttachmentRescansController_list_v1'],
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

/** Sections with only the items the user may see (empty sections dropped). */
export function visibleNavigation(permissions: readonly string[]): NavSection[] {
  const granted = new Set(permissions);
  return NAVIGATION.map((section) => ({
    ...section,
    items: section.items.filter((item) => passesGate(item.gate, granted)),
  })).filter((section) => section.items.length > 0);
}

/** The first route the user may open (the `/` redirect); `/settings` is always allowed. */
export function firstPermittedHref(permissions: readonly string[]): string {
  const granted = new Set(permissions);
  return NAV_ITEMS.find((item) => passesGate(item.gate, granted))?.href ?? '/settings';
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

/** Plan references for the "arrives in step N" states (UnavailableState). */
export const PLAN_STEPS: Readonly<Record<string, string>> = {
  '7.2': 'Step 7.2: Email Explorer and Email Details (docs/plan/execution-plan.md)',
  '7.3': 'Step 7.3: Visual policy builder (docs/plan/execution-plan.md)',
  '8.1': 'Step 8.1: Journaling and compliance archiving (docs/plan/execution-plan.md)',
  '8.2': 'Step 8.2: M365 / Google Workspace connectors (docs/plan/execution-plan.md)',
  '8.3': 'Step 8.3: Deployment manager (docs/plan/execution-plan.md)',
};

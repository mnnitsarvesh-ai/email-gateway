/**
 * Synthetic dataset types of the Google Workspace simulators (design note D12): Admin SDK Reports
 * (`login`, `token`), Directory (users, organizational units, OAuth tokens) and Gmail settings
 * (auto-forwarding, filters, delegates). Shapes follow the provider JSON the Google adapter reads.
 * Synthetic data only: `.example` domains, documentation IP ranges (RFC 5737 / RFC 3849), the
 * customer id `Cexample01`; no real customer, user, credential or address.
 *
 * Simulator sources import only `node:*` modules and each other (import-guard test).
 */
import type { SimMailbox } from './types';

export interface GsActivityParameter {
  name: string;
  value?: string;
  multiValue?: string[];
  boolValue?: boolean;
  intValue?: string;
}

export interface GsActivityEvent {
  type?: string;
  name: string;
  parameters?: GsActivityParameter[];
}

/** One Admin SDK Reports activity (`activities.list` item). */
export interface GsActivity {
  id: {
    time: string;
    uniqueQualifier: string;
    applicationName: 'login' | 'token';
    customerId: string;
  };
  actor: { email?: string; profileId?: string; callerType?: string };
  ipAddress?: string;
  networkInfo?: { regionCode?: string; subdivisionCode?: string };
  events: GsActivityEvent[];
}

export interface GsUser {
  /** Directory user id (also the Reports `actor.profileId`). */
  id: string;
  primaryEmail: string;
  aliases: string[];
  suspended: boolean;
  archived?: boolean;
  orgUnitPath: string;
  changePasswordAtNextLogin: boolean;
  /** Super administrator: writes on this user need a super-administrator subject (403 otherwise). */
  isAdmin: boolean;
  /** Delegated administrator (may call the Admin SDK, not on super administrators). */
  isDelegatedAdmin?: boolean;
  /** Gmail enabled for the user (settings calls answer 400 failedPrecondition otherwise). */
  gmailEnabled?: boolean;
}

export interface GsOrgUnit {
  orgUnitId: string;
  orgUnitPath: string;
  name: string;
}

/** A third-party OAuth token of a user (Directory `tokens`). */
export interface GsToken {
  clientId: string;
  displayText: string;
  scopes: string[];
  anonymous?: boolean;
  nativeApp?: boolean;
}

export interface GsAutoForwarding {
  enabled: boolean;
  emailAddress?: string;
  disposition?: 'leaveInInbox' | 'archive' | 'trash' | 'markRead' | 'dispositionUnspecified';
}

export interface GsFilter {
  id: string;
  criteria?: {
    from?: string;
    to?: string;
    subject?: string;
    query?: string;
    negatedQuery?: string;
    hasAttachment?: boolean;
  };
  action?: { addLabelIds?: string[]; removeLabelIds?: string[]; forward?: string };
}

export interface GsDelegate {
  delegateEmail: string;
  verificationStatus:
    'accepted' | 'pending' | 'rejected' | 'expired' | 'verificationStatusUnspecified';
}

export interface GsGmailSettings {
  autoForwarding: GsAutoForwarding;
  filters: GsFilter[];
  delegates: GsDelegate[];
}

export interface GsCustomer {
  /** Google customer id in 8.2's validated format (`C` + alphanumerics). */
  customerId: string;
  domains: string[];
  users: GsUser[];
  orgUnits: GsOrgUnit[];
  /** Reports activities of the `login` and `token` applications. */
  activities: GsActivity[];
  /** OAuth tokens per user id. */
  tokens: Record<string, GsToken[]>;
  /** Gmail settings per user id. */
  gmail: Record<string, GsGmailSettings>;
  /** Reports retention in days (start times older than this are refused). Default 180. */
  reportsRetentionDays?: number;
  /** Step API-1: Gmail mailbox state per user id (created on first use). */
  mailboxes?: Record<string, SimMailbox>;
}

export interface GoogleSimData {
  customers: GsCustomer[];
}

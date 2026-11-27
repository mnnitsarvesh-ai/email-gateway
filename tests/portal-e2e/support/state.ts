/**
 * Per-run state shared by the seeder and the specs: generated credentials, public ids of the
 * seeded entities and the expected report figures. Lives in `tests/portal-e2e/.auth/state.json`
 * (git-ignored, mode 0600) and in memory; it is never printed.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { PACKAGE_ROOT } from './env';

export const AUTH_DIR = resolve(PACKAGE_ROOT, '.auth');
export const STATE_FILE = resolve(AUTH_DIR, 'state.json');

export const USER_KEYS = [
  'alphaAdmin',
  'alphaAnalyst',
  'alphaReadOnly',
  'alphaReviewer',
  'alphaAuditor',
  'alphaDomainAdmin',
  'alphaMailbox',
  'alphaMfaAdmin',
  'alphaApprover',
  'alphaAuditorMfa',
  // Step 8.6: a compliance officer (archive access only, MFA) and the admin of the archive-only
  // organization gamma.
  'alphaCompliance',
  // Step 8.6 review fix: an organization admin without archive access who signs in with MFA (the
  // delegation of archive access needs an MFA session).
  'alphaAccessAdmin',
  'betaAdmin',
  'gammaAdmin',
  // Step AI-1: the assistant tenants (seed/assistant.ts): delta has the assistant on (admin,
  // analyst with assistant:use, mailbox user without it); epsilon has the tenant setting off.
  'deltaAdmin',
  'deltaAnalyst',
  'deltaMailbox',
  // Step AI-2: an organization admin of delta who signs in with MFA (high-risk confirmations ask
  // for the password and the authenticator code).
  'deltaMfaAdmin',
  // Step AI-4: two security analysts of delta with MFA and ato:respond (four eyes in chat: one
  // requests an ATO response, the other approves it; the requester is refused).
  'deltaResponderA',
  'deltaResponderB',
  // Step AI-5: a compliance officer of delta with MFA (retention, eDiscovery and legal holds in
  // chat; seed/assistant.ts prepareAssistantCompliance).
  'deltaCompliance',
  'epsilonAdmin',
  // Step API-1: the API-mode tenant zeta (seed/api-mode.ts): an organization admin (mode changes,
  // feeds) and a read-only user (no write control).
  'zetaAdmin',
  'zetaReadOnly',
  // Step API-2: a zeta security analyst with MFA (approves a mailbox entry's restore).
  'zetaApprover',
  'platformAdmin',
] as const;
export type UserKey = (typeof USER_KEYS)[number];

export interface E2eUser {
  email: string;
  password: string;
  roles: string[];
  organization: 'alpha' | 'beta' | 'gamma' | 'delta' | 'epsilon' | 'zeta' | 'platform';
  /** Base32 TOTP secret once MFA is enabled (seeded, or enrolled through the UI). */
  totpSecret?: string;
  /** Last TOTP step sent to the api (each step is accepted once). */
  lastTotpStep?: number;
  /** Unused recovery codes captured during enrollment. */
  recoveryCodes?: string[];
}

export interface DashboardExpectation {
  total: number;
  inbound: number;
  outbound: number;
  internal: number;
  spamBlocked: number;
  malware: number;
  phishing: number;
  quarantinedMessages: number;
  quarantineEntries: number;
  delivered: number;
  deliveries: number;
  /** delivered ÷ (delivered + bounced + failed + expired), not rounded. */
  successRate: number | null;
  /** Smallest histogram bound (ms) holding ≥ 95 % of the completed initial rounds. */
  p95UpperBoundMs: number | null;
  averageMs: number | null;
  /** Σ per threat verdict over the range (threat trends widget). */
  threatVerdicts: Record<string, number>;
  topDomains: Array<{ name: string; threats: number; inbound: number; deleted: boolean }>;
  unattributed: { inbound: number; threats: number };
}

export interface E2eState {
  runId: string;
  seededAt: string;
  users: Record<UserKey, E2eUser>;
  orgs: Record<
    'alpha' | 'beta' | 'gamma' | 'delta' | 'epsilon' | 'zeta',
    { id: string; name: string; slug: string }
  >;
  alpha: {
    domainId: string;
    domainName: string;
    deletedDomainName: string;
    memberCount: number;
    userCount: number;
    messagesLast24h: number;
    messageId: string;
    approvalEntryId: string;
    approvalMessageId: string;
    previewEntryId: string;
    previewText: string;
    auditRows: number;
    webhookId: string;
    pendingApprovalId: string;
    memberUserId: string;
    /** Step 7.2: public ids of the explorer and details messages by plan key (seed/plan.ts). */
    explorer: Record<string, string>;
    /** The message of the quarantine entry with a sanitized HTML part (preview). */
    previewMessageId: string;
    /** `received_at` (ISO) of every alpha message of the last two hours, ascending. */
    recentReceivedAt: string[];
  };
  beta: {
    domainId: string;
    domainName: string;
    messageId: string;
    entryId: string;
    approvalId: string;
    webhookId: string;
    marker: string;
    /** Beta's twin of alpha search message 1 (same sender and Message-ID). */
    twinMessageId: string;
    /** A saved explorer view of the beta administrator. */
    savedViewId: string;
  };
  /** Step 7.3: seeded policy builder, DLP and BEC data (seed/policies.ts). */
  policies: {
    departments: Array<{ id: string; name: string }>;
    /** Alpha's "E2E outbound data guard": v1 superseded, v2 active, v3 draft. */
    policyId: string;
    policyName: string;
    /** An alpha DLP policy without rules. */
    dlpPolicyId: string;
    dlpPolicyName: string;
    /** An alpha BEC suppression rule (lifted by dlp-bec-config.spec). */
    suppressionId: string;
    beta: {
      policyId: string;
      policyName: string;
      patternId: string;
      executiveId: string;
      suppressionId: string;
    };
  };
  expected: { dashboard7d: DashboardExpectation };
  /** Step 8.1: archive tenants (seed/archive.ts); alpha's records are captured during the run. */
  /** Step 8.4: account takeover accounts and incidents (seed/ato.ts) and the plan's figures. */
  ato: {
    alpha: Array<{ key: string; accountId: string; address: string; incidentId: string | null }>;
    beta: Array<{ key: string; accountId: string; address: string; incidentId: string | null }>;
    expected: {
      monitored: number;
      highRisk: number;
      criticalRisk: number;
      activeIncidents: number;
      criticalIncidents: number;
      failedLogins: number;
      suspiciousLogins: number;
      suspiciousOutbound: number;
    };
  };
  /** Step AI-1: the assistant tenant delta (seed/assistant.ts). */
  assistant: {
    delta: {
      /** Delta's policies in creation order (two active, one draft). */
      policies: Array<{ id: string; name: string; status: 'active' | 'draft' }>;
      /** Subjects of delta's messages held in quarantine today. */
      quarantinedSubjects: string[];
      /** Step AI-3: the public id of `deltaMfaAdmin` (the self-guard directive targets it). */
      mfaAdminUserId: string;
      /** Step AI-3: a seeded read-only delta user that only the assistant spec uses (disabled). */
      offboardUser: { id: string; email: string };
      /** Step AI-5: delta's compliance rows (seed/assistant.ts prepareAssistantCompliance). */
      compliance: {
        defaultPolicyId: string;
        retentionPolicy: { id: string; name: string; retentionDays: number };
        holdCase: { id: string; name: string };
        hold: { id: string; name: string };
      };
      /** Step AI-4: delta's ATO account with an open incident (seed/ato.ts DELTA_ATO_PLAN). */
      ato: { accountId: string; address: string; incidentId: string };
    };
  };
  /** Step API-1: the API-mode tenant zeta (seed/api-mode.ts). */
  apiMode: {
    domains: Record<'api' | 'hybrid' | 'inline' | 'switch', string>;
    domainNames: Record<'api' | 'hybrid' | 'inline' | 'switch', string>;
    m365ConnectionId: string;
    googleConnectionId: string;
    m365Name: string;
    googleName: string;
    mailboxes: string[];
    /** Step API-2 (seed/api-mode.ts seedRemediation). */
    remediation: {
      quarantinedDetectionId: string;
      entryId: string;
      failedActionId: string;
      failedDetectionId: string;
      taggedDetectionId: string;
      remediableDetectionId: string;
    };
  };
  archive: {
    custodian: string;
    policyId: string;
    policyName: string;
    /** Beta's captured-to-be message (isolation target). */
    betaMessageId: string;
  };
}

let cached: E2eState | undefined;

export function writeState(state: E2eState): void {
  mkdirSync(AUTH_DIR, { recursive: true, mode: 0o700 });
  const tmp = `${STATE_FILE}.tmp`;
  writeFileSync(tmp, JSON.stringify(state, null, 2), { mode: 0o600 });
  renameSync(tmp, STATE_FILE);
  chmodSync(STATE_FILE, 0o600);
  cached = state;
}

export function readState(): E2eState {
  if (cached) return cached;
  if (!existsSync(STATE_FILE)) {
    throw new Error('No seeded state: run `pnpm --filter @email-gateway/portal-e2e seed` first');
  }
  cached = JSON.parse(readFileSync(STATE_FILE, 'utf8')) as E2eState;
  return cached;
}

/** Re-reads the file (another spec file may have enrolled MFA since). */
export function reloadState(): E2eState {
  cached = undefined;
  return readState();
}

export function updateUser(key: UserKey, patch: Partial<E2eUser>): E2eUser {
  const state = reloadState();
  state.users[key] = { ...state.users[key], ...patch };
  writeState(state);
  return state.users[key];
}

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
  'alphaDomainAdmin',
  'alphaMailbox',
  'alphaMfaAdmin',
  'alphaApprover',
  'betaAdmin',
  'platformAdmin',
] as const;
export type UserKey = (typeof USER_KEYS)[number];

export interface E2eUser {
  email: string;
  password: string;
  roles: string[];
  organization: 'alpha' | 'beta' | 'platform';
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
  orgs: Record<'alpha' | 'beta', { id: string; name: string; slug: string }>;
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
  };
  beta: {
    domainId: string;
    domainName: string;
    messageId: string;
    entryId: string;
    approvalId: string;
    webhookId: string;
    marker: string;
  };
  expected: { dashboard7d: DashboardExpectation };
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

import type {
  DomainOwnershipMethod,
  DomainProviderCheckResult,
  DomainStatus,
  DomainVerificationStatus,
} from '@email-gateway/database';

/**
 * Ownership through the organization's bound provider tenant (step API-4 B3, ADR-0107;
 * docs/plan/steps/38-api-mode-parity-onboarding.md). Pure rules: which connection a request
 * uses, what the scheduler does with a provider verification row, and the ownership view. The
 * integration-worker writes the provider's answer; the api applies the win through the same
 * first-to-verify-wins transaction as a TXT check (P-I6).
 */

/** A connection that can prove ownership (bound, not disabled, active `*.mail_flow` grant). */
export interface CapableConnection {
  id: bigint;
  publicId: string;
}

/** Statuses from which a provider check can be requested (`failed` is restarted first, D3). */
export const PROVIDER_CHECK_DOMAIN_STATUSES: ReadonlySet<DomainStatus> = new Set<DomainStatus>([
  'pending_verification',
  'failed',
]);

export type ConnectionChoice =
  | { ok: true; connection: CapableConnection }
  | {
      ok: false;
      reason: 'none' | 'not_capable' | 'connection_required';
      candidates: string[];
    };

/**
 * B3.1: the connection of a request — the given one (it must qualify), else the one of the
 * domain's previous provider check when it still qualifies, else the only one; several and none
 * given → `connection_required` with the candidates.
 */
export function chooseConnection(
  capable: readonly CapableConnection[],
  requested: string | undefined,
  previousConnectionId: bigint | null,
): ConnectionChoice {
  if (requested !== undefined) {
    const match = capable.find((c) => c.publicId === requested.toLowerCase());
    return match
      ? { ok: true, connection: match }
      : { ok: false, reason: 'not_capable', candidates: [] };
  }
  if (capable.length === 0) return { ok: false, reason: 'none', candidates: [] };
  if (previousConnectionId !== null) {
    const previous = capable.find((c) => c.id === previousConnectionId);
    if (previous) return { ok: true, connection: previous };
  }
  if (capable.length === 1) return { ok: true, connection: capable[0]! };
  return {
    ok: false,
    reason: 'connection_required',
    candidates: capable.map((c) => c.publicId),
  };
}

/** A `provider_tenant` verification row as the scheduler reads it (locked). */
export interface ProviderVerificationState {
  status: DomainVerificationStatus;
  providerResult: DomainProviderCheckResult | null;
  providerErrorCode: string | null;
  expiresAt: Date;
}

/** What the scheduler does with one provider row (B3.4). */
export type ProviderResultAction =
  | { kind: 'claim' }
  | { kind: 'fail'; lastError: string }
  | { kind: 'expire' }
  | { kind: 'wait' }
  | { kind: 'done' };

/**
 * B3.4: a pending row of a domain that still waits for ownership — result `verified` → claim
 * through the first-to-verify-wins transaction; any other result → the row fails with the result
 * code as `last_error` (the domain stays pending; TXT still works); no result by `expires_at` →
 * expired; else wait. A row of a domain that no longer waits (a TXT win, deletion) fails with
 * `domain_not_pending`. Rows that are no longer pending are done.
 */
export function providerResultAction(
  domainStatus: DomainStatus | null,
  row: ProviderVerificationState,
  now: Date,
): ProviderResultAction {
  if (row.status !== 'pending') return { kind: 'done' };
  if (domainStatus !== 'pending_verification')
    return { kind: 'fail', lastError: 'domain_not_pending' };
  if (row.providerResult === 'verified') return { kind: 'claim' };
  if (row.providerResult !== null) {
    const code =
      row.providerResult === 'error' && row.providerErrorCode
        ? `error:${row.providerErrorCode}`
        : row.providerResult;
    return { kind: 'fail', lastError: code.slice(0, 512) };
  }
  if (now.getTime() >= row.expiresAt.getTime()) return { kind: 'expire' };
  return { kind: 'wait' };
}

/** The ownership block of the domain views (B3). */
export interface OwnershipViewInput {
  domainStatus: DomainStatus;
  method: DomainOwnershipMethod | null;
  latest: {
    id: bigint;
    status: DomainVerificationStatus;
    providerResult: DomainProviderCheckResult | null;
    connectionPublicId: string | null;
    createdAt: Date;
    providerCheckedAt: Date | null;
    expiresAt: Date;
  } | null;
  capableConnections: number;
}

export function ownershipView(input: OwnershipViewInput) {
  const latest = input.latest;
  return {
    method: input.method,
    providerCheck:
      latest === null
        ? null
        : {
            id: latest.id.toString(),
            status: latest.status,
            result: latest.providerResult,
            connectionId: latest.connectionPublicId,
            requestedAt: latest.createdAt.toISOString(),
            checkedAt: latest.providerCheckedAt?.toISOString() ?? null,
            expiresAt: latest.expiresAt.toISOString(),
          },
    providerCheckAvailable:
      PROVIDER_CHECK_DOMAIN_STATUSES.has(input.domainStatus) && input.capableConnections > 0,
  };
}

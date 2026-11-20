import type { IntakeKind } from './intake-wizard';
import { isProviderKind } from './intake-wizard';

/**
 * Kind-specific rules of a journal intake source (step 8.6 D1). Pure: the service applies them
 * before any write and maps the outcomes to `400` (field shape), `422
 * journal_intake_connection_invalid` (reason codes) and `422 journal_intake_networks_invalid`.
 */

/** The 8.2 provider of a provider kind. */
export const PROVIDER_OF_KIND: Readonly<
  Partial<Record<IntakeKind, 'microsoft_365' | 'google_workspace'>>
> = Object.freeze({
  microsoft_365_journal: 'microsoft_365',
  google_workspace_copy: 'google_workspace',
});

/** Field issues (`field: message`) of a create or update body for its kind; empty = valid. */
export function sourceFieldIssues(
  kind: IntakeKind,
  fields: { providerConnectionId?: unknown; networks?: unknown },
  mode: 'create' | 'update',
): string[] {
  const issues: string[] = [];
  if (isProviderKind(kind)) {
    if (mode === 'create' && fields.providerConnectionId === undefined) {
      issues.push(`providerConnectionId: Required for ${kind}`);
    }
    if (fields.networks !== undefined) {
      issues.push(`networks: Not allowed for ${kind} (the provider's egress ranges apply)`);
    }
  } else {
    if (fields.providerConnectionId !== undefined) {
      issues.push(`providerConnectionId: Not allowed for ${kind}`);
    }
    if (mode === 'create' && fields.networks === undefined) {
      issues.push(`networks: Required for ${kind}`);
    }
  }
  return issues;
}

/** The facts of an 8.2 connection that decide whether a source may use it. */
export interface ConnectionFacts {
  provider: 'microsoft_365' | 'google_workspace';
  status: 'draft' | 'connecting' | 'configuring' | 'active' | 'disabled';
  activeTenantKey: string | null;
  externalTenantId: string | null;
}

/**
 * Why a connection cannot back a source of `kind` (D1: same provider, not disabled, bound
 * tenant), or null. A connection of another organization is resolved as `not_found` by the
 * caller (the same refusal, so an id of another tenant is never confirmed).
 */
export function connectionIssue(kind: IntakeKind, c: ConnectionFacts | null): string | null {
  if (c === null) return 'not_found';
  if (PROVIDER_OF_KIND[kind] !== c.provider) return 'provider_mismatch';
  if (c.status === 'disabled') return 'disabled';
  if (c.activeTenantKey === null || c.externalTenantId === null) return 'tenant_not_bound';
  return null;
}

/** The size ceiling of a source: never above the platform's JOURNAL_INTAKE_MAX_MESSAGE_BYTES. */
export function maxMessageBytesIssue(
  value: number | null | undefined,
  platformMax: number,
): string | null {
  if (value === undefined || value === null) return null;
  return value > platformMax
    ? `maxMessageBytes: Must be at most ${platformMax} (JOURNAL_INTAKE_MAX_MESSAGE_BYTES)`
    : null;
}

/** The status a resumed source returns to (D1: `active` once verified). */
export const resumedStatus = (verifiedAt: Date | null): 'active' | 'pending_verification' =>
  verifiedAt === null ? 'pending_verification' : 'active';

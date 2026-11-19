import { DEFAULT_PROVIDER_RELAY_PROOF } from '@email-gateway/mail-routing';
import { shortFingerprint } from '@email-gateway/provider-integrations';
import { z } from 'zod';
import { ATTESTATIONS_SCHEMA, MAX_ATTESTATIONS } from './provider-connections.constants';
import type {
  ConnectionDetailView,
  ConnectionSummaryView,
  GrantView,
} from './dto/provider-connections.schemas';
import type {
  ConnectionAggregate,
  ConnectionListRow,
  ConnectionRow,
  GrantRow,
} from './repositories/provider-connections.repository';

/**
 * Response mappers of the provider-connection routes (step 8.2 §5). They receive rows that never
 * carry the credential ciphertext (the repositories do not select it) and emit only fingerprints,
 * dates, statuses and non-secret ids (ADR-0077).
 */

const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());

const stringList = z.array(z.string().max(512)).max(256);
const asList = (value: unknown): string[] | null => {
  const parsed = stringList.safeParse(value);
  return parsed.success ? parsed.data : null;
};

/** `a•••@example.com`: enough to recognize the delegated administrator, not to harvest it. */
export function maskEmail(email: string | null): string | null {
  if (email === null) return null;
  const at = email.lastIndexOf('@');
  if (at <= 0) return '•••';
  return `${email[0]}•••${email.slice(at)}`;
}

export interface AttestationEntry {
  code: string;
  userId: string | null;
  at: string;
}

const attestationsDocument = z.object({
  schema: z.literal(ATTESTATIONS_SCHEMA),
  items: z
    .array(
      z.object({
        code: z.string().max(64),
        userId: z.string().max(64).nullable(),
        at: z.iso.datetime(),
      }),
    )
    .max(MAX_ATTESTATIONS),
});

/** `provider-attestations/1` of the row (an invalid stored document reads as none). */
export function attestationsOf(stored: unknown): AttestationEntry[] {
  const parsed = attestationsDocument.safeParse(stored);
  return parsed.success ? parsed.data.items : [];
}

export function attestationsDocumentOf(items: readonly AttestationEntry[]): {
  schema: string;
  items: Array<{ code: string; userId: string | null; at: string }>;
} {
  return {
    schema: ATTESTATIONS_SCHEMA,
    items: items.map((item) => ({ code: item.code, userId: item.userId, at: item.at })),
  };
}

/** The relay proof policy in effect and whether it is the provider default (D8). */
export function relayProofOf(row: Pick<ConnectionRow, 'provider' | 'relayProof'>): {
  policy: Record<string, unknown>;
  isDefault: boolean;
} {
  if (row.relayProof === null || typeof row.relayProof !== 'object') {
    return { policy: { ...DEFAULT_PROVIDER_RELAY_PROOF[row.provider] }, isDefault: true };
  }
  return { policy: { ...(row.relayProof as Record<string, unknown>) }, isDefault: false };
}

export function toGrantView(row: GrantRow): GrantView {
  return {
    id: row.publicId,
    profile: row.profile,
    profileVersion: row.profileVersion,
    authMethod: row.authMethod,
    status: row.status,
    clientId: row.clientId,
    subjectEmail: maskEmail(row.subjectEmail),
    credentialFingerprint:
      row.credentialFingerprint === null ? null : shortFingerprint(row.credentialFingerprint),
    credentialVersion: row.credentialVersion,
    credentialSetAt: iso(row.credentialSetAt),
    credentialExpiresAt: iso(row.credentialExpiresAt),
    requestedPermissions: asList(row.requestedPermissions) ?? [],
    observedPermissions: asList(row.observedPermissions),
    missingPermissions: asList(row.missingPermissions),
    excessPermissions: asList(row.excessPermissions),
    consentedAt: iso(row.consentedAt),
    verifyRequestedAt: iso(row.verifyRequestedAt),
    verifiedAt: iso(row.verifiedAt),
    lastErrorCode: row.lastErrorCode,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function toConnectionSummary(row: ConnectionListRow): ConnectionSummaryView {
  return {
    id: row.publicId,
    provider: row.provider,
    displayName: row.displayName,
    status: row.status,
    tenantName: row.externalTenantName,
    outboundMode: row.outboundMode,
    internalRouting: row.internalRouting,
    health: row.healthStatus,
    healthChangedAt: iso(row.healthChangedAt),
    domainCount: row.domainCount,
    createdAt: row.createdAt.toISOString(),
  };
}

export function toConnectionDetail(aggregate: ConnectionAggregate): ConnectionDetailView {
  const c = aggregate.connection;
  const proof = relayProofOf(c);
  return {
    ...toConnectionSummary({ ...c, domainCount: aggregate.domains.length }),
    tenantId: c.externalTenantId,
    tenantVerifiedAt: iso(c.tenantVerifiedAt),
    grants: aggregate.grants.map(toGrantView),
    domains: aggregate.domains.map((d) => ({
      id: d.domainPublicId,
      name: d.name,
      providerVerification: d.providerVerification,
    })),
    relayConnectorId: aggregate.connector?.publicId ?? null,
    relayProof: proof.policy,
    relayProofIsDefault: proof.isDefault,
    attestations: attestationsOf(c.attestations),
    routeTokenVersion: c.routeTokenVersion,
    routeTokenPendingVersion: c.routeTokenPendingVersion,
    healthCheckedAt: iso(c.healthCheckedAt),
    nextHealthCheckAt: iso(c.nextHealthCheckAt),
    disabledAt: iso(c.disabledAt),
    rowVersion: c.rowVersion,
    updatedAt: c.updatedAt.toISOString(),
  };
}

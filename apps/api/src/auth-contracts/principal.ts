/**
 * Who is calling (D9). Built by the authentication guard from a verified credential and the
 * database, never from client-supplied tenant identifiers.
 */

/** An active, audited platform override into a customer organization (D9). */
export interface OverrideContext {
  id: string; // UUID
  reason: string;
  targetOrganizationId: bigint;
  targetOrganizationPublicId: string;
  expiresAt: Date;
}

export interface UserPrincipal {
  kind: 'user';
  userId: bigint;
  userPublicId: string;
  organizationId: bigint; // the user's home organization
  organizationPublicId: string;
  organizationKind: 'customer' | 'platform';
  sessionId: string; // family_id
  mfaAuthenticated: boolean;
  mfaEnrollmentRequired: boolean;
  permissions: ReadonlySet<string>; // effective (already intersected under override)
  override?: OverrideContext;
}

export interface ApiKeyPrincipal {
  kind: 'api_key';
  apiKeyId: bigint;
  apiKeyPublicId: string;
  organizationId: bigint;
  organizationPublicId: string;
  permissions: ReadonlySet<string>;
}

export type Principal = UserPrincipal | ApiKeyPrincipal;

import type { ProtectionMode } from '@email-gateway/mailbox-api';
import type { Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';

/** The feature that entitles API mode (catalog `FEATURE_KEYS`, D1). */
export const API_MODE_FEATURE = 'api_mode_protection';

export interface OrgDomain {
  id: bigint;
  /** Lower-case domain name. */
  name: string;
  configuredMode: ProtectionMode | null;
  /** `COALESCE(domains.protection_mode, organizations.protection_mode)`. */
  effectiveMode: ProtectionMode;
}

export interface OrgApiModeState {
  organizationId: bigint;
  organizationMode: ProtectionMode;
  /** Feature `api_mode_protection` effective (organization row, else the plan default). */
  entitled: boolean;
  /** Entitled and ≥ 1 non-deleted domain with effective mode api or hybrid (D1). */
  active: boolean;
  /** Non-deleted domains of the organization. */
  domains: OrgDomain[];
}

/** The effective boolean feature: the organization row, else the plan's `default_features`. */
export function featureEnabled(
  row: { enabled: boolean } | null,
  planDefaults: unknown,
  key: string,
): boolean {
  if (row) return row.enabled;
  const value =
    planDefaults && typeof planDefaults === 'object' && !Array.isArray(planDefaults)
      ? (planDefaults as Record<string, unknown>)[key]
      : undefined;
  return value === true;
}

export const isApiSide = (mode: ProtectionMode | null | undefined): boolean =>
  mode === 'api' || mode === 'hybrid';

/** D1: entitled and at least one API-side domain. */
export function apiModeActive(entitled: boolean, domains: readonly OrgDomain[]): boolean {
  return entitled && domains.some((d) => isApiSide(d.effectiveMode));
}

/**
 * The organization's API-mode state on the writer (mail-path decisions never use the replica,
 * ADR-0014): its mode, the entitlement and its non-deleted domains with their effective modes.
 * Null for an unknown organization.
 */
export async function loadOrgApiModeState(
  db: Db,
  organizationId: bigint,
): Promise<OrgApiModeState | null> {
  const org = await db.organization.findUnique({
    where: { id: organizationId },
    select: {
      id: true,
      protectionMode: true,
      plan: { select: { defaultFeatures: true } },
    },
  });
  if (!org) return null;
  if (org.id !== organizationId) throw new InconsistentReadError('organizations');
  const [feature, domains] = await Promise.all([
    db.organizationFeature.findUnique({
      where: { organizationId_featureKey: { organizationId, featureKey: API_MODE_FEATURE } },
      select: { enabled: true },
    }),
    db.domain.findMany({
      where: { organizationId, deletedAt: null },
      select: { id: true, name: true, protectionMode: true, organizationId: true },
      orderBy: { id: 'asc' },
    }),
  ]);
  const list: OrgDomain[] = [];
  for (const d of domains) {
    if (d.organizationId !== organizationId) throw new InconsistentReadError('domains');
    list.push({
      id: d.id,
      name: d.name.toLowerCase().replace(/\.$/, ''),
      configuredMode: d.protectionMode,
      effectiveMode: d.protectionMode ?? org.protectionMode,
    });
  }
  const entitled = featureEnabled(feature, org.plan.defaultFeatures, API_MODE_FEATURE);
  return {
    organizationId,
    organizationMode: org.protectionMode,
    entitled,
    active: apiModeActive(entitled, list),
    domains: list,
  };
}

/** The organization domain of an address (exact domain match), or null. */
export function domainForAddress(domains: readonly OrgDomain[], address: string): OrgDomain | null {
  const at = address.lastIndexOf('@');
  if (at <= 0) return null;
  const name = address
    .slice(at + 1)
    .trim()
    .toLowerCase()
    .replace(/\.$/, '');
  return domains.find((d) => d.name === name) ?? null;
}

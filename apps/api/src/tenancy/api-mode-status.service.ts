import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { OrganizationFeaturesService } from './organization-features.service';

/** The plan feature of API-mode protection (step API-1 §3.3, D1). */
export const API_MODE_FEATURE = 'api_mode_protection';

/** The three protection modes (ADR-0098). */
export const PROTECTION_MODES = ['inline', 'api', 'hybrid'] as const;
export type ProtectionModeValue = (typeof PROTECTION_MODES)[number];

/** Non-deleted domains of an organization per EFFECTIVE mode (domain ?? organization). */
export type DomainsByEffectiveMode = Record<ProtectionModeValue, number>;

/** The API-mode facts of one organization (writer, or the caller's transaction). */
export interface ApiModeStatus {
  /** `api_mode_protection` effective (feature row, else the plan default). */
  entitled: boolean;
  /** Entitled and at least one non-deleted domain is effective `api` or `hybrid` (D1). */
  active: boolean;
  organizationMode: ProtectionModeValue;
  domainsByEffectiveMode: DomainsByEffectiveMode;
}

/**
 * Counts per effective mode from the grouped `(protection_mode)` rows of the domains and the
 * organization's own mode: a NULL domain mode inherits the organization's (D1). Pure.
 */
export function effectiveModeCounts(
  organizationMode: ProtectionModeValue,
  rows: ReadonlyArray<{ mode: ProtectionModeValue | null; count: number }>,
): DomainsByEffectiveMode {
  const out: DomainsByEffectiveMode = { inline: 0, api: 0, hybrid: 0 };
  for (const row of rows) out[row.mode ?? organizationMode] += row.count;
  return out;
}

/**
 * "API mode active" for an organization (step API-1 D1): the feature `api_mode_protection` is
 * effective **and** at least one non-deleted domain has an effective mode in (`api`, `hybrid`).
 * It entitles journal intake without archiving (D6) and drives detect scanning (D8). Read on the
 * writer (authorization decisions never use the replica); tests override it with a double.
 */
@Injectable()
export class ApiModeStatusService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly features: OrganizationFeaturesService,
  ) {}

  async status(organizationId: bigint, client?: Prisma.TransactionClient): Promise<ApiModeStatus> {
    const db = client ?? this.prisma;
    const [entitled, org, grouped] = await Promise.all([
      this.features.isEffectivelyEnabled(organizationId, API_MODE_FEATURE, client),
      db.organization.findUnique({
        where: { id: organizationId },
        select: { protectionMode: true },
      }),
      db.domain.groupBy({
        by: ['protectionMode'],
        where: { organizationId, status: { not: 'deleted' } },
        _count: { _all: true },
      }),
    ]);
    const organizationMode = org?.protectionMode ?? 'inline';
    const counts = effectiveModeCounts(
      organizationMode,
      grouped.map((g) => ({ mode: g.protectionMode, count: g._count._all })),
    );
    return {
      entitled,
      active: entitled && counts.api + counts.hybrid > 0,
      organizationMode,
      domainsByEffectiveMode: counts,
    };
  }

  /** D1: entitled and at least one effective `api`/`hybrid` domain. */
  async isActive(organizationId: bigint, client?: Prisma.TransactionClient): Promise<boolean> {
    return (await this.status(organizationId, client)).active;
  }
}

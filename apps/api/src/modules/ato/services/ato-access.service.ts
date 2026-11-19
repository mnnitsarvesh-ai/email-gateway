import { BadRequestException, Injectable } from '@nestjs/common';
import {
  isLearning,
  resolveAtoSettings,
  type ResolvedAtoSettings,
} from '@email-gateway/ato-detection';
import type { Prisma } from '@email-gateway/database';
import type { IncidentActor } from '@email-gateway/security-incidents';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import { ATO_FEATURE, ATO_PERMISSIONS } from '../ato.constants';
import { atoNotEnabled } from '../ato.errors';
import { type Capabilities, parseCapabilities } from '../domain/ato-views';
import { PublicIdSchema } from '../dto/ato.schemas';
import { AtoReadRepository, type Db } from '../repositories/ato-read.repository';

type Tx = Prisma.TransactionClient;

/** A path id (`{accountId}`, `{responseId}`, …): a UUID, `400` before any read; lower-cased. */
export function parsePublicId(raw: unknown, name: string): string {
  const parsed = PublicIdSchema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException([`${name}: must be a UUID`]);
  return parsed.data.toLowerCase();
}

/** The organization's ATO settings as every reader sees them (stored over the defaults). */
export interface LoadedAtoSettings {
  settings: ResolvedAtoSettings;
  stored: Record<string, unknown>;
  invalid: boolean;
  version: number;
  rowVersion: number;
  learningStartedAt: Date | null;
  learning: boolean;
  learningEndsAt: Date | null;
  updatedAt: Date | null;
}

/**
 * Shared rules of the ATO module (step 8.4 D17, D21): the plan feature gate (writer read: reads
 * answer `featureEnabled: false` with empty data, mutations `403 ato_not_enabled`), the settings
 * every view resolves, the worker capabilities and the incident actor of a principal.
 */
@Injectable()
export class AtoAccessService {
  constructor(
    private readonly features: OrganizationFeaturesService,
    private readonly reads: AtoReadRepository,
    private readonly audit: AuditService,
  ) {}

  now(): Date {
    return new Date();
  }

  /** Whether `ato_detection` is enabled for the organization (writer). */
  enabled(scope: TenantScope, tx?: Tx): Promise<boolean> {
    return this.features.isEnabled(scope.organizationId, ATO_FEATURE, tx);
  }

  /** `403 ato_not_enabled` unless the feature is enabled (inside the mutation's transaction). */
  async requireEnabled(scope: TenantScope, tx?: Tx): Promise<void> {
    if (!(await this.enabled(scope, tx))) throw atoNotEnabled();
  }

  /** The organization's settings (defaults when none are stored yet; invalid → defaults). */
  async settings(scope: TenantScope, db?: Db): Promise<LoadedAtoSettings> {
    const row = await this.reads.settingsRow(scope, db);
    const { settings, invalid } = resolveAtoSettings(row?.settings ?? null);
    const now = this.now();
    const learningEndsAt = row
      ? new Date(row.learningStartedAt.getTime() + settings.learningDays * 86_400_000)
      : null;
    return {
      settings,
      stored:
        row &&
        row.settings !== null &&
        typeof row.settings === 'object' &&
        !Array.isArray(row.settings)
          ? (row.settings as Record<string, unknown>)
          : {},
      invalid: row !== null && invalid,
      version: row?.version ?? 0,
      rowVersion: row?.rowVersion ?? 0,
      learningStartedAt: row?.learningStartedAt ?? null,
      learning: row ? isLearning(settings, row.learningStartedAt, now) : false,
      learningEndsAt,
      updatedAt: row?.updatedAt ?? null,
    };
  }

  /** The worker capabilities (D17; stale or missing → unknown). */
  async capabilities(): Promise<Capabilities> {
    return parseCapabilities(await this.reads.capabilitiesRaw(), this.now());
  }

  /** The incident actor of a principal (public ids; the internal user id for user columns). */
  actorOf(principal: Principal): IncidentActor {
    const audit = this.audit.actorFrom(principal);
    return principal.kind === 'user'
      ? {
          type: 'user',
          id: principal.userPublicId,
          userId: principal.userId,
          ...(audit.override && { override: audit.override }),
        }
      : { type: 'api_key', id: principal.apiKeyPublicId };
  }

  /** A user with `ato:respond` and an MFA session (who may decide and roll back). */
  static canRespondWithMfa(principal: Principal): boolean {
    return (
      principal.kind === 'user' &&
      principal.mfaAuthenticated &&
      principal.permissions.has(ATO_PERMISSIONS.respond)
    );
  }

  /** The public id of the caller (user or API key). */
  static callerPublicId(principal: Principal): string {
    return principal.kind === 'user' ? principal.userPublicId : principal.apiKeyPublicId;
  }
}

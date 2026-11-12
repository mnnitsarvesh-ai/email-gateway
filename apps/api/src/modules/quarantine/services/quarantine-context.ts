import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import {
  type QuarantinePlatformBounds,
  type QuarantineSettings,
  QUARANTINE_PERMISSIONS,
  resolveQuarantineSettings,
} from '@email-gateway/quarantine';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { QuarantineConfig } from '../quarantine.constants';
import { QuarantineReadRepository } from '../repositories/quarantine-read.repository';
import { QuarantineWriteRepository } from '../repositories/quarantine-write.repository';
import { MetricsService } from '@email-gateway/common';

/** The end user of a self route (Q15): a user principal with a verified, active address. */
export interface SelfCaller {
  principal: UserPrincipal;
  userId: bigint;
  /** Lower-cased verified email: the only recipient address the caller may see. */
  address: string;
}

export const permissionsOf = (principal: Principal): string[] => [...principal.permissions];

/**
 * Who calls and under which tenant settings (step 5.3 Q15, Q24): the effective quarantine
 * settings (stored document + defaults + platform bounds + `organization_settings`; an invalid
 * stored document falls back to the defaults and is counted) and the self-service caller.
 */
@Injectable()
export class QuarantineContext {
  private readonly invalidSettings;

  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<
      QuarantineConfig,
      'QUARANTINE_MAX_HOLD_DAYS' | 'QUARANTINE_MAX_REVIEW_DAYS'
    >,
    private readonly reads: QuarantineReadRepository,
    private readonly writes: QuarantineWriteRepository,
    metrics: MetricsService,
  ) {
    this.invalidSettings = metrics.counter(
      'quarantine_settings_invalid_total',
      'Stored quarantine settings documents that failed validation (defaults applied)',
    );
  }

  get bounds(): QuarantinePlatformBounds {
    return {
      maxHoldDays: this.config.QUARANTINE_MAX_HOLD_DAYS,
      maxReviewDays: this.config.QUARANTINE_MAX_REVIEW_DAYS,
    };
  }

  /** Effective settings from the replica (views, pre-checks, catalog). */
  async settings(scope: TenantScope): Promise<QuarantineSettings> {
    const [row, org] = await Promise.all([
      this.reads.settings(scope),
      this.reads.orgSettings(scope),
    ]);
    return this.resolve(row?.settings ?? null, org);
  }

  /** Effective settings on the writer (deciding reads, echo-checked). */
  async settingsTx(tx: Prisma.TransactionClient, scope: TenantScope): Promise<QuarantineSettings> {
    const [doc, org] = await Promise.all([
      this.writes.settingsDocument(tx, scope),
      this.writes.orgSettings(tx, scope),
    ]);
    return this.resolve(doc, org);
  }

  resolve(raw: unknown, org: Parameters<typeof resolveQuarantineSettings>[2]): QuarantineSettings {
    const resolved = resolveQuarantineSettings(raw, this.bounds, org);
    if (resolved.violations.length > 0) this.invalidSettings.inc();
    return resolved.settings;
  }

  /**
   * Q15: a user principal (API keys and platform overrides are refused), holding
   * `quarantine:self`, active, with a verified email. `403` otherwise.
   */
  async selfCaller(principal: Principal, scope: TenantScope): Promise<SelfCaller> {
    if (principal.kind !== 'user' || scope.via !== 'member') {
      throw new ForbiddenException('Self-service routes are for mailbox users only');
    }
    if (!principal.permissions.has(QUARANTINE_PERMISSIONS.self)) {
      throw new ForbiddenException('Missing permission');
    }
    const identity = await this.reads.identity(principal.userId);
    if (identity === null || !identity.active || !identity.emailVerified) {
      throw new ForbiddenException('A verified email address is required');
    }
    return { principal, userId: principal.userId, address: identity.email };
  }

  /** The approver's own verified address (SoD by address, Q14); null when unverified. */
  async verifiedEmail(userId: bigint): Promise<string | null> {
    const identity = await this.reads.identity(userId);
    return identity !== null && identity.emailVerified ? identity.email : null;
  }
}

import { ConflictException, Inject, Injectable, Logger } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import { RevokeReason } from '../../auth/auth.constants';
import { PrincipalCacheService } from '../../auth/services/principal-cache.service';
import { SessionService } from '../../auth/services/session.service';
import {
  assertCanCancelDeletion,
  assertCanConfirmDeletion,
  assertCanRequestDeletion,
  computePurgeAfter,
} from '../domain/deletion-state';
import { assertPlatform, type OrganizationAccess } from '../domain/organization-access';
import type {
  DeletionCancelInput,
  DeletionConfirmInput,
  DeletionRequestInput,
} from '../dto/organizations.schemas';
import { type DeletionStateResponse, toDeletionStateResponse } from '../organization.mapper';
import { OrganizationsRepository, type VisibleOrganization } from '../organizations.repository';
import { type RequestOrigin, requireVisible } from './organization-guards';

export type DeletionConfig = Pick<
  ApiConfig,
  'ORG_DELETION_RETENTION_DAYS' | 'ORG_DELETION_CONFIRM_WINDOW_HOURS'
>;

const CONCURRENT_CHANGE = 'The organization status changed concurrently';

/**
 * Organization deletion workflow (D12): request (suspended organizations only) → confirmation by
 * a second platform user within the window → `deleted` with `purge_after`; cancellable until the
 * purge time. Active legal holds block request and confirmation. The purge itself is deferred
 * (docs/runbooks/organization-deletion.md). Every step is a catalog function, audited, and
 * (except reading the state) requires an MFA session (route decorators).
 */
@Injectable()
export class OrganizationDeletionService {
  private readonly logger = new Logger(OrganizationDeletionService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: DeletionConfig,
    private readonly repository: OrganizationsRepository,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly sessions: SessionService,
    private readonly principalCache: PrincipalCacheService,
  ) {}

  async get(access: OrganizationAccess, publicId: string): Promise<DeletionStateResponse> {
    assertPlatform(access);
    return this.present(await requireVisible(this.repository, access, publicId));
  }

  /** Step 1: `suspended` → `pending_deletion`. */
  async request(
    principal: UserPrincipal,
    access: OrganizationAccess,
    publicId: string,
    input: DeletionRequestInput,
    origin: RequestOrigin,
  ): Promise<DeletionStateResponse> {
    assertPlatform(access);
    const org = await this.transactions.run(async (tx) => {
      const found = await requireVisible(this.repository, access, publicId, tx);
      const current = await this.repository.lockAndReload(tx, found);
      assertCanRequestDeletion(
        current,
        input.confirmSlug,
        await this.repository.activeLegalHolds(current, tx),
      );
      const now = new Date();
      const moved = await this.repository.transition(tx, current, ['suspended'], {
        statusBeforeDeletion: current.status,
        status: 'pending_deletion',
        statusChangedAt: now,
        deletionRequestedAt: now,
        deletionRequestedByUserId: principal.userId,
        deletionReason: input.reason,
        deletionConfirmedAt: null,
        deletionConfirmedByUserId: null,
        purgeAfter: null,
      });
      if (!moved) throw new ConflictException(CONCURRENT_CHANGE);
      await this.audit.record(
        {
          organizationId: current.id,
          actor: this.audit.actorFrom(principal),
          action: 'organization.deletion_requested',
          resourceType: 'organization',
          resourceId: current.publicId,
          sourceIp: origin.ip,
          metadata: {
            reason: input.reason,
            confirmationWindowHours: this.config.ORG_DELETION_CONFIRM_WINDOW_HOURS,
          },
        },
        tx,
      );
      return this.repository.reload(tx, current);
    });
    await this.principalCache.invalidateOrganization(org.id);
    return this.present(org);
  }

  /**
   * Step 2 (four-eyes): `pending_deletion` → `deleted`. Revokes every API key (in the
   * transaction) and every session (after commit), and invalidates the authentication caches.
   */
  async confirm(
    principal: UserPrincipal,
    access: OrganizationAccess,
    publicId: string,
    input: DeletionConfirmInput,
    origin: RequestOrigin,
  ): Promise<DeletionStateResponse> {
    assertPlatform(access);
    const { org, revokedPrefixes } = await this.transactions.run(async (tx) => {
      const found = await requireVisible(this.repository, access, publicId, tx);
      const current = await this.repository.lockAndReload(tx, found);
      const now = new Date();
      assertCanConfirmDeletion(
        current,
        {
          confirmSlug: input.confirmSlug,
          actorUserId: principal.userId,
          now,
          windowHours: this.config.ORG_DELETION_CONFIRM_WINDOW_HOURS,
        },
        await this.repository.activeLegalHolds(current, tx),
      );
      const purgeAfter = computePurgeAfter(
        now,
        this.config.ORG_DELETION_RETENTION_DAYS,
        await this.repository.latestArchiveRetainUntil(current, tx),
      );
      const moved = await this.repository.transition(tx, current, ['pending_deletion'], {
        status: 'deleted',
        statusChangedAt: now,
        deletedAt: now,
        deletionConfirmedAt: now,
        deletionConfirmedByUserId: principal.userId,
        purgeAfter,
      });
      if (!moved) throw new ConflictException(CONCURRENT_CHANGE);
      const prefixes = await this.repository.revokeApiKeys(tx, current, now);
      await this.audit.record(
        {
          organizationId: current.id,
          actor: this.audit.actorFrom(principal),
          action: 'organization.deletion_confirmed',
          resourceType: 'organization',
          resourceId: current.publicId,
          sourceIp: origin.ip,
          metadata: { purgeAfter, apiKeysRevoked: prefixes.length },
        },
        tx,
      );
      return { org: await this.repository.reload(tx, current), revokedPrefixes: prefixes };
    });

    const sessions = await this.sessions.revokeAllForOrganization(
      org.id,
      RevokeReason.organizationDeleted,
    );
    await this.principalCache.invalidateOrganization(org.id);
    for (const prefix of revokedPrefixes) await this.principalCache.invalidateApiKey(prefix);
    this.logger.log({
      message: 'Organization deletion confirmed',
      organizationId: org.publicId,
      sessionsRevoked: sessions,
      apiKeysRevoked: revokedPrefixes.length,
    });
    return this.present(org);
  }

  /**
   * Step 3: `pending_deletion`, or `deleted` before `purge_after`, → `suspended`. The deletion
   * fields are cleared; the audit trail keeps the history. Re-activation is a separate status
   * change; API keys revoked by the confirmation stay revoked.
   */
  async cancel(
    principal: UserPrincipal,
    access: OrganizationAccess,
    publicId: string,
    input: DeletionCancelInput,
    origin: RequestOrigin,
  ): Promise<DeletionStateResponse> {
    assertPlatform(access);
    const org = await this.transactions.run(async (tx) => {
      const found = await requireVisible(this.repository, access, publicId, tx);
      const current = await this.repository.lockAndReload(tx, found);
      const now = new Date();
      assertCanCancelDeletion(current, now);
      const requester = current.deletionRequestedByUserId;
      const confirmer = current.deletionConfirmedByUserId;
      const ids = await this.repository.userPublicIds(
        [requester, confirmer].filter((id): id is bigint => id !== null),
        tx,
      );
      const moved = await this.repository.transition(tx, current, [current.status], {
        status: 'suspended',
        statusChangedAt: now,
        deletedAt: null,
        deletionRequestedAt: null,
        deletionRequestedByUserId: null,
        deletionReason: null,
        deletionConfirmedAt: null,
        deletionConfirmedByUserId: null,
        statusBeforeDeletion: null,
        purgeAfter: null,
      });
      if (!moved) throw new ConflictException(CONCURRENT_CHANGE);
      await this.audit.record(
        {
          organizationId: current.id,
          actor: this.audit.actorFrom(principal),
          action: 'organization.deletion_cancelled',
          resourceType: 'organization',
          resourceId: current.publicId,
          sourceIp: origin.ip,
          metadata: {
            reason: input.reason,
            fromStatus: current.status,
            requestedAt: current.deletionRequestedAt,
            requestedBy: requester === null ? null : (ids.get(requester) ?? null),
            requestReason: current.deletionReason,
            confirmedAt: current.deletionConfirmedAt,
            confirmedBy: confirmer === null ? null : (ids.get(confirmer) ?? null),
            purgeAfter: current.purgeAfter,
          },
        },
        tx,
      );
      return this.repository.reload(tx, current);
    });
    await this.principalCache.invalidateOrganization(org.id);
    return this.present(org);
  }

  private async present(org: VisibleOrganization): Promise<DeletionStateResponse> {
    const ids = await this.repository.userPublicIds(
      [org.deletionRequestedByUserId, org.deletionConfirmedByUserId].filter(
        (id): id is bigint => id !== null,
      ),
    );
    return toDeletionStateResponse(
      org,
      ids,
      this.config.ORG_DELETION_CONFIRM_WINDOW_HOURS,
      new Date(),
    );
  }
}

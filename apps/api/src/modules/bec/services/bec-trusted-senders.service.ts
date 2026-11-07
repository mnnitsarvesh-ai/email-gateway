import { Inject, Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import { isUniqueViolation } from '../../domains/repositories/domains.repository';
import {
  becExists,
  becLimitReached,
  becNotFound,
  becVersionConflict,
  trustedDomainFreemail,
} from '../bec.errors';
import { checkTrustedExpiry, normalizeTrustedValue } from '../domain/bec-inputs';
import type {
  BecTrustedSenderCreate,
  BecTrustedSenderListQuery,
  BecTrustedSenderPage,
  BecTrustedSenderUpdate,
  BecTrustedSenderView,
} from '../dto/bec.schemas';
import {
  BecProfilesRepository,
  type TrustedSenderRow,
} from '../repositories/bec-profiles.repository';
import { BEC_AUDIT, BEC_RESOURCE, BecWriter, iso, userIdOf } from './bec-writer';

export function trustedSenderView(row: TrustedSenderRow, now: Date): BecTrustedSenderView {
  return {
    id: row.publicId,
    kind: row.kind,
    value: row.value,
    reason: row.reason,
    expiresAt: iso(row.expiresAt),
    expired: row.expiresAt !== null && row.expiresAt.getTime() <= now.getTime(),
    version: row.version,
    createdByUserId: row.createdBy?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

const image = (row: TrustedSenderRow) => ({
  kind: row.kind,
  value: row.value,
  reason: row.reason,
  expiresAt: iso(row.expiresAt),
  version: row.version,
});

/**
 * Trusted senders of the caller's organization (step 4.4 B7, B18): an exact address (normalized,
 * lower case) or a registrable domain (url-security; free-mail domains refused with
 * `422 trusted_domain_freemail`), unique per `(kind, value)` (`409 trusted_sender_exists`), a
 * reason and an optional expiry (future, ≤ 365 days). At most `BEC_MAX_TRUSTED_SENDERS` per
 * organization. Trust applies only when the message authenticates as From (the engine's rule).
 * Writes on the writer with their audit row in the same transaction; lists on the replica.
 */
@Injectable()
export class BecTrustedSendersService {
  private readonly logger = new Logger(BecTrustedSendersService.name);

  constructor(
    @Inject(API_CONFIG) private readonly limits: { BEC_MAX_TRUSTED_SENDERS: number },
    private readonly repository: BecProfilesRepository,
    private readonly writer: BecWriter,
    private readonly audit: AuditService,
  ) {}

  async list(scope: TenantScope, query: BecTrustedSenderListQuery): Promise<BecTrustedSenderPage> {
    const now = new Date();
    const rows = await this.repository.listTrustedSenders(scope, {
      ...pageWindow(query),
      ...(query.kind !== undefined && { kind: query.kind }),
    });
    return toPage(rows, query.limit, (row) => trustedSenderView(row, now));
  }

  async create(
    principal: Principal,
    scope: TenantScope,
    body: BecTrustedSenderCreate,
    client: ClientContext,
  ): Promise<BecTrustedSenderView> {
    const now = new Date();
    const { value, freemail } = normalizeTrustedValue(body.kind, body.value);
    if (freemail) throw trustedDomainFreemail();
    const expiresAt = checkTrustedExpiry(body.expiresAt, now);
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const existing = await this.repository.findTrustedByValue(tx, scope, body.kind, value);
        if (existing) throw becExists('trusted_sender', existing.publicId);
        const count = await this.repository.countTrustedSenders(tx, scope);
        if (count >= this.limits.BEC_MAX_TRUSTED_SENDERS) {
          throw becLimitReached('trusted_senders', this.limits.BEC_MAX_TRUSTED_SENDERS);
        }
        const row = await this.repository.createTrustedSender(
          tx,
          scope,
          uuidv7(),
          { kind: body.kind, value, reason: body.reason, expiresAt },
          userIdOf(principal),
        );
        await this.record(
          principal,
          scope,
          client,
          BEC_AUDIT.trustedCreated,
          row.publicId,
          {
            after: image(row),
          },
          tx,
        );
        return trustedSenderView(row, now);
      });
      this.logChange('created', scope, view.id, view.kind);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw becExists('trusted_sender', null);
      throw error;
    }
  }

  async update(
    principal: Principal,
    scope: TenantScope,
    id: string,
    body: BecTrustedSenderUpdate,
    client: ClientContext,
  ): Promise<BecTrustedSenderView> {
    const now = new Date();
    const expiresAt =
      body.expiresAt === undefined ? undefined : checkTrustedExpiry(body.expiresAt, now);
    const view = await this.writer.run(async (tx) => {
      const current = await this.repository.findTrustedForUpdate(tx, scope, id);
      if (!current) throw becNotFound('trusted_sender');
      if (current.version !== body.version) throw becVersionConflict(current.version);
      const updated = await this.repository.updateTrustedSender(
        tx,
        scope,
        current.id,
        body.version,
        {
          reason: body.reason ?? current.reason,
          expiresAt: expiresAt === undefined ? current.expiresAt : expiresAt,
        },
      );
      if (!updated) throw becVersionConflict(current.version);
      const row = await this.repository.trustedById(tx, scope, current.id);
      await this.record(
        principal,
        scope,
        client,
        BEC_AUDIT.trustedUpdated,
        row.publicId,
        {
          before: image(current),
          after: image(row),
        },
        tx,
      );
      return trustedSenderView(row, now);
    });
    this.logChange('updated', scope, view.id, view.kind);
    return view;
  }

  async remove(
    principal: Principal,
    scope: TenantScope,
    id: string,
    version: number | undefined,
    client: ClientContext,
  ): Promise<void> {
    const kind = await this.writer.run(async (tx) => {
      const current = await this.repository.findTrustedForUpdate(tx, scope, id);
      if (!current) throw becNotFound('trusted_sender');
      if (version !== undefined && current.version !== version) {
        throw becVersionConflict(current.version);
      }
      await this.repository.deleteTrustedSender(tx, scope, current.id);
      await this.record(
        principal,
        scope,
        client,
        BEC_AUDIT.trustedDeleted,
        current.publicId,
        {
          before: image(current),
        },
        tx,
      );
      return current.kind;
    });
    this.logChange('deleted', scope, id, kind);
  }

  private record(
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    action: string,
    resourceId: string,
    metadata: Record<string, unknown>,
    tx: Parameters<AuditService['record']>[1],
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: BEC_RESOURCE.trusted,
        resourceId,
        sourceIp: client.ip,
        metadata,
      },
      tx,
    );
  }

  /** Ids and kinds only: addresses and domains are never logged. */
  private logChange(change: string, scope: TenantScope, id: string, kind: string): void {
    this.logger.log({
      message: `bec trusted sender ${change}`,
      organizationId: scope.organizationId.toString(),
      id,
      kind,
    });
  }
}

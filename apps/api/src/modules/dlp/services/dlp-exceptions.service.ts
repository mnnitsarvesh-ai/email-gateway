import { Inject, Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import { isUniqueViolation } from '../../domains/repositories/domains.repository';
import {
  dlpExists,
  dlpLimitReached,
  dlpNotFound,
  dlpReferenceInvalid,
  dlpVersionConflict,
} from '../dlp.errors';
import {
  checkExceptionExpiry,
  exceptionTargetKey,
  normalizeExceptionValue,
} from '../domain/dlp-inputs';
import type {
  DlpExceptionCreate,
  DlpExceptionListQuery,
  DlpExceptionPage,
  DlpExceptionUpdate,
  DlpExceptionView,
} from '../dto/dlp.schemas';
import { DlpConfigRepository } from '../repositories/dlp-config.repository';
import { DlpAuditor, exceptionImage, exceptionView } from './dlp-views';
import { DLP_AUDIT, DLP_RESOURCE, DlpWriter, userIdOf } from './dlp-writer';

type Limits = { DLP_EXCEPTIONS_MAX_PER_TENANT: number; DLP_EXCEPTION_MAX_DAYS: number };

/**
 * DLP exceptions (step 4.5 D12, D21): a sender or recipient address or domain (normalized;
 * domains through url-security), an optional target (one policy or one rule of the
 * organization, else every rule), optional detector/category filters, a required reason and a
 * required expiry (future, ≤ DLP_EXCEPTION_MAX_DAYS). Unique per (scope, value, target)
 * (`409 dlp_exception_exists`), at most DLP_EXCEPTIONS_MAX_PER_TENANT per organization. Writes
 * under the organization row lock with the audit row and before-image in the same transaction.
 * Expired exceptions are listed (`expired: true`) and ignored by the engine.
 */
@Injectable()
export class DlpExceptionsService {
  private readonly logger = new Logger(DlpExceptionsService.name);

  constructor(
    @Inject(API_CONFIG) private readonly limits: Limits,
    private readonly repository: DlpConfigRepository,
    private readonly writer: DlpWriter,
    private readonly auditor: DlpAuditor,
  ) {}

  async list(scope: TenantScope, query: DlpExceptionListQuery): Promise<DlpExceptionPage> {
    const now = new Date();
    const rows = await this.repository.listExceptions(scope, {
      ...pageWindow(query),
      now,
      ...(query.scope !== undefined && { scope: query.scope }),
      ...(query.active !== undefined && { active: query.active }),
    });
    return toPage(rows, query.limit, (row) => exceptionView(row, now));
  }

  async create(
    principal: Principal,
    scope: TenantScope,
    body: DlpExceptionCreate,
    client: ClientContext,
  ): Promise<DlpExceptionView> {
    const now = new Date();
    const value = normalizeExceptionValue(body.scope, body.value);
    const expiresAt = checkExceptionExpiry(body.expiresAt, now, this.limits.DLP_EXCEPTION_MAX_DAYS);
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const target = await this.target(tx, scope, body);
        const targetKey = exceptionTargetKey(target);
        const existing = await this.repository.exceptionByKey(tx, scope, {
          scope: body.scope,
          value,
          targetKey,
        });
        if (existing) throw dlpExists('exception', existing.publicId);
        const count = await this.repository.countExceptions(tx, scope);
        if (count >= this.limits.DLP_EXCEPTIONS_MAX_PER_TENANT) {
          throw dlpLimitReached('exceptions', this.limits.DLP_EXCEPTIONS_MAX_PER_TENANT);
        }
        const row = await this.repository.createException(
          tx,
          scope,
          uuidv7(now.getTime()),
          {
            scope: body.scope,
            value,
            policyId: target.policyId,
            ruleId: target.ruleId,
            targetKey,
            filters: body.filters ?? null,
            reason: body.reason,
            expiresAt,
            enabled: body.enabled,
          },
          userIdOf(principal),
        );
        await this.record(tx, principal, scope, client, DLP_AUDIT.exceptionCreated, row.publicId, {
          after: exceptionImage(row),
        });
        return exceptionView(row, now);
      });
      this.logChange('created', scope, view.id, view.scope);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw dlpExists('exception', null);
      throw error;
    }
  }

  async update(
    principal: Principal,
    scope: TenantScope,
    id: string,
    body: DlpExceptionUpdate,
    client: ClientContext,
  ): Promise<DlpExceptionView> {
    const now = new Date();
    const expiresAt =
      body.expiresAt === undefined
        ? undefined
        : checkExceptionExpiry(body.expiresAt, now, this.limits.DLP_EXCEPTION_MAX_DAYS);
    const view = await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      const current = await this.repository.findExceptionForUpdate(tx, scope, id);
      if (!current) throw dlpNotFound('exception');
      if (current.version !== body.version) throw dlpVersionConflict(current.version);
      const updated = await this.repository.updateException(
        tx,
        scope,
        current.id,
        body.version,
        {
          reason: body.reason ?? current.reason,
          expiresAt: expiresAt ?? current.expiresAt,
          enabled: body.enabled ?? current.enabled,
          filters:
            body.filters === undefined
              ? (exceptionImage(current).filters ?? null)
              : (body.filters ?? null),
        },
        userIdOf(principal),
      );
      if (!updated) throw dlpVersionConflict(current.version);
      const row = await this.repository.exceptionById(tx, scope, current.id);
      await this.record(tx, principal, scope, client, DLP_AUDIT.exceptionUpdated, row.publicId, {
        before: exceptionImage(current),
        after: exceptionImage(row),
      });
      return exceptionView(row, now);
    });
    this.logChange('updated', scope, view.id, view.scope);
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
      await this.repository.lockOrganization(tx, scope);
      const current = await this.repository.findExceptionForUpdate(tx, scope, id);
      if (!current) throw dlpNotFound('exception');
      if (version !== undefined && current.version !== version) {
        throw dlpVersionConflict(current.version);
      }
      await this.repository.deleteException(tx, scope, current.id);
      await this.record(
        tx,
        principal,
        scope,
        client,
        DLP_AUDIT.exceptionDeleted,
        current.publicId,
        {
          before: exceptionImage(current),
        },
      );
      return current.scope;
    });
    this.logChange('deleted', scope, id, kind);
  }

  /** The policy or rule an exception targets (the organization's, else `400`). */
  private async target(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    body: DlpExceptionCreate,
  ): Promise<{ policyId: bigint | null; ruleId: bigint | null }> {
    if (body.ruleId !== undefined) {
      const ruleId = await this.repository.ruleIdOf(tx, scope, body.ruleId);
      if (ruleId === null) throw dlpReferenceInvalid('ruleId');
      return { policyId: null, ruleId };
    }
    if (body.policyId !== undefined) {
      const policyId = await this.repository.policyIdOf(tx, scope, body.policyId);
      if (policyId === null) throw dlpReferenceInvalid('policyId');
      return { policyId, ruleId: null };
    }
    return { policyId: null, ruleId: null };
  }

  private record(
    tx: Prisma.TransactionClient,
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    action: string,
    resourceId: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    return this.auditor.record(tx, {
      principal,
      scope,
      client,
      action,
      resourceType: DLP_RESOURCE.exception,
      resourceId,
      metadata,
    });
  }

  /** Ids and scopes only: addresses and domains are never logged. */
  private logChange(change: string, scope: TenantScope, id: string, kind: string): void {
    this.logger.log({
      message: `dlp exception ${change}`,
      organizationId: scope.organizationId.toString(),
      id,
      scope: kind,
    });
  }
}

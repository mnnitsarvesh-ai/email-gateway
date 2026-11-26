import { BadRequestException, Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import type { z } from 'zod';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import {
  API_MODE_FEATURE,
  ApiModeStatusService,
  effectiveModeCounts,
} from '../../../tenancy/api-mode-status.service';
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import { formatZodIssues } from '../../../validation/zod-validation.pipe';
import {
  assertCanManage,
  type OrganizationAccess,
} from '../../organizations/domain/organization-access';
import {
  API_MODE_AUDIT,
  API_MODE_OPERATIONS,
  API_MODE_RESOURCES,
  API_MODE_TX_TIMEOUT_MS,
} from '../api-mode.constants';
import {
  apiModeNotEnabled,
  domainNotFound,
  mxPointsToGateway,
  organizationNotFound,
} from '../api-mode.errors';
import {
  decideDomainModeChange,
  decideOrganizationModeChange,
  effectiveModeOf,
  type ModeRefusal,
} from '../domain/protection-mode';
import {
  type DomainModeChangeView,
  type OrganizationModeChangeView,
  type OrganizationProtectionModeView,
  PublicIdSchema,
  PutDomainModeBodySchema,
  PutOrganizationModeBodySchema,
} from '../dto/api-mode.schemas';
import { ApiModeRepository, type DomainModeRow } from '../repositories/api-mode.repository';

type Tx = Prisma.TransactionClient;

/** A path id: a UUID, `400` before any read (lower-cased). */
export function parsePublicId(raw: unknown, name: string): string {
  const parsed = PublicIdSchema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException([`${name}: must be a UUID`]);
  return parsed.data.toLowerCase();
}

/** A body parsed in the service (after the Idempotency-Key checks); `400 validation_failed`. */
export function parseBody<S extends z.ZodType>(schema: S, raw: unknown): z.output<S> {
  const parsed = schema.safeParse(raw ?? {});
  if (!parsed.success) throw new BadRequestException(formatZodIssues(parsed.error));
  return parsed.data;
}

const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());

function refusalError(refusal: ModeRefusal) {
  return refusal.code === 'api_mode_not_enabled'
    ? apiModeNotEnabled()
    : mxPointsToGateway(refusal.domains);
}

/**
 * Protection modes of the organization and its domains (step API-1 D1, D2; ADR-0098): reads, and
 * the two keyed, audited changes. The rules are the pure `domain/protection-mode.ts`; this
 * service locks the organization row (then the domain row), so a concurrent organization and
 * domain change serialize and the MX check sees the committed state. A change never touches
 * inline mail flow (N2). An unchanged value answers `200` without an audit row.
 */
@Injectable()
export class ProtectionModeService {
  constructor(
    private readonly repository: ApiModeRepository,
    private readonly status: ApiModeStatusService,
    private readonly features: OrganizationFeaturesService,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
  ) {}

  now(): Date {
    return new Date();
  }

  /** `GET /organizations/{id}/protection-mode` (D2 block). */
  async getOrganization(
    access: OrganizationAccess,
    rawId: unknown,
  ): Promise<OrganizationProtectionModeView> {
    const org = await this.repository.findOrganization(access, parsePublicId(rawId, 'id'));
    if (org === null) throw organizationNotFound();
    const s = await this.status.status(org.id);
    return {
      mode: org.protectionMode,
      changedAt: iso(org.protectionModeChangedAt),
      entitled: s.entitled,
      active: s.active,
      domainsByEffectiveMode: s.domainsByEffectiveMode,
    };
  }

  private async entitled(organizationId: bigint, tx: Tx): Promise<boolean> {
    return this.features.isEffectivelyEnabled(organizationId, API_MODE_FEATURE, tx);
  }

  /** `PUT /organizations/{id}/protection-mode` (keyed; D2). */
  async putOrganization(
    access: OrganizationAccess,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<OrganizationModeChangeView>> {
    assertCanManage(access);
    const publicId = parsePublicId(input.id, 'id');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(PutOrganizationModeBodySchema, input.body);
    const operation = API_MODE_OPERATIONS.organizationMode;
    return this.idempotency.execute<OrganizationModeChangeView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(access.principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        const found = await this.repository.findOrganization(access, publicId, tx);
        if (found === null) throw organizationNotFound();
        const org = await this.repository.lockOrganization(tx, found.id);
        if (org === null) throw organizationNotFound();
        const domains = await this.repository.domainModes(tx, org.id);
        const entitled = await this.entitled(org.id, tx);
        const decision = decideOrganizationModeChange({
          from: org.protectionMode,
          to: body.mode,
          entitled,
          domains,
        });
        if (decision.kind === 'refused') throw refusalError(decision.refusal);
        const view = (
          mode: typeof org.protectionMode,
          changedAt: Date | null,
          changed: boolean,
        ): OrganizationModeChangeView => {
          const counts = effectiveModeCounts(
            mode,
            domains.map((d) => ({ mode: d.configured, count: 1 })),
          );
          return {
            organizationId: org.publicId,
            mode,
            changedAt: iso(changedAt),
            entitled,
            active: entitled && counts.api + counts.hybrid > 0,
            domainsByEffectiveMode: counts,
            changed,
            inheritingDomains: domains.filter((d) => d.configured === null).length,
          };
        };
        if (decision.kind === 'unchanged') {
          return {
            statusCode: 200,
            body: view(org.protectionMode, org.protectionModeChangedAt, false),
          };
        }
        const now = this.now();
        await this.repository.setOrganizationMode(tx, org.id, decision.to, now);
        await this.audit.record(
          {
            organizationId: org.id,
            actor: this.audit.actorFrom(access.principal),
            action: API_MODE_AUDIT.organizationModeChanged,
            resourceType: API_MODE_RESOURCES.organization,
            resourceId: org.publicId,
            sourceIp,
            metadata: {
              from: decision.from,
              to: decision.to,
              reason: body.reason,
              inheritingDomains: decision.inheritingDomains,
              effectiveApiDomains: decision.effectiveApiDomains,
            },
          },
          tx,
        );
        return { statusCode: 200, body: view(decision.to, now, true) };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  /** `PUT /domains/{domainId}/protection-mode` (keyed; D2; `inherit` clears the own mode). */
  async putDomain(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<DomainModeChangeView>> {
    const publicId = parsePublicId(input.id, 'domainId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(PutDomainModeBodySchema, input.body);
    const operation = API_MODE_OPERATIONS.domainMode;
    return this.idempotency.execute<DomainModeChangeView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        // Organization first, then the domain: the same lock order as the organization change.
        const org = await this.repository.lockOrganization(tx, scope.organizationId);
        if (org === null) throw domainNotFound();
        const domain = await this.repository.lockDomain(tx, scope, publicId);
        if (domain === null) throw domainNotFound();
        const decision = decideDomainModeChange({
          domain,
          organizationMode: org.protectionMode,
          requested: body.mode,
          entitled: await this.entitled(org.id, tx),
        });
        if (decision.kind === 'refused') throw refusalError(decision.refusal);
        const view = (
          d: Pick<DomainModeRow, 'publicId' | 'name' | 'configured' | 'changedAt'>,
          changed: boolean,
        ): DomainModeChangeView => ({
          domainId: d.publicId,
          name: d.name,
          protectionMode: {
            configured: d.configured,
            effective: effectiveModeOf(d.configured, org.protectionMode),
            inherited: d.configured === null,
            changedAt: iso(d.changedAt),
          },
          changed,
        });
        if (decision.kind === 'unchanged') return { statusCode: 200, body: view(domain, false) };
        const now = this.now();
        if (
          !(await this.repository.setDomainMode(tx, scope, domain.id, decision.toConfigured, now))
        ) {
          throw domainNotFound();
        }
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: API_MODE_AUDIT.domainModeChanged,
            resourceType: API_MODE_RESOURCES.domain,
            resourceId: domain.publicId,
            sourceIp,
            metadata: {
              fromConfigured: decision.fromConfigured,
              toConfigured: decision.toConfigured,
              fromEffective: decision.fromEffective,
              toEffective: decision.toEffective,
              reason: body.reason,
            },
          },
          tx,
        );
        return {
          statusCode: 200,
          body: view({ ...domain, configured: decision.toConfigured, changedAt: now }, true),
        };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }
}

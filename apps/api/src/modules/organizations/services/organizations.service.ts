import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import type { z } from 'zod';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import { type Page, pageWindow, toPage } from '../../../http/pagination';
import { RevokeReason } from '../../auth/auth.constants';
import { InvitationService } from '../../auth/services/invitation.service';
import { PrincipalCacheService } from '../../auth/services/principal-cache.service';
import { SessionService } from '../../auth/services/session.service';
import {
  assertCanManage,
  assertPlatform,
  type OrganizationAccess,
} from '../domain/organization-access';
import { parsePlanDefaults, planChanges } from '../domain/plan-materialization';
import type {
  CreatedOrganizationResponseSchema,
  CreateOrganizationInput,
  ListOrganizationsQuery,
  StatusChangeInput,
  UpdateOrganizationInput,
} from '../dto/organizations.schemas';
import { type OrganizationResponse, toOrganizationResponse } from '../organization.mapper';
import {
  isUniqueViolation,
  OrganizationsRepository,
  type SettingsWrite,
} from '../organizations.repository';
import {
  assertMutable,
  type RequestOrigin,
  requireActivePlan,
  requireVisible,
} from './organization-guards';
import { OrganizationSettingsService } from './organization-settings.service';

export type OrganizationsConfig = Pick<ApiConfig, 'APP_ENV'>;
export type CreatedOrganizationResponse = z.output<typeof CreatedOrganizationResponseSchema>;

/** The role every initial administrator receives (D12). */
export const INITIAL_ADMIN_ROLE = 'organization_admin';

const DUPLICATE_SLUG = 'An organization with this slug already exists';

/**
 * Organization catalog (D12): create, list, read, update and status changes. Creation, plan
 * changes and status changes are platform functions (`platform:organizations`); members see and
 * manage only their own organization.
 */
@Injectable()
export class OrganizationsService {
  private readonly logger = new Logger(OrganizationsService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: OrganizationsConfig,
    private readonly repository: OrganizationsRepository,
    private readonly settings: OrganizationSettingsService,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly invitations: InvitationService,
    private readonly sessions: SessionService,
    private readonly principalCache: PrincipalCacheService,
  ) {}

  /**
   * `POST /organizations`: one writer transaction creates the organization, its settings, the
   * plan's limits and features (`source plan`), the deployment row and the optional invited
   * administrator. The invitation email is sent after commit.
   */
  async create(
    principal: UserPrincipal,
    access: OrganizationAccess,
    input: CreateOrganizationInput,
    origin: RequestOrigin,
  ): Promise<CreatedOrganizationResponse> {
    assertPlatform(access);
    const plan = await requireActivePlan(this.repository, input.planCode);
    if (await this.repository.slugExists(input.slug)) throw new ConflictException(DUPLICATE_SLUG);
    const defaults = parsePlanDefaults(plan.defaultLimits, plan.defaultFeatures);
    const settings: SettingsWrite = await this.settings.initialSettings(
      defaults.limits.get('quarantine_retention_days') ?? null,
      input.settings,
    );

    const result = await this.transactions
      .run(async (tx) => {
        const org = await this.repository.create(tx, {
          slug: input.slug,
          name: input.name,
          planId: plan.id,
          deploymentMode: input.deploymentMode,
          dataRegion: input.dataRegion,
        });
        await this.repository.createSettings(tx, org, settings);
        await this.repository.createEntitlements(tx, org, defaults.limits, defaults.features);
        const now = new Date();
        await this.repository.createDeployment(
          tx,
          org,
          input.deploymentMode === 'saas'
            ? {
                deploymentMode: 'saas',
                region: input.dataRegion,
                environment: this.config.APP_ENV,
                status: 'active',
                provisionedAt: now,
              }
            : {
                // Provisioning of dedicated deployments arrives with step 8.3.
                deploymentMode: 'dedicated',
                region: input.deployment!.region,
                environment: input.deployment!.environment,
                status: 'provisioning',
                provisionedAt: null,
              },
        );

        let admin: { id: bigint; publicId: string; token: string; expiresAt: Date } | null = null;
        if (input.initialAdmin) {
          const roleId = await this.repository.systemRoleId(tx, INITIAL_ADMIN_ROLE);
          if (roleId === null) {
            throw new InternalServerErrorException('System roles are missing; run pnpm db:seed');
          }
          const user = await this.repository.createInvitedUser(tx, org, {
            email: input.initialAdmin.email,
            displayName: input.initialAdmin.displayName,
            roleId,
            grantedByUserId: principal.userId,
          });
          const issued = await this.invitations.createToken(tx, {
            userId: user.id,
            organizationId: org.id,
            createdByUserId: principal.userId,
          });
          admin = { ...user, token: issued.token, expiresAt: issued.expiresAt };
          await this.audit.record(
            {
              organizationId: org.id,
              actor: this.audit.actorFrom(principal),
              action: 'user.invited',
              resourceType: 'user',
              resourceId: user.publicId,
              sourceIp: origin.ip,
              metadata: { roleKeys: [INITIAL_ADMIN_ROLE], initialAdmin: true },
            },
            tx,
          );
        }

        await this.audit.record(
          {
            organizationId: org.id,
            actor: this.audit.actorFrom(principal),
            action: 'organization.created',
            resourceType: 'organization',
            resourceId: org.publicId,
            sourceIp: origin.ip,
            metadata: {
              slug: org.slug,
              planCode: plan.code,
              deploymentMode: input.deploymentMode,
              dataRegion: input.dataRegion,
              initialAdminUserId: admin?.publicId ?? null,
            },
          },
          tx,
        );
        return { org: await this.repository.reload(tx, org), admin };
      })
      .catch((err: unknown) => {
        // A concurrent creation with the same slug loses on the unique key.
        if (isUniqueViolation(err)) throw new ConflictException(DUPLICATE_SLUG);
        throw err;
      });

    let initialAdmin: CreatedOrganizationResponse['initialAdmin'] = null;
    if (result.admin && input.initialAdmin) {
      const sent = await this.invitations.sendInvitation({
        email: input.initialAdmin.email,
        displayName: input.initialAdmin.displayName,
        organizationName: result.org.name,
        token: result.admin.token,
        expiresAt: result.admin.expiresAt,
      });
      initialAdmin = {
        id: result.admin.publicId,
        email: input.initialAdmin.email,
        status: 'invited',
        invitationExpiresAt: result.admin.expiresAt.toISOString(),
        invitationSent: sent,
      };
    }
    this.logger.log({ message: 'Organization created', organizationId: result.org.publicId });
    return { ...toOrganizationResponse(result.org), initialAdmin };
  }

  /** `GET /organizations` (reader): the catalog for platform access, else the own organization. */
  async list(
    access: OrganizationAccess,
    query: ListOrganizationsQuery,
  ): Promise<Page<OrganizationResponse>> {
    const rows = await this.repository.list(access, {
      ...pageWindow(query),
      ...(query.status && { status: query.status }),
      ...(query.kind && { kind: query.kind }),
      ...(query.planCode && { planCode: query.planCode }),
      ...(query.deploymentMode && { deploymentMode: query.deploymentMode }),
      ...(query.q && { q: query.q.toLowerCase() }),
    });
    return toPage(rows, query.limit, toOrganizationResponse);
  }

  async get(access: OrganizationAccess, publicId: string): Promise<OrganizationResponse> {
    return toOrganizationResponse(await requireVisible(this.repository, access, publicId));
  }

  /**
   * `PUT /organizations/{id}`: the name (own organization with `organization:manage`, or the
   * catalog) and the plan (catalog only). A plan change re-materializes the plan-sourced limits
   * and features and keeps overrides.
   */
  async update(
    access: OrganizationAccess,
    publicId: string,
    input: UpdateOrganizationInput,
    origin: RequestOrigin,
  ): Promise<OrganizationResponse> {
    assertCanManage(access);
    if (input.planCode !== undefined && access.kind !== 'platform') {
      throw new ForbiddenException('Changing the plan requires platform:organizations');
    }
    const { org, planChanged } = await this.transactions.run(async (tx) => {
      const found = await requireVisible(this.repository, access, publicId, tx);
      const current = await this.repository.lockAndReload(tx, found);
      assertMutable(current);

      const changes: Record<string, { from: string; to: string }> = {};
      const data: { name?: string; planId?: bigint } = {};
      if (input.name !== current.name) {
        changes.name = { from: current.name, to: input.name };
        data.name = input.name;
      }
      if (input.planCode !== undefined && input.planCode !== current.plan.code) {
        const plan = await requireActivePlan(this.repository, input.planCode, tx);
        const defaults = parsePlanDefaults(plan.defaultLimits, plan.defaultFeatures);
        const limits = planChanges(
          (await this.repository.listLimits(current, tx)).map((r) => ({
            key: r.limitKey,
            source: r.source,
          })),
          defaults.limits,
        );
        const features = planChanges(
          (await this.repository.listFeatures(current, tx)).map((r) => ({
            key: r.featureKey,
            source: r.source,
          })),
          defaults.features,
        );
        for (const { key, value } of limits.set) {
          await this.repository.upsertLimit(tx, current, key, value, 'plan');
        }
        await this.repository.deleteLimits(tx, current, limits.remove);
        for (const { key, value } of features.set) {
          await this.repository.upsertFeature(tx, current, key, {
            enabled: value,
            config: null,
            source: 'plan',
          });
        }
        await this.repository.deleteFeatures(tx, current, features.remove);
        changes.planCode = { from: current.plan.code, to: plan.code };
        data.planId = plan.id;
      }
      if (Object.keys(changes).length === 0) return { org: current, planChanged: false };

      await this.repository.update(tx, current, data);
      await this.audit.record(
        {
          organizationId: current.id,
          actor: this.audit.actorFrom(access.principal),
          action: 'organization.updated',
          resourceType: 'organization',
          resourceId: current.publicId,
          sourceIp: origin.ip,
          metadata: { changedFields: Object.keys(changes), changes },
        },
        tx,
      );
      return {
        org: await this.repository.reload(tx, current),
        planChanged: data.planId !== undefined,
      };
    });
    // Features (e.g. api_access) are checked at authentication.
    if (planChanged) await this.principalCache.invalidateOrganization(org.id);
    return toOrganizationResponse(org);
  }

  /**
   * `PATCH /organizations/{id}/status`: only `active ↔ suspended`, never the platform
   * organization. Suspension revokes every session of the organization and invalidates its
   * cached principals and API keys, so access stops immediately.
   */
  async changeStatus(
    access: OrganizationAccess,
    publicId: string,
    input: StatusChangeInput,
    origin: RequestOrigin,
  ): Promise<OrganizationResponse> {
    assertPlatform(access);
    const org = await this.transactions.run(async (tx) => {
      const found = await requireVisible(this.repository, access, publicId, tx);
      const current = await this.repository.lockAndReload(tx, found);
      if (current.status !== 'active' && current.status !== 'suspended') {
        throw new ConflictException('The organization is pending deletion or deleted');
      }
      if (current.kind === 'platform' && input.status === 'suspended') {
        throw new ConflictException('The platform organization cannot be suspended');
      }
      if (current.status === input.status) {
        throw new ConflictException(`The organization is already ${input.status}`);
      }
      const now = new Date();
      const moved = await this.repository.transition(tx, current, [current.status], {
        status: input.status,
        statusReason: input.reason ?? null,
        statusChangedAt: now,
      });
      if (!moved) throw new ConflictException('The organization status changed concurrently');
      await this.audit.record(
        {
          organizationId: current.id,
          actor: this.audit.actorFrom(access.principal),
          action: 'organization.status_changed',
          resourceType: 'organization',
          resourceId: current.publicId,
          sourceIp: origin.ip,
          metadata: { from: current.status, to: input.status, reason: input.reason ?? null },
        },
        tx,
      );
      return this.repository.reload(tx, current);
    });

    if (input.status === 'suspended') {
      const revoked = await this.sessions.revokeAllForOrganization(
        org.id,
        RevokeReason.organizationSuspended,
      );
      this.logger.log({ message: 'Organization suspended', sessionsRevoked: revoked });
    }
    await this.principalCache.invalidateOrganization(org.id);
    return toOrganizationResponse(org);
  }
}

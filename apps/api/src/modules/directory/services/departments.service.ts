import { Inject, Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import { EMPTY_SETTINGS_SHA256, referencesOf } from '../../policies/domain/policy-definition';
import { addressKey } from '../../policies/domain/policy-round';
import { PoliciesManagementRepository } from '../../policies/repositories/policies-management.repository';
import {
  PolicyAuditor,
  PolicyMetrics,
  type PolicyOperation,
  PolicyWriter,
  userIdOf,
} from '../../policies/services/policy-writer';
import {
  departmentConflict,
  departmentInUse,
  departmentLimitReached,
  departmentMemberExists,
  departmentMemberLimitReached,
  departmentMemberNotFound,
  departmentNameTaken,
  departmentNotFound,
  memberAddressNotTenant,
  memberUserNotTenant,
} from '../directory.errors';
import type {
  DepartmentCreate,
  DepartmentListQuery,
  DepartmentPage,
  DepartmentUpdate,
  DepartmentView,
  MemberCreate,
  MemberListQuery,
  MemberPage,
  MemberView,
} from '../dto/directory.schemas';
import {
  type DepartmentRow,
  DepartmentsRepository,
  type MemberRow,
} from '../repositories/departments.repository';

type Tx = Prisma.TransactionClient;
type Settings = { DEPARTMENT_MAX_PER_ORG: number; DEPARTMENT_MAX_MEMBERS: number };

/** `audit_logs.action` of the directory changes (P22); metadata = ids and counts only. */
export const DEPARTMENT_AUDIT = {
  created: 'department.created',
  updated: 'department.updated',
  deleted: 'department.deleted',
  memberAdded: 'department.member_added',
  memberRemoved: 'department.member_removed',
} as const;
type DepartmentAuditAction = (typeof DEPARTMENT_AUDIT)[keyof typeof DEPARTMENT_AUDIT];

const isUniqueViolation = (error: unknown): boolean =>
  error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';

export function departmentView(row: DepartmentRow): DepartmentView {
  return {
    id: row.publicId,
    name: row.name,
    description: row.description,
    memberCount: row._count.members,
    rowVersion: row.rowVersion,
    createdByUserId: row.createdBy?.publicId ?? null,
    updatedByUserId: row.updatedBy?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function memberView(departmentPublicId: string, row: MemberRow): MemberView {
  return {
    id: row.publicId,
    departmentId: departmentPublicId,
    kind: row.user !== null ? 'user' : 'address',
    address: row.user !== null ? null : row.address,
    userId: row.user?.publicId ?? null,
    createdByUserId: row.createdBy?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
  };
}

/**
 * Tenant departments and their members (step 5.2 P5, P22): the directory policies reference by
 * public id (`sender.department`, `recipient.department`). Membership is live data: a change
 * applies to the next evaluation without a publish and is not a generation change (the resolved
 * memberships are part of the hashed evaluation input). Reads use the replica; writes run on the
 * writer under the organization's `policy_settings` lock (the same serialization point as policy
 * activation, so a department cannot be deleted while a version referencing it is activated),
 * audited in the same transaction with ids and counts only (never addresses).
 */
@Injectable()
export class DepartmentsService {
  private readonly logger = new Logger(DepartmentsService.name);

  constructor(
    @Inject(API_CONFIG) private readonly settings: Settings,
    private readonly repository: DepartmentsRepository,
    private readonly policies: PoliciesManagementRepository,
    private readonly writer: PolicyWriter,
    private readonly auditor: PolicyAuditor,
    private readonly metrics: PolicyMetrics,
  ) {}

  async list(scope: TenantScope, query: DepartmentListQuery): Promise<DepartmentPage> {
    const rows = await this.repository.list(scope, pageWindow(query));
    return toPage(rows, query.limit, departmentView);
  }

  async get(scope: TenantScope, departmentId: string): Promise<DepartmentView> {
    const row = await this.repository.find(scope, departmentId);
    if (!row) throw departmentNotFound();
    return departmentView(row);
  }

  async listMembers(
    scope: TenantScope,
    departmentId: string,
    query: MemberListQuery,
  ): Promise<MemberPage> {
    const department = await this.repository.find(scope, departmentId);
    if (!department) throw departmentNotFound();
    const rows = await this.repository.listMembers(scope, department.id, pageWindow(query));
    return toPage(rows, query.limit, (row) => memberView(department.publicId, row));
  }

  async create(
    principal: Principal,
    scope: TenantScope,
    body: DepartmentCreate,
    client: ClientContext,
  ): Promise<DepartmentView> {
    const view = await this.writer
      .run(async (tx) => {
        await this.policies.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
        const limit = this.settings.DEPARTMENT_MAX_PER_ORG;
        if ((await this.repository.countTx(tx, scope)) >= limit) {
          throw departmentLimitReached(limit);
        }
        if (await this.repository.nameTakenTx(tx, scope, body.name, null)) {
          throw departmentNameTaken();
        }
        const row = await this.repository.create(
          tx,
          scope,
          { publicId: uuidv7(), name: body.name, description: body.description ?? null },
          userIdOf(principal),
        );
        await this.record(tx, principal, scope, client, DEPARTMENT_AUDIT.created, row.publicId, {
          departmentId: row.publicId,
          rowVersion: row.rowVersion,
        });
        return departmentView(row);
      })
      .catch((error: unknown) => {
        throw isUniqueViolation(error) ? departmentNameTaken() : error;
      });
    this.changed('department_created', scope, view.id);
    return view;
  }

  async update(
    principal: Principal,
    scope: TenantScope,
    departmentId: string,
    body: DepartmentUpdate,
    client: ClientContext,
  ): Promise<DepartmentView> {
    const outcome = await this.writer
      .run(async (tx) => {
        await this.policies.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
        const current = await this.repository.forUpdate(tx, scope, departmentId);
        if (!current) throw departmentNotFound();
        if (current.rowVersion !== body.expectedRowVersion) {
          throw departmentConflict(current.rowVersion);
        }
        const changed: string[] = [];
        if (body.name !== undefined && body.name !== current.name) changed.push('name');
        if (body.description !== undefined && body.description !== current.description) {
          changed.push('description');
        }
        if (changed.length === 0) return { changed, view: departmentView(current) };
        if (
          changed.includes('name') &&
          (await this.repository.nameTakenTx(tx, scope, body.name!, current.id))
        ) {
          throw departmentNameTaken();
        }
        const ok = await this.repository.update(
          tx,
          scope,
          current.id,
          current.rowVersion,
          {
            ...(changed.includes('name') && { name: body.name! }),
            ...(changed.includes('description') && { description: body.description ?? null }),
          },
          userIdOf(principal),
        );
        if (!ok) throw departmentConflict(current.rowVersion);
        const after = await this.repository.afterWrite(tx, scope, current.id);
        await this.record(tx, principal, scope, client, DEPARTMENT_AUDIT.updated, after.publicId, {
          departmentId: after.publicId,
          rowVersion: after.rowVersion,
          changedPaths: changed,
        });
        return { changed, view: departmentView(after) };
      })
      .catch((error: unknown) => {
        throw isUniqueViolation(error) ? departmentNameTaken() : error;
      });
    if (outcome.changed.length > 0) this.changed('department_updated', scope, departmentId);
    return outcome.view;
  }

  async remove(
    principal: Principal,
    scope: TenantScope,
    departmentId: string,
    expectedRowVersion: number | undefined,
    client: ClientContext,
  ): Promise<void> {
    await this.writer.run(async (tx) => {
      await this.policies.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
      const current = await this.repository.forUpdate(tx, scope, departmentId);
      if (!current) throw departmentNotFound();
      if (expectedRowVersion !== undefined && current.rowVersion !== expectedRowVersion) {
        throw departmentConflict(current.rowVersion);
      }
      // P5: refused while an active version of an active policy references it.
      const users = (await this.policies.activeVersionsTx(tx, scope))
        .filter((v) => referencesOf(v.references).departmentIds.includes(current.publicId))
        .map((v) => v.policyPublicId)
        .sort();
      if (users.length > 0) throw departmentInUse(users);
      const result = await this.repository.delete(tx, scope, current.id, expectedRowVersion);
      if (!result.deleted) throw departmentConflict(current.rowVersion);
      await this.record(tx, principal, scope, client, DEPARTMENT_AUDIT.deleted, current.publicId, {
        departmentId: current.publicId,
        rowVersion: current.rowVersion,
        memberCount: result.members,
      });
    });
    this.changed('department_deleted', scope, departmentId);
  }

  async addMember(
    principal: Principal,
    scope: TenantScope,
    departmentId: string,
    body: MemberCreate,
    client: ClientContext,
  ): Promise<MemberView> {
    // The address is normalized like the evaluation input (lower case, NFC, punycode domain).
    const address = 'address' in body ? addressKey(body.address.trim()) : null;
    const domain = address === null ? null : address.slice(address.lastIndexOf('@') + 1);
    if ('address' in body && (address === null || !address.includes('@') || domain === '')) {
      throw memberAddressNotTenant();
    }
    const view = await this.writer
      .run(async (tx) => {
        await this.policies.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
        const department = await this.repository.forUpdate(tx, scope, departmentId);
        if (!department) throw departmentNotFound();
        let key: { address: string } | { userId: bigint };
        if (address !== null) {
          if (!(await this.repository.activeDomainTx(tx, scope, domain!))) {
            throw memberAddressNotTenant();
          }
          key = { address };
        } else {
          const userId = await this.repository.userTx(
            tx,
            scope,
            (body as { userId: string }).userId,
          );
          if (userId === null) throw memberUserNotTenant();
          key = { userId };
        }
        if (await this.repository.memberExistsTx(tx, scope, department.id, key)) {
          throw departmentMemberExists();
        }
        const limit = this.settings.DEPARTMENT_MAX_MEMBERS;
        if ((await this.repository.countMembersTx(tx, scope, department.id)) >= limit) {
          throw departmentMemberLimitReached(limit);
        }
        const row = await this.repository.createMember(
          tx,
          scope,
          { publicId: uuidv7(), departmentId: department.id, ...key },
          userIdOf(principal),
        );
        await this.record(
          tx,
          principal,
          scope,
          client,
          DEPARTMENT_AUDIT.memberAdded,
          department.publicId,
          {
            departmentId: department.publicId,
            memberId: row.publicId,
            kind: row.user !== null ? 'user' : 'address',
            userId: row.user?.publicId ?? null,
          },
        );
        return memberView(department.publicId, row);
      })
      .catch((error: unknown) => {
        throw isUniqueViolation(error) ? departmentMemberExists() : error;
      });
    this.changed('member_added', scope, departmentId);
    return view;
  }

  async removeMember(
    principal: Principal,
    scope: TenantScope,
    departmentId: string,
    memberId: string,
    client: ClientContext,
  ): Promise<void> {
    await this.writer.run(async (tx) => {
      await this.policies.lockSettings(tx, scope, EMPTY_SETTINGS_SHA256);
      const department = await this.repository.forUpdate(tx, scope, departmentId);
      if (!department) throw departmentNotFound();
      const member = await this.repository.memberForUpdate(tx, scope, department.id, memberId);
      if (!member) throw departmentMemberNotFound();
      if (!(await this.repository.deleteMember(tx, scope, member.id))) {
        throw departmentMemberNotFound();
      }
      await this.record(
        tx,
        principal,
        scope,
        client,
        DEPARTMENT_AUDIT.memberRemoved,
        department.publicId,
        {
          departmentId: department.publicId,
          memberId: member.publicId,
          kind: member.user !== null ? 'user' : 'address',
        },
      );
    });
    this.changed('member_removed', scope, departmentId);
  }

  private record(
    tx: Tx,
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    action: DepartmentAuditAction,
    resourceId: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    return this.auditor.record(tx, {
      principal,
      scope,
      client,
      action,
      resourceType: 'tenant_department',
      resourceId,
      metadata,
    });
  }

  private changed(operation: PolicyOperation, scope: TenantScope, id: string): void {
    this.metrics.changes.inc({ operation });
    this.logger.log({
      message: `directory ${operation.replace('_', ' ')}`,
      organizationId: scope.organizationId.toString(),
      id,
    });
  }
}

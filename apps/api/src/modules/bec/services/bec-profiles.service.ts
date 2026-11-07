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
  vendorDomainFreemail,
} from '../bec.errors';
import {
  normalizeAddresses,
  normalizeAliases,
  normalizedProfileName,
  normalizeVendorDomains,
} from '../domain/bec-inputs';
import type {
  BecExecutiveCreate,
  BecExecutivePage,
  BecExecutiveUpdate,
  BecExecutiveView,
  BecProfileListQuery,
  BecVendorCreate,
  BecVendorPage,
  BecVendorUpdate,
  BecVendorView,
} from '../dto/bec.schemas';
import {
  BecProfilesRepository,
  type ExecutiveData,
  type ExecutiveRow,
  type VendorData,
  type VendorRow,
} from '../repositories/bec-profiles.repository';
import { BEC_AUDIT, BEC_RESOURCE, BecWriter, stringList, userIdOf } from './bec-writer';

/** The per-tenant caps of the profile routes (B18; `BEC_MAX_*`). */
export interface BecProfileLimits {
  BEC_MAX_EXECUTIVES: number;
  BEC_MAX_VENDORS: number;
}

export function executiveView(row: ExecutiveRow): BecExecutiveView {
  return {
    id: row.publicId,
    displayName: row.displayName,
    normalizedName: row.normalizedName,
    aliases: stringList(row.aliases),
    knownAddresses: stringList(row.knownAddresses),
    title: row.title,
    enabled: row.enabled,
    version: row.version,
    createdByUserId: row.createdBy?.publicId ?? null,
    updatedByUserId: row.updatedBy?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function vendorView(row: VendorRow): BecVendorView {
  return {
    id: row.publicId,
    name: row.name,
    normalizedName: row.normalizedName,
    aliases: stringList(row.aliases),
    domains: stringList(row.domains),
    knownSenders: stringList(row.knownSenders),
    paymentChangeSensitive: row.paymentChangeSensitive,
    enabled: row.enabled,
    version: row.version,
    createdByUserId: row.createdBy?.publicId ?? null,
    updatedByUserId: row.updatedBy?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

/** What the audit rows keep of a profile (the tenant's own directory data, no message content). */
const executiveImage = (row: ExecutiveRow) => ({
  displayName: row.displayName,
  aliases: stringList(row.aliases),
  knownAddresses: stringList(row.knownAddresses),
  title: row.title,
  enabled: row.enabled,
  version: row.version,
});

const vendorImage = (row: VendorRow) => ({
  name: row.name,
  aliases: stringList(row.aliases),
  domains: stringList(row.domains),
  knownSenders: stringList(row.knownSenders),
  paymentChangeSensitive: row.paymentChangeSensitive,
  enabled: row.enabled,
  version: row.version,
});

/** Executive profile data from a create body or a stored row patched with an update body. */
function executiveData(input: {
  displayName: string;
  aliases: readonly string[];
  knownAddresses: readonly string[];
  title: string | null;
  enabled: boolean;
}): ExecutiveData {
  return {
    displayName: input.displayName.trim(),
    normalizedName: normalizedProfileName('displayName', input.displayName),
    aliases: normalizeAliases('aliases', input.aliases),
    knownAddresses: normalizeAddresses('knownAddresses', input.knownAddresses),
    title: input.title === null ? null : input.title.trim(),
    enabled: input.enabled,
  };
}

function vendorData(input: {
  name: string;
  aliases: readonly string[];
  domains: readonly string[];
  knownSenders: readonly string[];
  paymentChangeSensitive: boolean;
  enabled: boolean;
}): VendorData {
  const { domains, freemailIndex } = normalizeVendorDomains(input.domains);
  if (freemailIndex !== null) throw vendorDomainFreemail(freemailIndex);
  return {
    name: input.name.trim(),
    normalizedName: normalizedProfileName('name', input.name),
    aliases: normalizeAliases('aliases', input.aliases),
    domains,
    knownSenders: normalizeAddresses('knownSenders', input.knownSenders),
    paymentChangeSensitive: input.paymentChangeSensitive,
    enabled: input.enabled,
  };
}

/**
 * Executive and vendor profiles of the caller's organization (step 4.4 B5, B18): names
 * normalized with the B5 normalization of `@email-gateway/bec` (unique per tenant on the
 * normalized name: `409 executive_exists` / `vendor_exists`), addresses normalized (IDNA, lower
 * case), vendor domains normalized by url-security to registrable domains (public suffixes and
 * free-mail domains refused), per-tenant caps (`BEC_MAX_EXECUTIVES`, `BEC_MAX_VENDORS`,
 * `409 bec_limit_reached`), optimistic `version` (`409 version_conflict`). Writes run on the
 * writer (BecWriter: 120 s budget, echo-checked reads, one retry, then 503) with their audit row
 * (before-image on update/delete) in the same transaction; lists read the replica. The
 * organization comes from the authenticated scope only; another tenant's id is a 404.
 */
@Injectable()
export class BecProfilesService {
  private readonly logger = new Logger(BecProfilesService.name);

  constructor(
    @Inject(API_CONFIG) private readonly limits: BecProfileLimits,
    private readonly repository: BecProfilesRepository,
    private readonly writer: BecWriter,
    private readonly audit: AuditService,
  ) {}

  // ------------------------------------------------------------------------------- executives

  async listExecutives(scope: TenantScope, query: BecProfileListQuery): Promise<BecExecutivePage> {
    const rows = await this.repository.listExecutives(scope, {
      ...pageWindow(query),
      ...(query.enabled !== undefined && { enabled: query.enabled }),
    });
    return toPage(rows, query.limit, executiveView);
  }

  async getExecutive(scope: TenantScope, id: string): Promise<BecExecutiveView> {
    const row = await this.repository.findExecutive(scope, id);
    if (!row) throw becNotFound('executive');
    return executiveView(row);
  }

  async createExecutive(
    principal: Principal,
    scope: TenantScope,
    body: BecExecutiveCreate,
    client: ClientContext,
  ): Promise<BecExecutiveView> {
    const data = executiveData({ ...body, title: body.title ?? null });
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const existing = await this.repository.findExecutiveByName(tx, scope, data.normalizedName);
        if (existing) throw becExists('executive', existing.publicId);
        const count = await this.repository.countExecutives(tx, scope);
        if (count >= this.limits.BEC_MAX_EXECUTIVES) {
          throw becLimitReached('executives', this.limits.BEC_MAX_EXECUTIVES);
        }
        const row = await this.repository.createExecutive(
          tx,
          scope,
          uuidv7(),
          data,
          userIdOf(principal),
        );
        await this.record(
          principal,
          scope,
          client,
          BEC_AUDIT.executiveCreated,
          'executive',
          row.publicId,
          {
            after: executiveImage(row),
          },
          tx,
        );
        return executiveView(row);
      });
      this.logChange('executive', 'created', scope, view.id);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw becExists('executive', null);
      throw error;
    }
  }

  async updateExecutive(
    principal: Principal,
    scope: TenantScope,
    id: string,
    body: BecExecutiveUpdate,
    client: ClientContext,
  ): Promise<BecExecutiveView> {
    try {
      const view = await this.writer.run(async (tx) => {
        const current = await this.repository.findExecutiveForUpdate(tx, scope, id);
        if (!current) throw becNotFound('executive');
        if (current.version !== body.version) throw becVersionConflict(current.version);
        const data = executiveData({
          displayName: body.displayName ?? current.displayName,
          aliases: body.aliases ?? stringList(current.aliases),
          knownAddresses: body.knownAddresses ?? stringList(current.knownAddresses),
          title: body.title !== undefined ? body.title : current.title,
          enabled: body.enabled ?? current.enabled,
        });
        if (data.normalizedName !== current.normalizedName) {
          const other = await this.repository.findExecutiveByName(tx, scope, data.normalizedName);
          if (other && other.id !== current.id) throw becExists('executive', other.publicId);
        }
        const updated = await this.repository.updateExecutive(
          tx,
          scope,
          current.id,
          body.version,
          data,
          userIdOf(principal),
        );
        if (!updated) throw becVersionConflict(current.version);
        const row = await this.repository.executiveById(tx, scope, current.id);
        await this.record(
          principal,
          scope,
          client,
          BEC_AUDIT.executiveUpdated,
          'executive',
          row.publicId,
          {
            before: executiveImage(current),
            after: executiveImage(row),
          },
          tx,
        );
        return executiveView(row);
      });
      this.logChange('executive', 'updated', scope, view.id);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw becExists('executive', null);
      throw error;
    }
  }

  async deleteExecutive(
    principal: Principal,
    scope: TenantScope,
    id: string,
    version: number | undefined,
    client: ClientContext,
  ): Promise<void> {
    await this.writer.run(async (tx) => {
      const current = await this.repository.findExecutiveForUpdate(tx, scope, id);
      if (!current) throw becNotFound('executive');
      if (version !== undefined && current.version !== version) {
        throw becVersionConflict(current.version);
      }
      await this.repository.deleteExecutive(tx, scope, current.id);
      await this.record(
        principal,
        scope,
        client,
        BEC_AUDIT.executiveDeleted,
        'executive',
        current.publicId,
        {
          before: executiveImage(current),
        },
        tx,
      );
    });
    this.logChange('executive', 'deleted', scope, id);
  }

  // ---------------------------------------------------------------------------------- vendors

  async listVendors(scope: TenantScope, query: BecProfileListQuery): Promise<BecVendorPage> {
    const rows = await this.repository.listVendors(scope, {
      ...pageWindow(query),
      ...(query.enabled !== undefined && { enabled: query.enabled }),
    });
    return toPage(rows, query.limit, vendorView);
  }

  async getVendor(scope: TenantScope, id: string): Promise<BecVendorView> {
    const row = await this.repository.findVendor(scope, id);
    if (!row) throw becNotFound('vendor');
    return vendorView(row);
  }

  async createVendor(
    principal: Principal,
    scope: TenantScope,
    body: BecVendorCreate,
    client: ClientContext,
  ): Promise<BecVendorView> {
    const data = vendorData(body);
    try {
      const view = await this.writer.run(async (tx) => {
        await this.repository.lockOrganization(tx, scope);
        const existing = await this.repository.findVendorByName(tx, scope, data.normalizedName);
        if (existing) throw becExists('vendor', existing.publicId);
        const count = await this.repository.countVendors(tx, scope);
        if (count >= this.limits.BEC_MAX_VENDORS) {
          throw becLimitReached('vendors', this.limits.BEC_MAX_VENDORS);
        }
        const row = await this.repository.createVendor(
          tx,
          scope,
          uuidv7(),
          data,
          userIdOf(principal),
        );
        await this.record(
          principal,
          scope,
          client,
          BEC_AUDIT.vendorCreated,
          'vendor',
          row.publicId,
          {
            after: vendorImage(row),
          },
          tx,
        );
        return vendorView(row);
      });
      this.logChange('vendor', 'created', scope, view.id);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw becExists('vendor', null);
      throw error;
    }
  }

  async updateVendor(
    principal: Principal,
    scope: TenantScope,
    id: string,
    body: BecVendorUpdate,
    client: ClientContext,
  ): Promise<BecVendorView> {
    try {
      const view = await this.writer.run(async (tx) => {
        const current = await this.repository.findVendorForUpdate(tx, scope, id);
        if (!current) throw becNotFound('vendor');
        if (current.version !== body.version) throw becVersionConflict(current.version);
        const data = vendorData({
          name: body.name ?? current.name,
          aliases: body.aliases ?? stringList(current.aliases),
          domains: body.domains ?? stringList(current.domains),
          knownSenders: body.knownSenders ?? stringList(current.knownSenders),
          paymentChangeSensitive: body.paymentChangeSensitive ?? current.paymentChangeSensitive,
          enabled: body.enabled ?? current.enabled,
        });
        if (data.normalizedName !== current.normalizedName) {
          const other = await this.repository.findVendorByName(tx, scope, data.normalizedName);
          if (other && other.id !== current.id) throw becExists('vendor', other.publicId);
        }
        const updated = await this.repository.updateVendor(
          tx,
          scope,
          current.id,
          body.version,
          data,
          userIdOf(principal),
        );
        if (!updated) throw becVersionConflict(current.version);
        const row = await this.repository.vendorById(tx, scope, current.id);
        await this.record(
          principal,
          scope,
          client,
          BEC_AUDIT.vendorUpdated,
          'vendor',
          row.publicId,
          {
            before: vendorImage(current),
            after: vendorImage(row),
          },
          tx,
        );
        return vendorView(row);
      });
      this.logChange('vendor', 'updated', scope, view.id);
      return view;
    } catch (error) {
      if (isUniqueViolation(error)) throw becExists('vendor', null);
      throw error;
    }
  }

  async deleteVendor(
    principal: Principal,
    scope: TenantScope,
    id: string,
    version: number | undefined,
    client: ClientContext,
  ): Promise<void> {
    await this.writer.run(async (tx) => {
      const current = await this.repository.findVendorForUpdate(tx, scope, id);
      if (!current) throw becNotFound('vendor');
      if (version !== undefined && current.version !== version) {
        throw becVersionConflict(current.version);
      }
      await this.repository.deleteVendor(tx, scope, current.id);
      await this.record(
        principal,
        scope,
        client,
        BEC_AUDIT.vendorDeleted,
        'vendor',
        current.publicId,
        {
          before: vendorImage(current),
        },
        tx,
      );
    });
    this.logChange('vendor', 'deleted', scope, id);
  }

  private record(
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    action: string,
    resource: 'executive' | 'vendor',
    resourceId: string,
    metadata: Record<string, unknown>,
    tx: Parameters<AuditService['record']>[1],
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: BEC_RESOURCE[resource],
        resourceId,
        sourceIp: client.ip,
        metadata,
      },
      tx,
    );
  }

  /** Ids only: names and addresses are never logged. */
  private logChange(resource: string, change: string, scope: TenantScope, id: string): void {
    this.logger.log({
      message: `bec ${resource} ${change}`,
      organizationId: scope.organizationId.toString(),
      id,
    });
  }
}

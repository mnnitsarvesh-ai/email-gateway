import { BadRequestException, ConflictException, Inject, Injectable } from '@nestjs/common';
import {
  DomainNameError,
  isDomainAtOrUnder,
  MAX_DOMAIN_NAME_LENGTH,
  normalizeDomainName,
  type Prisma,
} from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import { type Page, pageWindow, toPage } from '../../../http/pagination';
import { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import type { ClientContext } from '../../auth/services/session.service';
import { nextStatus, statusChangeEvent } from '../domain/state-machine';
import {
  toCleanupRecords,
  toDnsRecordView,
  toDomainDetail,
  toDomainSummary,
} from '../domain.mapper';
import { DomainAuditAction, FIRST_CHECK_DELAY_SECONDS } from '../domains.constants';
import { DOMAIN_OWNED_ELSEWHERE, domainAlreadyExists, domainNotFound } from '../domains.errors';
import type {
  CreatedDomain,
  CreateDomainInput,
  DnsRecordsResponse,
  DomainDetail,
  DomainStatusChangeInput,
  DomainSummary,
  ListDomainsQuery,
} from '../dto/domains.schemas';
import { DKIM_SELECTOR_LENGTH, dkimRecordHost, generateDkimKeyPair } from '../engine/dkim';
import { DkimKeysRepository } from '../repositories/dkim-keys.repository';
import { DnsRecordsRepository } from '../repositories/dns-records.repository';
import { DomainOwnershipRepository } from '../repositories/domain-ownership.repository';
import {
  type DomainRow,
  DomainsRepository,
  isUniqueViolation,
} from '../repositories/domains.repository';
import { VerificationsRepository } from '../repositories/verifications.repository';
import { DomainConfigurationService } from './domain-configuration.service';
import { DomainEventsService } from './domain-events.service';

export type DomainsConfig = Pick<
  ApiConfig,
  | 'APP_ENV'
  | 'DOMAIN_RESERVED_SUFFIXES'
  | 'GATEWAY_MX_HOSTS'
  | 'GATEWAY_SPF_INCLUDE'
  | 'DOMAIN_VERIFICATION_LABEL'
>;

/** The `max_domains` organization limit (step 1.3 D12). */
export const MAX_DOMAINS_LIMIT = 'max_domains';

/**
 * Longest domain name whose derived record hosts (D6: `<verification label>.<name>`,
 * `<selector>._domainkey.<name>`, `_dmarc.<name>`) still fit in a DNS name (253 characters).
 */
export function maxDomainNameLength(verificationLabel: string): number {
  const longestPrefix = Math.max(
    verificationLabel.length + 1,
    dkimRecordHost('x'.repeat(DKIM_SELECTOR_LENGTH), '').length,
    '_dmarc.'.length,
  );
  return MAX_DOMAIN_NAME_LENGTH - longestPrefix;
}

/**
 * Domain lifecycle (D2, D3, §4): create, list, read, DNS records, activate/suspend, delete.
 * Every method works inside the caller's tenant scope; another tenant's domain, a deleted
 * domain and an unknown id are all `404`.
 */
@Injectable()
export class DomainsService {
  private readonly allowTestNames: boolean;
  /** Names customers may not add: configured suffixes and the platform's own DNS names (D2). */
  private readonly reservedNames: readonly string[];
  /** Names longer than this would give record hosts over 253 characters (D2, D6). */
  private readonly maxNameLength: number;

  constructor(
    @Inject(API_CONFIG) private readonly config: DomainsConfig,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly limits: OrganizationLimitsService,
    private readonly domains: DomainsRepository,
    private readonly verifications: VerificationsRepository,
    private readonly records: DnsRecordsRepository,
    private readonly keys: DkimKeysRepository,
    private readonly ownership: DomainOwnershipRepository,
    private readonly configuration: DomainConfigurationService,
    private readonly events: DomainEventsService,
  ) {
    this.allowTestNames = config.APP_ENV === 'local' || config.APP_ENV === 'ci';
    this.reservedNames = [
      ...config.DOMAIN_RESERVED_SUFFIXES,
      ...config.GATEWAY_MX_HOSTS.map((mx) => mx.host),
      config.GATEWAY_SPF_INCLUDE,
    ].map((name) => name.toLowerCase().replace(/\.$/, ''));
    this.maxNameLength = maxDomainNameLength(config.DOMAIN_VERIFICATION_LABEL);
  }

  /** Normalized ASCII name, or `400` with the D2 error code in the message. */
  normalizeName(raw: string): string {
    let ascii: string;
    try {
      ascii = normalizeDomainName(raw, { allowTestNames: this.allowTestNames }).ascii;
    } catch (err) {
      if (err instanceof DomainNameError) {
        throw new BadRequestException([`name: ${err.message} (${err.code})`]);
      }
      throw err;
    }
    const reserved = this.reservedNames.find((suffix) => isDomainAtOrUnder(ascii, suffix));
    if (reserved !== undefined) {
      throw new BadRequestException([`name: Domain name is reserved (${reserved}) (reserved)`]);
    }
    if (ascii.length > this.maxNameLength) {
      throw new BadRequestException([
        `name: Domain name is too long for its DNS records (at most ${this.maxNameLength} ` +
          `characters) (too_long)`,
      ]);
    }
    return ascii;
  }

  /**
   * `POST /domains` (§4): the cheap refusals (`max_domains`, duplicate in the organization,
   * owned by another organization) are checked first so a refused request never pays for key
   * generation; keys are then generated outside the transaction; then, in one writer
   * transaction with the organization row locked, the same checks again, insert domain +
   * settings + verification + keys + record rows, audit `domain.created`.
   */
  async create(
    principal: Principal,
    scope: TenantScope,
    input: CreateDomainInput,
    client: ClientContext,
  ): Promise<CreatedDomain> {
    const name = this.normalizeName(input.name);
    await this.transactions.run((tx) => this.assertCanAdd(tx, scope, name));
    const pairs = await Promise.all([
      generateDkimKeyPair('rsa_2048'),
      ...(input.dkim?.ed25519 ? [generateDkimKeyPair('ed25519')] : []),
    ]);
    const now = new Date();
    let created: DomainRow;
    try {
      created = await this.transactions.run(async (tx) => {
        await this.limits.lockOrganization(tx, scope.organizationId);
        await this.assertCanAdd(tx, scope, name);
        const domain = await this.domains.create(tx, scope, {
          name,
          inboundEnabled: input.inboundEnabled,
          nextCheckAt: new Date(now.getTime() + FIRST_CHECK_DELAY_SECONDS * 1000),
          now,
        });
        await this.configuration.materialize(tx, scope, domain, { generated: pairs, now });
        await this.events.record(tx, {
          organizationId: scope.organizationId,
          domain,
          action: DomainAuditAction.Created,
          actor: this.audit.actorFrom(principal),
          sourceIp: client.ip,
          metadata: {
            inboundEnabled: domain.inboundEnabled,
            algorithms: pairs.map((p) => p.algorithm),
          },
        });
        return domain;
      });
    } catch (err) {
      // A concurrent create of the same name in this organization (live_name unique key).
      if (isUniqueViolation(err)) throw domainAlreadyExists();
      throw err;
    }
    const [detail, dnsRecords] = await Promise.all([
      this.get(scope, created.publicId),
      this.dnsRecords(scope, created.publicId),
    ]);
    return { ...detail, dnsRecords: dnsRecords.records };
  }

  /** `GET /domains`: non-deleted domains, newest first, from the replica. */
  async list(scope: TenantScope, query: ListDomainsQuery): Promise<Page<DomainSummary>> {
    const rows = await this.domains.list(
      scope,
      { ...(query.status && { status: query.status }), ...(query.q && { q: query.q }) },
      pageWindow(query),
    );
    return toPage(rows, query.limit, toDomainSummary);
  }

  /** `GET /domains/{id}` (writer). */
  async get(scope: TenantScope, publicId: string, now: Date = new Date()): Promise<DomainDetail> {
    const domain = await this.require(scope, publicId);
    return this.detail(scope, domain, now);
  }

  /** `GET /domains/{id}/dns-records`: what to publish, and retired selectors to clean up. */
  async dnsRecords(
    scope: TenantScope,
    publicId: string,
    now: Date = new Date(),
  ): Promise<DnsRecordsResponse> {
    const domain = await this.require(scope, publicId);
    const [records, keys] = await Promise.all([
      this.records.listForDomain(scope, domain.id),
      this.keys.listForDomain(scope, domain.id),
    ]);
    return {
      domainId: domain.publicId,
      records: records.map((r) => toDnsRecordView(r, domain.name)),
      cleanup: toCleanupRecords(keys, domain.name, now),
    };
  }

  /**
   * `PATCH /domains/{id}/status` (D3): verified → active (first activation sets
   * `activated_at`), active → suspended (with a reason), suspended → active. Anything else `409`.
   */
  async changeStatus(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    input: DomainStatusChangeInput,
    client: ClientContext,
  ): Promise<DomainDetail> {
    const now = new Date();
    await this.transactions.run(async (tx) => {
      const domain = await this.domains.lockByPublicId(tx, scope, publicId);
      if (!domain) throw domainNotFound();
      const to = nextStatus(domain.status, statusChangeEvent(input.status));
      const reason = to === 'suspended' ? (input.reason ?? null) : null;
      await this.domains.update(tx, scope, domain.id, {
        status: to,
        statusReason: reason,
        statusChangedAt: now,
        ...(to === 'active' && domain.activatedAt === null && { activatedAt: now }),
      });
      await this.events.transition(tx, {
        organizationId: scope.organizationId,
        domain,
        from: domain.status,
        to,
        reason,
        action: DomainAuditAction.StatusChanged,
        actor: this.audit.actorFrom(principal),
        sourceIp: client.ip,
        at: now,
      });
    });
    return this.get(scope, publicId, now);
  }

  /**
   * `DELETE /domains/{id}` (D3): soft delete (frees the name), no further checks, every
   * non-retired DKIM key revoked with its ciphertext cleared, pending verifications expired.
   * An active domain must be suspended first (`409`).
   */
  async remove(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    client: ClientContext,
  ): Promise<void> {
    const now = new Date();
    await this.transactions.run(async (tx) => {
      const domain = await this.domains.lockByPublicId(tx, scope, publicId);
      if (!domain) throw domainNotFound();
      const to = nextStatus(domain.status, 'delete');
      const keys = await this.keys.listForDomain(scope, domain.id, tx);
      const revocable = keys.filter((k) => k.status !== 'retired' && k.status !== 'revoked');
      await this.keys.revoke(
        tx,
        scope,
        revocable.map((k) => k.id),
      );
      await this.verifications.expirePending(tx, scope, domain.id);
      await this.domains.update(tx, scope, domain.id, {
        status: to,
        statusReason: null,
        statusChangedAt: now,
        deletedAt: now,
        nextCheckAt: null,
      });
      await this.events.transition(tx, {
        organizationId: scope.organizationId,
        domain,
        from: domain.status,
        to,
        reason: null,
        action: DomainAuditAction.Deleted,
        actor: this.audit.actorFrom(principal),
        sourceIp: client.ip,
        metadata: { revokedSelectors: revocable.map((k) => k.selector) },
        at: now,
      });
    });
  }

  /** `max_domains`, duplicate in the organization, owned by another organization (§4). */
  private async assertCanAdd(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    name: string,
  ): Promise<void> {
    const count = await this.domains.countLive(tx, scope);
    await this.limits.assertWithinLimit(tx, scope.organizationId, MAX_DOMAINS_LIMIT, count);
    if (await this.domains.existsLive(tx, scope, name)) throw domainAlreadyExists();
    const owner = await this.ownership.findVerifiedOwner(tx, name);
    if (owner && owner.organizationId !== scope.organizationId) {
      throw new ConflictException(DOMAIN_OWNED_ELSEWHERE);
    }
  }

  private async require(scope: TenantScope, publicId: string): Promise<DomainRow> {
    const domain = await this.domains.findByPublicId(scope, publicId);
    if (!domain) throw domainNotFound();
    return domain;
  }

  private async detail(scope: TenantScope, domain: DomainRow, now: Date): Promise<DomainDetail> {
    const [verification, dkimKeys] = await Promise.all([
      this.verifications.findCurrent(scope, domain.id),
      this.keys.listForDomain(scope, domain.id),
    ]);
    return toDomainDetail({
      domain,
      verification,
      dkimKeys,
      verificationLabel: this.config.DOMAIN_VERIFICATION_LABEL,
      now,
    });
  }
}

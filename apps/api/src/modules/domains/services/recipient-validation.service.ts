import {
  ConflictException,
  Inject,
  Injectable,
  UnprocessableEntityException,
} from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import { type Page, pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import {
  IMPLEMENTED_MODES,
  toRecipientValidationSettings,
  toRecipientValidationState,
} from '../domain/recipient-validation';
import { DomainAuditAction } from '../domains.constants';
import {
  ALLOW_LIST_EMPTY,
  domainNotFound,
  RECIPIENT_MODE_NOT_IMPLEMENTED,
  recipientLimitReached,
} from '../domains.errors';
import type {
  AddRecipientsResult,
  ListRecipientsQuery,
  RecipientsBody,
  RecipientValidationView,
  RecipientView,
  RemoveRecipientsResult,
  SetRecipientValidationInput,
} from '../dto/recipients.schemas';
import { type DomainRow, DomainsRepository } from '../repositories/domains.repository';
import { RecipientsRepository } from '../repositories/recipients.repository';
import { DomainEventsService } from './domain-events.service';

type Client = Prisma.TransactionClient;

export type RecipientValidationConfig = Pick<ApiConfig, 'DOMAIN_RECIPIENTS_MAX_PER_DOMAIN'>;

/**
 * Inbound recipient validation of a domain (step 2.2 D3, §4.1): the mode (accept-all or an
 * allow-list, enforced or monitor-only) stored in `domain_settings`, and the allow-list in
 * `domain_recipient_addresses`. The smtp-adapter reads both at RCPT time (cached up to 60 s).
 * Every method works inside the caller's tenant scope: another tenant's domain, a deleted
 * domain and an unknown id are `404`. Mutations lock the domain row and are audited (counts
 * only) in the same transaction.
 */
@Injectable()
export class RecipientValidationService {
  constructor(
    @Inject(API_CONFIG) private readonly config: RecipientValidationConfig,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly domains: DomainsRepository,
    private readonly recipients: RecipientsRepository,
    private readonly events: DomainEventsService,
  ) {}

  /** `GET /domains/{id}/recipient-validation` (writer). */
  async get(scope: TenantScope, publicId: string): Promise<RecipientValidationView> {
    const domain = await this.domains.findByPublicId(scope, publicId);
    if (!domain) throw domainNotFound();
    return this.view(scope, domain);
  }

  /**
   * `PUT /domains/{id}/recipient-validation`: `smtp_callout` / `ldap` → `422 Not implemented`;
   * `allow_list` + `reject` while the list is empty → `409`. Upserts `domain_settings`.
   */
  async set(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    input: SetRecipientValidationInput,
    client: ClientContext,
  ): Promise<RecipientValidationView> {
    await this.transactions.run(async (tx) => {
      const domain = await this.lockDomain(tx, scope, publicId);
      if (!IMPLEMENTED_MODES.has(input.mode)) {
        throw new UnprocessableEntityException(RECIPIENT_MODE_NOT_IMPLEMENTED);
      }
      const mode = input.mode as 'accept_all' | 'allow_list';
      const enforcement = input.enforcement ?? 'monitor';
      if (
        mode === 'allow_list' &&
        enforcement === 'reject' &&
        (await this.recipients.count(scope, domain.id, tx)) === 0
      ) {
        throw new ConflictException(ALLOW_LIST_EMPTY);
      }
      const before = toRecipientValidationState(
        await this.recipients.findSettings(scope, domain.id, tx),
      );
      const settings = toRecipientValidationSettings({ mode, enforcement });
      const after = toRecipientValidationState(settings);
      if (before.mode === after.mode && before.enforcement === after.enforcement) return;
      await this.recipients.upsertSettings(tx, scope, domain.id, settings);
      await this.events.record(tx, {
        organizationId: scope.organizationId,
        domain,
        action: DomainAuditAction.RecipientValidationChanged,
        actor: this.audit.actorFrom(principal),
        sourceIp: client.ip,
        metadata: {
          from: { mode: before.mode, enforcement: before.enforcement },
          to: { mode: after.mode, enforcement: after.enforcement },
        },
      });
    });
    return this.get(scope, publicId);
  }

  /** `GET /domains/{id}/recipients`: newest first, optional prefix filter, from the replica. */
  async list(
    scope: TenantScope,
    publicId: string,
    query: ListRecipientsQuery,
  ): Promise<Page<RecipientView>> {
    const domain = await this.domains.findByPublicId(scope, publicId);
    if (!domain) throw domainNotFound();
    const rows = await this.recipients.list(
      scope,
      domain.id,
      { ...(query.q !== undefined && { q: query.q }) },
      pageWindow(query),
    );
    return toPage(rows, query.limit, (row) => ({
      localPart: row.localPart,
      createdAt: row.createdAt.toISOString(),
    }));
  }

  /**
   * `POST /domains/{id}/recipients`: adds the local parts that are not on the list
   * (idempotent). The per-domain cap (`DOMAIN_RECIPIENTS_MAX_PER_DOMAIN`) is checked after the
   * insert inside the transaction, so an over-limit request changes nothing (`409`).
   */
  async add(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    body: RecipientsBody,
    client: ClientContext,
  ): Promise<AddRecipientsResult> {
    const localParts = [...new Set(body.localParts)];
    return this.transactions.run(async (tx) => {
      const domain = await this.lockDomain(tx, scope, publicId);
      const added = await this.recipients.addMany(
        tx,
        scope,
        domain.id,
        localParts,
        principal.kind === 'user' ? principal.userId : null,
      );
      if (added > 0) {
        const max = this.config.DOMAIN_RECIPIENTS_MAX_PER_DOMAIN;
        if ((await this.recipients.count(scope, domain.id, tx)) > max) {
          throw recipientLimitReached(max);
        }
        await this.events.record(tx, {
          organizationId: scope.organizationId,
          domain,
          action: DomainAuditAction.RecipientsAdded,
          actor: this.audit.actorFrom(principal),
          sourceIp: client.ip,
          metadata: { added, existing: localParts.length - added },
        });
      }
      return { added, existing: localParts.length - added };
    });
  }

  /** `POST /domains/{id}/recipients/remove`: deletes the listed local parts (idempotent). */
  async remove(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    body: RecipientsBody,
    client: ClientContext,
  ): Promise<RemoveRecipientsResult> {
    const localParts = [...new Set(body.localParts)];
    return this.transactions.run(async (tx) => {
      const domain = await this.lockDomain(tx, scope, publicId);
      const removed = await this.recipients.removeMany(tx, scope, domain.id, localParts);
      if (removed > 0) {
        await this.events.record(tx, {
          organizationId: scope.organizationId,
          domain,
          action: DomainAuditAction.RecipientsRemoved,
          actor: this.audit.actorFrom(principal),
          sourceIp: client.ip,
          metadata: { removed, requested: localParts.length },
        });
      }
      return { removed };
    });
  }

  private async lockDomain(tx: Client, scope: TenantScope, publicId: string): Promise<DomainRow> {
    const domain = await this.domains.lockByPublicId(tx, scope, publicId);
    if (!domain) throw domainNotFound();
    return domain;
  }

  private async view(scope: TenantScope, domain: DomainRow): Promise<RecipientValidationView> {
    const [settings, addressCount] = await Promise.all([
      this.recipients.findSettings(scope, domain.id),
      this.recipients.count(scope, domain.id),
    ]);
    return { domainId: domain.publicId, ...toRecipientValidationState(settings), addressCount };
  }
}

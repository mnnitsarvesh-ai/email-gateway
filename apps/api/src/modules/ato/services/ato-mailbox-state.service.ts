import { Injectable } from '@nestjs/common';
import { ATO_TRANSACTION_ISOLATION } from '@email-gateway/ato-detection';
import type { AtoProviderKind } from '@email-gateway/idp-adapters';
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
  ATO_MAILBOX_MAX_ITEMS,
  ATO_MAILBOX_REMOVED_DAYS,
  ATO_OPERATIONS,
  ATO_PROVIDER_AUDIT,
  ATO_TX_TIMEOUT_MS,
} from '../ato.constants';
import { atoAccountNotFound, atoProviderRefreshUnavailable } from '../ato.errors';
import type { MailboxRefreshView, MailboxStateView } from '../dto/ato-providers.schemas';
import {
  kindOf,
  mailboxItemView,
  mailboxStateStream,
  refreshSupported,
} from '../mappers/ato-providers.mapper';
import { AtoMailboxItemsRepository } from '../repositories/ato-mailbox-items.repository';
import {
  AtoProvidersRepository,
  type IntegrationRow,
} from '../repositories/ato-providers.repository';
import { AtoReadRepository } from '../repositories/ato-read.repository';
import { AtoAccessService, parsePublicId } from './ato-access.service';

const DAY_MS = 86_400_000;

/**
 * The mailbox state of a monitored account (step 8.5 §6 #12–#13, D8.3): the forwarding, inbox
 * rule, delegate and permission items the ato-worker's snapshots and audit records wrote (target
 * domains and trait codes only; never an address or a rule keyword), the account's provider
 * identities with their directory status, and the priority refresh request the worker serves in
 * its next poll. Reads on the replica; the refresh in a keyed writer transaction.
 */
@Injectable()
export class AtoMailboxStateService {
  constructor(
    private readonly reads: AtoReadRepository,
    private readonly items: AtoMailboxItemsRepository,
    private readonly providers: AtoProvidersRepository,
    private readonly access: AtoAccessService,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
  ) {}

  now(): Date {
    return new Date();
  }

  /** `GET /ato/accounts/{id}/mailbox-state` (#12): `404 ato_account_not_found` when off. */
  async get(scope: TenantScope, rawId: unknown): Promise<MailboxStateView> {
    const id = parsePublicId(rawId, 'accountId');
    if (!(await this.access.enabled(scope))) throw atoAccountNotFound();
    const account = await this.reads.account(scope, id);
    if (account === null) throw atoAccountNotFound();
    const now = this.now();
    const [items, identities] = await Promise.all([
      this.items.items(scope, account.id, {
        removedSince: new Date(now.getTime() - ATO_MAILBOX_REMOVED_DAYS * DAY_MS),
        limit: ATO_MAILBOX_MAX_ITEMS + 1,
      }),
      this.items.identities(scope, account.id),
    ]);
    const integrationIds = [
      ...new Set([
        ...items.map((i) => i.integrationId),
        ...identities.flatMap((i) => (i.integrationId === null ? [] : [i.integrationId])),
      ]),
    ];
    const integrations = (await this.providers.findByIds(scope, integrationIds)).flatMap((row) => {
      const kind = kindOf(row);
      return kind ? [{ row, kind }] : [];
    });
    const streams = await this.providers.streams(
      scope,
      integrations.map((i) => i.row.id),
    );
    const byId = new Map<bigint, { row: IntegrationRow; kind: AtoProviderKind }>(
      integrations.map((i) => [i.row.id, i]),
    );
    const visible = items.flatMap((item) => {
      const integration = byId.get(item.integrationId);
      return integration
        ? [mailboxItemView(item, { publicId: integration.row.publicId, kind: integration.kind })]
        : [];
    });
    const refreshTimes = identities
      .map((i) => i.mailboxRefreshRequestedAt)
      .filter((d): d is Date => d !== null)
      .map((d) => d.getTime());
    return {
      accountId: account.publicId,
      items: visible.slice(0, ATO_MAILBOX_MAX_ITEMS),
      truncated: items.length > ATO_MAILBOX_MAX_ITEMS,
      identities: identities.map((i) => {
        const integration = i.integrationId === null ? undefined : byId.get(i.integrationId);
        return {
          provider: i.provider,
          integrationId: integration?.row.publicId ?? null,
          userPrincipalName: i.userPrincipalName,
          directoryStatus: i.directoryStatus,
          directoryStatusAt: i.directoryStatusAt?.toISOString() ?? null,
          refreshRequestedAt: i.mailboxRefreshRequestedAt?.toISOString() ?? null,
          refreshSupported: integration
            ? refreshSupported(integration.row, integration.kind)
            : false,
        };
      }),
      integrations: integrations.map(({ row, kind }) => {
        const stream = streams.find(
          (s) => s.integrationId === row.id && s.stream === mailboxStateStream(kind),
        );
        return {
          id: row.publicId,
          provider: kind,
          displayName: row.displayName,
          status: row.status,
          lastSweepAt: stream?.lastSuccessAt?.toISOString() ?? null,
        };
      }),
      refreshRequestedAt:
        refreshTimes.length === 0 ? null : new Date(Math.max(...refreshTimes)).toISOString(),
    };
  }

  /**
   * `POST /ato/accounts/{id}/mailbox-state/refresh` (#13): flags the account's identities whose
   * integration supports a priority refresh; `202`; `409 ato_provider_refresh_unavailable` when
   * none does.
   */
  refresh(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: object,
    sourceIp: string | null,
  ): Promise<IdempotentResult<MailboxRefreshView>> {
    const id = parsePublicId(rawId, 'accountId');
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = ATO_OPERATIONS.mailboxRefresh;
    return this.idempotency.execute<MailboxRefreshView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: id,
        fingerprint: requestFingerprint({ operation, resourceId: id, body }),
      },
      async (tx) => {
        await this.access.requireEnabled(scope, tx);
        const account = await this.reads.account(scope, id, tx);
        if (account === null) throw atoAccountNotFound();
        const identities = await this.items.identities(scope, account.id, tx);
        const ids = [
          ...new Set(
            identities.flatMap((i) => (i.integrationId === null ? [] : [i.integrationId])),
          ),
        ];
        const supported = (await this.providers.findByIds(scope, ids, tx)).filter((row) => {
          const kind = kindOf(row);
          return kind !== null && refreshSupported(row, kind);
        });
        if (supported.length === 0) throw atoProviderRefreshUnavailable();
        const now = this.now();
        const flagged = await this.items.requestRefresh(tx, scope, {
          accountId: account.id,
          integrationIds: supported.map((r) => r.id),
          at: now,
        });
        if (flagged === 0) throw atoProviderRefreshUnavailable();
        const integrationIds = supported.map((r) => r.publicId);
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: ATO_PROVIDER_AUDIT.mailboxRefreshRequested,
            resourceType: 'ato_account',
            resourceId: account.publicId,
            sourceIp,
            metadata: { integrationIds, identities: flagged },
          },
          tx,
        );
        return {
          statusCode: 202,
          body: {
            accountId: account.publicId,
            requestedAt: now.toISOString(),
            identities: flagged,
            integrationIds,
          },
        };
      },
      { timeoutMs: ATO_TX_TIMEOUT_MS, isolationLevel: ATO_TRANSACTION_ISOLATION },
    );
  }
}

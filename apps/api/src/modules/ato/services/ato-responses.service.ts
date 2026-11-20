import { Injectable } from '@nestjs/common';
import {
  ATO_TRANSACTION_ISOLATION,
  type ResponseActionType,
  type ResponseTarget,
} from '@email-gateway/ato-detection';
import { atoMailboxSha256 } from '@email-gateway/security-contracts';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import {
  decodeListCursor,
  encodeListCursor,
  listBinding,
  timeIdKeyOf,
  timeIdKeys,
} from '../../messages/domain/v1-list';
import { IncidentStores } from '../../incidents/incident-stores';
import { ATO_CURSOR_RESOURCES, ATO_OPERATIONS, ATO_TX_TIMEOUT_MS } from '../ato.constants';
import {
  atoAccountNotFound,
  atoIncidentNotFound,
  atoResponseNotFound,
  mapAtoStoreError,
} from '../ato.errors';
import { attemptView, responseView, restrictionView } from '../domain/ato-views';
import type {
  ApproveBody,
  CancelBody,
  ReasonBody,
  RequestResponseBody,
  ResponseDetailView,
  ResponseListQuery,
  ResponsePage,
} from '../dto/ato.schemas';
import { AtoReadRepository, type Db, type ResponseRow } from '../repositories/ato-read.repository';
import { AtoAccessService, parsePublicId } from './ato-access.service';
import { CodedHttpException } from '../../../http/coded-exception';
import { HttpStatus } from '@nestjs/common';

const invalid = (message: string): CodedHttpException =>
  new CodedHttpException(HttpStatus.UNPROCESSABLE_ENTITY, 'ato_response_invalid', message);

/**
 * Response actions (step 8.4 §5.1 #16–#22, D13, ADR-0072): request on an ATO incident (users and
 * API keys), the list and detail (attempts and restriction), approve (users with MFA, never the
 * requester; gateway actions execute in the same transaction), reject, cancel (pending only) and
 * rollback (users with MFA; restrictions lifted in the same transaction). Every mutation runs in
 * one writer transaction with the transactional Idempotency-Key through the `AtoStore`, which
 * enforces the state machine, the separation of duties and the approval window and writes the
 * timeline, audit rows and events.
 */
@Injectable()
export class AtoResponsesService {
  constructor(
    private readonly reads: AtoReadRepository,
    private readonly access: AtoAccessService,
    private readonly stores: IncidentStores,
    private readonly idempotency: IdempotencyService,
    private readonly codec: CursorCodec,
  ) {}

  private async views(principal: Principal, scope: TenantScope, rows: ResponseRow[], db?: Db) {
    const connectorIds = rows.flatMap((r) => {
      const t = (r.target ?? {}) as { connectorId?: unknown };
      return typeof t.connectorId === 'string' ? [t.connectorId] : [];
    });
    const connectors = await this.reads.connectorPublicIds(scope, connectorIds, db);
    const abilities = {
      userWithMfaAndRespond: AtoAccessService.canRespondWithMfa(principal),
      callerPublicId: AtoAccessService.callerPublicId(principal),
    };
    return rows.map((r) => responseView(r, connectors, abilities));
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    query: ResponseListQuery,
  ): Promise<ResponsePage> {
    const binding = listBinding({
      resource: ATO_CURSOR_RESOURCES.responses,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    if (!(await this.access.enabled(scope))) return { data: [], nextCursor: null };
    const f = query.filters;
    let incidentId: bigint | undefined;
    let accountId: bigint | undefined;
    if (f.incidentId?.values?.[0] !== undefined) {
      const incident = await this.reads.atoIncident(scope, f.incidentId.values[0]);
      if (incident === null) return { data: [], nextCursor: null };
      incidentId = incident.id;
    }
    if (f.accountId?.values?.[0] !== undefined) {
      const account = await this.reads.account(scope, f.accountId.values[0]);
      if (account === null) return { data: [], nextCursor: null };
      accountId = account.id;
    }
    const rows = await this.reads.responses(scope, {
      filters: {
        statuses: f.status?.values,
        actionTypes: f.actionType?.values,
        incidentId,
        accountId,
      },
      after: timeIdKeyOf(decoded),
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched: rows,
      limit: query.limit,
      keyOf: (r) => ({ at: r.createdAt, id: r.id }),
    });
    return {
      data: await this.views(principal, scope, rows.slice(0, decision.rows)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next)),
    };
  }

  async detail(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    db?: Db,
  ): Promise<ResponseDetailView> {
    const id = parsePublicId(rawId, 'responseId');
    if (db === undefined && !(await this.access.enabled(scope))) throw atoResponseNotFound();
    const row = await this.reads.response(scope, id, db);
    if (row === null) throw atoResponseNotFound();
    const [[view], attempts, restriction] = await Promise.all([
      this.views(principal, scope, [row], db),
      this.reads.responseAttempts(scope, row.id, db),
      row.restrictionId === null
        ? Promise.resolve(null)
        : this.reads.restrictionById(scope, row.restrictionId, db),
    ]);
    return {
      ...view!,
      attempts: attempts.map(attemptView),
      restriction: restriction ? restrictionView(restriction) : null,
    };
  }

  private keyed<T>(
    principal: Principal,
    scope: TenantScope,
    idempotencyKey: unknown,
    operation: string,
    resourceId: string,
    body: unknown,
    work: (tx: Db) => Promise<{ statusCode: number; body: T }>,
  ): Promise<IdempotentResult<T>> {
    const key = parseIdempotencyKey(idempotencyKey);
    return this.idempotency.execute<T>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId,
        fingerprint: requestFingerprint({ operation, resourceId, body }),
      },
      async (tx) => {
        await this.access.requireEnabled(scope, tx);
        try {
          return await work(tx);
        } catch (error) {
          return mapAtoStoreError(error);
        }
      },
      { timeoutMs: ATO_TX_TIMEOUT_MS, isolationLevel: ATO_TRANSACTION_ISOLATION },
    );
  }

  /** The response target of a request (§5.1 #16): defaults by account kind; connector ids mapped. */
  private async target(
    scope: TenantScope,
    tx: Db,
    type: ResponseActionType,
    account: { publicId: string; kind: string; address: string | null; connectorId: bigint | null },
    body: RequestResponseBody,
  ): Promise<ResponseTarget> {
    const base = { accountPublicId: account.publicId };
    if (type !== 'restrict_smtp_sending' && type !== 'block_smtp_auth') {
      if (body.target && body.target.scope !== 'account') {
        throw invalid('This action targets the account');
      }
      return { ...base, scope: 'account' };
    }
    const scopeOf =
      body.target?.scope ??
      (type === 'restrict_smtp_sending' && account.kind === 'mailbox' ? 'mailbox' : 'connector');
    if (scopeOf === 'account') throw invalid('This action targets a mailbox or a connector');
    if (scopeOf === 'mailbox') {
      if (account.kind !== 'mailbox' || !account.address) {
        throw invalid('Mailbox scope needs a mailbox account');
      }
      return { ...base, scope: 'mailbox', mailboxSha256: atoMailboxSha256(account.address) };
    }
    let connectorId: bigint | null = account.connectorId;
    if (body.target?.connectorId !== undefined) {
      connectorId = await this.reads.connectorByPublicId(
        scope,
        body.target.connectorId.toLowerCase(),
        tx,
      );
      if (connectorId === null) throw invalid('Unknown connector');
    }
    if (connectorId === null) throw invalid('A connector scope needs target.connectorId');
    return {
      ...base,
      scope: scopeOf,
      connectorId: connectorId.toString(),
      ...(scopeOf === 'connector_ip' && { cidr: body.target?.cidr ?? null }),
    };
  }

  /**
   * Step 8.5 (D9.7, D9.8): the provider parameters of `remove_forwarding_rule` (one present
   * mailbox item of the account, or every external forwarding item: the default) and
   * `revoke_oauth_grant` (`appIdHash`, required). Other action types take no `params`.
   */
  private async providerParams(
    scope: TenantScope,
    tx: Db,
    type: RequestResponseBody['actionType'],
    accountId: bigint,
    params: RequestResponseBody['params'],
  ): Promise<Record<string, string>> {
    const given = params ?? {};
    const keys = Object.keys(given);
    if (type === 'remove_forwarding_rule') {
      if (given.appIdHash !== undefined) throw invalid('appIdHash applies to revoke_oauth_grant');
      if (given.itemId !== undefined && given.scope !== undefined) {
        throw invalid('Give either params.itemId or params.scope, not both');
      }
      if (given.itemId !== undefined) {
        const itemId = given.itemId.toLowerCase();
        if (!(await this.reads.presentMailboxItemOfAccount(scope, accountId, itemId, tx))) {
          throw invalid('The mailbox item is not a present item of this account');
        }
        return { itemId };
      }
      return { scope: 'all_external' };
    }
    if (type === 'revoke_oauth_grant') {
      if (given.appIdHash === undefined || keys.length !== 1) {
        throw invalid('revoke_oauth_grant needs params.appIdHash (and nothing else)');
      }
      return { appIdHash: given.appIdHash };
    }
    if (keys.length > 0) throw invalid('params apply to identity-provider actions only');
    return {};
  }

  /** `POST /ato/incidents/{incidentId}/responses` (#16): `201` with the action. */
  request(
    principal: Principal,
    scope: TenantScope,
    rawIncidentId: unknown,
    idempotencyKey: unknown,
    body: RequestResponseBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<ResponseDetailView>> {
    const incidentPublicId = parsePublicId(rawIncidentId, 'incidentId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.responseRequest,
      incidentPublicId,
      body,
      async (tx) => {
        const incident = await this.reads.atoIncident(scope, incidentPublicId, tx);
        if (incident === null) throw atoIncidentNotFound();
        const [account] = await this.reads.accountsByIds(scope, [incident.subjectRefId], tx);
        if (!account) throw atoAccountNotFound();
        const type = body.actionType;
        if (type === 'record_manual_action' && body.description === undefined) {
          throw invalid('record_manual_action needs a description of what was done');
        }
        if (type !== 'record_manual_action' && body.description !== undefined) {
          throw invalid('description is accepted for record_manual_action only');
        }
        const restriction = type === 'restrict_smtp_sending' || type === 'block_smtp_auth';
        if (!restriction && (body.durationMinutes !== undefined || body.mode !== undefined)) {
          throw invalid('durationMinutes and mode apply to SMTP restrictions only');
        }
        const target = await this.target(scope, tx, type, account, body);
        const params: Record<string, string | number | boolean> = {
          ...(body.durationMinutes !== undefined && { durationMinutes: body.durationMinutes }),
          ...(body.mode !== undefined && { mode: body.mode }),
          ...(body.description !== undefined && { description: body.description }),
          ...(await this.providerParams(scope, tx, type, account.id, body.params)),
        };
        const action = await this.stores.ato.requestResponse(tx, {
          organizationId: scope.organizationId,
          accountId: account.id,
          incidentId: incident.id,
          actionType: type,
          target,
          params,
          actor: this.access.actorOf(principal),
          reason: body.reason,
          authorization: 'manual',
          providerKind: await this.reads.providerKind(scope, tx),
          sourceIp,
        });
        return { statusCode: 201, body: await this.detail(principal, scope, action.publicId, tx) };
      },
    );
  }

  private decided(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    operation: string,
    body: unknown,
    apply: (tx: Db, actionId: bigint) => Promise<unknown>,
  ): Promise<IdempotentResult<ResponseDetailView>> {
    const id = parsePublicId(rawId, 'responseId');
    return this.keyed(principal, scope, idempotencyKey, operation, id, body, async (tx) => {
      const action = await this.stores.ato.findAction(tx, scope.organizationId, id);
      if (action === null) throw atoResponseNotFound();
      await apply(tx, action.id);
      return { statusCode: 200, body: await this.detail(principal, scope, id, tx) };
    });
  }

  /** `POST /ato/responses/{id}/approve` (#19). */
  approve(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    key: unknown,
    body: ApproveBody,
    sourceIp: string | null,
  ) {
    return this.decided(
      principal,
      scope,
      rawId,
      key,
      ATO_OPERATIONS.responseApprove,
      body,
      (tx, actionId) =>
        this.stores.ato.decideResponse(tx, {
          organizationId: scope.organizationId,
          actionId,
          decision: 'approve',
          actor: this.access.actorOf(principal),
          reason: body.reason ?? null,
          sourceIp,
        }),
    );
  }

  /** `POST /ato/responses/{id}/reject` (#20). */
  reject(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    key: unknown,
    body: ReasonBody,
    sourceIp: string | null,
  ) {
    return this.decided(
      principal,
      scope,
      rawId,
      key,
      ATO_OPERATIONS.responseReject,
      body,
      (tx, actionId) =>
        this.stores.ato.decideResponse(tx, {
          organizationId: scope.organizationId,
          actionId,
          decision: 'reject',
          actor: this.access.actorOf(principal),
          reason: body.reason,
          sourceIp,
        }),
    );
  }

  /** `POST /ato/responses/{id}/cancel` (#21): pending actions only. */
  cancel(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    key: unknown,
    body: CancelBody,
    sourceIp: string | null,
  ) {
    return this.decided(
      principal,
      scope,
      rawId,
      key,
      ATO_OPERATIONS.responseCancel,
      body,
      (tx, actionId) =>
        this.stores.ato.cancelResponse(tx, {
          organizationId: scope.organizationId,
          actionId,
          actor: this.access.actorOf(principal),
          reason: body.reason ?? null,
          sourceIp,
        }),
    );
  }

  /** `POST /ato/responses/{id}/rollback` (#22): restrictions lifted in the same transaction. */
  rollback(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    key: unknown,
    body: ReasonBody,
    sourceIp: string | null,
  ) {
    return this.decided(
      principal,
      scope,
      rawId,
      key,
      ATO_OPERATIONS.responseRollback,
      body,
      (tx, actionId) =>
        this.stores.ato.requestRollback(tx, {
          organizationId: scope.organizationId,
          actionId,
          actor: this.access.actorOf(principal),
          reason: body.reason,
          sourceIp,
        }),
    );
  }
}

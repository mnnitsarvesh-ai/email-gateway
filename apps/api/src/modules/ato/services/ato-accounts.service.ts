import { Inject, Injectable } from '@nestjs/common';
import { ATO_TRANSACTION_ISOLATION } from '@email-gateway/ato-detection';
import type { AtoAccount } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiConventionMetrics } from '../../../http/api-metrics';
import { CursorCodec, cursorInvalid } from '../../../http/cursor/cursor-codec';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { rangeWindow, resolveRange } from '../../../http/listing/range';
import { decideKeysetPage, decideScanPage } from '../../../http/listing/scan-budget';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  instantKey,
  listBinding,
  timeIdKeyOf,
  timeIdKeys,
} from '../../messages/domain/v1-list';
import { IncidentStores } from '../../incidents/incident-stores';
import {
  ATO_AUDIT,
  ATO_CURSOR_RESOURCES,
  ATO_OPERATIONS,
  ATO_RANGES,
  ATO_TX_TIMEOUT_MS,
  type AtoConfig,
} from '../ato.constants';
import {
  atoAccountConflict,
  atoAccountNotFound,
  atoOverrideNotFound,
  atoTrustedContextNotFound,
  mapAtoStoreError,
} from '../ato.errors';
import {
  accountDetail,
  accountSummary,
  activityView,
  authEventView,
  scoreView,
  signalView,
  trustedContextView,
} from '../domain/ato-views';
import type {
  AccountDetailView,
  AccountListQuery,
  AccountPage,
  ActivityQuery,
  ActivityView,
  AddTrustedContextBody,
  AuthEventListQuery,
  AuthEventPage,
  ClearOverrideBody,
  ScoreHistoryQuery,
  ScorePage,
  SetOverrideBody,
  SignalListQuery,
  SignalPage,
  UpdateAccountBody,
} from '../dto/ato.schemas';
import { AtoAccountVersionRepository } from '../repositories/ato-account-version.repository';
import {
  type AccountKey,
  type AccountSort,
  AtoReadRepository,
  type Db,
  type TimeKey,
} from '../repositories/ato-read.repository';
import { AtoAccessService, parsePublicId } from './ato-access.service';

const DAY = 86_400_000;

type TrustedContextView = AccountDetailView['trustedContexts'][number];

/**
 * Monitored accounts (step 8.4 §5.1 #3–#13): the list (keyset per sort, scan-bounded with
 * residual filters), the detail, protection (CAS on `row_version`), signals, auth events (first
 * page audited `ato.auth_events.viewed`), activity, score history, overrides (rescoring in the
 * same transaction) and trusted contexts. Reads on the replica (echo-checked); mutations in one
 * writer transaction with the transactional Idempotency-Key, through the `AtoStore`, which
 * writes the audit rows.
 */
@Injectable()
export class AtoAccountsService {
  constructor(
    @Inject(API_CONFIG) private readonly config: Pick<AtoConfig, 'API_LIST_SCAN_BUDGET_ROWS'>,
    private readonly reads: AtoReadRepository,
    private readonly versions: AtoAccountVersionRepository,
    private readonly access: AtoAccessService,
    private readonly stores: IncidentStores,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
    private readonly metrics: ApiConventionMetrics,
  ) {}

  now(): Date {
    return new Date();
  }

  // ---------------------------------------------------------------- list

  private accountKey(sort: AccountSort, keys: readonly string[]): AccountKey {
    const id = decimalKey(keys[1]);
    if (sort === '-riskScore') {
      const value = Number(keys[0]);
      if (!/^\d{1,3}$/.test(keys[0] ?? '') || value > 100) throw cursorInvalid();
      return { value, id };
    }
    if (sort === '-lastSignalAt') return { value: instantKey(keys[0]), id };
    if (keys[0] === undefined || keys[0].length === 0 || keys[0].length > 320)
      throw cursorInvalid();
    return { value: keys[0], id };
  }

  private accountKeys(key: AccountKey): string[] {
    const v = key.value instanceof Date ? key.value.toISOString() : String(key.value);
    return [v, key.id.toString()];
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    query: AccountListQuery,
  ): Promise<AccountPage> {
    const binding = listBinding({
      resource: ATO_CURSOR_RESOURCES.accounts,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    if (!(await this.access.enabled(scope))) return { data: [], nextCursor: null };
    const sort = query.sort;
    const after = decoded ? this.accountKey(sort, decoded.keys) : undefined;
    const f = query.filters;
    const q = f.q?.values?.[0]?.trim().toLowerCase();
    if (q !== undefined && q.length < 2) return { data: [], nextCursor: null };
    let domainId: bigint | undefined;
    if (f.domainId?.values?.[0] !== undefined) {
      const found = await this.reads.domainIdByPublicId(scope, f.domainId.values[0]);
      if (found === null) return { data: [], nextCursor: null };
      domainId = found;
    }
    const filters = {
      kinds: f.kind?.values,
      levels: f.level?.values,
      minScore: f.minScore?.values?.[0],
      hasActiveIncident: f.hasActiveIncident?.values?.[0],
      protected: f.protected?.values?.[0],
      domainId,
      q,
    };
    const residual =
      filters.kinds !== undefined ||
      filters.levels !== undefined ||
      filters.hasActiveIncident !== undefined ||
      filters.protected !== undefined ||
      filters.domainId !== undefined ||
      (filters.minScore !== undefined && sort !== '-riskScore') ||
      (q !== undefined && sort !== 'address');
    const take = query.limit + 1;
    const keyOf = (row: AtoAccount) => this.reads.accountKeyOf(sort, row);
    let rows;
    let next: AccountKey | null;
    if (!residual) {
      rows = await this.reads.listAccounts(scope, { filters, sort, after, take });
      const decision = decideKeysetPage({ fetched: rows, limit: query.limit, keyOf });
      rows = rows.slice(0, decision.rows);
      next = decision.next;
    } else {
      const boundary = await this.reads.accountBoundary(
        scope,
        sort,
        after,
        this.config.API_LIST_SCAN_BUDGET_ROWS,
      );
      const fetched = await this.reads.listAccounts(scope, {
        filters,
        sort,
        after,
        boundary,
        take,
      });
      const decision = decideScanPage({ fetched, limit: query.limit, boundary, keyOf });
      if (decision.budgetExhausted) {
        this.metrics.scanBudgetExhausted.inc({ resource: ATO_CURSOR_RESOURCES.accounts });
      }
      rows = fetched.slice(0, decision.rows);
      next = decision.next;
    }
    return {
      data: rows.map(accountSummary),
      nextCursor:
        next === null ? null : encodeListCursor(this.codec, binding, this.accountKeys(next)),
    };
  }

  // ---------------------------------------------------------------- detail

  private async requireAccount(scope: TenantScope, rawId: unknown, db?: Db) {
    const publicId = parsePublicId(rawId, 'accountId');
    const row = await this.reads.account(scope, publicId, db);
    if (row === null) throw atoAccountNotFound();
    return row;
  }

  async detail(scope: TenantScope, rawId: unknown, db?: Db): Promise<AccountDetailView> {
    const id = parsePublicId(rawId, 'accountId');
    if (db === undefined && !(await this.access.enabled(scope))) throw atoAccountNotFound();
    const row = await this.requireAccount(scope, id, db);
    const [extras, capabilities] = await Promise.all([
      this.reads.accountExtras(scope, row, this.now(), db),
      this.access.capabilities(),
    ]);
    return accountDetail(row, extras, capabilities.view);
  }

  // ---------------------------------------------------------------- sub-lists

  async signals(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    query: SignalListQuery,
  ): Promise<SignalPage> {
    const binding = listBinding({
      resource: ATO_CURSOR_RESOURCES.signals,
      principal,
      filters: { ...query.filters, account: { values: [parsePublicId(rawId, 'accountId')] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    if (!(await this.access.enabled(scope))) throw atoAccountNotFound();
    const account = await this.requireAccount(scope, rawId);
    const range = resolveRange(query, {
      defaultMs: ATO_RANGES.signals.defaultDays * DAY,
      maxDays: ATO_RANGES.signals.maxDays,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const after = timeIdKeyOf(decoded);
    const f = query.filters;
    const residual = f.category !== undefined || f.status !== undefined || f.strength !== undefined;
    const take = query.limit + 1;
    const keyOf = (r: { detectedAt: Date; id: bigint }): TimeKey => ({
      at: r.detectedAt,
      id: r.id,
    });
    const input = {
      where: { accountId: account.id },
      range,
      categories: f.category?.values,
      statuses: f.status?.values,
      strengths: f.strength?.values,
      after,
      take,
    };
    let rows;
    let next: TimeKey | null;
    if (!residual) {
      rows = await this.reads.signals(scope, input);
      const decision = decideKeysetPage({ fetched: rows, limit: query.limit, keyOf });
      rows = rows.slice(0, decision.rows);
      next = decision.next;
    } else {
      const boundary = await this.reads.signalBoundary(
        scope,
        input.where,
        range,
        after,
        this.config.API_LIST_SCAN_BUDGET_ROWS,
      );
      const fetched = await this.reads.signals(scope, { ...input, boundary });
      const decision = decideScanPage({ fetched, limit: query.limit, boundary, keyOf });
      if (decision.budgetExhausted) {
        this.metrics.scanBudgetExhausted.inc({ resource: ATO_CURSOR_RESOURCES.signals });
      }
      rows = fetched.slice(0, decision.rows);
      next = decision.next;
    }
    return {
      data: rows.map(signalView),
      nextCursor:
        next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(next), rangeWindow(range)),
    };
  }

  async authEvents(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    query: AuthEventListQuery,
    sourceIp: string | null,
  ): Promise<AuthEventPage> {
    const binding = listBinding({
      resource: ATO_CURSOR_RESOURCES.authEvents,
      principal,
      filters: { ...query.filters, account: { values: [parsePublicId(rawId, 'accountId')] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    if (!(await this.access.enabled(scope))) throw atoAccountNotFound();
    const account = await this.requireAccount(scope, rawId);
    const range = resolveRange(query, {
      defaultMs: ATO_RANGES.authEvents.defaultDays * DAY,
      maxDays: ATO_RANGES.authEvents.maxDays,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const after = timeIdKeyOf(decoded);
    const f = query.filters;
    const country = f.country?.values?.[0]?.toUpperCase();
    const input = {
      accountId: account.id,
      range,
      outcomes: f.outcome?.values,
      sources: f.source?.values,
      ip: f.ip?.values?.[0],
      country,
      after,
      take: query.limit + 1,
    };
    const residual =
      input.outcomes !== undefined ||
      input.sources !== undefined ||
      input.ip !== undefined ||
      input.country !== undefined;
    const keyOf = (r: { occurredAt: Date; id: bigint }): TimeKey => ({
      at: r.occurredAt,
      id: r.id,
    });
    let rows;
    let next: TimeKey | null;
    if (!residual) {
      rows = await this.reads.authEvents(scope, input);
      const decision = decideKeysetPage({ fetched: rows, limit: query.limit, keyOf });
      rows = rows.slice(0, decision.rows);
      next = decision.next;
    } else {
      const boundary = await this.reads.authEventBoundary(
        scope,
        account.id,
        range,
        after,
        this.config.API_LIST_SCAN_BUDGET_ROWS,
      );
      const fetched = await this.reads.authEvents(scope, { ...input, boundary });
      const decision = decideScanPage({ fetched, limit: query.limit, boundary, keyOf });
      if (decision.budgetExhausted) {
        this.metrics.scanBudgetExhausted.inc({ resource: ATO_CURSOR_RESOURCES.authEvents });
      }
      rows = fetched.slice(0, decision.rows);
      next = decision.next;
    }
    if (decoded === undefined) {
      // D17: the first page of an account's authentication history is audited (no IP addresses).
      await this.audit.record({
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action: ATO_AUDIT.authEventsViewed,
        resourceType: 'ato_account',
        resourceId: account.publicId,
        sourceIp,
        metadata: {
          kind: account.kind,
          rangeDays: Math.ceil((range.to.getTime() - range.from.getTime()) / DAY),
          filters: Object.keys(query.filters).sort(),
          returned: rows.length,
        },
      });
    }
    return {
      data: rows.map(authEventView),
      nextCursor:
        next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(next), rangeWindow(range)),
    };
  }

  async activity(scope: TenantScope, rawId: unknown, query: ActivityQuery): Promise<ActivityView> {
    if (!(await this.access.enabled(scope))) throw atoAccountNotFound();
    const account = await this.requireAccount(scope, rawId);
    const range = resolveRange(query, {
      defaultMs: ATO_RANGES.activity.defaultDays * DAY,
      maxDays: ATO_RANGES.activity.maxDays,
      now: this.now(),
    });
    const rows = await this.reads.activity(scope, account.id, range);
    return activityView(account.publicId, range, rows);
  }

  async scoreHistory(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    query: ScoreHistoryQuery,
  ): Promise<ScorePage> {
    const binding = listBinding({
      resource: ATO_CURSOR_RESOURCES.scoreHistory,
      principal,
      filters: { account: { values: [parsePublicId(rawId, 'accountId')] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    if (!(await this.access.enabled(scope))) throw atoAccountNotFound();
    const account = await this.requireAccount(scope, rawId);
    const range = resolveRange(query, {
      defaultMs: ATO_RANGES.scoreHistory.defaultDays * DAY,
      maxDays: ATO_RANGES.scoreHistory.maxDays,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const rows = await this.reads.scores(scope, {
      accountId: account.id,
      range,
      after: timeIdKeyOf(decoded),
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched: rows,
      limit: query.limit,
      keyOf: (r) => ({ at: r.computedAt, id: r.id }),
    });
    return {
      data: rows.slice(0, decision.rows).map(scoreView),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next), rangeWindow(range)),
    };
  }

  // ---------------------------------------------------------------- mutations

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

  /** `PATCH /ato/accounts/{id}` (#5): protection with CAS on the account's `row_version`. */
  update(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: UpdateAccountBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<AccountDetailView>> {
    const id = parsePublicId(rawId, 'accountId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.accountUpdate,
      id,
      body,
      async (tx) => {
        const store = this.stores.ato;
        const found = await store.findAccount(tx, scope.organizationId, id);
        if (found === null) throw atoAccountNotFound();
        const [locked] = await store.lockAccounts(tx, scope.organizationId, [found.id]);
        if (!locked || locked.rowVersion !== body.expectedRowVersion) {
          throw atoAccountConflict(locked?.rowVersion ?? found.rowVersion);
        }
        const reason = body.protected ? (body.reason ?? null) : null;
        if (
          locked.protected !== body.protected ||
          (body.protected && locked.protectedReason !== reason)
        ) {
          await store.setProtected(tx, {
            organizationId: scope.organizationId,
            accountId: locked.id,
            protected: body.protected,
            reason,
            actor: this.access.actorOf(principal),
            sourceIp,
          });
          await this.versions.bump(tx, scope, locked.id);
        }
        return { statusCode: 200, body: await this.detail(scope, id, tx) };
      },
    );
  }

  /** `PUT /ato/accounts/{id}/override` (#10): replaces the override and rescores. */
  setOverride(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: SetOverrideBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<AccountDetailView>> {
    const id = parsePublicId(rawId, 'accountId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.overrideSet,
      id,
      body,
      async (tx) => {
        const found = await this.stores.ato.findAccount(tx, scope.organizationId, id);
        if (found === null) throw atoAccountNotFound();
        await this.stores.ato.setOverride(tx, {
          organizationId: scope.organizationId,
          accountId: found.id,
          verdict: body.verdict,
          reason: body.reason,
          expiresAt: new Date(this.stores.now().getTime() + body.expiresInHours * 3_600_000),
          actor: this.access.actorOf(principal),
          sourceIp,
        });
        return { statusCode: 200, body: await this.detail(scope, id, tx) };
      },
    );
  }

  /** `POST /ato/accounts/{id}/override/clear` (#11). */
  clearOverride(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: ClearOverrideBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<AccountDetailView>> {
    const id = parsePublicId(rawId, 'accountId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.overrideClear,
      id,
      body,
      async (tx) => {
        const found = await this.stores.ato.findAccount(tx, scope.organizationId, id);
        if (found === null) throw atoAccountNotFound();
        const result = await this.stores.ato.clearOverride(tx, {
          organizationId: scope.organizationId,
          accountId: found.id,
          reason: body.reason,
          actor: this.access.actorOf(principal),
          sourceIp,
        });
        if (result === null) throw atoOverrideNotFound();
        return { statusCode: 200, body: await this.detail(scope, id, tx) };
      },
    );
  }

  /** `POST /ato/accounts/{id}/trusted-contexts` (#12): `201` with the context. */
  addTrustedContext(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: AddTrustedContextBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<TrustedContextView>> {
    const id = parsePublicId(rawId, 'accountId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.trustedContextAdd,
      id,
      body,
      async (tx) => {
        const found = await this.stores.ato.findAccount(tx, scope.organizationId, id);
        if (found === null) throw atoAccountNotFound();
        const { publicId } = await this.stores.ato.addTrustedContext(tx, {
          organizationId: scope.organizationId,
          accountId: found.id,
          kind: body.kind,
          value: body.value,
          reason: body.reason,
          expiresAt: new Date(this.stores.now().getTime() + body.expiresInDays * DAY),
          source: 'analyst',
          actor: this.access.actorOf(principal),
          sourceIp,
        });
        const context = await this.reads.trustedContext(scope, found.id, publicId, tx);
        if (context === null) throw atoTrustedContextNotFound();
        return { statusCode: 201, body: trustedContextView(context) };
      },
    );
  }

  /** `DELETE /ato/accounts/{id}/trusted-contexts/{contextId}` (#13): `204`. */
  removeTrustedContext(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    rawContextId: unknown,
    idempotencyKey: unknown,
    sourceIp: string | null,
  ): Promise<IdempotentResult<{ id: string; deleted: true }>> {
    const id = parsePublicId(rawId, 'accountId');
    const contextId = parsePublicId(rawContextId, 'contextId');
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      ATO_OPERATIONS.trustedContextRemove,
      contextId,
      null,
      async (tx) => {
        const found = await this.stores.ato.findAccount(tx, scope.organizationId, id);
        if (found === null) throw atoAccountNotFound();
        const context = await this.reads.trustedContext(scope, found.id, contextId, tx);
        if (context === null) throw atoTrustedContextNotFound();
        await this.stores.ato.removeTrustedContext(tx, {
          organizationId: scope.organizationId,
          publicId: contextId,
          actor: this.access.actorOf(principal),
          sourceIp,
        });
        return { statusCode: 204, body: { id: contextId, deleted: true as const } };
      },
    );
  }
}

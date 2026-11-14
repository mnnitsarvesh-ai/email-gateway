import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../api-config.token';
import { AuditService } from '../../audit/audit.service';
import type { UserPrincipal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../config';
import { TransactionRunner } from '../../database/transaction-runner';
import { CursorCodec } from '../../http/cursor/cursor-codec';
import { InconsistentReadError } from '../../http/listing/echo-check';
import { decideKeysetPage } from '../../http/listing/scan-budget';
import type { ClientContext } from '../auth/services/session.service';
import { forbiddenFilter } from '../messages/domain/message-list-plan';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
} from '../messages/domain/v1-list';
import { MessageListQuerySchema } from '../messages/dto/message-data.schemas';
import { messageFilterForbidden } from '../messages/messages.errors';
import {
  savedViewConflict,
  savedViewLimitReached,
  savedViewNameTaken,
  savedViewNotFound,
  savedViewsMemberOnly,
} from './saved-views.errors';
import { SavedViewsRepository, type SavedViewRow, type ViewOwner } from './saved-views.repository';
import {
  type CreateSavedViewBody,
  definitionIssues,
  SAVED_VIEWS_RESOURCE,
  type SavedView,
  type SavedViewDefinition,
  SavedViewDefinitionSchema,
  type SavedViewListQuery,
  type SavedViewPage,
  type UpdateSavedViewBody,
} from './saved-views.schemas';

/** Writer transaction budget of the saved view writes (6.1 D15 default). */
export const SAVED_VIEWS_TX_TIMEOUT_MS = 15_000;

/** Audit actions (§2 E4): the view's public id and kind only (names and filters are data). */
export const SAVED_VIEW_AUDIT = {
  created: 'saved_view.created',
  updated: 'saved_view.updated',
  deleted: 'saved_view.deleted',
} as const;

type Config = Pick<ApiConfig, 'SAVED_VIEWS_MAX_PER_USER' | 'API_MESSAGES_MAX_RANGE_DAYS'>;

/**
 * The API view of a row. Stored definitions passed the structural and semantic checks on write;
 * on read only the structure is checked (a view whose filters no longer apply is still served,
 * the explorer applies what it can, §2 E10). A structurally corrupted row is never served.
 */
export function toSavedView(row: SavedViewRow): SavedView {
  const parsed = SavedViewDefinitionSchema.safeParse(row.definition);
  if (!parsed.success) throw new InconsistentReadError('saved_views.definition');
  const definition = parsed.data;
  return {
    id: row.publicId,
    kind: row.kind,
    name: row.name,
    definition,
    rowVersion: row.rowVersion,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

const isUniqueViolation = (err: unknown): boolean =>
  err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002';

/**
 * Saved Email Explorer views (step 7.2 §2 E4, §3.3, ADR-0061 decision 7): per user, tenant-scoped,
 * kind `message_explorer`. Only users who are members of the scope's organization use them (API
 * keys are refused by the route, a platform override session here with `403
 * saved_views_member_only`); another user's or organization's view is `404
 * saved_view_not_found`. A definition is validated with the real `GET /messages` query schema
 * (`400 validation_failed`, paths under `definition`) and the filter-level permissions (`403
 * message_filter_forbidden`). Writes run in one writer transaction under the owner's row lock
 * (the per-user limit `SAVED_VIEWS_MAX_PER_USER`, `409 saved_view_limit_reached`), compare
 * `rowVersion` (`409 saved_view_conflict`), map the unique name to `409 saved_view_name_taken`
 * and write the audit row (`saved_view.created|updated|deleted`: public id and kind only).
 * Reads use the writer too: they are read-after-write paths of the user's own settings.
 */
@Injectable()
export class SavedViewsService {
  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly repository: SavedViewsRepository,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {}

  async list(
    principal: UserPrincipal,
    scope: TenantScope,
    query: SavedViewListQuery,
  ): Promise<SavedViewPage> {
    const owner = this.member(principal, scope);
    const kind = query.filters.kind!.values![0]!;
    const binding = listBinding({
      resource: SAVED_VIEWS_RESOURCE,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const beforeId = decoded ? decimalKey(decoded.keys[0]) : undefined;
    const fetched = await this.repository.list(scope, owner, kind, {
      take: query.limit + 1,
      beforeId,
    });
    const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf: (r) => r.id });
    return {
      data: fetched.slice(0, decision.rows).map(toSavedView),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  async get(principal: UserPrincipal, scope: TenantScope, viewId: string): Promise<SavedView> {
    const owner = this.member(principal, scope);
    const row = await this.repository.find(scope, owner, viewId);
    if (!row) throw savedViewNotFound();
    return toSavedView(row);
  }

  async create(
    principal: UserPrincipal,
    scope: TenantScope,
    body: CreateSavedViewBody,
    client: ClientContext,
  ): Promise<SavedView> {
    const owner = this.member(principal, scope);
    this.checkDefinition(principal, body.definition);
    const limit = this.config.SAVED_VIEWS_MAX_PER_USER;
    try {
      const row = await this.runner.run(
        async (tx) => {
          await this.repository.lockOwner(tx, scope, owner);
          if ((await this.repository.count(tx, scope, owner, body.kind)) >= limit) {
            throw savedViewLimitReached(limit);
          }
          const created = await this.repository.create(tx, scope, owner, {
            kind: body.kind,
            name: body.name,
            definition: body.definition,
          });
          await this.record(tx, principal, scope, client, SAVED_VIEW_AUDIT.created, created);
          return created;
        },
        { timeoutMs: SAVED_VIEWS_TX_TIMEOUT_MS },
      );
      return toSavedView(row);
    } catch (err) {
      if (isUniqueViolation(err)) throw savedViewNameTaken();
      throw err;
    }
  }

  async update(
    principal: UserPrincipal,
    scope: TenantScope,
    viewId: string,
    body: UpdateSavedViewBody,
    client: ClientContext,
  ): Promise<SavedView> {
    const owner = this.member(principal, scope);
    this.checkDefinition(principal, body.definition);
    try {
      const row = await this.runner.run(
        async (tx) => {
          await this.repository.lockOwner(tx, scope, owner);
          const current = await this.repository.findWith(tx, scope, owner, viewId);
          if (!current) throw savedViewNotFound();
          if (current.rowVersion !== body.expectedRowVersion) {
            throw savedViewConflict(current.rowVersion);
          }
          const applied = await this.repository.update(
            tx,
            scope,
            owner,
            viewId,
            body.expectedRowVersion,
            { name: body.name, definition: body.definition },
          );
          if (!applied) throw savedViewConflict(current.rowVersion);
          // Read-after-write on the writer, in the transaction.
          const updated = await this.repository.findWith(tx, scope, owner, viewId);
          if (!updated) throw savedViewNotFound();
          await this.record(tx, principal, scope, client, SAVED_VIEW_AUDIT.updated, updated);
          return updated;
        },
        { timeoutMs: SAVED_VIEWS_TX_TIMEOUT_MS },
      );
      return toSavedView(row);
    } catch (err) {
      if (isUniqueViolation(err)) throw savedViewNameTaken();
      throw err;
    }
  }

  async remove(
    principal: UserPrincipal,
    scope: TenantScope,
    viewId: string,
    client: ClientContext,
  ): Promise<void> {
    const owner = this.member(principal, scope);
    await this.runner.run(
      async (tx) => {
        const current = await this.repository.findWith(tx, scope, owner, viewId);
        if (!current || !(await this.repository.delete(tx, scope, owner, viewId))) {
          throw savedViewNotFound();
        }
        await this.record(tx, principal, scope, client, SAVED_VIEW_AUDIT.deleted, current);
      },
      { timeoutMs: SAVED_VIEWS_TX_TIMEOUT_MS },
    );
  }

  /** A member of the scope's organization (never a platform override session). */
  private member(principal: UserPrincipal, scope: TenantScope): ViewOwner {
    if (scope.via !== 'member' || principal.override !== undefined) throw savedViewsMemberOnly();
    return { userId: principal.userId };
  }

  /** §3.3 semantic rules (400 with paths, never values), then the filter permissions (403). */
  private checkDefinition(principal: UserPrincipal, definition: SavedViewDefinition): void {
    const issues = definitionIssues(definition, this.config.API_MESSAGES_MAX_RANGE_DAYS);
    if (issues.length > 0) {
      throw new BadRequestException(issues.map((i) => `${i.path}: ${i.message}`));
    }
    const filters = MessageListQuerySchema.parse({
      ...definition.filters,
      sort: definition.sort,
    }).filters;
    const forbidden = forbiddenFilter(filters, principal.permissions);
    if (forbidden) throw messageFilterForbidden(forbidden.filter, forbidden.permission);
  }

  private record(
    tx: Prisma.TransactionClient,
    principal: UserPrincipal,
    scope: TenantScope,
    client: ClientContext,
    action: string,
    row: SavedViewRow,
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: 'saved_view',
        resourceId: row.publicId,
        sourceIp: client.ip,
        metadata: { kind: row.kind },
      },
      tx,
    );
  }
}

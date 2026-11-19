import { createHash } from 'node:crypto';
import { HttpStatus, Inject, Injectable } from '@nestjs/common';
import { ATO_TRANSACTION_ISOLATION } from '@email-gateway/ato-detection';
import {
  SECURITY_INCIDENT_SEVERITIES,
  type SecurityIncidentSeverity,
} from '@email-gateway/security-contracts';
import {
  INCIDENT_TRANSITIONS,
  type IncidentActor,
  type IncidentRow,
  RESOLUTION_REQUIREMENTS,
} from '@email-gateway/security-incidents';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedHttpException } from '../../../http/coded-exception';
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
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import { TransactionRunner } from '../../../database/transaction-runner';
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  instantKey,
  listBinding,
  timeIdKeyOf,
  timeIdKeys,
} from '../../messages/domain/v1-list';
import type { AtoConfig } from '../../ato/ato.constants';
import type {
  AddNoteBody,
  CreateIncidentBody,
  IncidentDetailView,
  IncidentListQuery,
  IncidentMessagePage,
  IncidentPage,
  IncidentReportView,
  IncidentSummaryView,
  MessagesQuery,
  TimelineEntryView,
  TimelinePage,
  TimelineQuery,
  UpdateIncidentBody,
} from '../dto/incidents.schemas';
import { PublicIdSchema } from '../dto/incidents.schemas';
import type { IncidentCategoryDefinition } from '../incident-categories';
import { IncidentStores } from '../incident-stores';
import {
  incidentAssigneeInvalid,
  incidentCategoryUnsupported,
  incidentFeedbackInvalid,
  incidentConflict,
  incidentNotFound,
  incidentSubjectNotFound,
  mapIncidentError,
} from '../incidents.errors';
import { IncidentMetrics } from './incident-metrics';
import {
  type Db,
  type IncidentKey,
  type IncidentListRow,
  IncidentsReadRepository,
} from '../repositories/incidents-read.repository';
import { BadRequestException } from '@nestjs/common';
import type { SecurityIncidentEvent } from '@email-gateway/database';

/** Cursor resources of the incident lists (ADR-0051). */
export const INCIDENT_CURSOR_RESOURCES = {
  incidents: 'security_incidents',
  timeline: 'security_incident_timeline',
  messages: 'security_incident_messages',
} as const;

/** Idempotency-Key operations of the incident mutations. */
export const INCIDENT_OPERATIONS = {
  create: 'incident.create',
  update: 'incident.update',
  addNote: 'incident.note_add',
} as const;

const TX_TIMEOUT_MS = 30_000;

export function parseIncidentId(raw: unknown): string {
  const parsed = PublicIdSchema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException(['incidentId: must be a UUID']);
  return parsed.data.toLowerCase();
}

const iso = (d: Date | null): string | null => (d ? d.toISOString() : null);
const opaque = (kind: string, id: bigint): string =>
  createHash('sha256')
    .update(`incident-${kind}|${id.toString()}`, 'utf8')
    .digest('hex')
    .slice(0, 20);

/**
 * The generic security incident routes (step 8.4 §5.2, D17, D24; ADR-0075). The caller sees only
 * incidents of the categories whose read permission it holds **and** whose plan feature is
 * enabled; anything else answers `404 incident_not_found` exactly like another tenant's id.
 * Mutations need the incident category's manage permission (else `404`) and its feature (else
 * the category's `403`, ATO: `ato_not_enabled`); they run through the shared `IncidentStore`
 * (row lock, row-version CAS, state machine, timeline, events, audit) in one writer transaction
 * with the transactional Idempotency-Key.
 */
@Injectable()
export class IncidentsService {
  constructor(
    @Inject(API_CONFIG) private readonly config: Pick<AtoConfig, 'API_ATO_REPORT_MAX_ITEMS'>,
    private readonly stores: IncidentStores,
    private readonly reads: IncidentsReadRepository,
    private readonly features: OrganizationFeaturesService,
    private readonly idempotency: IdempotencyService,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
    private readonly metrics: IncidentMetrics,
  ) {}

  now(): Date {
    return this.stores.now();
  }

  // ---------------------------------------------------------------- category access

  private async enabledFor(
    scope: TenantScope,
    def: IncidentCategoryDefinition,
    tx?: Db,
  ): Promise<boolean> {
    return def.featureKey === null
      ? true
      : this.features.isEnabled(scope.organizationId, def.featureKey, tx);
  }

  /** Categories the principal may read whose feature is on (registration order). */
  async readableCategories(principal: Principal, scope: TenantScope): Promise<string[]> {
    const allowed = this.stores.registry.categoriesReadableBy(principal.permissions);
    const out: string[] = [];
    for (const category of allowed) {
      const def = this.stores.definition(category);
      if (def && (await this.enabledFor(scope, def))) out.push(category);
    }
    return out;
  }

  private actorOf(principal: Principal): IncidentActor {
    const audit = this.audit.actorFrom(principal);
    return principal.kind === 'user'
      ? {
          type: 'user',
          id: principal.userPublicId,
          userId: principal.userId,
          ...(audit.override && { override: audit.override }),
        }
      : { type: 'api_key', id: principal.apiKeyPublicId };
  }

  private canManage(principal: Principal, category: string): boolean {
    return this.stores.registry
      .categoriesManageableBy(principal.permissions)
      .includes(category as never);
  }

  // ---------------------------------------------------------------- views

  private async summaries(
    scope: TenantScope,
    rows: IncidentListRow[],
    db?: Db,
  ): Promise<IncidentSummaryView[]> {
    const displays = new Map<string, Map<bigint, string | null>>();
    for (const category of new Set(rows.map((r) => r.category))) {
      const def = this.stores.definition(category);
      if (!def) continue;
      displays.set(
        category,
        await def.subjectDisplays(
          db ?? this.reads.replicaClient(),
          scope.organizationId,
          rows.filter((r) => r.category === category).map((r) => r.subjectRefId),
        ),
      );
    }
    return rows.map((r) => ({
      id: r.publicId,
      category: r.category,
      subject: {
        type: r.subjectType,
        id: r.subjectPublicId,
        display: displays.get(r.category)?.get(r.subjectRefId) ?? null,
      },
      origin: r.origin,
      status: r.status,
      severity: r.severity,
      titleCode: r.titleCode,
      reasonCodes: Array.isArray(r.reasonCodes)
        ? (r.reasonCodes as unknown[]).filter((c): c is string => typeof c === 'string')
        : [],
      detectedAt: r.detectedAt.toISOString(),
      lastEvidenceAt: iso(r.lastEvidenceAt),
      evidenceCount: r.evidenceCount,
      assigneeId: r.assigneePublicId,
      escalatedAt: iso(r.escalatedAt),
      resolvedAt: iso(r.resolvedAt),
      resolutionCode: r.resolutionCode,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
    }));
  }

  private allowedTransitions(
    principal: Principal,
    row: IncidentRow,
  ): IncidentDetailView['allowedTransitions'] {
    if (!this.canManage(principal, row.category)) return [];
    return INCIDENT_TRANSITIONS[row.status].map((to) => ({
      to,
      resolutionCodes: [...(RESOLUTION_REQUIREMENTS[to].codes ?? [])],
      noteRequired: RESOLUTION_REQUIREMENTS[to].noteRequired,
    }));
  }

  private async detailView(
    principal: Principal,
    scope: TenantScope,
    row: IncidentListRow,
    db: Db,
  ): Promise<IncidentDetailView> {
    const [summary] = await this.summaries(scope, [row], db);
    const handler = this.stores.registry.get(row.category);
    const def = this.stores.definition(row.category);
    let detail = await handler.loadDetail(db, row);
    if (def?.augmentDetail) detail = await def.augmentDetail(db, row, detail);
    const terminal = row.status === 'false_positive' || row.status === 'resolved';
    return {
      ...summary!,
      rowVersion: row.rowVersion,
      detectorVersion: row.detectorVersion,
      firstEvidenceAt: iso(row.firstEvidenceAt),
      assignedAt: iso(row.assignedAt),
      confirmedAt: iso(row.confirmedAt),
      mitigatedAt: iso(row.mitigatedAt),
      resolution: terminal
        ? { code: row.resolutionCode, note: row.resolutionNote, resolvedAt: iso(row.resolvedAt) }
        : null,
      createdBy: { type: row.createdByType, id: row.createdById },
      canManage: this.canManage(principal, row.category),
      allowedTransitions: this.allowedTransitions(principal, row),
      evidence: await this.reads.linkCounts(scope, row.id, db),
      detail: JSON.parse(
        JSON.stringify(detail, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)),
      ) as Record<string, unknown>,
    };
  }

  private timelineView(e: SecurityIncidentEvent): TimelineEntryView {
    return {
      id: opaque('event', e.id),
      at: e.createdAt.toISOString(),
      type: e.eventType,
      actor: { type: e.actorType, id: e.actorId },
      fromStatus: e.fromStatus,
      toStatus: e.toStatus,
      fromSeverity: e.fromSeverity,
      toSeverity: e.toSeverity,
      note: e.note,
      details: e.details ?? null,
    };
  }

  // ---------------------------------------------------------------- reads

  async list(
    principal: Principal,
    scope: TenantScope,
    query: IncidentListQuery,
  ): Promise<IncidentPage> {
    const binding = listBinding({
      resource: INCIDENT_CURSOR_RESOURCES.incidents,
      principal,
      filters: {
        ...query.filters,
        ...(query.detectedFrom && { detectedFrom: { gte: query.detectedFrom } }),
        ...(query.detectedTo && { detectedTo: { lt: query.detectedTo } }),
      },
      sort: query.sort,
    });
    const sort = query.sort;
    const decoded = decodeListCursor(
      this.codec,
      binding,
      query.cursor,
      sort === '-severity' ? 3 : 2,
    );
    let after: IncidentKey | undefined;
    if (decoded) {
      if (sort === '-severity') {
        const severity = decoded.keys[0] as SecurityIncidentSeverity;
        if (!SECURITY_INCIDENT_SEVERITIES.includes(severity)) throw cursorInvalid();
        after = { severity, at: instantKey(decoded.keys[1]), id: decimalKey(decoded.keys[2]) };
      } else {
        const k = timeIdKeyOf(decoded)!;
        after = { at: k.at, id: k.id };
      }
    }
    const readable = await this.readableCategories(principal, scope);
    const f = query.filters;
    const requested = f.category?.values;
    const categories = requested ? readable.filter((c) => requested.includes(c)) : readable;
    if (categories.length === 0) return { data: [], nextCursor: null };
    const assigneeRaw = f.assignee?.values?.[0];
    let assignee: bigint | null | undefined;
    if (assigneeRaw === 'me') {
      if (principal.kind !== 'user') return { data: [], nextCursor: null };
      assignee = principal.userId;
    } else if (assigneeRaw === 'unassigned') {
      assignee = null;
    } else if (assigneeRaw !== undefined) {
      const parsed = PublicIdSchema.safeParse(assigneeRaw);
      if (!parsed.success) {
        throw new BadRequestException(['assignee: must be me, unassigned or a user id']);
      }
      const id = await this.reads.activeUserId(scope, parsed.data.toLowerCase());
      if (id === null) return { data: [], nextCursor: null };
      assignee = id;
    }
    const rows = await this.reads.list(scope, {
      filters: {
        categories,
        statuses: f.status?.values,
        severities: f.severity?.values,
        assignee,
        subjectType: f.subjectType?.values?.[0] as never,
        subjectPublicId: f.subjectId?.values?.[0]?.toLowerCase(),
        origin: f.origin?.values?.[0],
        detectedFrom: query.detectedFrom,
        detectedTo: query.detectedTo,
      },
      sort,
      after,
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched: rows,
      limit: query.limit,
      keyOf: (r) => r,
    });
    const next = decision.next;
    return {
      data: await this.summaries(scope, rows.slice(0, decision.rows)),
      nextCursor:
        next === null
          ? null
          : encodeListCursor(
              this.codec,
              binding,
              sort === '-severity'
                ? [next.severity, next.detectedAt.toISOString(), next.id.toString()]
                : timeIdKeys({ at: next.detectedAt, id: next.id }),
            ),
    };
  }

  private async readable(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    db?: Db,
  ): Promise<IncidentListRow> {
    const id = parseIncidentId(rawId);
    const categories = await this.readableCategories(principal, scope);
    const row = await this.reads.get(scope, id, categories, db);
    if (row === null) throw incidentNotFound();
    return row;
  }

  async get(principal: Principal, scope: TenantScope, rawId: unknown): Promise<IncidentDetailView> {
    const row = await this.readable(principal, scope, rawId);
    return this.detailView(principal, scope, row, this.reads.replicaClient());
  }

  async timeline(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    query: TimelineQuery,
  ): Promise<TimelinePage> {
    const id = parseIncidentId(rawId);
    const binding = listBinding({
      resource: INCIDENT_CURSOR_RESOURCES.timeline,
      principal,
      filters: { incident: { values: [id] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const row = await this.readable(principal, scope, id);
    const rows = await this.reads.timeline(scope, {
      incidentId: row.id,
      after: timeIdKeyOf(decoded),
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched: rows,
      limit: query.limit,
      keyOf: (e) => ({ at: e.createdAt, id: e.id }),
    });
    return {
      data: rows.slice(0, decision.rows).map((e) => this.timelineView(e)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next)),
    };
  }

  async messages(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    query: MessagesQuery,
  ): Promise<IncidentMessagePage> {
    const id = parseIncidentId(rawId);
    const binding = listBinding({
      resource: INCIDENT_CURSOR_RESOURCES.messages,
      principal,
      filters: { incident: { values: [id] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const row = await this.readable(principal, scope, id);
    const rows = await this.reads.messages(scope, {
      incidentId: row.id,
      after: timeIdKeyOf(decoded),
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched: rows,
      limit: query.limit,
      keyOf: (m) => ({ at: m.receivedAt, id: m.messageId }),
    });
    return {
      data: rows.slice(0, decision.rows).map((m) => ({
        id: m.publicId,
        receivedAt: m.receivedAt.toISOString(),
        direction: m.direction as 'inbound' | 'outbound' | 'internal',
        finalVerdict: m.finalVerdict,
        finalAction: m.finalAction,
        riskScore: m.riskScore,
        riskLevel: m.riskLevel,
        recipientCount: m.recipientCount,
        externalDomainCount: m.externalDomainCount,
        findingCodes: m.findingCodes,
      })),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next)),
    };
  }

  /** `GET /incidents/{id}/report` (I8): assembled on the replica, then audited on the writer. */
  async report(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    sourceIp: string | null,
  ): Promise<IncidentReportView> {
    const row = await this.readable(principal, scope, rawId);
    const report = await this.reads.report(this.stores.registry, row, {
      maxItems: this.config.API_ATO_REPORT_MAX_ITEMS,
      now: this.now(),
    });
    // The library's report names linked messages by internal id; the api answers public ids
    // only (§5): map them through `message_identities` (a message without one is left out).
    const publicIds = await this.reads.messagePublicIds(
      scope,
      report.messages.flatMap((m) => (/^\d{1,20}$/.test(m.messageId) ? [BigInt(m.messageId)] : [])),
    );
    const def = this.stores.definition(row.category);
    const sections = def?.augmentReport
      ? await def.augmentReport(this.reads.replicaClient(), row, report.sections)
      : report.sections;
    const messages = report.messages.flatMap((m) => {
      const publicId = publicIds.get(m.messageId);
      return publicId ? [{ ...m, messageId: publicId }] : [];
    });
    await this.runner.run((tx) =>
      this.stores.incidents.recordReportExport(tx, row, this.actorOf(principal), sourceIp),
    );
    this.metrics.operations.inc({ category: row.category, operation: 'report', result: 'ok' });
    return JSON.parse(
      JSON.stringify({ ...report, messages, sections }, (_k, v: unknown) =>
        typeof v === 'bigint' ? v.toString() : v,
      ),
    ) as IncidentReportView;
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
        try {
          return await work(tx);
        } catch (error) {
          for (const def of this.stores.definitions) def.mapError?.(error);
          return mapIncidentError(error, (id) => this.reads.publicIdOf(scope, id, tx));
        }
      },
      { timeoutMs: TX_TIMEOUT_MS, isolationLevel: ATO_TRANSACTION_ISOLATION },
    );
  }

  /** The incident of a mutation: manageable category (else 404), feature on (else its 403). */
  private async manageable(
    principal: Principal,
    scope: TenantScope,
    id: string,
    tx: Db,
  ): Promise<IncidentListRow> {
    const categories = this.stores.registry.categoriesManageableBy(principal.permissions);
    const row = await this.reads.get(scope, id, categories, tx);
    if (row === null) throw incidentNotFound();
    const def = this.stores.definition(row.category);
    if (!def) throw incidentNotFound();
    if (!(await this.enabledFor(scope, def, tx))) throw def.notEnabled();
    return row;
  }

  /** `POST /incidents` (I2): a manual incident for a subject of a registered category. */
  create(
    principal: Principal,
    scope: TenantScope,
    idempotencyKey: unknown,
    body: CreateIncidentBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<IncidentDetailView>> {
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      INCIDENT_OPERATIONS.create,
      '-',
      body,
      async (tx) => {
        const handler = this.stores.registry.find(body.category);
        const def = this.stores.definition(body.category);
        if (!handler || !def || !handler.subjectTypes.includes(body.subject.type as never)) {
          throw incidentCategoryUnsupported();
        }
        if (!this.canManage(principal, body.category)) {
          throw new CodedHttpException(
            HttpStatus.FORBIDDEN,
            'forbidden',
            'Missing permission for this incident category',
          );
        }
        if (!(await this.enabledFor(scope, def, tx))) throw def.notEnabled();
        const subject = await handler.resolveSubject(tx, scope.organizationId, {
          type: body.subject.type,
          publicId: body.subject.id.toLowerCase(),
        });
        if (subject === null) throw incidentSubjectNotFound();
        const incident = await def.openManual(
          { ato: this.stores.ato, incidents: this.stores.incidents },
          tx,
          {
            organizationId: scope.organizationId,
            subjectType: body.subject.type,
            subject,
            severity: body.severity ?? 'medium',
            note: body.reason,
            actor: this.actorOf(principal),
            sourceIp,
          },
        );
        this.metrics.operations.inc({ category: body.category, operation: 'create', result: 'ok' });
        const row = await this.reads.get(scope, incident.publicId, [body.category], tx);
        if (row === null) throw incidentNotFound();
        return { statusCode: 201, body: await this.detailView(principal, scope, row, tx) };
      },
    );
  }

  /** `PATCH /incidents/{id}` (I4): severity, assignment, status (with feedback), note. */
  update(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: UpdateIncidentBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<IncidentDetailView>> {
    const id = parseIncidentId(rawId);
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      INCIDENT_OPERATIONS.update,
      id,
      body,
      async (tx) => {
        const row = await this.manageable(principal, scope, id, tx);
        const store = this.stores.incidents;
        const locked = await store.lockForUpdate(tx, scope.organizationId, row.id);
        if (locked === null) throw incidentNotFound();
        if (locked.rowVersion !== body.expectedRowVersion)
          throw incidentConflict(locked.rowVersion);
        const actor = this.actorOf(principal);
        const base = { organizationId: scope.organizationId, incidentId: row.id, actor, sourceIp };
        if (body.categoryFeedback !== undefined && body.status !== 'false_positive') {
          throw incidentFeedbackInvalid();
        }
        if (body.resolution !== undefined && body.status === undefined) {
          throw incidentFeedbackInvalid();
        }
        if (body.severity !== undefined) {
          await store.setSeverity(tx, { ...base, severity: body.severity });
        }
        if (body.assigneeId !== undefined) {
          let assigneeUserId: bigint | null = null;
          if (body.assigneeId !== null) {
            assigneeUserId = await this.reads.activeUserId(
              scope,
              body.assigneeId.toLowerCase(),
              tx,
            );
            if (assigneeUserId === null) {
              throw incidentAssigneeInvalid();
            }
          }
          await store.assign(tx, { ...base, assigneeUserId });
        }
        let noteUsed = false;
        if (body.status !== undefined && body.status !== locked.status) {
          const note = body.resolution?.note ?? body.note ?? null;
          noteUsed = body.resolution === undefined && body.note !== undefined;
          await store.transition(tx, {
            ...base,
            to: body.status,
            resolutionCode: body.resolution?.code ?? null,
            note,
            feedback: body.categoryFeedback,
          });
        }
        if (body.note !== undefined && !noteUsed) {
          await store.addNote(tx, { ...base, note: body.note });
        }
        this.metrics.operations.inc({ category: row.category, operation: 'update', result: 'ok' });
        const after = await this.reads.get(scope, id, [row.category], tx);
        if (after === null) throw incidentNotFound();
        return { statusCode: 200, body: await this.detailView(principal, scope, after, tx) };
      },
    );
  }

  /** `POST /incidents/{id}/notes` (I5): `201` with the timeline entry. */
  addNote(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: AddNoteBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<TimelineEntryView>> {
    const id = parseIncidentId(rawId);
    return this.keyed(
      principal,
      scope,
      idempotencyKey,
      INCIDENT_OPERATIONS.addNote,
      id,
      body,
      async (tx) => {
        const row = await this.manageable(principal, scope, id, tx);
        const event = await this.stores.incidents.addNote(tx, {
          organizationId: scope.organizationId,
          incidentId: row.id,
          actor: this.actorOf(principal),
          note: body.note,
          sourceIp,
        });
        this.metrics.operations.inc({ category: row.category, operation: 'note', result: 'ok' });
        return { statusCode: 201, body: this.timelineView(event) };
      },
    );
  }
}

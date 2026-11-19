/**
 * `IncidentStore` (D24, ADR-0075): the only writer of `security_incidents`,
 * `security_incident_events` and `security_incident_links`. Every method takes the caller's
 * Prisma transaction client first and never opens or retries a transaction itself: the caller's
 * transaction makes the incident row, its timeline entry, its outbox event and its audit row one
 * atomic change. State changes run under the row lock (`SELECT … FOR UPDATE`) with a row-version
 * compare-and-set.
 */
import { Prisma } from '@email-gateway/database';
import { EventTypes } from '@email-gateway/event-contracts';
import {
  isActiveSecurityIncidentStatus,
  SECURITY_INCIDENT_CATEGORIES,
  SECURITY_INCIDENT_LINK_TYPES,
  SECURITY_INCIDENT_ORIGINS,
  SECURITY_INCIDENT_SEVERITIES,
  securityIncidentSeverityRank,
  type SecurityIncidentCategory,
  type SecurityIncidentLinkType,
  type SecurityIncidentOrigin,
  type SecurityIncidentResolutionCode,
  type SecurityIncidentSeverity,
  type SecurityIncidentStatus,
  type SecurityIncidentSubjectType,
} from '@email-gateway/security-contracts';
import { writeAuditRow, type LibraryAuditEntry } from './audit';
import { IncidentActiveConflictError, IncidentError, IncidentVersionConflictError } from './errors';
import { insertRegisteredOutboxRow } from './outbox';
import type { IncidentCategoryRegistry, IncidentTx } from './registry';
import type { IncidentEventRow, IncidentRow } from './rows';
import {
  checkTransition,
  isTerminalIncidentStatus,
  isValidFreeNote,
  normalizeNote,
} from './transitions';
import {
  INCIDENT_AUDIT_RESOURCE_TYPE,
  INCIDENT_EVENT_TYPE_MAX_LENGTH,
  INCIDENT_EVENT_TYPE_PATTERN,
  INCIDENT_EVIDENCE_EVENT_THROTTLE_MS,
  INCIDENT_LINK_CAPS,
  INCIDENT_MAX_REASON_CODES,
  INCIDENT_REASON_CODE_PATTERN,
  type IncidentActor,
  type IncidentAuditAction,
  type IncidentChangedField,
} from './vocabulary';

export interface IncidentStoreOptions {
  registry: IncidentCategoryRegistry;
  /** Injected clock (tests); default `new Date()`. */
  now?: () => Date;
}

export interface OpenIncidentInput {
  organizationId: bigint;
  category: SecurityIncidentCategory;
  subject: {
    type: SecurityIncidentSubjectType;
    refId: bigint;
    refTime: Date | null;
    publicId: string;
  };
  origin: SecurityIncidentOrigin;
  severity: SecurityIncidentSeverity;
  titleCode: string | null;
  reasonCodes: readonly string[];
  detectorVersion: string | null;
  detectedAt: Date;
  actor: IncidentActor;
  /** Optional opening note (manual incidents), 1–4000 characters. */
  note?: string | null;
  /** Extra details of the `created` timeline entry (bounded, no content). */
  details?: Record<string, unknown>;
  /** Source IP of the request (api) for the audit row. */
  sourceIp?: string | null;
}

export interface TransitionInput {
  organizationId: bigint;
  incidentId: bigint;
  to: SecurityIncidentStatus;
  actor: IncidentActor;
  resolutionCode?: SecurityIncidentResolutionCode | null;
  note?: string | null;
  /** The category's `categoryFeedback` (validated with the handler's schema). */
  feedback?: unknown;
  /** Compare-and-set against the version the caller read (optional). */
  expectedRowVersion?: number;
  sourceIp?: string | null;
}

export interface IncidentLinkInput {
  type: SecurityIncidentLinkType;
  refId: bigint;
  refTime: Date;
}

export interface LinkResult {
  /** Links inserted per type (new rows only). */
  linked: Record<SecurityIncidentLinkType, number>;
  /** Links not stored because the per-type cap was reached (count only). */
  overflow: Record<SecurityIncidentLinkType, number>;
}

export interface UpdateEventInput {
  previousStatus: SecurityIncidentStatus;
  previousSeverity: SecurityIncidentSeverity;
  changedFields: readonly IncidentChangedField[];
  actorType: IncidentActor['type'];
}

export interface IncidentListFilter {
  /** Categories the caller may read (empty = nothing). */
  categories: readonly SecurityIncidentCategory[];
  statuses?: readonly SecurityIncidentStatus[];
  /** Keyset: incidents with an id lower than this. */
  beforeId?: bigint;
  limit?: number;
}

const emptyCounts = (): Record<SecurityIncidentLinkType, number> =>
  Object.fromEntries(SECURITY_INCIDENT_LINK_TYPES.map((t) => [t, 0])) as Record<
    SecurityIncidentLinkType,
    number
  >;

const isUniqueViolation = (error: unknown): boolean =>
  error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';

export class IncidentStore {
  readonly registry: IncidentCategoryRegistry;
  private readonly clock: () => Date;

  constructor(options: IncidentStoreOptions) {
    this.registry = options.registry;
    this.clock = options.now ?? (() => new Date());
  }

  now(): Date {
    return this.clock();
  }

  // ---------------------------------------------------------------- open

  /**
   * Opens an incident: the row, the `created` timeline entry, `security.incident.created.v1` and
   * the `security_incident.created` audit row. One active incident per (organization, category,
   * subject): a second one throws `IncidentActiveConflictError` with the active incident's id.
   */
  async open(tx: IncidentTx, input: OpenIncidentInput): Promise<IncidentRow> {
    const handler = this.registry.find(input.category);
    if (!handler || !(SECURITY_INCIDENT_CATEGORIES as readonly string[]).includes(input.category)) {
      throw new IncidentError('incident_category_unknown', 'Unknown incident category');
    }
    if (!handler.subjectTypes.includes(input.subject.type)) {
      throw new IncidentError('incident_subject_invalid', 'Subject type not allowed for category');
    }
    if (!(SECURITY_INCIDENT_ORIGINS as readonly string[]).includes(input.origin)) {
      throw new IncidentError('incident_input_invalid', 'Unknown origin');
    }
    if (!(SECURITY_INCIDENT_SEVERITIES as readonly string[]).includes(input.severity)) {
      throw new IncidentError('incident_input_invalid', 'Unknown severity');
    }
    const reasonCodes = [...new Set(input.reasonCodes)];
    if (
      reasonCodes.length > INCIDENT_MAX_REASON_CODES ||
      reasonCodes.some((c) => c.length > 64 || !INCIDENT_REASON_CODE_PATTERN.test(c)) ||
      (input.titleCode !== null &&
        (input.titleCode.length > 64 || !INCIDENT_REASON_CODE_PATTERN.test(input.titleCode)))
    ) {
      throw new IncidentError('incident_input_invalid', 'Malformed reason or title code');
    }
    const note = normalizeNote(input.note);
    if (note !== null && !isValidFreeNote(note)) {
      throw new IncidentError('incident_note_invalid', 'Note must be 1-4000 characters');
    }

    const existing = await this.findActiveForSubject(tx, input);
    if (existing) throw new IncidentActiveConflictError(existing.id);

    let row: IncidentRow;
    try {
      row = await tx.securityIncident.create({
        data: {
          organizationId: input.organizationId,
          category: input.category,
          subjectType: input.subject.type,
          subjectRefId: input.subject.refId,
          subjectRefTime: input.subject.refTime,
          subjectPublicId: input.subject.publicId,
          origin: input.origin,
          status: 'open',
          severity: input.severity,
          titleCode: input.titleCode,
          reasonCodes,
          detectorVersion: input.detectorVersion,
          detectedAt: input.detectedAt,
          createdByType: input.actor.type,
          createdById: input.actor.id,
        },
      });
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const active = await this.findActiveForSubject(tx, input);
      throw new IncidentActiveConflictError(active?.id ?? null);
    }
    await this.insertEvent(tx, row, {
      eventType: 'created',
      actor: input.actor,
      toStatus: 'open',
      toSeverity: row.severity,
      note,
      details: {
        origin: row.origin,
        reasonCodes,
        ...(input.details ?? {}),
      },
    });
    await this.emitCreated(tx, row);
    await this.audit(
      tx,
      row,
      'security_incident.created',
      input.actor,
      {
        category: row.category,
        origin: row.origin,
        severity: row.severity,
        subjectType: row.subjectType,
        subjectPublicId: row.subjectPublicId,
      },
      input.sourceIp,
    );
    return row;
  }

  private async findActiveForSubject(
    tx: IncidentTx,
    input: Pick<OpenIncidentInput, 'organizationId' | 'category' | 'subject'>,
  ): Promise<IncidentRow | null> {
    return tx.securityIncident.findFirst({
      where: {
        organizationId: input.organizationId,
        category: input.category,
        subjectType: input.subject.type,
        subjectRefId: input.subject.refId,
        activeMarker: 1,
      },
    });
  }

  /** The active incident of a subject in a category (null when none). */
  findActive(
    tx: IncidentTx,
    organizationId: bigint,
    category: SecurityIncidentCategory,
    subject: { type: SecurityIncidentSubjectType; refId: bigint },
  ): Promise<IncidentRow | null> {
    return this.findActiveForSubject(tx, {
      organizationId,
      category,
      subject: { ...subject, refTime: null, publicId: '' },
    });
  }

  // ---------------------------------------------------------------- reads

  /**
   * Locks the incident row of the organization (`FOR UPDATE`); null for none or another tenant.
   * The category's subject rows are locked first (`lockSubject`: lock order subject → incident,
   * the order of the ATO detect role), so an api mutation never deadlocks with a detection.
   */
  async lockForUpdate(
    tx: IncidentTx,
    organizationId: bigint,
    incidentId: bigint,
  ): Promise<IncidentRow | null> {
    const current = await tx.securityIncident.findUnique({ where: { id: incidentId } });
    if (!current || current.organizationId !== organizationId) return null;
    const handler = this.registry.find(current.category);
    if (handler?.lockSubject) await handler.lockSubject(tx, current);
    const rows = await tx.$queryRaw<{ id: bigint }[]>`
      SELECT id FROM security_incidents
      WHERE id = ${incidentId} AND organization_id = ${organizationId}
      FOR UPDATE`;
    if (rows.length === 0) return null;
    const row = await tx.securityIncident.findUnique({ where: { id: incidentId } });
    if (!row || row.organizationId !== organizationId) return null;
    return row;
  }

  /**
   * An incident by public id, visible only when its category is among `categories` (the
   * categories the caller may read): another tenant's or another category's incident is `null`,
   * exactly like a missing one (D17).
   */
  async findByPublicId(
    tx: IncidentTx,
    organizationId: bigint,
    publicId: string,
    categories: readonly SecurityIncidentCategory[],
  ): Promise<IncidentRow | null> {
    if (categories.length === 0) return null;
    const row = await tx.securityIncident.findUnique({ where: { publicId } });
    if (!row || row.organizationId !== organizationId) return null;
    return categories.includes(row.category) ? row : null;
  }

  /** Incidents of the organization in the readable categories, newest id first (keyset). */
  async list(
    tx: IncidentTx,
    organizationId: bigint,
    filter: IncidentListFilter,
  ): Promise<IncidentRow[]> {
    // Only categories the schema knows can match a row (a registered category that a later
    // migration has not appended yet matches nothing, never an error).
    const categories = filter.categories.filter((c) =>
      (SECURITY_INCIDENT_CATEGORIES as readonly string[]).includes(c),
    );
    if (categories.length === 0) return [];
    const limit = Math.min(Math.max(filter.limit ?? 25, 1), 100);
    return tx.securityIncident.findMany({
      where: {
        organizationId,
        category: { in: categories },
        ...(filter.statuses && { status: { in: [...filter.statuses] } }),
        ...(filter.beforeId !== undefined && { id: { lt: filter.beforeId } }),
      },
      orderBy: { id: 'desc' },
      take: limit,
    });
  }

  /** Timeline entries in order (`created_at`, `id`), keyset after `afterId`. */
  timeline(
    tx: IncidentTx,
    organizationId: bigint,
    incidentId: bigint,
    options: { afterId?: bigint; limit?: number } = {},
  ): Promise<IncidentEventRow[]> {
    const limit = Math.min(Math.max(options.limit ?? 100, 1), 1000);
    return tx.securityIncidentEvent.findMany({
      where: {
        organizationId,
        incidentId,
        ...(options.afterId !== undefined && { id: { gt: options.afterId } }),
      },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take: limit,
    });
  }

  private async requireLocked(
    tx: IncidentTx,
    organizationId: bigint,
    incidentId: bigint,
    expectedRowVersion?: number,
  ): Promise<IncidentRow> {
    const row = await this.lockForUpdate(tx, organizationId, incidentId);
    if (!row) throw new IncidentError('incident_not_found', 'Incident not found');
    if (expectedRowVersion !== undefined && row.rowVersion !== expectedRowVersion) {
      throw new IncidentVersionConflictError(expectedRowVersion, row.rowVersion);
    }
    return row;
  }

  /** Compare-and-set update of a locked row; returns the updated row. */
  private async casUpdate(
    tx: IncidentTx,
    row: IncidentRow,
    data: Prisma.SecurityIncidentUncheckedUpdateManyInput,
  ): Promise<IncidentRow> {
    const result = await tx.securityIncident.updateMany({
      where: { id: row.id, organizationId: row.organizationId, rowVersion: row.rowVersion },
      data: { ...data, rowVersion: { increment: 1 } },
    });
    if (result.count !== 1) {
      const current = await tx.securityIncident.findUnique({
        where: { id: row.id },
        select: { rowVersion: true },
      });
      throw new IncidentVersionConflictError(row.rowVersion, current?.rowVersion ?? -1);
    }
    return tx.securityIncident.findUniqueOrThrow({ where: { id: row.id } });
  }

  // ---------------------------------------------------------------- transitions

  /**
   * Applies a state transition under the row lock (D12): the edge, resolution code and note are
   * checked, the category feedback validated, the row updated by compare-and-set, the timeline
   * entry written, the category hook run (same transaction), `security.incident.updated.v1`
   * emitted and the audit row written.
   */
  async transition(tx: IncidentTx, input: TransitionInput): Promise<IncidentRow> {
    const row = await this.requireLocked(
      tx,
      input.organizationId,
      input.incidentId,
      input.expectedRowVersion,
    );
    const handler = this.registry.find(row.category);
    if (!handler) throw new IncidentError('incident_category_unknown', 'Unknown incident category');
    const refusal = checkTransition(row.status, input.to, input);
    if (refusal !== null) {
      const code =
        refusal === 'transition_not_allowed'
          ? 'incident_transition_not_allowed'
          : refusal === 'resolution_required'
            ? 'incident_resolution_required'
            : refusal === 'resolution_invalid'
              ? 'incident_resolution_invalid'
              : refusal === 'note_required'
                ? 'incident_note_required'
                : 'incident_note_invalid';
      throw new IncidentError(code, `Transition ${row.status} -> ${input.to} refused: ${refusal}`, {
        from: row.status,
        to: input.to,
      });
    }
    let feedback: unknown = undefined;
    if (input.feedback !== undefined && input.feedback !== null) {
      if (!handler.feedbackSchema) {
        throw new IncidentError('incident_feedback_invalid', 'This category accepts no feedback');
      }
      const parsed = handler.feedbackSchema.safeParse(input.feedback);
      if (!parsed.success) {
        throw new IncidentError('incident_feedback_invalid', 'Malformed category feedback');
      }
      feedback = parsed.data;
    }
    const at = this.clock();
    const note = normalizeNote(input.note);
    const terminal = isTerminalIncidentStatus(input.to);
    const data: Prisma.SecurityIncidentUncheckedUpdateManyInput = { status: input.to };
    if (input.to === 'confirmed' && row.confirmedAt === null) data.confirmedAt = at;
    if (input.to === 'mitigated') data.mitigatedAt = at;
    if (terminal) {
      data.resolvedAt = at;
      data.resolvedByUserId = input.actor.type === 'user' ? (input.actor.userId ?? null) : null;
      data.resolutionCode = input.resolutionCode ?? null;
      data.resolutionNote = note;
    }
    const updated = await this.casUpdate(tx, row, data);
    await this.insertEvent(tx, updated, {
      eventType: 'status_changed',
      actor: input.actor,
      fromStatus: row.status,
      toStatus: input.to,
      note,
      details: terminal ? { resolutionCode: input.resolutionCode ?? null } : null,
    });
    if (handler.onTransition) {
      await handler.onTransition(tx, updated, row.status, input.to, input.actor, feedback);
    }
    const changed: IncidentChangedField[] = terminal ? ['status', 'resolution'] : ['status'];
    const emitted = await this.emitUpdated(tx, updated, {
      previousStatus: row.status,
      previousSeverity: row.severity,
      changedFields: changed,
      actorType: input.actor.type,
    });
    await this.audit(
      tx,
      emitted,
      'security_incident.status_changed',
      input.actor,
      {
        category: row.category,
        from: row.status,
        to: input.to,
        resolutionCode: input.resolutionCode ?? null,
        noteLength: note === null ? 0 : [...note].length,
        feedback: feedback === undefined ? false : true,
      },
      input.sourceIp,
    );
    return emitted;
  }

  // ---------------------------------------------------------------- assignment and severity

  /**
   * Assigns the incident to a user of the same organization (active, not deleted) or clears the
   * assignment (`assigneeUserId` null). Refused on a terminal incident.
   */
  async assign(
    tx: IncidentTx,
    input: {
      organizationId: bigint;
      incidentId: bigint;
      assigneeUserId: bigint | null;
      actor: IncidentActor;
      expectedRowVersion?: number;
      sourceIp?: string | null;
    },
  ): Promise<IncidentRow> {
    const row = await this.requireLocked(
      tx,
      input.organizationId,
      input.incidentId,
      input.expectedRowVersion,
    );
    if (isTerminalIncidentStatus(row.status)) {
      throw new IncidentError('incident_closed', 'The incident is closed');
    }
    let assigneePublicId: string | null = null;
    if (input.assigneeUserId !== null) {
      const user = await tx.user.findFirst({
        where: {
          id: input.assigneeUserId,
          organizationId: input.organizationId,
          deletedAt: null,
          status: 'active',
        },
        select: { publicId: true },
      });
      if (!user) throw new IncidentError('incident_assignee_invalid', 'Unknown assignee');
      assigneePublicId = user.publicId;
    }
    if (row.assignedUserId === input.assigneeUserId) return row;
    const at = this.clock();
    const updated = await this.casUpdate(tx, row, {
      assignedUserId: input.assigneeUserId,
      assignedAt: input.assigneeUserId === null ? null : at,
    });
    await this.insertEvent(tx, updated, {
      eventType: 'assigned',
      actor: input.actor,
      details: { assigneePublicId },
    });
    const emitted = await this.emitUpdated(tx, updated, {
      previousStatus: row.status,
      previousSeverity: row.severity,
      changedFields: ['assignee'],
      actorType: input.actor.type,
    });
    await this.audit(
      tx,
      emitted,
      'security_incident.assigned',
      input.actor,
      { assigneePublicId },
      input.sourceIp,
    );
    return emitted;
  }

  /**
   * Sets the severity. A **system** actor only raises it (automatic escalation never
   * de-escalates, D12): a lower or equal severity is a no-op. Users may lower it. Refused on a
   * terminal incident.
   */
  async setSeverity(
    tx: IncidentTx,
    input: {
      organizationId: bigint;
      incidentId: bigint;
      severity: SecurityIncidentSeverity;
      actor: IncidentActor;
      reason?: string | null;
      expectedRowVersion?: number;
      sourceIp?: string | null;
      /** Already locked row (callers that hold the lock). */
      locked?: IncidentRow;
    },
  ): Promise<IncidentRow> {
    const row =
      input.locked ??
      (await this.requireLocked(
        tx,
        input.organizationId,
        input.incidentId,
        input.expectedRowVersion,
      ));
    if (isTerminalIncidentStatus(row.status)) {
      throw new IncidentError('incident_closed', 'The incident is closed');
    }
    const current = securityIncidentSeverityRank(row.severity);
    const next = securityIncidentSeverityRank(input.severity);
    if (next === current || (input.actor.type === 'system' && next < current)) return row;
    const updated = await this.casUpdate(tx, row, { severity: input.severity });
    await this.insertEvent(tx, updated, {
      eventType: 'severity_changed',
      actor: input.actor,
      fromSeverity: row.severity,
      toSeverity: input.severity,
      note: normalizeNote(input.reason),
    });
    const emitted = await this.emitUpdated(tx, updated, {
      previousStatus: row.status,
      previousSeverity: row.severity,
      changedFields: ['severity'],
      actorType: input.actor.type,
    });
    await this.audit(
      tx,
      emitted,
      'security_incident.severity_changed',
      input.actor,
      { from: row.severity, to: input.severity },
      input.sourceIp,
    );
    return emitted;
  }

  /**
   * Escalates: severity at least `minSeverity` (default `high`), `escalated_at` set and an
   * `escalated` timeline entry (D13 `escalate_investigation`). Refused on a terminal incident.
   */
  async escalate(
    tx: IncidentTx,
    input: {
      organizationId: bigint;
      incidentId: bigint;
      actor: IncidentActor;
      minSeverity?: SecurityIncidentSeverity;
      reason?: string | null;
      sourceIp?: string | null;
    },
  ): Promise<IncidentRow> {
    const row = await this.requireLocked(tx, input.organizationId, input.incidentId);
    if (isTerminalIncidentStatus(row.status)) {
      throw new IncidentError('incident_closed', 'The incident is closed');
    }
    const min = input.minSeverity ?? 'high';
    const raised =
      securityIncidentSeverityRank(min) > securityIncidentSeverityRank(row.severity)
        ? min
        : row.severity;
    const at = this.clock();
    const updated = await this.casUpdate(tx, row, {
      escalatedAt: at,
      ...(raised !== row.severity && { severity: raised }),
    });
    await this.insertEvent(tx, updated, {
      eventType: 'escalated',
      actor: input.actor,
      fromSeverity: row.severity,
      toSeverity: raised,
      note: normalizeNote(input.reason),
    });
    if (raised === row.severity) return updated;
    const emitted = await this.emitUpdated(tx, updated, {
      previousStatus: row.status,
      previousSeverity: row.severity,
      changedFields: ['severity'],
      actorType: input.actor.type,
    });
    await this.audit(
      tx,
      emitted,
      'security_incident.severity_changed',
      input.actor,
      { from: row.severity, to: raised, escalated: true },
      input.sourceIp,
    );
    return emitted;
  }

  // ---------------------------------------------------------------- notes, links, events

  /** Adds an investigation note (1–4000 characters) to the timeline; audited (length only). */
  async addNote(
    tx: IncidentTx,
    input: {
      organizationId: bigint;
      incidentId: bigint;
      actor: IncidentActor;
      note: string;
      sourceIp?: string | null;
    },
  ): Promise<IncidentEventRow> {
    const note = normalizeNote(input.note);
    if (note === null || !isValidFreeNote(note)) {
      throw new IncidentError('incident_note_invalid', 'Note must be 1-4000 characters');
    }
    const row = await this.requireLocked(tx, input.organizationId, input.incidentId);
    const event = await this.insertEvent(tx, row, {
      eventType: 'note_added',
      actor: input.actor,
      note,
    });
    await this.audit(
      tx,
      row,
      'security_incident.note_added',
      input.actor,
      { noteLength: [...note].length },
      input.sourceIp,
    );
    return event;
  }

  /**
   * Links evidence (D12): per-type caps (`ato_signal` 2 000, `ato_auth_event` 1 000, `message`
   * 500); links beyond a cap are counted, not stored; duplicates are ignored. Updates
   * `evidence_count` (stored links) and the first/last evidence times.
   */
  async link(
    tx: IncidentTx,
    input: { organizationId: bigint; incidentId: bigint; links: readonly IncidentLinkInput[] },
  ): Promise<LinkResult> {
    const result: LinkResult = { linked: emptyCounts(), overflow: emptyCounts() };
    if (input.links.length === 0) return result;
    const byType = new Map<SecurityIncidentLinkType, IncidentLinkInput[]>();
    for (const link of input.links) {
      if (!(SECURITY_INCIDENT_LINK_TYPES as readonly string[]).includes(link.type)) {
        throw new IncidentError('incident_input_invalid', 'Unknown link type');
      }
      const key = `${link.refId.toString()}|${link.refTime.getTime()}`;
      const list = byType.get(link.type) ?? [];
      if (!list.some((l) => `${l.refId.toString()}|${l.refTime.getTime()}` === key))
        list.push(link);
      byType.set(link.type, list);
    }
    let minTime: Date | null = null;
    let maxTime: Date | null = null;
    let inserted = 0;
    for (const [type, links] of byType) {
      const existing = await tx.securityIncidentLink.count({
        where: { incidentId: input.incidentId, linkType: type },
      });
      const room = Math.max(0, INCIDENT_LINK_CAPS[type] - existing);
      const take = links.slice(0, room);
      result.overflow[type] += links.length - take.length;
      if (take.length > 0) {
        const created = await tx.securityIncidentLink.createMany({
          data: take.map((l) => ({
            organizationId: input.organizationId,
            incidentId: input.incidentId,
            linkType: type,
            refId: l.refId,
            refTime: l.refTime,
          })),
          skipDuplicates: true,
        });
        result.linked[type] += created.count;
        inserted += created.count;
      }
      for (const l of links) {
        if (minTime === null || l.refTime < minTime) minTime = l.refTime;
        if (maxTime === null || l.refTime > maxTime) maxTime = l.refTime;
      }
    }
    if (minTime !== null && maxTime !== null) {
      await tx.$executeRaw`
        UPDATE security_incidents
        SET evidence_count = evidence_count + ${inserted},
            first_evidence_at = IF(first_evidence_at IS NULL OR first_evidence_at > ${minTime},
                                   ${minTime}, first_evidence_at),
            last_evidence_at = IF(last_evidence_at IS NULL OR last_evidence_at < ${maxTime},
                                  ${maxTime}, last_evidence_at)
        WHERE id = ${input.incidentId} AND organization_id = ${input.organizationId}`;
    }
    return result;
  }

  /**
   * Writes a timeline entry (generic or category-prefixed type such as `ato.response_requested`).
   * The incident must belong to the organization.
   */
  async recordEvent(
    tx: IncidentTx,
    input: {
      organizationId: bigint;
      incidentId: bigint;
      eventType: string;
      actor: IncidentActor;
      note?: string | null;
      details?: Record<string, unknown> | null;
      fromStatus?: SecurityIncidentStatus | null;
      toStatus?: SecurityIncidentStatus | null;
      fromSeverity?: SecurityIncidentSeverity | null;
      toSeverity?: SecurityIncidentSeverity | null;
    },
  ): Promise<IncidentEventRow> {
    if (
      input.eventType.length > INCIDENT_EVENT_TYPE_MAX_LENGTH ||
      !INCIDENT_EVENT_TYPE_PATTERN.test(input.eventType)
    ) {
      throw new IncidentError('incident_input_invalid', 'Malformed event type');
    }
    const row = await tx.securityIncident.findFirst({
      where: { id: input.incidentId, organizationId: input.organizationId },
    });
    if (!row) throw new IncidentError('incident_not_found', 'Incident not found');
    return this.insertEvent(tx, row, input);
  }

  private async insertEvent(
    tx: IncidentTx,
    row: IncidentRow,
    input: {
      eventType: string;
      actor: IncidentActor;
      note?: string | null;
      details?: Record<string, unknown> | null;
      fromStatus?: SecurityIncidentStatus | null;
      toStatus?: SecurityIncidentStatus | null;
      fromSeverity?: SecurityIncidentSeverity | null;
      toSeverity?: SecurityIncidentSeverity | null;
    },
  ): Promise<IncidentEventRow> {
    return tx.securityIncidentEvent.create({
      data: {
        organizationId: row.organizationId,
        incidentId: row.id,
        eventType: input.eventType,
        actorType: input.actor.type,
        actorId: input.actor.id,
        fromStatus: input.fromStatus ?? null,
        toStatus: input.toStatus ?? null,
        fromSeverity: input.fromSeverity ?? null,
        toSeverity: input.toSeverity ?? null,
        note: input.note ?? null,
        details:
          input.details === null || input.details === undefined
            ? Prisma.DbNull
            : (JSON.parse(JSON.stringify(input.details, jsonReplacer)) as Prisma.InputJsonValue),
        createdAt: this.clock(),
      },
    });
  }

  // ---------------------------------------------------------------- events and audit

  /** `security.incident.created.v1` (registry-validated outbox insert). */
  async emitCreated(tx: IncidentTx, row: IncidentRow): Promise<string> {
    return insertRegisteredOutboxRow(tx, {
      organizationId: row.organizationId,
      eventType: EventTypes.SecurityIncidentCreated,
      aggregateId: row.id.toString(),
      at: this.clock(),
      payload: {
        incidentId: row.id.toString(),
        incidentPublicId: row.publicId,
        category: row.category,
        subject: { type: row.subjectType, publicId: row.subjectPublicId },
        origin: row.origin,
        severity: row.severity,
        status: 'open',
        detectedAt: row.detectedAt.toISOString(),
        reasonCodes: Array.isArray(row.reasonCodes) ? row.reasonCodes : [],
      },
    });
  }

  /**
   * `security.incident.updated.v1`. Status, severity, assignee and resolution changes are always
   * emitted; an update whose only changed field is `evidence` is emitted at most once per
   * 15 minutes per incident (`last_update_event_at`). Returns the row (with the new
   * `last_update_event_at` when emitted).
   */
  async emitUpdated(
    tx: IncidentTx,
    row: IncidentRow,
    update: UpdateEventInput,
  ): Promise<IncidentRow> {
    const at = this.clock();
    const evidenceOnly = update.changedFields.every((f) => f === 'evidence');
    if (
      evidenceOnly &&
      row.lastUpdateEventAt !== null &&
      at.getTime() - row.lastUpdateEventAt.getTime() < INCIDENT_EVIDENCE_EVENT_THROTTLE_MS
    ) {
      return row;
    }
    await insertRegisteredOutboxRow(tx, {
      organizationId: row.organizationId,
      eventType: EventTypes.SecurityIncidentUpdated,
      aggregateId: row.id.toString(),
      at,
      payload: {
        incidentId: row.id.toString(),
        incidentPublicId: row.publicId,
        category: row.category,
        subject: { type: row.subjectType, publicId: row.subjectPublicId },
        status: row.status,
        previousStatus: update.previousStatus,
        severity: row.severity,
        previousSeverity: update.previousSeverity,
        assigned: row.assignedUserId !== null,
        changedFields: [...new Set(update.changedFields)],
        actorType: update.actorType,
        updatedAt: at.toISOString(),
      },
    });
    await tx.securityIncident.update({
      where: { id: row.id },
      data: { lastUpdateEventAt: at },
      select: { id: true },
    });
    return { ...row, lastUpdateEventAt: at };
  }

  /**
   * Records an evidence addition: one `evidence_linked` timeline entry (≤ 10 codes) and the
   * throttled `security.incident.updated.v1` with `evidence`.
   */
  async recordEvidence(
    tx: IncidentTx,
    row: IncidentRow,
    input: { codes: readonly string[]; counts: Record<string, number> },
  ): Promise<IncidentRow> {
    await this.insertEvent(tx, row, {
      eventType: 'evidence_linked',
      actor: { type: 'system', id: null },
      details: { codes: [...new Set(input.codes)].slice(0, 10), counts: input.counts },
    });
    return this.emitUpdated(tx, row, {
      previousStatus: row.status,
      previousSeverity: row.severity,
      changedFields: ['evidence'],
      actorType: 'system',
    });
  }

  /** Records an exported report: `report_exported` timeline entry and the audit row. */
  async recordReportExport(
    tx: IncidentTx,
    row: IncidentRow,
    actor: IncidentActor,
    sourceIp?: string | null,
  ): Promise<void> {
    await this.insertEvent(tx, row, { eventType: 'report_exported', actor });
    await this.audit(tx, row, 'security_incident.report_exported', actor, {}, sourceIp);
  }

  /**
   * One audit row (resource type `security_incident`, resource id = public id), mirroring
   * `AuditService.record`.
   */
  async audit(
    tx: IncidentTx,
    row: Pick<IncidentRow, 'organizationId' | 'publicId' | 'category'>,
    action: IncidentAuditAction,
    actor: IncidentActor,
    metadata: Record<string, unknown> = {},
    sourceIp?: string | null,
  ): Promise<void> {
    const entry: LibraryAuditEntry = {
      organizationId: row.organizationId,
      actor,
      action,
      resourceType: INCIDENT_AUDIT_RESOURCE_TYPE,
      resourceId: row.publicId,
      sourceIp: sourceIp ?? null,
      metadata: { category: row.category, ...metadata },
    };
    await writeAuditRow(tx, entry);
  }
}

function jsonReplacer(_key: string, value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString(10);
  return value;
}

/** Whether an incident row is active (non-terminal). */
export const isActiveIncident = (row: Pick<IncidentRow, 'status'>): boolean =>
  isActiveSecurityIncidentStatus(row.status);

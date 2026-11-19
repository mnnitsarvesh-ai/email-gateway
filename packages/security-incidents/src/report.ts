/**
 * Generic security incident report (D16 `GET /incidents/{id}/report`): summary, timeline, notes,
 * resolution, evidence counts, related messages (masked sender per ADR-0062; never a subject,
 * recipient or body) and the category's own sections from its handler. JSON only; the portal
 * renders a print view. The api audits the export through `IncidentStore.recordReportExport`.
 */
import type { IncidentCategoryRegistry, IncidentReportSection, IncidentTx } from './registry';
import type { IncidentEventRow, IncidentRow } from './rows';

export const INCIDENT_REPORT_VERSION = 'security-incident-report/1';

export interface IncidentReportMessage {
  messageId: string;
  receivedAt: string;
  direction: string;
  /** Envelope sender masked like ADR-0062 `maskAddress` (first code point + `***@domain`). */
  senderMasked: string | null;
}

export interface IncidentReport {
  version: typeof INCIDENT_REPORT_VERSION;
  generatedAt: string;
  incident: {
    id: string;
    category: string;
    subject: { type: string; id: string };
    origin: string;
    status: string;
    severity: string;
    titleCode: string | null;
    reasonCodes: string[];
    detectorVersion: string | null;
    detectedAt: string;
    firstEvidenceAt: string | null;
    lastEvidenceAt: string | null;
    evidenceCount: number;
    assigned: boolean;
    escalatedAt: string | null;
    confirmedAt: string | null;
    mitigatedAt: string | null;
    resolvedAt: string | null;
  };
  resolution: { code: string | null; note: string | null } | null;
  timeline: Array<{
    at: string;
    type: string;
    actorType: string;
    actorId: string | null;
    fromStatus: string | null;
    toStatus: string | null;
    fromSeverity: string | null;
    toSeverity: string | null;
    details: unknown;
  }>;
  notes: Array<{ at: string; actorType: string; actorId: string | null; note: string }>;
  evidence: Record<string, number>;
  messages: IncidentReportMessage[];
  /** True when the timeline or messages were cut at `maxItems`. */
  truncated: boolean;
  sections: IncidentReportSection[];
}

/**
 * Masks an address like ADR-0062 `maskAddress`: keeps the first Unicode code point of the local
 * part and the domain as stored, splitting at the last `@`. Non-addresses become `***`.
 */
export function maskAddress(address: string): string {
  const at = address.lastIndexOf('@');
  if (at <= 0) return '***';
  const first = [...address.slice(0, at)][0] ?? '';
  return `${first}***@${address.slice(at + 1)}`;
}

const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());

/** Pure assembly of the report from rows already read (unit-testable). */
export function buildIncidentReport(input: {
  incident: IncidentRow;
  events: readonly IncidentEventRow[];
  evidence: Record<string, number>;
  messages: readonly IncidentReportMessage[];
  sections: readonly IncidentReportSection[];
  truncated: boolean;
  generatedAt: Date;
}): IncidentReport {
  const row = input.incident;
  const terminal = row.status === 'false_positive' || row.status === 'resolved';
  return {
    version: INCIDENT_REPORT_VERSION,
    generatedAt: input.generatedAt.toISOString(),
    incident: {
      id: row.publicId,
      category: row.category,
      subject: { type: row.subjectType, id: row.subjectPublicId },
      origin: row.origin,
      status: row.status,
      severity: row.severity,
      titleCode: row.titleCode,
      reasonCodes: Array.isArray(row.reasonCodes) ? (row.reasonCodes as string[]) : [],
      detectorVersion: row.detectorVersion,
      detectedAt: row.detectedAt.toISOString(),
      firstEvidenceAt: iso(row.firstEvidenceAt),
      lastEvidenceAt: iso(row.lastEvidenceAt),
      evidenceCount: row.evidenceCount,
      assigned: row.assignedUserId !== null,
      escalatedAt: iso(row.escalatedAt),
      confirmedAt: iso(row.confirmedAt),
      mitigatedAt: iso(row.mitigatedAt),
      resolvedAt: iso(row.resolvedAt),
    },
    resolution: terminal ? { code: row.resolutionCode, note: row.resolutionNote } : null,
    timeline: input.events.map((e) => ({
      at: e.createdAt.toISOString(),
      type: e.eventType,
      actorType: e.actorType,
      actorId: e.actorId,
      fromStatus: e.fromStatus,
      toStatus: e.toStatus,
      fromSeverity: e.fromSeverity,
      toSeverity: e.toSeverity,
      details: e.details ?? null,
    })),
    notes: input.events
      .filter((e) => e.eventType === 'note_added' && e.note !== null)
      .map((e) => ({
        at: e.createdAt.toISOString(),
        actorType: e.actorType,
        actorId: e.actorId,
        note: e.note as string,
      })),
    evidence: { ...input.evidence },
    messages: [...input.messages],
    truncated: input.truncated,
    sections: [...input.sections],
  };
}

/**
 * Reads and assembles the report of one incident (writer or replica client). `maxItems` bounds the
 * timeline and the related messages (`API_ATO_REPORT_MAX_ITEMS`).
 */
export async function assembleIncidentReport(
  tx: IncidentTx,
  registry: IncidentCategoryRegistry,
  incident: IncidentRow,
  options: { maxItems: number; now: Date },
): Promise<IncidentReport> {
  const maxItems = Math.max(1, Math.min(options.maxItems, 5000));
  const events = await tx.securityIncidentEvent.findMany({
    where: { organizationId: incident.organizationId, incidentId: incident.id },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    take: maxItems + 1,
  });
  const groups = await tx.securityIncidentLink.groupBy({
    by: ['linkType'],
    where: { organizationId: incident.organizationId, incidentId: incident.id },
    _count: { _all: true },
  });
  const evidence: Record<string, number> = {};
  for (const g of groups) evidence[g.linkType] = g._count._all;
  const messageLinks = await tx.securityIncidentLink.findMany({
    where: {
      organizationId: incident.organizationId,
      incidentId: incident.id,
      linkType: 'message',
    },
    orderBy: [{ refTime: 'asc' }, { refId: 'asc' }],
    take: maxItems + 1,
    select: { refId: true, refTime: true },
  });
  const messages: IncidentReportMessage[] = [];
  for (const link of messageLinks.slice(0, maxItems)) {
    const message = await tx.emailMessage.findUnique({
      where: { id_receivedAt: { id: link.refId, receivedAt: link.refTime } },
      select: { organizationId: true, direction: true, envelopeFrom: true },
    });
    if (!message || message.organizationId !== incident.organizationId) continue;
    messages.push({
      messageId: link.refId.toString(),
      receivedAt: link.refTime.toISOString(),
      direction: message.direction,
      senderMasked: message.envelopeFrom ? maskAddress(message.envelopeFrom) : null,
    });
  }
  const handler = registry.find(incident.category);
  const sections = handler ? await handler.reportSections(tx, incident) : [];
  return buildIncidentReport({
    incident,
    events: events.slice(0, maxItems),
    evidence,
    messages,
    sections,
    truncated: events.length > maxItems || messageLinks.length > maxItems,
    generatedAt: options.now,
  });
}

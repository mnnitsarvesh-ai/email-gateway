import { Injectable, Logger } from '@nestjs/common';
import {
  atoRangeFor,
  REPORT_OMIT_REASONS,
  REPORT_RANGES,
  REPORT_SECTIONS,
  type ReportOmitReason,
  type ReportRange,
  type ReportSection,
} from '@email-gateway/assistant';
import type { UserPrincipal } from '../../../../auth-contracts/principal';
import type { TenantScope } from '../../../../auth-contracts/tenant-scope';
import { REPORT_VIEW_DELIVERIES } from '../../assistant.constants';
import { assistantReportNotFound } from '../../assistant.errors';
import type { ReportResultView, ReportView } from '../../dto/assistant.schemas';
import {
  type DeliveryRow,
  ReportDeliveriesRepository,
} from '../../repositories/report-deliveries.repository';
import {
  type ReportObjectRow,
  ReportsRepository,
  type ReportWithRefs,
} from '../../repositories/reports.repository';
import { isReportKeyOf, ReportObjectError, ReportObjectStore } from './report-object-store';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

const SECTION_SET: ReadonlySet<string> = new Set(REPORT_SECTIONS);
const REASON_SET: ReadonlySet<string> = new Set(REPORT_OMIT_REASONS);

/** The stored `sections` JSON → included sections and omissions (unknown values dropped). */
export function sectionsOf(value: unknown): {
  included: ReportSection[];
  omitted: Array<{ section: ReportSection; reason: ReportOmitReason; code: string | null }>;
  atoRange: ReportRange | null;
} {
  const v = isRecord(value) ? value : {};
  const included = (Array.isArray(v.included) ? v.included : []).filter(
    (s): s is ReportSection => typeof s === 'string' && SECTION_SET.has(s),
  );
  const omitted = (Array.isArray(v.omitted) ? v.omitted : []).flatMap((o) =>
    isRecord(o) &&
    typeof o.section === 'string' &&
    SECTION_SET.has(o.section) &&
    typeof o.reason === 'string' &&
    REASON_SET.has(o.reason)
      ? [
          {
            section: o.section as ReportSection,
            reason: o.reason as ReportOmitReason,
            code: typeof o.code === 'string' ? o.code : null,
          },
        ]
      : [],
  );
  const atoRange =
    typeof v.atoRange === 'string' && (REPORT_RANGES as readonly string[]).includes(v.atoRange)
      ? (v.atoRange as ReportRange)
      : null;
  return { included, omitted, atoRange };
}

/** The stored `figures` JSON → `{ label, value }[]` (at most 8). */
export function figuresOf(value: unknown): Array<{ label: string; value: string }> {
  return (Array.isArray(value) ? value : [])
    .flatMap((f) =>
      isRecord(f) && typeof f.label === 'string' && typeof f.value === 'string'
        ? [{ label: f.label, value: f.value }]
        : [],
    )
    .slice(0, 8);
}

/** Row → `ReportView` (§4.1; public ids only, ISO instants, deliveries newest first). */
export function reportView(row: ReportWithRefs, deliveries: readonly DeliveryRow[]): ReportView {
  const sections = sectionsOf(row.sections);
  return {
    id: row.publicId,
    conversationId: row.conversationPublicId,
    executionId: row.executionPublicId,
    status: row.status,
    title: row.title,
    period: {
      from: row.periodFrom.toISOString(),
      to: row.periodTo.toISOString(),
      granularity: row.granularity,
      atoRange: sections.atoRange ?? atoRangeFor(row.periodTo.getTime() - row.periodFrom.getTime()),
    },
    sections: sections.included,
    omitted: sections.omitted,
    figures: figuresOf(row.figures),
    sizeBytes: row.sizeBytes,
    sha256: row.sha256,
    templateVersion: row.templateVersion,
    createdAt: row.createdAt.toISOString(),
    deliveries: deliveries.slice(0, REPORT_VIEW_DELIVERIES).map((d) => ({
      id: d.publicId,
      to: d.recipientAddress,
      recipientKind: d.recipientKind,
      status: d.status,
      errorCode: d.errorCode,
      requestedAt: d.requestedAt.toISOString(),
      sentAt: d.sentAt === null ? null : d.sentAt.toISOString(),
    })),
  };
}

/**
 * The reports of the assistant as their owner sees them (step AI-R §4.1, D6, D7): `GET
 * /assistant/reports/{reportId}` (owner only — organization of the scope, the user, the platform
 * override id — else `404 assistant_report_not_found`; the HTML from object storage only while
 * the report is `available`, inside JSON, never as `text/html`) and the deletion of report
 * objects after a content purge (retention job and the conversation delete route). Logs carry
 * ids and codes only, never keys or HTML.
 */
@Injectable()
export class ReportsService {
  private readonly logger = new Logger(ReportsService.name);

  constructor(
    private readonly reports: ReportsRepository,
    private readonly deliveries: ReportDeliveriesRepository,
    private readonly store: ReportObjectStore,
  ) {}

  now(): Date {
    return new Date();
  }

  async get(
    principal: UserPrincipal,
    scope: TenantScope,
    reportId: string,
  ): Promise<ReportResultView> {
    const owner = { scope, userId: principal.userId };
    const row = await this.reports.findOwned(owner, principal.override?.id ?? null, reportId);
    if (!row) throw assistantReportNotFound();
    const deliveries = await this.deliveries.listForReport(
      scope.organizationId,
      row.id,
      REPORT_VIEW_DELIVERIES,
    );
    return { report: reportView(row, deliveries), html: await this.htmlOf(row) };
  }

  /** The stored HTML of an available report; null otherwise or when the object is unreadable. */
  private async htmlOf(row: ReportWithRefs): Promise<string | null> {
    if (row.status !== 'available' || row.objectKey === null || row.sha256 === null) return null;
    try {
      const bytes = await this.store.get(
        row.organizationId,
        row.objectKey,
        Math.max(row.sizeBytes ?? 0, 1),
        row.sha256,
      );
      return bytes.toString('utf8');
    } catch (error) {
      if (!(error instanceof ReportObjectError)) throw error;
      this.logger.warn({
        message: 'Assistant report object unreadable',
        reportId: row.publicId,
        code: error.why,
      });
      return null;
    }
  }

  /**
   * Deletes one purged report's object (a missing object counts as deleted; a key outside the
   * organization's prefix is never requested and only cleared) and stamps the row. False when
   * the store failed (the row stays for the next run).
   */
  async deleteObject(row: ReportObjectRow, now: Date = this.now()): Promise<boolean> {
    try {
      if (row.objectKey !== null && isReportKeyOf(row.objectKey, row.organizationId)) {
        await this.store.delete(row.organizationId, row.objectKey);
      }
    } catch (error) {
      this.logger.warn({
        message: 'Assistant report object delete failed',
        reportRowId: row.id.toString(),
        code: (error as { name?: unknown }).name ?? 'error',
      });
      return false;
    }
    return this.reports.markObjectDeleted(row.organizationId, row.id, now);
  }

  /** D7: the objects of one conversation's purged reports right after `DELETE` (best effort). */
  async deleteConversationObjects(organizationId: bigint, conversationId: bigint): Promise<number> {
    let deleted = 0;
    try {
      for (const row of await this.reports.objectsOfConversation(organizationId, conversationId)) {
        if (await this.deleteObject(row)) deleted += 1;
      }
    } catch (error) {
      this.logger.warn({
        message: 'Assistant report objects of a deleted conversation left to the retention job',
        code: (error as { name?: unknown }).name ?? 'error',
      });
    }
    return deleted;
  }
}

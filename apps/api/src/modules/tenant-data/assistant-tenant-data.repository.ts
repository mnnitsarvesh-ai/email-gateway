import { Injectable } from '@nestjs/common';
import { PrismaService, S3Service } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import {
  isReportKeyOf,
  ReportObjectStore,
} from '../assistant/services/reports/report-object-store';

/**
 * The organization's AI assistant tables in the order the organization purge deletes them (step
 * AI-1 §3, D12, ADR-0094; step AI-2 §3, D7; step AI-R D7; docs/runbooks/organization-deletion.md):
 * report deliveries, report jobs (step AI-6: they reference their report) and reports (each
 * batch deletes its report objects from the mail bucket, then its rows), feedback (step AI-6: it
 * references messages) and pseudonym mappings (step AI-6), action confirmations (they reference
 * executions, turns and conversations), tool executions and messages (they reference turns and
 * conversations), turns, conversations, the daily usage rows (organization, then per user, step
 * AI-6), the organization's provider key (step AI-6, ciphertext only) and finally the settings
 * row. Every table references `organizations` with RESTRICT, so the
 * organization row cannot go while any of them holds a row; the conversation children also
 * cascade from their conversation (a backstop only: the explicit order keeps every statement
 * short). Independent of the other purge repositories (no foreign key to or from another area).
 */
export const ASSISTANT_PURGE_ORDER = [
  'ai_chat_report_deliveries',
  'ai_chat_report_jobs',
  'ai_chat_reports',
  'ai_chat_feedback',
  'ai_chat_pseudonyms',
  'ai_chat_action_confirmations',
  'ai_chat_tool_executions',
  'ai_chat_messages',
  'ai_chat_turns',
  'ai_chat_conversations',
  'ai_chat_usage_daily',
  'ai_chat_usage_user_daily',
  'ai_chat_provider_keys',
  'ai_chat_settings',
] as const;
export type AssistantPurgeTable = (typeof ASSISTANT_PURGE_ORDER)[number];

/** Rows one purge statement deletes (short statements, no long row locks). */
export const ASSISTANT_PURGE_BATCH = 500;

export interface AssistantPurgeCounts extends Record<AssistantPurgeTable, number> {
  /** Report objects deleted from the mail bucket (a missing object counts as deleted). */
  reportObjects: number;
}

/**
 * Deletes an organization's assistant rows for the organization purge. Writer only, `systemScope`
 * of the organization; each statement is its own autocommit `DELETE … WHERE organization_id = ?
 * ORDER BY … LIMIT n` on an index whose leading column is `organization_id`, repeated until fewer
 * than n rows go, so a crash leaves a resumable, consistent state and a re-run continues where it
 * stopped (0 everywhere once done). Never touches another organization's rows. The rows hold
 * conversation text, masked metadata cards, execution metadata and the stored requests, snapshots
 * and impact summaries of action confirmations, report metadata and report email recipients,
 * feedback comments, pseudonym values and report job metadata (no email body, no attachment, no
 * confirmation token: only its hash; the organization's provider key only as ciphertext); the report
 * HTML lives in the mail bucket under `org/<org>/assistant/report/` and is deleted per batch of
 * report rows before those rows (only keys under that prefix; a missing object is success; any
 * other S3 error aborts the purge, which is re-run). The `audit_logs` rows of the tool executions
 * stay (append-only, own retention).
 */
@Injectable()
export class AssistantTenantDataRepository {
  private readonly store: ReportObjectStore;

  constructor(
    private readonly prisma: PrismaService,
    s3: S3Service,
  ) {
    // The global S3Service (the tenant-data module provides no assistant services).
    this.store = new ReportObjectStore(s3);
  }

  async purgeOrganization(
    scope: TenantScope,
    batch: number = ASSISTANT_PURGE_BATCH,
  ): Promise<AssistantPurgeCounts> {
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const counts = {
      ...(Object.fromEntries(ASSISTANT_PURGE_ORDER.map((t) => [t, 0])) as Record<
        AssistantPurgeTable,
        number
      >),
      reportObjects: 0,
    };
    for (const table of ASSISTANT_PURGE_ORDER) {
      if (table === 'ai_chat_reports') {
        await this.purgeReports(scope.organizationId, batch, counts);
        continue;
      }
      for (;;) {
        const deleted = await this.deleteBatch(table, scope.organizationId, batch);
        counts[table] += deleted;
        if (deleted < batch) break;
      }
    }
    return counts;
  }

  /**
   * `ai_chat_reports` in batches ordered by id: each batch's objects are deleted from the mail
   * bucket first (only keys under the organization's report prefix), then its rows.
   */
  private async purgeReports(
    organizationId: bigint,
    batch: number,
    counts: AssistantPurgeCounts,
  ): Promise<void> {
    for (;;) {
      const rows = await this.prisma.$queryRaw<
        Array<{ id: bigint; organization_id: bigint; object_key: string | null }>
      >`SELECT id, organization_id, object_key FROM ai_chat_reports
        WHERE organization_id = ${organizationId}
        ORDER BY user_id, created_at, id LIMIT ${batch}`;
      if (rows.some((row) => BigInt(row.organization_id) !== organizationId)) {
        throw new Error('assistant purge: report read returned another organization');
      }
      if (rows.length === 0) break;
      for (const row of rows) {
        if (row.object_key === null || !isReportKeyOf(row.object_key, organizationId)) continue;
        await this.store.delete(organizationId, row.object_key);
        counts.reportObjects += 1;
      }
      const ids = rows.map((row) => BigInt(row.id));
      counts.ai_chat_reports += await this.prisma.$executeRaw`DELETE FROM ai_chat_reports
        WHERE organization_id = ${organizationId} AND id IN (${Prisma.join(ids)})`;
      if (rows.length < batch) break;
    }
  }

  /** One batch; the table name comes from the fixed purge order, never from input. */
  private deleteBatch(
    table: Exclude<AssistantPurgeTable, 'ai_chat_reports'>,
    organizationId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
      case 'ai_chat_report_deliveries':
        // Index (organization_id, requested_at); before the reports (FK, CASCADE backstop).
        return this.prisma.$executeRaw`DELETE FROM ai_chat_report_deliveries
          WHERE organization_id = ${organizationId} ORDER BY requested_at, id LIMIT ${batch}`;
      case 'ai_chat_report_jobs':
        // Step AI-6. Index (organization_id, created_at); before the reports (FK, CASCADE).
        return this.prisma.$executeRaw`DELETE FROM ai_chat_report_jobs
          WHERE organization_id = ${organizationId} ORDER BY created_at, id LIMIT ${batch}`;
      case 'ai_chat_feedback':
        // Step AI-6. Index (organization_id, created_at); before the messages (FK, CASCADE).
        return this.prisma.$executeRaw`DELETE FROM ai_chat_feedback
          WHERE organization_id = ${organizationId} ORDER BY created_at, id LIMIT ${batch}`;
      case 'ai_chat_pseudonyms':
        // Step AI-6. Index (organization_id, created_at); before the conversations.
        return this.prisma.$executeRaw`DELETE FROM ai_chat_pseudonyms
          WHERE organization_id = ${organizationId} ORDER BY created_at, id LIMIT ${batch}`;
      case 'ai_chat_action_confirmations':
        // Index (organization_id, user_id, status, expires_at). Deleted before the executions
        // (the proposal execution cascades to its confirmation, but organization_id is RESTRICT
        // and the explicit statement keeps every batch short).
        return this.prisma.$executeRaw`DELETE FROM ai_chat_action_confirmations
          WHERE organization_id = ${organizationId}
          ORDER BY user_id, status, expires_at, id LIMIT ${batch}`;
      case 'ai_chat_tool_executions':
        // Index (organization_id, created_at).
        return this.prisma.$executeRaw`DELETE FROM ai_chat_tool_executions
          WHERE organization_id = ${organizationId} ORDER BY created_at, id LIMIT ${batch}`;
      case 'ai_chat_messages':
        // Index (organization_id, created_at).
        return this.prisma.$executeRaw`DELETE FROM ai_chat_messages
          WHERE organization_id = ${organizationId} ORDER BY created_at, id LIMIT ${batch}`;
      case 'ai_chat_turns':
        // Index (organization_id, started_at); messages and executions are gone.
        return this.prisma.$executeRaw`DELETE FROM ai_chat_turns
          WHERE organization_id = ${organizationId} ORDER BY started_at, id LIMIT ${batch}`;
      case 'ai_chat_conversations':
        // Index (organization_id, user_id, status, last_turn_at, id); the children are gone.
        return this.prisma.$executeRaw`DELETE FROM ai_chat_conversations
          WHERE organization_id = ${organizationId}
          ORDER BY user_id, status, last_turn_at, id LIMIT ${batch}`;
      case 'ai_chat_usage_daily':
        // Primary key (organization_id, day, provider, model).
        return this.prisma.$executeRaw`DELETE FROM ai_chat_usage_daily
          WHERE organization_id = ${organizationId} ORDER BY day, provider, model LIMIT ${batch}`;
      case 'ai_chat_usage_user_daily':
        // Step AI-6. Primary key (organization_id, day, user_id, provider, model, key_source).
        return this.prisma.$executeRaw`DELETE FROM ai_chat_usage_user_daily
          WHERE organization_id = ${organizationId}
          ORDER BY day, user_id, provider, model, key_source LIMIT ${batch}`;
      case 'ai_chat_provider_keys':
        // Step AI-6. Primary key (organization_id): at most one row.
        return this.prisma.$executeRaw`DELETE FROM ai_chat_provider_keys
          WHERE organization_id = ${organizationId} ORDER BY organization_id LIMIT ${batch}`;
      case 'ai_chat_settings':
        // Primary key (organization_id): at most one row.
        return this.prisma.$executeRaw`DELETE FROM ai_chat_settings
          WHERE organization_id = ${organizationId} ORDER BY organization_id LIMIT ${batch}`;
    }
  }
}

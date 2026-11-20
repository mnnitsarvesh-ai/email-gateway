import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { TenantScope } from '../../auth-contracts/tenant-scope';

/**
 * The organization's AI assistant tables in the order the organization purge deletes them (step
 * AI-1 §3, D12, ADR-0094; docs/runbooks/organization-deletion.md): tool executions and messages
 * (they reference turns and conversations), turns, conversations, the daily usage rows and
 * finally the settings row. Every table references `organizations` with RESTRICT, so the
 * organization row cannot go while any of them holds a row; the conversation children also
 * cascade from their conversation (a backstop only: the explicit order keeps every statement
 * short). Independent of the other purge repositories (no foreign key to or from another area).
 */
export const ASSISTANT_PURGE_ORDER = [
  'ai_chat_tool_executions',
  'ai_chat_messages',
  'ai_chat_turns',
  'ai_chat_conversations',
  'ai_chat_usage_daily',
  'ai_chat_settings',
] as const;
export type AssistantPurgeTable = (typeof ASSISTANT_PURGE_ORDER)[number];

/** Rows one purge statement deletes (short statements, no long row locks). */
export const ASSISTANT_PURGE_BATCH = 500;

export type AssistantPurgeCounts = Record<AssistantPurgeTable, number>;

/**
 * Deletes an organization's assistant rows for the organization purge. Writer only, `systemScope`
 * of the organization; each statement is its own autocommit `DELETE … WHERE organization_id = ?
 * ORDER BY … LIMIT n` on an index whose leading column is `organization_id`, repeated until fewer
 * than n rows go, so a crash leaves a resumable, consistent state and a re-run continues where it
 * stopped (0 everywhere once done). Never touches another organization's rows. The rows hold
 * conversation text, masked metadata cards and execution metadata (no email body, no attachment,
 * no credential, no S3 object); the `audit_logs` rows of the tool executions stay (append-only,
 * own retention).
 */
@Injectable()
export class AssistantTenantDataRepository {
  constructor(private readonly prisma: PrismaService) {}

  async purgeOrganization(
    scope: TenantScope,
    batch: number = ASSISTANT_PURGE_BATCH,
  ): Promise<AssistantPurgeCounts> {
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const counts = Object.fromEntries(
      ASSISTANT_PURGE_ORDER.map((t) => [t, 0]),
    ) as AssistantPurgeCounts;
    for (const table of ASSISTANT_PURGE_ORDER) {
      for (;;) {
        const deleted = await this.deleteBatch(table, scope.organizationId, batch);
        counts[table] += deleted;
        if (deleted < batch) break;
      }
    }
    return counts;
  }

  /** One batch; the table name comes from the fixed purge order, never from input. */
  private deleteBatch(
    table: AssistantPurgeTable,
    organizationId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
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
      case 'ai_chat_settings':
        // Primary key (organization_id): at most one row.
        return this.prisma.$executeRaw`DELETE FROM ai_chat_settings
          WHERE organization_id = ${organizationId} ORDER BY organization_id LIMIT ${batch}`;
    }
  }
}

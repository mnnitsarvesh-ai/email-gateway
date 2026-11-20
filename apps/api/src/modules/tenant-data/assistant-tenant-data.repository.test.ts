import type { PrismaService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import {
  ASSISTANT_PURGE_BATCH,
  ASSISTANT_PURGE_ORDER,
  AssistantTenantDataRepository,
} from './assistant-tenant-data.repository';

const SCOPE = systemScope(42n);

function writerDouble(answers: number[]) {
  const statements: Array<{ sql: string; values: unknown[] }> = [];
  const writer = {
    $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      statements.push({ sql: strings.join('?').replace(/\s+/g, ' ').trim(), values });
      return Promise.resolve(answers.shift() ?? 0);
    },
  } as unknown as PrismaService;
  return { writer, statements };
}

const tableOf = (sql: string) => /^DELETE FROM (\w+)/.exec(sql)![1];

describe('AssistantTenantDataRepository.purgeOrganization (step AI-1 D12)', () => {
  it('deletes executions, messages, turns, conversations, usage, then settings, in batches until a short batch', async () => {
    // executions 2+2+1, messages 0, turns 2+0, conversations 1, usage 2+2+0, settings 1.
    const { writer, statements } = writerDouble([2, 2, 1, 0, 2, 0, 1, 2, 2, 0, 1]);
    const counts = await new AssistantTenantDataRepository(writer).purgeOrganization(SCOPE, 2);
    expect(counts).toEqual({
      ai_chat_tool_executions: 5,
      ai_chat_messages: 0,
      ai_chat_turns: 2,
      ai_chat_conversations: 1,
      ai_chat_usage_daily: 4,
      ai_chat_settings: 1,
    });
    expect(statements.map((s) => tableOf(s.sql))).toEqual([
      'ai_chat_tool_executions',
      'ai_chat_tool_executions',
      'ai_chat_tool_executions',
      'ai_chat_messages',
      'ai_chat_turns',
      'ai_chat_turns',
      'ai_chat_conversations',
      'ai_chat_usage_daily',
      'ai_chat_usage_daily',
      'ai_chat_usage_daily',
      'ai_chat_settings',
    ]);
    for (const s of statements) {
      // Scoped to the organization only, on an index led by organization_id, bounded.
      expect(s.sql).toMatch(/^DELETE FROM \w+ WHERE organization_id = \? ORDER BY .+ LIMIT \?$/);
      expect(s.values).toEqual([42n, 2]);
    }
  });

  it('deletes children before their parents (FK-safe order) and covers all six tables', () => {
    const at = (t: (typeof ASSISTANT_PURGE_ORDER)[number]) => ASSISTANT_PURGE_ORDER.indexOf(t);
    expect(new Set(ASSISTANT_PURGE_ORDER).size).toBe(6);
    expect(at('ai_chat_tool_executions')).toBeLessThan(at('ai_chat_turns'));
    expect(at('ai_chat_messages')).toBeLessThan(at('ai_chat_turns'));
    expect(at('ai_chat_turns')).toBeLessThan(at('ai_chat_conversations'));
    expect(ASSISTANT_PURGE_ORDER.at(-1)).toBe('ai_chat_settings');
    // audit_logs (append-only, own retention) is never deleted here.
    expect(ASSISTANT_PURGE_ORDER).not.toContain('audit_logs' as never);
  });

  it('is a no-op (one short statement per table) for an organization without assistant rows', async () => {
    const { writer, statements } = writerDouble([]);
    const counts = await new AssistantTenantDataRepository(writer).purgeOrganization(SCOPE);
    expect(Object.values(counts)).toEqual([0, 0, 0, 0, 0, 0]);
    expect(statements).toHaveLength(6);
    for (const s of statements) expect(s.values).toEqual([42n, ASSISTANT_PURGE_BATCH]);
  });

  it('refuses a non-positive or non-integer batch', async () => {
    const { writer, statements } = writerDouble([]);
    const repo = new AssistantTenantDataRepository(writer);
    await expect(repo.purgeOrganization(SCOPE, 0)).rejects.toThrow(/batch/);
    await expect(repo.purgeOrganization(SCOPE, 1.5)).rejects.toThrow(/batch/);
    expect(statements).toHaveLength(0);
  });
});

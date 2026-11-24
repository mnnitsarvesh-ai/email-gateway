import type { PrismaService, S3Service } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import {
  ASSISTANT_PURGE_BATCH,
  ASSISTANT_PURGE_ORDER,
  AssistantTenantDataRepository,
} from './assistant-tenant-data.repository';

const SCOPE = systemScope(42n);

interface ReportRowDouble {
  id: bigint;
  organization_id: bigint;
  object_key: string | null;
}

/**
 * A writer double: `$executeRaw` answers from `answers` in order; `$queryRaw` (the report batch
 * read) answers from `reportBatches` in order. Records every statement.
 */
function writerDouble(answers: number[], reportBatches: ReportRowDouble[][] = []) {
  const statements: Array<{ sql: string; values: unknown[] }> = [];
  const sql = (strings: TemplateStringsArray) => strings.join('?').replace(/\s+/g, ' ').trim();
  const writer = {
    $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      statements.push({ sql: sql(strings), values });
      return Promise.resolve(answers.shift() ?? 0);
    },
    $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      statements.push({ sql: sql(strings), values });
      return Promise.resolve(reportBatches.shift() ?? []);
    },
  } as unknown as PrismaService;
  return { writer, statements };
}

/**
 * An S3 double of the versioned mail bucket: every key holds two versions (`v2` current, `v1`
 * noncurrent) except the `missing` ones, which hold none. Records the listed keys and every
 * deleted `key@versionId`.
 */
function s3Double(missing: string[] = []) {
  const listed: string[] = [];
  const deleted: string[] = [];
  const s3 = {
    mailBucket: 'test-mail',
    client: {
      send: (command: {
        constructor: { name: string };
        input: { Key?: string; Prefix?: string; VersionId?: string };
      }) => {
        const { name } = command.constructor;
        if (name === 'ListObjectVersionsCommand') {
          const key = command.input.Prefix!;
          listed.push(key);
          return Promise.resolve({
            Versions: missing.includes(key)
              ? []
              : [
                  { Key: key, VersionId: 'v2' },
                  { Key: key, VersionId: 'v1' },
                ],
            IsTruncated: false,
          });
        }
        if (name !== 'DeleteObjectCommand') throw new Error('unexpected');
        deleted.push(`${command.input.Key!}@${command.input.VersionId!}`);
        return Promise.resolve({});
      },
    },
  } as unknown as S3Service;
  return { s3, listed, deleted };
}

const tableOf = (sql: string) => /^(?:DELETE FROM|SELECT .+ FROM) (\w+)/.exec(sql)![1];
const KEY = (n: number) =>
  `org/42/assistant/report/2026/11/23/0193d000-0000-7000-8000-00000000000${n}.html`;

describe('AssistantTenantDataRepository.purgeOrganization (step AI-1 D12, AI-2 D7, AI-R D7)', () => {
  it('deletes deliveries, reports (objects first), confirmations, executions, messages, turns, conversations, usage, then settings', async () => {
    // deliveries 2+0; reports: batch of 2 (objects, then 2 rows), short batch of 1 (no object);
    // confirmations 2+1, executions 2+2+1, messages 0, turns 2+0, conversations 1, usage 2+2+0,
    // settings 1.
    const { writer, statements } = writerDouble(
      [2, 0, 2, 1, 2, 1, 2, 2, 1, 0, 2, 0, 1, 2, 2, 0, 1],
      [
        [
          { id: 1n, organization_id: 42n, object_key: KEY(1) },
          { id: 2n, organization_id: 42n, object_key: KEY(2) },
        ],
        [{ id: 3n, organization_id: 42n, object_key: null }],
      ],
    );
    const { s3, listed, deleted } = s3Double([KEY(2)]);
    const counts = await new AssistantTenantDataRepository(writer, s3).purgeOrganization(SCOPE, 2);
    expect(counts).toEqual({
      ai_chat_report_deliveries: 2,
      ai_chat_reports: 3,
      ai_chat_action_confirmations: 3,
      ai_chat_tool_executions: 5,
      ai_chat_messages: 0,
      ai_chat_turns: 2,
      ai_chat_conversations: 1,
      ai_chat_usage_daily: 4,
      ai_chat_settings: 1,
      reportObjects: 2,
    });
    // Only keys of the organization's report prefix; every version of a key is deleted (the
    // mail bucket is versioned); a missing object (no version) counts as deleted.
    expect(listed).toEqual([KEY(1), KEY(2)]);
    expect(deleted).toEqual([`${KEY(1)}@v2`, `${KEY(1)}@v1`]);
    expect(statements.map((s) => tableOf(s.sql))).toEqual([
      'ai_chat_report_deliveries',
      'ai_chat_report_deliveries',
      'ai_chat_reports',
      'ai_chat_reports',
      'ai_chat_reports',
      'ai_chat_reports',
      'ai_chat_action_confirmations',
      'ai_chat_action_confirmations',
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
      // Scoped to the organization only and bounded (reports: by the ids of the batch read).
      expect(s.sql).toMatch(
        /(WHERE organization_id = \? (ORDER BY .+ )?LIMIT \?|WHERE organization_id = \? AND id IN \(\?\))$/,
      );
      expect(s.values[0]).toBe(42n);
    }
  });

  it('refuses a report batch of another organization and never deletes a foreign key', async () => {
    const { writer } = writerDouble([0], [[{ id: 9n, organization_id: 43n, object_key: KEY(1) }]]);
    const { s3, deleted } = s3Double();
    await expect(
      new AssistantTenantDataRepository(writer, s3).purgeOrganization(SCOPE, 2),
    ).rejects.toThrow(/another organization/);
    expect(deleted).toEqual([]);

    const foreign = writerDouble(
      [0, 1],
      [[{ id: 9n, organization_id: 42n, object_key: 'org/43/assistant/report/x.html' }]],
    );
    const other = s3Double();
    const counts = await new AssistantTenantDataRepository(
      foreign.writer,
      other.s3,
    ).purgeOrganization(SCOPE, 2);
    expect(other.deleted).toEqual([]);
    expect(counts.reportObjects).toBe(0);
  });

  it('deletes children before their parents (FK-safe order) and covers all nine tables', () => {
    const at = (t: (typeof ASSISTANT_PURGE_ORDER)[number]) => ASSISTANT_PURGE_ORDER.indexOf(t);
    expect(new Set(ASSISTANT_PURGE_ORDER).size).toBe(9);
    expect(ASSISTANT_PURGE_ORDER[0]).toBe('ai_chat_report_deliveries');
    expect(at('ai_chat_report_deliveries')).toBeLessThan(at('ai_chat_reports'));
    expect(at('ai_chat_reports')).toBeLessThan(at('ai_chat_conversations'));
    // Confirmations reference executions, turns and conversations (step AI-2 §3).
    expect(at('ai_chat_action_confirmations')).toBeLessThan(at('ai_chat_tool_executions'));
    expect(at('ai_chat_action_confirmations')).toBeLessThan(at('ai_chat_turns'));
    expect(at('ai_chat_action_confirmations')).toBeLessThan(at('ai_chat_conversations'));
    expect(at('ai_chat_tool_executions')).toBeLessThan(at('ai_chat_turns'));
    expect(at('ai_chat_messages')).toBeLessThan(at('ai_chat_turns'));
    expect(at('ai_chat_turns')).toBeLessThan(at('ai_chat_conversations'));
    expect(ASSISTANT_PURGE_ORDER.at(-1)).toBe('ai_chat_settings');
    // audit_logs (append-only, own retention) is never deleted here.
    expect(ASSISTANT_PURGE_ORDER).not.toContain('audit_logs' as never);
  });

  it('is a no-op (one short statement per table) for an organization without assistant rows', async () => {
    const { writer, statements } = writerDouble([]);
    const { s3, deleted } = s3Double();
    const counts = await new AssistantTenantDataRepository(writer, s3).purgeOrganization(SCOPE);
    expect(Object.values(counts)).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    expect(statements).toHaveLength(9);
    for (const s of statements) expect(s.values).toEqual([42n, ASSISTANT_PURGE_BATCH]);
    expect(deleted).toEqual([]);
  });

  it('refuses a non-positive or non-integer batch', async () => {
    const { writer, statements } = writerDouble([]);
    const repo = new AssistantTenantDataRepository(writer, s3Double().s3);
    await expect(repo.purgeOrganization(SCOPE, 0)).rejects.toThrow(/batch/);
    await expect(repo.purgeOrganization(SCOPE, 1.5)).rejects.toThrow(/batch/);
    expect(statements).toHaveLength(0);
  });
});

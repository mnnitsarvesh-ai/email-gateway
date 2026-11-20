import type { PrismaService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import {
  JOURNAL_INTAKE_PURGE_ORDER,
  JournalIntakeTenantDataRepository,
} from './journal-intake-tenant-data.repository';

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

describe('JournalIntakeTenantDataRepository.purgeOrganization (step 8.6)', () => {
  it('deletes counters, intake messages, then sources, in batches until a short batch', async () => {
    const { writer, statements } = writerDouble([2, 1, 2, 2, 0, 1]);
    const counts = await new JournalIntakeTenantDataRepository(writer).purgeOrganization(SCOPE, 2);
    expect(counts).toEqual({
      journal_intake_counters: 3,
      journal_intake_messages: 4,
      journal_intake_sources: 1,
    });
    const tableOf = (sql: string) => /^DELETE FROM (\w+)/.exec(sql)![1];
    expect(statements.map((s) => tableOf(s.sql))).toEqual([
      'journal_intake_counters',
      'journal_intake_counters',
      'journal_intake_messages',
      'journal_intake_messages',
      'journal_intake_messages',
      'journal_intake_sources',
    ]);
    for (const s of statements) {
      expect(s.sql).toMatch(/WHERE organization_id = \? ORDER BY .+ LIMIT \?$/);
      expect(s.values).toEqual([42n, 2]);
    }
  });

  it('never deletes the archive dedupe or record-source rows (the archive-worker does)', () => {
    expect(JOURNAL_INTAKE_PURGE_ORDER).not.toContain('archive_dedupe_keys' as never);
    expect(JOURNAL_INTAKE_PURGE_ORDER).not.toContain('archive_record_sources' as never);
  });

  it('refuses a non-positive batch', async () => {
    const { writer } = writerDouble([]);
    await expect(
      new JournalIntakeTenantDataRepository(writer).purgeOrganization(SCOPE, 0),
    ).rejects.toThrow(/batch/);
  });
});

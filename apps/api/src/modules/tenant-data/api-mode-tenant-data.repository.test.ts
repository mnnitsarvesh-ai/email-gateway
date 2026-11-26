import type { PrismaService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import {
  API_MODE_PURGE_ORDER,
  ApiModeTenantDataRepository,
} from './api-mode-tenant-data.repository';

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

describe('ApiModeTenantDataRepository.purgeOrganization (step API-1 §3.2)', () => {
  it('deletes the six tables in FK-safe order, in batches until a short batch', async () => {
    // copies 2+1, dedupe 0, addresses 2+0, mailboxes 1, counters 2+2+1, connections 1
    const { writer, statements } = writerDouble([2, 1, 0, 2, 0, 1, 2, 2, 1, 1]);
    const counts = await new ApiModeTenantDataRepository(writer).purgeOrganization(SCOPE, 2);
    expect(counts).toEqual({
      api_message_copies: 3,
      api_copy_dedupe_keys: 0,
      api_mailbox_addresses: 2,
      api_mailboxes: 1,
      api_mode_counters: 5,
      api_mode_connections: 1,
    });
    const tableOf = (sql: string) => /^DELETE FROM (\w+)/.exec(sql)![1];
    expect(statements.map((s) => tableOf(s.sql))).toEqual([
      'api_message_copies',
      'api_message_copies',
      'api_copy_dedupe_keys',
      'api_mailbox_addresses',
      'api_mailbox_addresses',
      'api_mailboxes',
      'api_mode_counters',
      'api_mode_counters',
      'api_mode_counters',
      'api_mode_connections',
    ]);
    for (const s of statements) {
      expect(s.sql).toMatch(/WHERE organization_id = \? ORDER BY .+ LIMIT \?$/);
      expect(s.values).toEqual([42n, 2]);
    }
  });

  it('copies and dedupe keys go before mailboxes; counters and mailboxes before connections', () => {
    const at = (t: (typeof API_MODE_PURGE_ORDER)[number]) => API_MODE_PURGE_ORDER.indexOf(t);
    expect(at('api_message_copies')).toBeLessThan(at('api_mailboxes'));
    expect(at('api_copy_dedupe_keys')).toBeLessThan(at('api_mailboxes'));
    expect(at('api_mailboxes')).toBeLessThan(at('api_mode_connections'));
    expect(at('api_mode_counters')).toBeLessThan(at('api_mode_connections'));
  });

  it('refuses a non-positive batch', async () => {
    const { writer } = writerDouble([]);
    await expect(
      new ApiModeTenantDataRepository(writer).purgeOrganization(SCOPE, 0),
    ).rejects.toThrow(/batch/);
  });
});

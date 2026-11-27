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
  it('deletes the twelve tables in FK-safe order, in batches until a short batch', async () => {
    // targets 2+1, clawbacks 1, reports 0, actions 2+0, policies 1, settings 1, copies 2+1,
    // dedupe 0, addresses 2+0, mailboxes 1, counters 2+2+1, connections 1
    const { writer, statements } = writerDouble([
      2, 1, 1, 0, 2, 0, 1, 1, 2, 1, 0, 2, 0, 1, 2, 2, 1, 1,
    ]);
    const counts = await new ApiModeTenantDataRepository(writer).purgeOrganization(SCOPE, 2);
    expect(counts).toEqual({
      api_clawback_targets: 3,
      api_clawbacks: 1,
      api_user_reports: 0,
      api_remediation_actions: 2,
      api_remediation_policies: 1,
      api_mode_org_settings: 1,
      api_message_copies: 3,
      api_copy_dedupe_keys: 0,
      api_mailbox_addresses: 2,
      api_mailboxes: 1,
      api_mode_counters: 5,
      api_mode_connections: 1,
    });
    const tableOf = (sql: string) => /^DELETE FROM (\w+)/.exec(sql)![1];
    expect(statements.map((s) => tableOf(s.sql))).toEqual([
      'api_clawback_targets',
      'api_clawback_targets',
      'api_clawbacks',
      'api_user_reports',
      'api_remediation_actions',
      'api_remediation_actions',
      'api_remediation_policies',
      'api_mode_org_settings',
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

  it('step API-2 §3.4: remediation actions before mailboxes and connections, policies first', () => {
    const at = (t: (typeof API_MODE_PURGE_ORDER)[number]) => API_MODE_PURGE_ORDER.indexOf(t);
    expect(at('api_remediation_actions')).toBeLessThan(at('api_mailboxes'));
    expect(at('api_remediation_actions')).toBeLessThan(at('api_mode_connections'));
    // Policies reference domains and the organization (RESTRICT): the whole API-mode purge runs
    // before the domain purge, and the policies go in it.
    expect(API_MODE_PURGE_ORDER).toContain('api_remediation_policies');
  });

  it('step API-3 §3.4: targets and clawbacks, then reports, before actions, mailboxes, connections', () => {
    const at = (t: (typeof API_MODE_PURGE_ORDER)[number]) => API_MODE_PURGE_ORDER.indexOf(t);
    expect(at('api_clawback_targets')).toBeLessThan(at('api_clawbacks'));
    expect(at('api_clawbacks')).toBeLessThan(at('api_user_reports'));
    expect(at('api_user_reports')).toBeLessThan(at('api_remediation_actions'));
    expect(at('api_user_reports')).toBeLessThan(at('api_mailboxes'));
    expect(at('api_user_reports')).toBeLessThan(at('api_mode_connections'));
    expect(API_MODE_PURGE_ORDER).toContain('api_mode_org_settings');
  });

  it('refuses a non-positive batch', async () => {
    const { writer } = writerDouble([]);
    await expect(
      new ApiModeTenantDataRepository(writer).purgeOrganization(SCOPE, 0),
    ).rejects.toThrow(/batch/);
  });
});

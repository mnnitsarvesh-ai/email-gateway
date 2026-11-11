import type { PrismaReadService, PrismaService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import { DomainsRepository } from './domains.repository';
import { MessagesRepository } from './messages.repository';
import { PoliciesRepository } from './policies.repository';
import { QuarantineRepository } from './quarantine.repository';
import {
  RISK_PURGE_BATCH,
  RISK_PURGE_ORDER,
  RiskTenantDataRepository,
} from './risk-tenant-data.repository';
import {
  POLICY_PURGE_BATCH,
  POLICY_PURGE_ORDER,
  PolicyTenantDataRepository,
} from './policy-tenant-data.repository';

interface Call {
  client: 'writer' | 'reader';
  model: string;
  method: string;
  args: { where?: unknown; take?: number; orderBy?: unknown };
}

/** A Prisma stand-in that records every model call and answers with `results` (or defaults). */
function recordingClients(results: Record<string, unknown> = {}) {
  const calls: Call[] = [];
  const make = (client: Call['client']) =>
    new Proxy(
      {},
      {
        get: (_t, model: string) =>
          new Proxy(
            {},
            {
              get: (_m, method: string) => (args: Call['args']) => {
                calls.push({ client, model, method, args });
                const key = `${model}.${method}`;
                if (key in results) return Promise.resolve(results[key]);
                return Promise.resolve(method === 'findMany' ? [] : null);
              },
            },
          ),
      },
    );
  const writer = make('writer') as unknown as PrismaService;
  const reader = { client: make('reader') } as unknown as PrismaReadService;
  return { writer, reader, calls };
}

/** True when `value` contains `organizationId: <id>` at any depth. */
function scopedTo(value: unknown, id: bigint): boolean {
  if (value === null || typeof value !== 'object') return false;
  if ((value as { organizationId?: unknown }).organizationId === id) return true;
  return Object.values(value).some((v) => scopedTo(v, id));
}

const SCOPE = systemScope(42n);
const PUBLIC_ID = '0190a0b0-0000-7000-8000-0000000000f1';

function expectEveryQueryScoped(calls: Call[]): void {
  expect(calls.length).toBeGreaterThan(0);
  for (const call of calls) {
    expect(scopedTo(call.args.where, 42n), `${call.model}.${call.method}`).toBe(true);
  }
}

describe('tenant-scoped repositories (D9)', () => {
  it('domains: by public id with the organization (writer), lists on the reader, never deleted', async () => {
    const { writer, reader, calls } = recordingClients();
    const repo = new DomainsRepository(writer, reader);
    await repo.findByPublicId(SCOPE, PUBLIC_ID);
    await repo.list(SCOPE, { take: 26, beforeId: 9n });
    expectEveryQueryScoped(calls);
    expect(calls.map((c) => `${c.client}:${c.method}`)).toEqual([
      'writer:findFirst',
      'reader:findMany',
    ]);
    const live = { status: { not: 'deleted' } };
    expect(calls[0]!.args.where).toEqual({ publicId: PUBLIC_ID, ...live, organizationId: 42n });
    expect(calls[1]!.args.where).toEqual({ ...live, id: { lt: 9n }, organizationId: 42n });
  });

  it('policies: soft-deleted policies are excluded', async () => {
    const { writer, reader, calls } = recordingClients();
    const repo = new PoliciesRepository(writer, reader);
    await repo.findByPublicId(SCOPE, PUBLIC_ID);
    await repo.list(SCOPE, { take: 500 });
    expectEveryQueryScoped(calls);
    for (const call of calls) expect(call.args.where).toMatchObject({ deletedAt: null });
    expect(calls[1]!.args.take).toBe(101);
  });

  it('quarantine: scoped lookups and lists', async () => {
    const { writer, reader, calls } = recordingClients();
    const repo = new QuarantineRepository(writer, reader);
    await repo.findByPublicId(SCOPE, PUBLIC_ID);
    await repo.list(SCOPE, { take: 10 });
    expectEveryQueryScoped(calls);
  });

  it('messages: registry and partitioned row both carry the organization', async () => {
    const receivedAt = new Date('2026-11-02T08:00:00Z');
    const { writer, reader, calls } = recordingClients({
      'messageIdentity.findFirst': { id: 77n, publicId: PUBLIC_ID, receivedAt },
      'emailMessage.findFirst': { id: 77n, receivedAt, organizationId: 42n },
    });
    const repo = new MessagesRepository(writer, reader);
    const found = await repo.findByPublicId(SCOPE, PUBLIC_ID);
    expect(found).toMatchObject({ id: 77n, publicId: PUBLIC_ID });
    expectEveryQueryScoped(calls);
    expect(calls[1]!.args.where).toEqual({ id: 77n, receivedAt, organizationId: 42n });
  });

  it('messages: an identity of another organization is never followed', async () => {
    const { writer, reader, calls } = recordingClients();
    const repo = new MessagesRepository(writer, reader);
    expect(await repo.findByPublicId(SCOPE, PUBLIC_ID)).toBeNull();
    expect(calls.map((c) => c.model)).toEqual(['messageIdentity']);
  });

  it('messages: range list with keyset cursor, scoped identities, rows without identity dropped', async () => {
    const from = new Date('2026-11-01T00:00:00Z');
    const to = new Date('2026-11-02T00:00:00Z');
    const after = { receivedAt: new Date('2026-11-01T12:00:00Z'), id: 5n };
    const { writer, reader, calls } = recordingClients({
      'emailMessage.findMany': [
        { id: 4n, receivedAt: from, organizationId: 42n },
        { id: 3n, receivedAt: from, organizationId: 42n },
      ],
      'messageIdentity.findMany': [{ id: 4n, publicId: PUBLIC_ID }],
    });
    const repo = new MessagesRepository(writer, reader);
    const rows = await repo.listRecent(SCOPE, { from, to }, { take: 26, after });
    expect(rows.map((r) => r.id)).toEqual([4n]);
    expectEveryQueryScoped(calls);
    expect(calls.every((c) => c.client === 'reader')).toBe(true);
    expect(calls[0]!.args.where).toMatchObject({
      organizationId: 42n,
      receivedAt: { gte: from, lt: to },
      OR: [
        { receivedAt: { lt: after.receivedAt } },
        { receivedAt: after.receivedAt, id: { lt: 5n } },
      ],
    });
    expect(calls[0]!.args.orderBy).toEqual([{ receivedAt: 'desc' }, { id: 'desc' }]);
  });
});

describe('organization purge: risk scoring (step 5.1 §3)', () => {
  /** A writer stand-in whose `$executeRaw` records each statement and answers from `answers`. */
  function rawWriter(answers: number[]) {
    const statements: Array<{ sql: string; values: unknown[] }> = [];
    const writer = {
      $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
        statements.push({ sql: strings.join('?').replace(/\s+/g, ' ').trim(), values });
        return Promise.resolve(answers.shift() ?? 0);
      },
    } as unknown as PrismaService;
    return { writer, statements };
  }

  it('deletes scores, then versions, then the profile, in batches of the organization only', async () => {
    // Scores: a full batch then a short one; versions: one short batch; profile: one row.
    const { writer, statements } = rawWriter([2, 1, 1, 1]);
    const counts = await new RiskTenantDataRepository(writer).purgeOrganization(SCOPE, 2);
    expect(counts).toEqual({
      message_risk_scores: 3,
      risk_scoring_profile_versions: 1,
      risk_scoring_profiles: 1,
    });
    expect(statements.map((s) => s.sql)).toEqual([
      'DELETE FROM message_risk_scores WHERE organization_id = ? LIMIT ?',
      'DELETE FROM message_risk_scores WHERE organization_id = ? LIMIT ?',
      'DELETE FROM risk_scoring_profile_versions WHERE organization_id = ? ORDER BY id LIMIT ?',
      'DELETE FROM risk_scoring_profiles WHERE organization_id = ? ORDER BY id LIMIT ?',
    ]);
    for (const statement of statements) expect(statement.values).toEqual([42n, 2]);
    expect(RISK_PURGE_ORDER).toEqual([
      'message_risk_scores',
      'risk_scoring_profile_versions',
      'risk_scoring_profiles',
    ]);
  });

  it('is a no-op for an organization without risk rows, and refuses a non-positive batch', async () => {
    const { writer, statements } = rawWriter([]);
    const repo = new RiskTenantDataRepository(writer);
    expect(await repo.purgeOrganization(SCOPE)).toEqual({
      message_risk_scores: 0,
      risk_scoring_profile_versions: 0,
      risk_scoring_profiles: 0,
    });
    expect(statements).toHaveLength(3);
    expect(statements[0]!.values).toEqual([42n, RISK_PURGE_BATCH]);
    await expect(repo.purgeOrganization(SCOPE, 0)).rejects.toThrow('batch must be positive');
  });
});

describe('organization purge: policy engine and directory (step 5.2 P22)', () => {
  function rawWriter(answers: number[]) {
    const statements: Array<{ sql: string; values: unknown[] }> = [];
    const writer = {
      $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
        statements.push({ sql: strings.join('?').replace(/\s+/g, ' ').trim(), values });
        return Promise.resolve(answers.shift() ?? 0);
      },
    } as unknown as PrismaService;
    return { writer, statements };
  }

  it('deletes in RESTRICT-safe order, in batches, the partitioned table without ORDER BY', async () => {
    // Evaluations: a full batch then a short one; every other table one short batch.
    const { writer, statements } = rawWriter([2, 1, 0, 1, 2, 0, 1, 1, 1, 1]);
    const counts = await new PolicyTenantDataRepository(writer).purgeOrganization(SCOPE, 2);
    expect(counts).toEqual({
      policy_execution_logs: 3,
      policy_actions: 0,
      policy_conditions: 1,
      policy_versions: 2,
      policy_exceptions: 1,
      email_policies: 1,
      policy_settings: 1,
      tenant_department_members: 1,
      tenant_departments: 0,
    });
    expect(statements.map((s) => s.sql)).toEqual([
      'DELETE FROM policy_execution_logs WHERE organization_id = ? LIMIT ?',
      'DELETE FROM policy_execution_logs WHERE organization_id = ? LIMIT ?',
      'DELETE FROM policy_actions WHERE organization_id = ? ORDER BY id LIMIT ?',
      'DELETE FROM policy_conditions WHERE organization_id = ? ORDER BY id LIMIT ?',
      'DELETE FROM policy_versions WHERE organization_id = ? ORDER BY id LIMIT ?',
      'DELETE FROM policy_versions WHERE organization_id = ? ORDER BY id LIMIT ?',
      'DELETE FROM policy_exceptions WHERE organization_id = ? ORDER BY id LIMIT ?',
      'DELETE FROM email_policies WHERE organization_id = ? ORDER BY id LIMIT ?',
      'DELETE FROM policy_settings WHERE organization_id = ? ORDER BY id LIMIT ?',
      'DELETE FROM tenant_department_members WHERE organization_id = ? ORDER BY id LIMIT ?',
      'DELETE FROM tenant_departments WHERE organization_id = ? ORDER BY id LIMIT ?',
    ]);
    for (const statement of statements) expect(statement.values).toEqual([42n, 2]);
    expect(POLICY_PURGE_ORDER.indexOf('tenant_department_members')).toBeLessThan(
      POLICY_PURGE_ORDER.indexOf('tenant_departments'),
    );
  });

  it('is a no-op without rows and refuses a non-positive batch', async () => {
    const { writer, statements } = rawWriter([]);
    const repo = new PolicyTenantDataRepository(writer);
    expect(Object.values(await repo.purgeOrganization(SCOPE)).every((n) => n === 0)).toBe(true);
    expect(statements).toHaveLength(POLICY_PURGE_ORDER.length);
    expect(statements[0]!.values).toEqual([42n, POLICY_PURGE_BATCH]);
    await expect(repo.purgeOrganization(SCOPE, -1)).rejects.toThrow('batch must be positive');
  });
});

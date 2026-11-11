import { describe, expect, it, vi } from 'vitest';
import {
  storedEvaluation,
  quarantineDomainDefinition,
} from '../../../../test/support/policy-fixtures';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { canonicalJson, sha256Hex } from '@email-gateway/policy-dsl';
import { PolicyExecutionQuerySchema } from '../dto/policies.schemas';
import type { PolicyExecutionsRepository } from '../repositories/policy-executions.repository';
import type { PolicyFactsRepository } from '../repositories/policy-facts.repository';
import {
  decodeHistoryCursor,
  encodeHistoryCursor,
  PolicyHistoryService,
} from './policy-history.service';

const SCOPE = systemScope(1n);
const POLICY = '0190f0f0-0000-7000-8000-00000000aaaa';
const def = quarantineDomainDefinition('bad.example');
const source = {
  generation: '4',
  settings: null,
  platformDefaultId: 'pol-default/1',
  policies: [
    {
      publicId: POLICY,
      versionNo: 2,
      definition: def,
      definitionSha256: sha256Hex(canonicalJson(def)),
    },
  ],
};

function row(id: bigint, receivedAt: Date, facts = { sender: { envelope: 'x@bad.example' } }) {
  const { row: stored } = storedEvaluation(facts, source, { scanId: 900n + id });
  return { ...stored, id, receivedAt, messageId: 70n + id };
}

function setup(rows: Array<Record<string, unknown>>) {
  const executions = {
    history: vi.fn(() => Promise.resolve(rows)),
    messagePublicIds: vi.fn(() =>
      Promise.resolve(new Map([[71n, '0190f0f0-0000-7000-8000-000000000071']])),
    ),
    forMessage: vi.fn(() => Promise.resolve(rows)),
  };
  const facts = {
    message: vi.fn((_s: unknown, id: string) =>
      Promise.resolve(id === 'm' ? { id: 71n, publicId: 'm', receivedAt: new Date() } : null),
    ),
  };
  const service = new PolicyHistoryService(
    { POLICY_HISTORY_MAX_RANGE_DAYS: 31 },
    executions as unknown as PolicyExecutionsRepository,
    facts as unknown as PolicyFactsRepository,
  );
  return { service, executions };
}

const query = (q: Record<string, string>) =>
  PolicyExecutionQuerySchema.parse({
    from: '2026-11-01T00:00:00.000Z',
    to: '2026-11-15T00:00:00.000Z',
    ...q,
  });

describe('PolicyHistoryService (P16, P22)', () => {
  it('maps rows to ids, enums, counts and hashes and pages by (receivedAt, id)', async () => {
    const t = new Date('2026-11-10T00:00:00.000Z');
    const { service, executions } = setup([row(1n, t), row(2n, t), row(3n, t)]);
    const page = await service.history(SCOPE, query({ limit: '2', disposition: 'quarantine' }));
    expect(page.data).toHaveLength(2);
    expect(page.data[0]).toMatchObject({
      messageId: '0190f0f0-0000-7000-8000-000000000071',
      disposition: 'quarantine',
      finalAction: 'quarantine',
      decisive: {
        source: 'tenant_rule',
        policyId: POLICY,
        versionNo: 2,
        ruleId: 'quarantine-domain',
      },
      generation: '4',
      matchedRuleCount: 1,
      overrideApplied: false,
      trigger: 'scanned',
    });
    expect(page.data[1]!.messageId).toBeNull();
    expect(page.data[0]!.actions[0]).toEqual({ type: 'QUARANTINE', status: 'enforced' });
    expect(JSON.stringify(page)).not.toContain('bad.example');
    expect(decodeHistoryCursor(page.nextCursor!)).toEqual({ receivedAt: t, id: 2n });
    expect(executions.history).toHaveBeenCalledWith(
      SCOPE,
      expect.objectContaining({ take: 3, disposition: 'quarantine' }),
    );
    await service.history(SCOPE, query({ cursor: page.nextCursor! }));
    expect(executions.history).toHaveBeenLastCalledWith(
      SCOPE,
      expect.objectContaining({ before: { receivedAt: t, id: 2n } }),
    );
  });

  it('refuses a range above the bound, a reversed range and a forged cursor', async () => {
    const { service } = setup([]);
    await expect(
      service.history(SCOPE, query({ to: '2026-12-15T00:00:00.000Z' })),
    ).rejects.toThrow();
    expect(() =>
      PolicyExecutionQuerySchema.parse({
        from: '2026-11-02T00:00:00Z',
        to: '2026-11-01T00:00:00Z',
      }),
    ).toThrow();
    expect(() => PolicyExecutionQuerySchema.parse({ from: '2026-11-02T00:00:00Z' })).toThrow();
    expect(() => decodeHistoryCursor('bm9wZQ')).toThrow();
    const c = encodeHistoryCursor({ receivedAt: new Date(5), id: 9n });
    expect(decodeHistoryCursor(c)).toEqual({ receivedAt: new Date(5), id: 9n });
  });

  it('lists the evaluations of a message (404 for another tenant)', async () => {
    const { service } = setup([
      row(1n, new Date()),
      { ...row(2n, new Date()), disposition: 'broken' },
    ]);
    const res = await service.forMessage(SCOPE, 'm');
    expect(res.data).toHaveLength(1);
    expect(res.data[0]).toMatchObject({ disposition: 'quarantine', lifecycleRound: 0 });
    expect(JSON.stringify(res)).not.toContain('decisivePolicyVersionId');
    await expect(service.forMessage(SCOPE, 'other')).rejects.toThrow('Message not found');
  });
});

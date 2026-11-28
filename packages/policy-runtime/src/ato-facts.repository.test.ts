import type { Prisma } from '@email-gateway/database';
import { atoSubjectHash } from '@email-gateway/security-contracts';
import { describe, expect, it, vi } from 'vitest';
import { type AtoFactsResult, AtoFactsRepository } from './ato-facts.repository';
import { InconsistentPolicyReadError, type PolicyRead } from './errors';

const ORG = 41n;
const ADDRESS = 'ceo@corp.example';
const HASH = atoSubjectHash('mailbox', ADDRESS);

const feature = (overrides: Record<string, unknown> = {}) => ({
  organizationId: ORG,
  featureKey: 'ato_detection',
  enabled: 1,
  settingsOrganizationId: null,
  mode: null,
  ...overrides,
});
const account = (overrides: Record<string, unknown> = {}) => ({
  accountId: 7n,
  organizationId: ORG,
  kind: 'mailbox',
  subjectHash: HASH,
  riskScore: 64,
  riskLevel: 'high',
  incidentId: null,
  incidentOrganizationId: null,
  incidentCategory: null,
  incidentSubjectRefId: null,
  incidentSeverity: null,
  incidentStatus: null,
  ...overrides,
});

function harness(features: unknown[], accounts: unknown[]) {
  const queries: string[] = [];
  const tx = {
    $queryRaw: vi.fn((strings: TemplateStringsArray, ...values: unknown[]) => {
      const sql = strings.join('?');
      queries.push(sql);
      if (sql.includes('organization_features')) {
        expect(values).toEqual([ORG, 'ato_detection']);
        return Promise.resolve(features);
      }
      expect(values).toEqual([ORG, ORG, HASH]);
      return Promise.resolve(accounts);
    }),
  } as unknown as Prisma.TransactionClient;
  const reads: PolicyRead[] = [];
  const results: AtoFactsResult[] = [];
  const repo = new AtoFactsRepository((read) => reads.push(read), {
    observe: (result) => results.push(result),
  });
  return { tx, repo, reads, results, queries };
}

describe('AtoFactsRepository (step 8.4 D23)', () => {
  it('resolves a monitored account with its active incident (two point reads)', async () => {
    const h = harness(
      [feature({ settingsOrganizationId: ORG, mode: 'monitor' })],
      [
        account({
          incidentId: 9n,
          incidentOrganizationId: ORG,
          incidentCategory: 'account_takeover',
          incidentSubjectRefId: 7n,
          incidentSeverity: 'critical',
          incidentStatus: 'investigating',
        }),
      ],
    );
    expect(await h.repo.read(h.tx, ORG, ADDRESS)).toEqual({
      accountKnown: true,
      riskScore: 64,
      riskLevel: 'high',
      incidentSeverity: 'critical',
      incidentStatus: 'investigating',
    });
    expect(h.queries).toHaveLength(2);
    expect(h.queries[1]).toContain("i.category = 'account_takeover'");
    expect(h.queries[1]).toContain('i.active_marker = 1');
    expect(h.results).toEqual(['resolved']);
  });

  it('feature off, absent or mode off: no facts and no account read', async () => {
    for (const rows of [
      [],
      [feature({ enabled: 0 })],
      [feature({ mode: 'off', settingsOrganizationId: ORG })],
    ]) {
      const h = harness(rows, []);
      expect(await h.repo.read(h.tx, ORG, ADDRESS)).toBeNull();
      expect(h.queries).toHaveLength(1);
      expect(h.results).toEqual(['disabled']);
    }
  });

  it('an unknown sender is accountKnown false, score 0, level low', async () => {
    const h = harness([feature()], []);
    expect(await h.repo.read(h.tx, ORG, ADDRESS)).toEqual({
      accountKnown: false,
      riskScore: 0,
      riskLevel: 'low',
      incidentSeverity: null,
      incidentStatus: null,
    });
    expect(h.results).toEqual(['unknown_account']);
  });

  it('an active incident about another subject is ignored', async () => {
    const h = harness(
      [feature()],
      [
        account({
          incidentId: 9n,
          incidentOrganizationId: ORG,
          incidentCategory: 'account_takeover',
          incidentSubjectRefId: 8n,
          incidentSeverity: 'high',
          incidentStatus: 'open',
        }),
      ],
    );
    expect(await h.repo.read(h.tx, ORG, ADDRESS)).toMatchObject({
      incidentSeverity: null,
      incidentStatus: null,
    });
  });

  it.each([
    [
      'feature of another organization',
      [feature({ organizationId: 42n })],
      [account()],
      'ato_settings',
    ],
    [
      'settings of another organization',
      [feature({ settingsOrganizationId: 42n })],
      [account()],
      'ato_settings',
    ],
    [
      'account of another organization',
      [feature()],
      [account({ organizationId: 42n })],
      'ato_accounts',
    ],
    [
      'another subject hash',
      [feature()],
      [account({ subjectHash: 'f'.repeat(64) })],
      'ato_accounts',
    ],
    [
      'an incident of another organization',
      [feature()],
      [
        account({
          incidentId: 9n,
          incidentOrganizationId: 42n,
          incidentCategory: 'account_takeover',
          incidentSubjectRefId: 7n,
          incidentSeverity: 'high',
          incidentStatus: 'open',
        }),
      ],
      'ato_accounts',
    ],
  ])(
    'an echo-check mismatch (%s) is a retryable inconsistent read',
    async (_, features, accounts, read) => {
      const h = harness(features, accounts);
      await expect(h.repo.read(h.tx, ORG, ADDRESS)).rejects.toBeInstanceOf(
        InconsistentPolicyReadError,
      );
      expect(h.reads).toEqual([read]);
      expect(h.results).toEqual(['error']);
    },
  );

  it('a database error propagates (the evaluation transaction fails and is retried)', async () => {
    const tx = {
      $queryRaw: vi.fn(() => Promise.reject(new Error('db down'))),
    } as unknown as Prisma.TransactionClient;
    const results: AtoFactsResult[] = [];
    const repo = new AtoFactsRepository(() => undefined, { observe: (r) => results.push(r) });
    await expect(repo.read(tx, ORG, ADDRESS)).rejects.toThrow('db down');
    expect(results).toEqual(['error']);
  });

  it('an address that cannot be an account is not applicable', async () => {
    const h = harness([feature()], []);
    expect(await h.repo.read(h.tx, ORG, 'not an address')).toBeNull();
    expect(h.results).toEqual(['not_applicable']);
  });
});

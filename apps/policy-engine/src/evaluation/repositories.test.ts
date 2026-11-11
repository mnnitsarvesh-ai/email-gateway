import { POLICY_DEFAULT_PLATFORM_ID, PolicyInputError } from '@email-gateway/policy-dsl';
import { describe, expect, it, vi } from 'vitest';
import { DirectoryRepository } from './directory.repository';
import { InconsistentPolicyReadError } from './errors';
import { FactsRepository, type RoundRef } from './facts.repository';
import { definition, POLICY_A, RULES } from './fixtures.test-support';
import { SnapshotCache } from './snapshot-cache';
import { type LoadedSnapshot, SnapshotRepository } from './snapshot.repository';

const RECEIVED = new Date('2026-11-10T09:59:00.000Z');
const ref: RoundRef = {
  messageId: 100n,
  receivedAt: RECEIVED,
  organizationId: 7n,
  round: 0,
  trigger: 'scanned',
  scanId: 900n,
};
const keyed = { messageId: 100n, receivedAt: RECEIVED, organizationId: 7n };
const scanKeyed = { ...keyed, scanId: 900n };

/** A transaction double answering every read of a clean scanned round. */
function factsTx(overrides: Record<string, unknown> = {}) {
  const many = (rows: unknown[]) => ({ findMany: vi.fn(() => Promise.resolve(rows)) });
  return {
    emailMessage: {
      findFirst: vi.fn(() =>
        Promise.resolve({
          id: 100n,
          receivedAt: RECEIVED,
          organizationId: 7n,
          direction: 'inbound',
          envelopeFrom: 'a@x.example',
          headerFrom: null,
          clientIp: null,
          clientName: null,
          sizeBytes: 1,
          recipientCount: 1,
          attachmentCount: 0,
          lifecycleRound: 0,
          ...(overrides.message as object),
        }),
      ),
    },
    emailRecipient: many([{ ...keyed, rcptSeq: 0, address: 'b@corp.example' }]),
    emailAttachment: many([]),
    messageUrl: many([]),
    emailScan: {
      findFirst: vi.fn(() =>
        Promise.resolve({
          id: 900n,
          ...keyed,
          lifecycleRound: 0,
          scanKind: 'initial',
          status: 'completed',
          scanVerdict: 'clean',
          reasonCodes: [],
          requiredEngines: ['rspamd'],
          completedAt: RECEIVED,
          ...(overrides.scan as object),
        }),
      ),
    },
    scanEngineResult: many([
      { ...scanKeyed, isFinal: true, engine: 'rspamd', outcome: 'clean', reasonCodes: [] },
    ]),
    emailAuthResult: many([]),
    becScanResult: many([]),
    dlpScanResult: many([]),
    messageRiskScore: many(
      (overrides.risk as unknown[]) ?? [
        { ...scanKeyed, lifecycleRound: 0, revision: 0, status: 'scored' },
      ],
    ),
    attachmentScanResult: many([]),
    urlScanResult: many([]),
    urlRewrite: many([]),
    emailMessageParse: {
      findFirst: vi.fn(() =>
        Promise.resolve(
          overrides.parse === undefined
            ? { ...keyed, status: 'failed', completedAt: RECEIVED }
            : overrides.parse,
        ),
      ),
    },
  };
}

describe('FactsRepository (P8, §6 echo checks)', () => {
  it('reads every P8 row of the round, organization-scoped', async () => {
    const tx = factsTx();
    const rows = await new FactsRepository(vi.fn()).read(tx as never, ref);
    expect(rows).toMatchObject({
      trigger: 'scanned',
      message: { direction: 'inbound', lifecycleRound: 0 },
      recipients: [{ rcptSeq: 0, address: 'b@corp.example' }],
      scan: { scanId: 900n, status: 'completed' },
      finals: [{ engine: 'rspamd', outcome: 'clean' }],
      risk: [{ revision: 0 }],
      auth: null,
      urlRewrite: null,
    });
    expect(tx.emailRecipient.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { messageId: 100n, receivedAt: RECEIVED, organizationId: 7n },
      }),
    );
  });

  it.each([
    ['message of another organization', { message: { organizationId: 8n } }, 'message'],
    ['message of another round', { message: { lifecycleRound: 1 } }, 'message'],
    ['scan of another message', { scan: { messageId: 101n } }, 'scan'],
    ['scan of another round', { scan: { lifecycleRound: 2 } }, 'scan'],
    [
      'risk row of another scan',
      { risk: [{ ...scanKeyed, scanId: 901n, lifecycleRound: 0, revision: 0 }] },
      'risk',
    ],
    ['risk revision 2', { risk: [{ ...scanKeyed, lifecycleRound: 0, revision: 2 }] }, 'risk'],
    [
      'two revision-0 rows',
      {
        risk: [
          { ...scanKeyed, lifecycleRound: 0, revision: 0 },
          { ...scanKeyed, lifecycleRound: 0, revision: 0 },
        ],
      },
      'risk',
    ],
  ])(
    'a shifted read (%s) is a retryable InconsistentPolicyReadError',
    async (_l, overrides, read) => {
      const sink = vi.fn();
      await expect(
        new FactsRepository(sink).read(factsTx(overrides) as never, ref),
      ).rejects.toBeInstanceOf(InconsistentPolicyReadError);
      expect(sink).toHaveBeenCalledWith(read);
    },
  );

  it('refuses a scan that is not final as malformed input (dead letter)', async () => {
    await expect(
      new FactsRepository(vi.fn()).read(factsTx({ scan: { status: 'running' } }) as never, ref),
    ).rejects.toBeInstanceOf(PolicyInputError);
  });

  it('parse failures read the parse row completion time and no scan rows', async () => {
    const tx = factsTx();
    const rows = await new FactsRepository(vi.fn()).read(tx as never, {
      ...ref,
      trigger: 'parse_failed',
      scanId: null,
    });
    expect(rows).toMatchObject({ scan: null, parseFailedAt: RECEIVED, finals: [], risk: [] });
    expect(tx.emailScan.findFirst).not.toHaveBeenCalled();
    await expect(
      new FactsRepository(vi.fn()).read(factsTx({ parse: null }) as never, {
        ...ref,
        trigger: 'parse_failed',
        scanId: null,
      }),
    ).rejects.toBeInstanceOf(PolicyInputError);
  });
});

/** A transaction double for the snapshot reads. */
function snapshotTx(options: {
  settings?: { organizationId: bigint; generation: bigint; settings: unknown } | null;
  versionOverrides?: Record<string, unknown>;
  definitionDoc?: ReturnType<typeof definition>;
}) {
  const d = options.definitionDoc ?? definition('inbound', [RULES.quarantineInbound]);
  return {
    policySettings: { findFirst: vi.fn(() => Promise.resolve(options.settings ?? null)) },
    emailPolicy: {
      findMany: vi.fn(() =>
        Promise.resolve([
          {
            id: 10n,
            publicId: POLICY_A,
            organizationId: 7n,
            status: 'active',
            deletedAt: null,
            activeVersionId: 20n,
          },
        ]),
      ),
    },
    policyVersion: {
      findMany: vi.fn(() =>
        Promise.resolve([
          {
            id: 20n,
            organizationId: 7n,
            policyId: 10n,
            version: 2,
            status: 'published',
            definition: d.definition,
            definitionSha256: d.definitionSha256,
            ...options.versionOverrides,
          },
        ]),
      ),
    },
  };
}

describe('SnapshotRepository (P12)', () => {
  const repo = () =>
    new SnapshotRepository(
      new SnapshotCache<LoadedSnapshot>(10),
      POLICY_DEFAULT_PLATFORM_ID,
      vi.fn(),
    );

  it('generation 0 without a settings row; compiles the active published versions with their ids', async () => {
    const r = repo();
    const tx = snapshotTx({});
    const first = await r.get(tx as never, 7n);
    expect(first.cache).toBe('miss');
    expect(first.compiled.generation).toBe('0');
    expect(first.compiled.policies).toHaveLength(1);
    expect(first.policyVersionIds).toEqual({ [`${POLICY_A}#2`]: '20' });
    // Same generation → cache hit, no policy reads.
    const second = await r.get(tx as never, 7n);
    expect(second.cache).toBe('hit');
    expect(tx.emailPolicy.findMany).toHaveBeenCalledTimes(1);
  });

  it('a new generation is a cache miss (next-evaluation-only)', async () => {
    const r = repo();
    await r.get(
      snapshotTx({ settings: { organizationId: 7n, generation: 4n, settings: {} } }) as never,
      7n,
    );
    const tx = snapshotTx({ settings: { organizationId: 7n, generation: 5n, settings: {} } });
    const next = await r.get(tx as never, 7n);
    expect(next).toMatchObject({ cache: 'miss' });
    expect(next.compiled.generation).toBe('5');
  });

  it('counts versions that no longer validate (excluded, never fatal)', async () => {
    const bad = definition('inbound', [
      {
        id: 'x',
        priority: 1,
        when: { field: 'nope', op: 'equals', value: 1 },
        actions: [{ type: 'QUARANTINE' }],
      },
    ]);
    const lookup = await repo().get(snapshotTx({ definitionDoc: bad }) as never, 7n);
    expect(lookup.invalidVersions).toBe(1);
    expect(lookup.compiled.policies).toHaveLength(0);
  });

  it.each([
    [
      'settings of another organization',
      { settings: { organizationId: 8n, generation: 1n, settings: {} } },
    ],
    ['version of another organization', { versionOverrides: { organizationId: 8n } }],
    ['version of another policy', { versionOverrides: { policyId: 11n } }],
    ['version not published', { versionOverrides: { status: 'draft' } }],
  ])('a shifted read (%s) is retryable', async (_l, options) => {
    await expect(repo().get(snapshotTx(options) as never, 7n)).rejects.toBeInstanceOf(
      InconsistentPolicyReadError,
    );
  });
});

describe('DirectoryRepository (P5)', () => {
  const DEPT = '0190f0f0-0000-7000-8000-0000000000d1';
  const USER = '0190f0f0-0000-7000-8000-0000000000e1';
  const tx = (members: unknown[], users: unknown[]) => ({
    tenantDepartment: {
      findMany: vi.fn(() => Promise.resolve([{ id: 3n, publicId: DEPT, organizationId: 7n }])),
    },
    tenantDepartmentMember: { findMany: vi.fn(() => Promise.resolve(members)) },
    user: { findMany: vi.fn(() => Promise.resolve(users)) },
  });

  it('maps addresses to referenced departments (by address or active user) and users', async () => {
    const t = tx(
      [
        { organizationId: 7n, departmentId: 3n, address: 'Fin@Corp.Example', userId: null },
        { organizationId: 7n, departmentId: 3n, address: null, userId: 9n },
        { organizationId: 7n, departmentId: 3n, address: 'other@corp.example', userId: null },
      ],
      [
        {
          id: 9n,
          publicId: USER,
          organizationId: 7n,
          email: 'cfo@corp.example',
          status: 'active',
          deletedAt: null,
        },
      ],
    );
    const maps = await new DirectoryRepository(vi.fn()).resolve(
      t as never,
      7n,
      { departmentIds: [DEPT], userIds: [USER] },
      ['fin@corp.example', 'cfo@corp.example'],
    );
    expect(maps).toEqual({
      departmentsByAddress: { 'fin@corp.example': [DEPT], 'cfo@corp.example': [DEPT] },
      usersByAddress: { 'cfo@corp.example': [USER] },
    });
    expect(t.tenantDepartment.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { organizationId: 7n, publicId: { in: [DEPT] } } }),
    );
  });

  it('bounds every read by the message addresses, never by department size', async () => {
    const t = tx(
      [{ organizationId: 7n, departmentId: 3n, address: null, userId: 9n }],
      [
        {
          id: 9n,
          publicId: USER,
          organizationId: 7n,
          email: 'cfo@corp.example',
          status: 'active',
          deletedAt: null,
        },
      ],
    );
    await new DirectoryRepository(vi.fn()).resolve(
      t as never,
      7n,
      { departmentIds: [DEPT], userIds: [] },
      ['cfo@corp.example', 'Fin@Corp.Example'],
    );
    expect(t.user.findMany).toHaveBeenCalledTimes(1);
    expect(t.user.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          organizationId: 7n,
          email: { in: ['cfo@corp.example', 'fin@corp.example'] },
          status: 'active',
          deletedAt: null,
        },
      }),
    );
    expect(t.tenantDepartmentMember.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          organizationId: 7n,
          departmentId: { in: [3n] },
          OR: [
            { address: { in: ['cfo@corp.example', 'fin@corp.example'] } },
            { userId: { in: [9n] } },
          ],
        },
      }),
    );
  });

  it('without a matching active user, members are matched by address only', async () => {
    const t = tx([], []);
    const maps = await new DirectoryRepository(vi.fn()).resolve(
      t as never,
      7n,
      { departmentIds: [DEPT], userIds: [USER] },
      ['gone@corp.example'],
    );
    expect(maps).toEqual({ departmentsByAddress: {}, usersByAddress: {} });
    expect(t.tenantDepartmentMember.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          organizationId: 7n,
          departmentId: { in: [3n] },
          OR: [{ address: { in: ['gone@corp.example'] } }],
        },
      }),
    );
  });

  it('ignores a looser collation match and refuses a user of another organization', async () => {
    const user = (over: Record<string, unknown>) => ({
      id: 9n,
      publicId: USER,
      organizationId: 7n,
      email: 'cfo@corp.example',
      status: 'active',
      deletedAt: null,
      ...over,
    });
    expect(
      await new DirectoryRepository(vi.fn()).resolve(
        tx([], [user({ email: 'cfó@corp.example' })]) as never,
        7n,
        { departmentIds: [], userIds: [USER] },
        ['cfo@corp.example'],
      ),
    ).toEqual({ departmentsByAddress: {}, usersByAddress: {} });
    const sink = vi.fn();
    await expect(
      new DirectoryRepository(sink).resolve(
        tx([], [user({ organizationId: 8n })]) as never,
        7n,
        { departmentIds: [], userIds: [USER] },
        ['cfo@corp.example'],
      ),
    ).rejects.toBeInstanceOf(InconsistentPolicyReadError);
    expect(sink).toHaveBeenCalledWith('users');
  });

  it('reads nothing without references and refuses rows of another organization', async () => {
    const t = tx([], []);
    expect(
      await new DirectoryRepository(vi.fn()).resolve(
        t as never,
        7n,
        { departmentIds: [], userIds: [] },
        ['a@b.example'],
      ),
    ).toEqual({ departmentsByAddress: {}, usersByAddress: {} });
    expect(t.tenantDepartment.findMany).not.toHaveBeenCalled();
    const sink = vi.fn();
    await expect(
      new DirectoryRepository(sink).resolve(
        tx(
          [{ organizationId: 8n, departmentId: 3n, address: 'a@b.example', userId: null }],
          [],
        ) as never,
        7n,
        { departmentIds: [DEPT], userIds: [] },
        ['a@b.example'],
      ),
    ).rejects.toBeInstanceOf(InconsistentPolicyReadError);
    expect(sink).toHaveBeenCalledWith('members');
  });
});

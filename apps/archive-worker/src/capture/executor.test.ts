import { createHash, randomBytes } from 'node:crypto';
import {
  archiveRecordObjectsSchema,
  decryptArchiveObject,
  resolveArchiveSettings,
  unwrapRecordKey,
} from '@email-gateway/archive';
import { describe, expect, it } from 'vitest';
import { FakeStorage, metricValue, silentLogger, testMetrics } from '../archive.test-support';
import type { TenantKeyService } from '../keys/tenant-keys';
import {
  DeterministicCaptureError,
  ObjectLockUnknownError,
  OriginalMissingError,
} from '../shared/errors';
import { ObjectLockState } from '../storage/archive-storage';
import { CaptureExecutor, type ClaimedIntent, Sha256Verify } from './executor';
import type { MessageFacts } from './facts';
import type { OrgArchiveContext } from './org-context';

const ORG = 42n;
const PUBLIC = '0190a5d0-0000-7000-8000-0000000000aa';
const tenantKey = randomBytes(32);
const keys = {
  active: () => Promise.resolve({ organizationId: ORG, version: 3, key: tenantKey }),
} as unknown as TenantKeyService;

function facts(eml: Buffer, overrides: Partial<MessageFacts['message']> = {}): MessageFacts {
  const receivedAt = new Date('2026-11-16T10:15:00.000Z');
  return {
    message: {
      id: 1001n,
      receivedAt,
      organizationId: ORG,
      publicId: PUBLIC,
      direction: 'inbound',
      status: 'delivered',
      statusReason: 'delivery_complete',
      statusChangedAt: receivedAt,
      lifecycleRound: 0,
      internetMessageId: '<a@b>',
      envelopeFrom: 'sender@partner.example',
      headerFrom: 'Sender <sender@partner.example>',
      subject: 'Quarterly',
      sizeBytes: eml.length,
      attachmentCount: 0,
      emlObjectKey: `org/${ORG}/eml/2026/11/16/1001.eml`,
      emlSha256: createHash('sha256').update(eml).digest('hex'),
      clientIp: null,
      clientHelo: null,
      clientName: null,
      finalVerdict: 'clean',
      finalAction: 'deliver',
      riskScore: 10,
      ...overrides,
    },
    recipients: [
      {
        id: 7n,
        seq: 0,
        address: 'user@corp.example',
        direction: 'inbound',
        status: 'delivered',
        finalAction: 'deliver',
      },
    ],
  };
}

const ctx = (lock: OrgArchiveContext['objectLockMode'] = 'none'): OrgArchiveContext => ({
  organizationId: ORG,
  entitled: true,
  enabled: true,
  settings: resolveArchiveSettings(null),
  settingsValid: true,
  generation: 5n,
  journalEnabledAt: new Date(0),
  objectLockMode: lock,
  defaultRetentionPolicyId: 9n,
  matcher: () => false,
  unresolved: 0,
  scopeTruncated: false,
});

const intent: ClaimedIntent = {
  id: 1n,
  receivedAt: new Date('2026-11-16T10:15:00.000Z'),
  organizationId: ORG,
  messageId: 1001n,
  leaseUntil: new Date('2026-11-16T11:00:00.000Z'),
  sourceJournal: true,
  sourcePolicy: false,
  policyRuleRef: null,
};

/** A writer with the message's journal inputs, no scan round, one default policy. */
function fakePrisma(options: { commit?: 'ok' | 'unique' | 'fail'; calls: string[] }) {
  const created: Record<string, unknown>[] = [];
  const tx = {
    emailArchive: {
      create: ({ data }: { data: Record<string, unknown> }) => {
        options.calls.push('tx:archive');
        if (options.commit === 'unique')
          return Promise.reject(Object.assign(new Error('dup'), { code: 'P2002' }));
        created.push(data);
        return Promise.resolve({ id: 77n });
      },
    },
    $executeRaw: () => {
      options.calls.push('tx:intent');
      return Promise.resolve(1);
    },
    archiveIndexQueue: {
      create: () => {
        options.calls.push('tx:index');
        return Promise.resolve({ id: 1n });
      },
    },
  };
  const prisma = {
    emailMessageParse: { findUnique: () => Promise.resolve(null) },
    emailHeader: { findMany: () => Promise.resolve([]) },
    emailAttachment: { findMany: () => Promise.resolve([]) },
    emailDelivery: { findMany: () => Promise.resolve([]) },
    emailScan: { findMany: () => Promise.resolve([]) },
    archiveRetentionPolicy: {
      findMany: () =>
        Promise.resolve([
          {
            id: 9n,
            organizationId: ORG,
            priority: 1,
            criteria: null,
            retentionDays: 30,
            onExpiry: 'delete',
            deletedAt: null,
          },
        ]),
    },
    $transaction: (fn: (t: typeof tx) => Promise<unknown>) => {
      if (options.commit === 'fail')
        return Promise.reject(Object.assign(new Error('db down'), { code: 'P1001' }));
      options.calls.push('tx:begin');
      return fn(tx);
    },
  };
  return { prisma, created };
}

function setup(
  _lock: 'none' | 'governance' = 'none',
  commit: 'ok' | 'unique' | 'fail' = 'ok',
  available: boolean | null = true,
) {
  const storage = new FakeStorage();
  const calls = storage.calls;
  const { prisma, created } = fakePrisma({ commit, calls });
  const lockState = new ObjectLockState('auto');
  if (available !== null) lockState.set(available);
  const { metrics, service } = testMetrics();
  const executor = new CaptureExecutor(prisma as never, {
    storage: storage.asStorage(),
    lockState,
    keys,
    metrics,
    logger: silentLogger,
    chunkBytes: 16_384,
    previewPartMaxBytes: 65_536,
    daySeconds: 86_400,
    now: () => new Date('2026-11-16T10:20:00.000Z'),
  });
  return { storage, calls, created, executor, service };
}

const input = (f: MessageFacts, c: OrgArchiveContext) => ({
  intent,
  facts: f,
  ctx: c,
  category: 'delivered' as const,
  sources: { journal: true, policy: false },
  recheckAt: new Date('2026-11-16T11:20:00.000Z'),
});

describe('CaptureExecutor (A5)', () => {
  it('writes EML, journal, then ONE transaction (record, intent, index op); objects decrypt to the original', async () => {
    const eml = randomBytes(40_000);
    const { storage, calls, created, executor } = setup();
    storage.seed('mail', `org/${ORG}/eml/2026/11/16/1001.eml`, eml);
    const result = await executor.capture(input(facts(eml), ctx()));
    expect(result).toMatchObject({ status: 'captured', archiveId: 77n });
    const order = calls.map((c) => c.split(':')[0]);
    expect(order).toEqual(['upload', 'put', 'tx', 'tx', 'tx', 'tx']);
    expect(calls.slice(-4)).toEqual(['tx:begin', 'tx:archive', 'tx:intent', 'tx:index']);
    const row = created[0]!;
    expect(row).toMatchObject({
      status: 'active',
      category: 'delivered',
      keyVersion: 3,
      lockMode: 'none',
      lockUntil: null,
      sha256: facts(eml).message.emlSha256,
      retentionPolicyId: 9n,
      encryptionFormat: 'archive-object/1',
    });
    expect(row.retainUntil).toEqual(new Date('2026-12-16T10:15:00.000Z'));
    const objects = archiveRecordObjectsSchema.parse(row.objects);
    const dek = unwrapRecordKey(tenantKey, row.wrappedDek as string, {
      organizationId: ORG,
      messagePublicId: PUBLIC,
      captureId: objects.captureId,
      keyVersion: 3,
    });
    const sealed = await storage.getBuffer('archive', objects.eml.key, objects.eml.versionId);
    expect(
      decryptArchiveObject(sealed, {
        dek,
        kind: 'eml',
        organizationId: ORG,
        subjectId: PUBLIC,
      }).equals(eml),
    ).toBe(true);
    expect(objects.eml.key).toMatch(
      new RegExp(`^org/${ORG}/archive/2026/11/16/${PUBLIC}/${objects.captureId}/eml.bin$`),
    );
    expect(objects.scans).toEqual([]);
  });

  it('aborts on an integrity mismatch: no object completed, nothing committed, metric counted', async () => {
    const eml = randomBytes(1_000);
    const { storage, calls, executor, service } = setup();
    storage.seed('mail', `org/${ORG}/eml/2026/11/16/1001.eml`, eml);
    await expect(
      executor.capture(input(facts(eml, { emlSha256: 'f'.repeat(64) }), ctx())),
    ).rejects.toMatchObject({
      code: 'integrity_mismatch',
    });
    expect(calls.some((c) => c.startsWith('tx:'))).toBe(false);
    expect(storage.versions('archive')).toHaveLength(0);
    expect(await metricValue(service, 'archive_integrity_failures_total')).toBe(1);
  });

  it('sends Object Lock headers for locked tenants; refuses when unavailable; retries when not probed', async () => {
    const eml = randomBytes(500);
    const locked = setup('governance');
    locked.storage.seed('mail', `org/${ORG}/eml/2026/11/16/1001.eml`, eml);
    await locked.executor.capture(input(facts(eml), ctx('governance')));
    expect(
      locked.calls
        .filter((c) => c.startsWith('upload') || c.startsWith('put'))
        .every((c) => c.endsWith(':governance')),
    ).toBe(true);
    expect(locked.created[0]).toMatchObject({ lockMode: 'governance' });
    expect((locked.created[0]!.lockUntil as Date).getTime()).toBe(
      (locked.created[0]!.retainUntil as Date).getTime(),
    );
    const off = setup('governance', 'ok', false);
    await expect(off.executor.capture(input(facts(eml), ctx('governance')))).rejects.toBeInstanceOf(
      DeterministicCaptureError,
    );
    const unknown = setup('governance', 'ok', null);
    await expect(
      unknown.executor.capture(input(facts(eml), ctx('governance'))),
    ).rejects.toBeInstanceOf(ObjectLockUnknownError);
  });

  it('deletes its own versions when the commit fails or loses the unique race (unlocked tenants)', async () => {
    const eml = randomBytes(500);
    const failing = setup('none', 'fail');
    failing.storage.seed('mail', `org/${ORG}/eml/2026/11/16/1001.eml`, eml);
    await expect(failing.executor.capture(input(facts(eml), ctx()))).rejects.toMatchObject({
      code: 'P1001',
    });
    expect(failing.storage.versions('archive')).toHaveLength(0);
    const racing = setup('none', 'unique');
    racing.storage.seed('mail', `org/${ORG}/eml/2026/11/16/1001.eml`, eml);
    expect(await racing.executor.capture(input(facts(eml), ctx()))).toEqual({
      status: 'lost_race',
    });
    expect(racing.storage.versions('archive')).toHaveLength(0);
    // Locked attempts cannot be deleted now: they stay for the orphan reconciliation.
    const lockedFail = setup('governance', 'fail');
    lockedFail.storage.seed('mail', `org/${ORG}/eml/2026/11/16/1001.eml`, eml);
    await expect(
      lockedFail.executor.capture(input(facts(eml), ctx('governance'))),
    ).rejects.toThrow();
    expect(lockedFail.storage.versions('archive')).toHaveLength(2);
  });

  it('reports a missing original as OriginalMissingError and refuses foreign keys', async () => {
    const eml = randomBytes(10);
    const { executor } = setup();
    await expect(executor.capture(input(facts(eml), ctx()))).rejects.toBeInstanceOf(
      OriginalMissingError,
    );
    await expect(
      executor.capture(input(facts(eml, { emlObjectKey: 'org/43/eml/x.eml' }), ctx())),
    ).rejects.toMatchObject({ code: 'facts_invalid' });
  });

  it('Sha256Verify passes matching streams through and errors at the end otherwise', async () => {
    const data = Buffer.from('hello');
    const ok = new Sha256Verify(createHash('sha256').update(data).digest('hex'));
    const out: Buffer[] = [];
    ok.on('data', (c: Buffer) => out.push(c));
    await new Promise((resolve, reject) => ok.on('end', resolve).on('error', reject).end(data));
    expect(Buffer.concat(out).equals(data)).toBe(true);
    const bad = new Sha256Verify('0'.repeat(64));
    bad.resume();
    await expect(
      new Promise((resolve, reject) => bad.on('end', resolve).on('error', reject).end(data)),
    ).rejects.toMatchObject({ code: 'integrity_mismatch' });
    expect(bad.mismatch).toBe(true);
  });
});

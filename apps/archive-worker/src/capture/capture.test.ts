import { resolveArchiveSettings } from '@email-gateway/archive';
import { NonRetryableError } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { EventTypes } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { FakeStorage, metricValue, silentLogger, testMetrics } from '../archive.test-support';
import { ArchiveRequestConsumer } from './consumer';
import {
  decimalsToStrings,
  directionsOf,
  isMalicious,
  type MessageFacts,
  partiesOf,
  sameParties,
} from './facts';
import { upsertIntents } from './intents';
import { buildJournal, parseCodes, readBodies } from './journal';
import {
  OrgContextCache,
  type OrgArchiveContext,
  resolveScope,
  SCOPE_MAX_DEPARTMENT_MEMBERS,
} from './org-context';
import { waitsFromElapsed } from './scheduler';
import { archiveRequest, JournalSweep, PolicyReconciler } from './sweeps';

const ORG = 42n;

const ctx = (over: Partial<OrgArchiveContext> = {}): OrgArchiveContext => ({
  organizationId: ORG,
  entitled: true,
  enabled: true,
  settings: resolveArchiveSettings(null),
  settingsValid: true,
  generation: 3n,
  journalEnabledAt: new Date(0),
  objectLockMode: 'none',
  defaultRetentionPolicyId: 1n,
  matcher: () => false,
  unresolved: 0,
  scopeTruncated: false,
  ...over,
});

const orgs = (c: OrgArchiveContext) =>
  ({ get: () => Promise.resolve(c) }) as unknown as OrgContextCache;

/** Captures every raw statement; answers `$queryRaw` from a queue. */
function rawDb(answers: unknown[][] = []) {
  const statements: Prisma.Sql[] = [];
  const cursors = new Map<string, { positionId: bigint | null; lastEventAt: Date | null }>();
  const db = {
    statements,
    cursors,
    $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      statements.push(Prisma.sql(strings, ...values));
      return Promise.resolve(answers.shift() ?? []);
    },
    $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      statements.push(Prisma.sql(strings, ...values));
      return Promise.resolve(1);
    },
    $transaction: (fn: (tx: unknown) => Promise<unknown>) => fn(db),
    streamCursor: {
      findUnique: ({ where }: { where: { name: string } }) => {
        const c = cursors.get(where.name);
        return Promise.resolve(c ? { name: where.name, ...c } : null);
      },
      upsert: ({
        create,
      }: {
        create: { name: string; positionId: bigint | null; lastEventAt: Date | null };
      }) => {
        cursors.set(create.name, {
          positionId: create.positionId,
          lastEventAt: create.lastEventAt,
        });
        return Promise.resolve(null);
      },
    },
    emailRecipient: { findMany: () => Promise.resolve([]) },
  };
  return db;
}

describe('intents (A2)', () => {
  it('upserts on (message_id, received_at) with OR-ed sources; conditions read the old values first', async () => {
    const db = rawDb();
    await upsertIntents(db as never, [
      {
        organizationId: ORG,
        messageId: 5n,
        receivedAt: new Date(0),
        direction: 'inbound',
        journal: false,
        policy: true,
        policyRuleRef: 'x'.repeat(200),
        settingsGeneration: 1n,
        nextCheckAt: new Date(1),
      },
    ]);
    const sql = db.statements[0]!.sql;
    expect(sql).toContain('ON DUPLICATE KEY UPDATE');
    // MySQL evaluates SET left to right: status must be decided before skip_reason is cleared,
    // and source_policy may only change after every condition that reads it.
    const order = [
      'next_check_at = IF',
      'closed_at = IF',
      'status = IF',
      'skip_reason = IF',
      'source_journal =',
      'source_policy =',
      'policy_rule_ref =',
    ].map((k) => sql.indexOf(`\n      ${k}`));
    expect(order.every((v, i) => v > 0 && (i === 0 || v > order[i - 1]!))).toBe(true);
    expect(db.statements[0]!.values).toContain('x'.repeat(128));
    // WP6 fix: a NEW source pulls a captured_open intent forward unless a replica holds its lease.
    expect(sql).toContain("archive_capture_intents.status = 'captured_open'");
    expect(sql).toContain('new.source_journal = 1 AND archive_capture_intents.source_journal = 0');
    expect(sql).toContain('archive_capture_intents.lease_until < NOW(3)');
    expect(await upsertIntents(db as never, [])).toBe(0);
  });
});

describe('sweeps (A2)', () => {
  const metrics = testMetrics();
  const opts = {
    metrics: metrics.metrics,
    logger: silentLogger,
    batchSize: 3,
    safetyLagSeconds: 120,
    now: () => new Date('2026-11-16T12:00:00.000Z'),
  };
  const row = (id: number, createdAt: string, org = ORG, direction = 'inbound') => ({
    id: BigInt(id),
    received_at: new Date(createdAt),
    organization_id: org,
    direction,
    envelope_from: 'a@partner.example',
    header_from: null,
    created_at: new Date(createdAt),
  });

  it('initializes the journal cursor at "now" (no backfill) and stops at the first row newer than the lag', async () => {
    const db = rawDb([
      [{ id: 100n }], // MAX(id) for start = now
      [
        row(101, '2026-11-16T11:50:00.000Z'),
        row(102, '2026-11-16T11:59:30.000Z'),
        row(103, '2026-11-16T11:50:00.000Z'),
      ],
    ]);
    const sweep = new JournalSweep(db as never, orgs(ctx()), {
      ...opts,
      start: 'now',
      cursorName: 'c',
    });
    const report = await sweep.runOnce();
    expect(report).toMatchObject({ scanned: 1, intents: 1, stoppedAtLag: true, more: false });
    // 103 (older) is NOT passed: the cursor stays at 101 so 102 is visited first next time.
    expect(db.cursors.get('c')).toMatchObject({ positionId: 101n });
    expect(db.statements[1]!.values).toContain(100n);
  });

  it('skips organizations that are not entitled, disabled, or before journal_enabled_at', async () => {
    for (const c of [
      ctx({ entitled: false }),
      ctx({ enabled: false }),
      ctx({ journalEnabledAt: new Date('2026-11-16T11:55:00.000Z') }),
    ]) {
      const db = rawDb([[row(1, '2026-11-16T11:50:00.000Z')]]);
      db.cursors.set('c', { positionId: 0n, lastEventAt: new Date(0) });
      const r = await new JournalSweep(db as never, orgs(c), {
        ...opts,
        start: 'oldest',
        cursorName: 'c',
      }).runOnce();
      expect(r).toMatchObject({ scanned: 1, intents: 0 });
      expect(db.cursors.get('c')!.positionId).toBe(1n);
    }
  });

  it('policy reconciler: only ARCHIVE actions with status requested; first rule ref kept', async () => {
    expect(archiveRequest([{ type: 'TAG', status: 'requested' }])).toEqual({
      requested: false,
      ruleRef: null,
    });
    expect(archiveRequest([{ type: 'ARCHIVE', status: 'skipped' }])).toEqual({
      requested: false,
      ruleRef: null,
    });
    expect(
      archiveRequest([{ type: 'ARCHIVE', status: 'requested', ruleRefs: ['a#1/r', 'b'] }]),
    ).toEqual({ requested: true, ruleRef: 'a#1/r' });
    expect(archiveRequest('nope')).toEqual({ requested: false, ruleRef: null });
    const db = rawDb([
      [
        {
          id: 1n,
          received_at: new Date('2026-11-16T11:00:00Z'),
          organization_id: ORG,
          message_id: 9n,
          direction: 'inbound',
          actions: JSON.stringify([{ type: 'ARCHIVE', status: 'requested', ruleRefs: ['p#1/r'] }]),
          created_at: new Date('2026-11-16T11:00:00Z'),
        },
        {
          id: 2n,
          received_at: new Date('2026-11-16T11:00:00Z'),
          organization_id: ORG,
          message_id: 10n,
          direction: 'inbound',
          actions: [],
          created_at: new Date('2026-11-16T11:00:00Z'),
        },
      ],
    ]);
    db.cursors.set('p', { positionId: 0n, lastEventAt: new Date(0) });
    const r = await new PolicyReconciler(db as never, orgs(ctx()), {
      ...opts,
      start: 'oldest',
      cursorName: 'p',
    }).runOnce();
    expect(r).toMatchObject({ scanned: 2, intents: 1 });
    const insert = db.statements.find((s) =>
      s.sql.includes('INSERT INTO archive_capture_intents'),
    )!;
    expect(insert.values).toContain('p#1/r');
    expect(db.cursors.get('p')!.positionId).toBe(2n);
  });

  it('waits follow 1, 2, 5, 15, 30 minutes then hourly', () => {
    const m = 60_000;
    expect(waitsFromElapsed(0)).toBe(0);
    expect(waitsFromElapsed(1 * m)).toBe(1);
    expect(waitsFromElapsed(3 * m)).toBe(2);
    expect(waitsFromElapsed(53 * m)).toBe(5);
    expect(waitsFromElapsed(53 * m + 2 * 60 * m)).toBe(7);
  });
});

describe('ArchiveRequestConsumer (A2 source 2)', () => {
  const receivedAt = new Date('2026-11-16T10:00:00.000Z');
  const payload = {
    messageId: '1001',
    receivedAt: receivedAt.toISOString(),
    direction: 'inbound',
    lifecycleRound: 0,
    emlS3Key: `org/${ORG}/eml/2026/11/16/1001.eml`,
    source: 'policy',
    ruleRef: '0190a5d0-0000-7000-8000-000000000001#3/archive-legal',
    policyGeneration: '7',
    requestedAt: receivedAt.toISOString(),
  };
  const envelope = (p: unknown = payload, org = ORG.toString()) => ({
    eventId: '0190a5d0-0000-7000-8000-0000000000ee',
    eventType: EventTypes.MessageArchiveRequested,
    occurredAt: receivedAt.toISOString(),
    correlationId: 'c',
    organizationId: org,
    payload: p,
  });
  function prisma(row: unknown, duplicate = false) {
    const db = rawDb();
    return Object.assign(db, {
      emailMessage: { findUnique: () => Promise.resolve(row) },
      messageIdempotency: {
        create: () =>
          duplicate
            ? Promise.reject(
                new Prisma.PrismaClientKnownRequestError('dup', {
                  code: 'P2002',
                  clientVersion: 'test',
                }),
              )
            : Promise.resolve({}),
      },
    });
  }
  const message = {
    id: 1001n,
    receivedAt,
    organizationId: ORG,
    direction: 'inbound',
    emlObjectKey: payload.emlS3Key,
  };

  it('upserts a policy intent under the ledger; duplicates are no-ops; unknown and foreign are acked', async () => {
    const { metrics, service } = testMetrics();
    const make = (row: unknown, dup = false) => {
      const db = prisma(row, dup);
      return {
        db,
        consumer: new ArchiveRequestConsumer(db as never, orgs(ctx()), {
          metrics,
          logger: silentLogger,
        }),
      };
    };
    const ok = make(message);
    expect(await ok.consumer.handle(envelope() as never)).toBe('handled');
    const insert = ok.db.statements.find((s) =>
      s.sql.includes('INSERT INTO archive_capture_intents'),
    )!;
    expect(insert.values).toContain(payload.ruleRef);
    expect(await make(message, true).consumer.handle(envelope() as never)).toBe('duplicate');
    expect(await make(null).consumer.process(envelope() as never)).toBe('unknown');
    expect(
      await make({ ...message, organizationId: 43n }).consumer.process(envelope() as never),
    ).toBe('foreign');
    expect(
      await make({ ...message, emlObjectKey: `org/${ORG}/part/x.text` }).consumer.process(
        envelope({ ...payload, emlS3Key: `org/${ORG}/part/x.text` }) as never,
      ),
    ).toBe('foreign');
    await expect(
      make(message).consumer.handle(envelope({ ...payload, extra: 1 }) as never),
    ).rejects.toBeInstanceOf(NonRetryableError);
    expect(await metricValue(service, 'archive_consumer_events_total', { result: 'intent' })).toBe(
      1,
    );
    expect(await metricValue(service, 'archive_consumer_events_total', { result: 'invalid' })).toBe(
      1,
    );
  });
});

describe('facts, journal and scope (A4, A5)', () => {
  const facts: MessageFacts = {
    message: {
      id: 1n,
      receivedAt: new Date('2026-11-16T10:00:00Z'),
      organizationId: ORG,
      publicId: '0190a5d0-0000-7000-8000-0000000000aa',
      ingestSource: 'gateway',
      direction: 'outbound',
      status: 'delivered',
      statusReason: null,
      statusChangedAt: new Date(),
      lifecycleRound: 0,
      internetMessageId: '<x@y>',
      envelopeFrom: 'me@corp.example',
      headerFrom: null,
      subject: 'S',
      sizeBytes: 10,
      attachmentCount: 1,
      emlObjectKey: `org/${ORG}/eml/x.eml`,
      emlSha256: 'A'.repeat(64),
      clientIp: null,
      clientHelo: null,
      clientName: null,
      finalVerdict: 'clean',
      finalAction: 'deliver',
      riskScore: null,
    },
    recipients: [
      {
        id: 10n,
        seq: 0,
        address: 'out@remote.example',
        direction: 'outbound',
        status: 'delivered',
        finalAction: 'deliver',
      },
      {
        id: 11n,
        seq: 1,
        address: 'in@corp.example',
        direction: 'internal',
        status: 'delivered',
        finalAction: null,
      },
    ],
  };

  it('parties, directions, malicious, decimals', () => {
    expect(partiesOf(facts)).toEqual({
      v: 1,
      from: 'me@corp.example',
      headerFrom: null,
      recipients: [
        {
          seq: 0,
          address: 'out@remote.example',
          direction: 'outbound',
          status: 'delivered',
          finalAction: 'deliver',
        },
        {
          seq: 1,
          address: 'in@corp.example',
          direction: 'internal',
          status: 'delivered',
          finalAction: null,
        },
      ],
    });
    // As MySQL returns the stored document (keys by length, then bytes): still the same.
    const mysqlOrder = JSON.parse(
      '{"v": 1, "from": "me@corp.example", "headerFrom": null, "recipients": [' +
        '{"seq": 0, "status": "delivered", "address": "out@remote.example", "direction": "outbound", "finalAction": "deliver"}, ' +
        '{"seq": 1, "status": "delivered", "address": "in@corp.example", "direction": "internal", "finalAction": null}]}',
    ) as unknown;
    expect(JSON.stringify(mysqlOrder)).not.toBe(JSON.stringify(partiesOf(facts)));
    expect(sameParties(mysqlOrder, partiesOf(facts))).toBe(true);
    expect(sameParties(JSON.stringify(mysqlOrder), partiesOf(facts))).toBe(true);
    // A real change (a recipient's status) or a different recipient order is a change.
    const changed = structuredClone(mysqlOrder) as { recipients: Array<{ status: string }> };
    changed.recipients[1]!.status = 'bounced';
    expect(sameParties(changed, partiesOf(facts))).toBe(false);
    const reordered = structuredClone(mysqlOrder) as { recipients: unknown[] };
    reordered.recipients.reverse();
    expect(sameParties(reordered, partiesOf(facts))).toBe(false);
    expect(sameParties(null, partiesOf(facts))).toBe(false);
    expect(sameParties('{', partiesOf(facts))).toBe(false);
    expect(directionsOf(facts).sort()).toEqual(['internal', 'outbound']);
    expect(isMalicious({ finalVerdict: 'malware' }, null)).toBe(true);
    expect(
      isMalicious(
        { finalVerdict: 'clean' },
        {
          attachments: [],
          urlResults: [{ verdict: 'malicious' }],
        },
      ),
    ).toBe(true);
    expect(
      isMalicious(
        { finalVerdict: 'clean' },
        {
          attachments: [{ verdict: 'clean' }],
          urlResults: [],
        },
      ),
    ).toBe(false);
    expect(decimalsToStrings({ score: new Prisma.Decimal('1.500'), n: 1 })).toEqual({
      score: '1.5',
      n: 1,
    });
  });

  it('builds a valid archive-journal/1 (hashes lower-cased, bounded parse codes, deliveries by seq)', () => {
    expect(
      parseCodes({
        status: 'parse_failed',
        failureReason: 'mime_depth',
        limitsExceeded: { parts: true, size: false },
        defects: [{ code: 'bad header' }, 'missing_boundary'],
        textBodyObjectKey: null,
        htmlBodyObjectKey: null,
      }),
    ).toEqual(['mime_depth', 'parts', 'missing_boundary']);
    const journal = buildJournal({
      facts,
      inputs: {
        parse: null,
        headers: [{ seq: 0, name: 'Subject', value: 'S' }],
        attachments: [
          {
            partIndex: 2,
            filename: 'a.pdf',
            declaredContentType: 'application/pdf',
            detectedContentType: null,
            sizeBytes: 3,
            sha256: 'B'.repeat(64),
          },
        ],
        deliveries: [
          {
            recipientId: 11n,
            status: 'delivered',
            deliveredAt: new Date('2026-11-16T10:00:05Z'),
            statusChangedAt: null,
          },
          { recipientId: 99n, status: 'x', deliveredAt: null, statusChangedAt: null },
        ],
      },
      bodies: { text: 'hi', html: null, truncated: false, unavailableReason: null },
      captureId: '0190a5d0-0000-7000-8000-0000000000bb',
      capturedAt: new Date('2026-11-16T10:01:00Z'),
      category: 'delivered',
      sources: { journal: true, policy: false },
      policyRuleRef: null,
      settingsGeneration: 2n,
    });
    expect(journal.message.emlSha256).toBe('a'.repeat(64));
    expect(journal.attachments[0]!.sha256).toBe('b'.repeat(64));
    expect(journal.deliveries).toEqual([
      { seq: 1, status: 'delivered', finalAt: '2026-11-16T10:00:05.000Z' },
    ]);
  });

  it('reads decoded parts with bounded ranges under org/<org>/part/ only', async () => {
    const storage = new FakeStorage();
    storage.seed('mail', `org/${ORG}/part/2026/11/16/1/1.text`, Buffer.from('x'.repeat(100)));
    const bodies = await readBodies(
      storage.asStorage(),
      ORG,
      {
        status: 'parsed',
        failureReason: null,
        limitsExceeded: null,
        defects: null,
        textBodyObjectKey: `org/${ORG}/part/2026/11/16/1/1.text`,
        htmlBodyObjectKey: `org/43/part/2026/11/16/1/1.html`,
      },
      10,
    );
    expect(bodies).toEqual({
      text: 'x'.repeat(10),
      html: null,
      truncated: true,
      unavailableReason: 'foreign_key',
    });
    const missing = await readBodies(
      storage.asStorage(),
      ORG,
      {
        status: 'parsed',
        failureReason: null,
        limitsExceeded: null,
        defects: null,
        textBodyObjectKey: `org/${ORG}/part/gone.text`,
        htmlBodyObjectKey: null,
      },
      10,
    );
    expect(missing.unavailableReason).toBe('part_missing');
    expect((await readBodies(storage.asStorage(), ORG, null, 10)).unavailableReason).toBe(
      'not_parsed',
    );
  });

  it('resolves scope ids inside the organization and counts what no longer resolves', async () => {
    const db = {
      user: {
        findMany: () =>
          Promise.resolve([{ organizationId: ORG, publicId: 'u1', email: 'ceo@corp.example' }]),
      },
      tenantDepartment: { findMany: () => Promise.resolve([{ id: 5n, organizationId: ORG }]) },
      tenantDepartmentMember: {
        findMany: () =>
          Promise.resolve([
            { organizationId: ORG, address: 'legal@corp.example', user: null },
            { organizationId: ORG, address: null, user: { email: 'cfo@corp.example' } },
          ]),
      },
      domain: { findMany: () => Promise.resolve([]) },
    };
    const settings = resolveArchiveSettings({
      scope: {
        mode: 'include',
        userIds: ['0190a5d0-0000-7000-8000-000000000001', '0190a5d0-0000-7000-8000-000000000002'],
        departmentIds: ['0190a5d0-0000-7000-8000-000000000003'],
        domainIds: ['0190a5d0-0000-7000-8000-000000000004'],
        addresses: ['A@corp.example'],
      },
    });
    const { scope, unresolved } = await resolveScope(db as never, ORG, settings);
    expect(unresolved).toBe(2); // one user, one domain
    expect(scope).toEqual({
      addresses: ['a@corp.example'],
      userEmails: ['ceo@corp.example'],
      departmentAddresses: ['legal@corp.example', 'cfo@corp.example'],
      domains: [],
    });
  });

  it('reads every department member in keyset pages and reports a truncation beyond the bound', async () => {
    const settings = resolveArchiveSettings({
      scope: { mode: 'include', departmentIds: ['0190a5d0-0000-7000-8000-000000000003'] },
    });
    const pages = (total: number) => {
      const calls: Array<{ after: bigint; take: number }> = [];
      const db = {
        tenantDepartment: { findMany: () => Promise.resolve([{ id: 5n, organizationId: ORG }]) },
        tenantDepartmentMember: {
          findMany: (args: { where: { id: { gt: bigint } }; take: number }) => {
            const after = args.where.id.gt;
            calls.push({ after, take: args.take });
            const rows = [];
            for (let id = after + 1n; id <= BigInt(total) && rows.length < args.take; id += 1n) {
              rows.push({ id, organizationId: ORG, address: `m${id}@corp.example`, user: null });
            }
            return Promise.resolve(rows);
          },
        },
      };
      return { db, calls };
    };
    const within = pages(25_001);
    const ok = await resolveScope(within.db as never, ORG, settings);
    expect(ok.truncated).toBe(false);
    expect(ok.scope.departmentAddresses).toHaveLength(25_001);
    expect(within.calls.map((c) => c.after)).toEqual([0n, 10_000n, 20_000n]);
    const beyond = pages(SCOPE_MAX_DEPARTMENT_MEMBERS + 5);
    const cut = await resolveScope(beyond.db as never, ORG, settings);
    expect(cut.truncated).toBe(true);
    expect(cut.scope.departmentAddresses).toHaveLength(SCOPE_MAX_DEPARTMENT_MEMBERS);
    // Reported once per settings generation: metric callback and a warn log.
    let reported = 0;
    const cache = new OrgContextCache(
      {
        ...beyond.db,
        organizationFeature: {
          findUnique: () =>
            Promise.resolve({ organizationId: ORG, featureKey: 'archiving', enabled: true }),
        },
        archiveSetting: {
          findUnique: () =>
            Promise.resolve({
              organizationId: ORG,
              enabled: true,
              settings: { scope: { mode: 'include', departmentIds: settings.scope.departmentIds } },
              generation: 2n,
              journalEnabledAt: new Date(0),
              objectLockMode: 'none',
              defaultRetentionPolicyId: 1n,
            }),
        },
      } as never,
      { ttlMs: 0, logger: silentLogger, onTruncated: () => (reported += 1) },
    );
    expect((await cache.get(ORG)).scopeTruncated).toBe(true);
    expect((await cache.get(ORG)).scopeTruncated).toBe(true);
    expect(reported).toBe(1);
  });

  it('OrgContextCache: entitlement and settings with defaults; an invalid document pauses journaling', async () => {
    const db = {
      organizationFeature: {
        findUnique: () =>
          Promise.resolve({ organizationId: ORG, featureKey: 'archiving', enabled: true }),
      },
      archiveSetting: {
        findUnique: () =>
          Promise.resolve({
            organizationId: ORG,
            enabled: true,
            settings: { bogus: 1 },
            generation: 4n,
            journalEnabledAt: new Date(0),
            objectLockMode: 'none',
            defaultRetentionPolicyId: 1n,
          }),
      },
    };
    const cache = new OrgContextCache(db as never, { ttlMs: 1_000, logger: silentLogger });
    const c = await cache.get(ORG);
    expect(c).toMatchObject({
      entitled: true,
      enabled: false,
      settingsValid: false,
      generation: 4n,
    });
    const none = new OrgContextCache(
      {
        organizationFeature: { findUnique: () => Promise.resolve(null) },
        archiveSetting: { findUnique: () => Promise.resolve(null) },
      } as never,
      { ttlMs: 1_000, logger: silentLogger },
    );
    expect(await none.get(ORG)).toMatchObject({
      entitled: false,
      enabled: false,
      objectLockMode: 'none',
      generation: 0n,
    });
  });
});

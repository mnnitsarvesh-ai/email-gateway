import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { IncidentCategoryRegistry, IncidentStore } from '@email-gateway/security-incidents';
import { atoIncidentHandler } from '../src/incident-handler';
import { ATO_TRANSACTION_ISOLATION, AtoStore } from '../src/store';
import { candidate, Fixtures, type Tx } from './support/fixtures';

/**
 * Regression (step 8.4 WP4): concurrent events of one hot account (a relay connector carries every
 * outbound message of its tenant) update the same `ato_account_activity_daily` row. The upsert used
 * `INSERT IGNORE` (a shared lock on the existing row) followed by `SELECT … FOR UPDATE`, so two
 * transactions upgrading their shared locks deadlocked (MySQL 1213, retried by the consumer with
 * a backoff: ~11 % of the events of the laptop volume run). `INSERT … ON DUPLICATE KEY UPDATE`
 * takes the exclusive lock at once: every concurrent update succeeds and none is lost.
 */
const fx = new Fixtures();
// eslint-disable-next-line prefer-const -- assigned after the registry that needs it lazily
let store: AtoStore;
const incidents = new IncidentStore({
  registry: new IncidentCategoryRegistry([atoIncidentHandler({ store: () => store })]),
});
store = new AtoStore({
  incidents,
  config: {
    approvalTtlHours: 24,
    automatedResponsesEnabled: true,
    maxAutomatedPerOrgPerHour: 10,
    maxActiveRestrictionsPerOrg: 500,
  },
});
let org: bigint;

beforeAll(async () => {
  org = await fx.organization('concurrency');
});

afterAll(async () => {
  await fx.cleanup();
});

describe('upsertActivityDay under concurrency', () => {
  it('32 concurrent transactions on one account-day: no deadlock, every delta counted', async () => {
    const at = new Date();
    const account = await fx.tx((tx) =>
      store.ensureAccount(tx, {
        organizationId: org,
        subject: { kind: 'smtp_connector', connectorId: 987_654_321n },
        at,
      }),
    );
    const results = await Promise.allSettled(
      Array.from({ length: 32 }, (_, i) =>
        fx.tx(async (tx) => {
          await store.upsertActivityDay(tx, {
            organizationId: org,
            accountId: account.id,
            delta: { at, messages: 1, recipients: 2, peer: `p${i % 4}` },
          });
          // Hold the row briefly, as the detection transaction does after the upsert.
          await tx.$queryRaw`SELECT SLEEP(0.005)`;
        }),
      ),
    );
    const failures = results.filter((r) => r.status === 'rejected');
    expect(failures).toEqual([]);
    const rows = await fx.prisma.atoAccountActivityDaily.findMany({
      where: { organizationId: org, accountId: account.id },
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ messages: 32, recipients: 64 });
    expect((rows[0]!.peers as { n: number }[]).reduce((s, p) => s + p.n, 0)).toBe(32);
  });
});

/**
 * Review round (step 8.4 closer): the store locks with `SELECT … FOR UPDATE` and then reads with
 * ordinary reads. Every ATO transaction pins READ COMMITTED (`ATO_TRANSACTION_ISOLATION`), so an
 * ordinary read after the lock wait sees what the lock holder committed, even when the transaction
 * already ran a consistent read before the lock (the ledger insert and `findAuthEvent` of the detect
 * transaction do). The interleaving is forced: B reads, A commits, B continues.
 */
describe('lock-then-read under the pinned isolation level', () => {
  const rc = <T>(fn: (tx: Tx) => Promise<T>): Promise<T> =>
    fx.prisma.$transaction(fn, {
      timeout: 120_000,
      maxWait: 30_000,
      isolationLevel: ATO_TRANSACTION_ISOLATION,
    });

  /** Runs B up to its first consistent read, then A to commit, then the rest of B. */
  async function interleave(
    a: (tx: Tx) => Promise<unknown>,
    b: (tx: Tx) => Promise<unknown>,
    accountId: bigint,
  ): Promise<void> {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let snapshotTaken!: () => void;
    const taken = new Promise<void>((resolve) => (snapshotTaken = resolve));
    const second = rc(async (tx) => {
      // A consistent (non-locking) read first, like the detect transaction's ledger insert.
      await tx.atoAccount.findUnique({ where: { id: accountId } });
      snapshotTaken();
      await gate;
      await b(tx);
    });
    await taken;
    await rc(a);
    release();
    await second;
  }

  it('an activity delta committed meanwhile is never lost', async () => {
    const at = new Date();
    const account = await fx.tx((tx) =>
      store.ensureAccount(tx, {
        organizationId: org,
        subject: { kind: 'smtp_connector', connectorId: 987_654_322n },
        at,
      }),
    );
    const delta = { at, messages: 1, recipients: 1 };
    await rc((tx) =>
      store.upsertActivityDay(tx, { organizationId: org, accountId: account.id, delta }),
    );
    await interleave(
      (tx) => store.upsertActivityDay(tx, { organizationId: org, accountId: account.id, delta }),
      (tx) => store.upsertActivityDay(tx, { organizationId: org, accountId: account.id, delta }),
      account.id,
    );
    const rows = await fx.prisma.atoAccountActivityDaily.findMany({
      where: { organizationId: org, accountId: account.id },
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ messages: 3, recipients: 3 });
  });

  it('a signal committed meanwhile is deduplicated, never recorded twice', async () => {
    const at = new Date();
    const account = await fx.tx((tx) =>
      store.ensureAccount(tx, {
        organizationId: org,
        subject: { kind: 'mailbox', address: fx.address('dedupe') },
        at,
      }),
    );
    const record = async (tx: Tx) => {
      const [locked] = await store.lockAccounts(tx, org, [account.id]);
      return store.recordSignals(tx, {
        organizationId: org,
        account: locked!,
        candidates: [candidate('ato.access.new_device', { subject: 'interleaved' })],
        settingsVersion: 1,
        at,
      });
    };
    await interleave(record, record, account.id);
    const signals = await fx.prisma.atoRiskSignal.findMany({
      where: { organizationId: org, accountId: account.id },
    });
    expect(signals).toHaveLength(1);
    expect(signals[0]!.occurrences).toBe(2);
  });
});

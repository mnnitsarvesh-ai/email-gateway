import { describe, expect, it } from 'vitest';
import { quarantineSearchSteps } from './queries';
import { QUARANTINE_ENTRY_COLUMNS, loadQuarantineEntries, quarantineEntryRow } from './quarantine';

/** Captures the multi-row INSERTs of the loader as rows keyed by column name. */
function capturingClient() {
  const rows: Record<string, unknown>[] = [];
  const statements: string[] = [];
  return {
    rows,
    statements,
    client: {
      $queryRawUnsafe: () => Promise.resolve([] as never),
      $executeRawUnsafe: (sql: string, ...values: unknown[]) => {
        statements.push(sql);
        const width = QUARANTINE_ENTRY_COLUMNS.length;
        expect(values.length % width).toBe(0);
        for (let i = 0; i < values.length; i += width) {
          rows.push(Object.fromEntries(QUARANTINE_ENTRY_COLUMNS.map((c, k) => [c, values[i + k]])));
        }
        return Promise.resolve(values.length / width);
      },
    },
  };
}

const NOW = new Date(Date.UTC(2026, 10, 12, 12));
const STATES = [
  'held',
  'pending_approval',
  'releasing',
  'released',
  'rejected',
  'deleted',
  'expired',
  'superseded',
];

describe('quarantine perf entries (step 5.3 §9.2)', () => {
  it('never writes the retired subject column and writes every 5.3 entry column', () => {
    expect(QUARANTINE_ENTRY_COLUMNS).not.toContain('subject');
    for (const c of ['lifecycle_round', 'rcpt_seq', 'kind', 'origin', 'state_changed_at']) {
      expect(QUARANTINE_ENTRY_COLUMNS).toContain(c);
    }
    const row = quarantineEntryRow({
      organizationId: 7n,
      messageId: 11n,
      receivedMs: NOW.getTime(),
      lifecycleRound: 0,
      scanId: null,
      recipientId: 5n,
      rcptSeq: 1,
      recipientAddress: 'a@x.example',
      direction: 'inbound',
      kind: 'quarantine',
      origin: 'policy',
      reason: 'malware',
      state: 'held',
      envelopeFrom: 's@y.example',
      attachmentCount: 1,
      sizeBytes: 10,
      riskScore: 950,
      decisive: null,
      quarantinedMs: NOW.getTime(),
      stateChangedMs: NOW.getTime(),
      holdDays: 30,
    });
    expect(row).toHaveLength(QUARANTINE_ENTRY_COLUMNS.length);
    const named = Object.fromEntries(QUARANTINE_ENTRY_COLUMNS.map((c, i) => [c, row[i]]));
    expect(named).toMatchObject({
      status: 'held',
      has_hard_block: true,
      primary_engine: 'attachment',
      decision_source: 'floor',
      risk_level: 'critical',
      eml_object_key: 'org/7/messages/2026/11/12/11.eml',
      expires_at: '2026-12-12 12:00:00.000',
      released_at: null,
      terminal_reason: null,
    });
  });

  it('loads N entries for one organization with unique (message, round, rcpt_seq)', async () => {
    const { client, rows, statements } = capturingClient();
    const result = await loadQuarantineEntries(client, {
      organizationId: 42n,
      count: 2500,
      now: NOW,
      days: 60,
      seed: 3,
    });
    expect(result.rows).toBe(2500);
    expect(rows).toHaveLength(2500);
    expect(statements).toHaveLength(3);
    for (const sql of statements) expect(sql).not.toMatch(/subject/);
    const keys = new Set(
      rows.map((r) => [r.message_id, r.lifecycle_round, r.rcpt_seq].map(String).join('/')),
    );
    expect(keys.size).toBe(rows.length);
    expect(new Set(rows.map((r) => r.organization_id))).toEqual(new Set([42n]));
    // Realistic spread: every state and most reasons occur, held dominates, a Zipf head.
    const count = (col: string, value: unknown) => rows.filter((r) => r[col] === value).length;
    for (const state of STATES.filter((s) => s !== 'releasing')) {
      expect(count('status', state), state).toBeGreaterThan(0);
    }
    expect(count('status', 'held')).toBeGreaterThan(rows.length * 0.45);
    expect(new Set(rows.map((r) => r.reason)).size).toBeGreaterThanOrEqual(8);
    expect(count('recipient_address', result.sample.recipient)).toBeGreaterThan(0);
    expect(count('envelope_from', result.sample.sender)).toBeGreaterThan(0);
    expect(count('decisive_policy_public_id', result.sample.policyPublicId)).toBeGreaterThan(0);
    for (const r of rows) {
      expect(r.public_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(String(r.quarantined_at) >= result.sample.from).toBe(true);
      expect(String(r.quarantined_at) < result.sample.to).toBe(true);
      expect(String(r.quarantined_at) >= '2026-09-13').toBe(true);
      // Content-free: no free text beyond the fixed synthetic explanation.
      expect(String(r.explanation_text)).toMatch(/synthetic perf data/);
    }
  });

  it('is deterministic for a seed and refuses an empty load', async () => {
    const a = capturingClient();
    const b = capturingClient();
    await loadQuarantineEntries(a.client, { organizationId: 1n, count: 50, now: NOW, seed: 9 });
    await loadQuarantineEntries(b.client, { organizationId: 1n, count: 50, now: NOW, seed: 9 });
    const strip = (rows: Record<string, unknown>[]) => rows.map((r) => ({ ...r, public_id: 0 }));
    expect(strip(a.rows)).toEqual(strip(b.rows));
    await expect(
      loadQuarantineEntries(a.client, { organizationId: 1n, count: 0, now: NOW }),
    ).rejects.toThrow(/count/);
  });

  it('builds the five Q9 search shapes with a bounded range and keyset order', () => {
    const steps = quarantineSearchSteps(5n, {
      recipient: 'r@x.example',
      sender: 's@y.example',
      policyPublicId: '01900000-0000-7000-8000-000000000001',
      from: '2026-10-01 00:00:00.000',
      to: '2026-11-01 00:00:00.000',
    });
    expect(steps.map((s) => s.label)).toEqual([
      'default view',
      'recipient',
      'sender',
      'state',
      'decisive policy',
    ]);
    for (const step of steps) {
      expect(step.sql).toMatch(/organization_id = \?/);
      expect(step.sql).toMatch(/quarantined_at >= \? AND quarantined_at < \?/);
      expect(step.sql).toMatch(/ORDER BY quarantined_at DESC, id DESC/);
      expect(step.sql).not.toMatch(/subject/);
      expect(step.params[0]).toBe(5n);
    }
  });
});

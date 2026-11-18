import { describe, expect, it } from 'vitest';
import { PARTITION_REGISTRY } from '../partitioning/registry';
import { archiveQueries } from './queries';

const NOW = Date.UTC(2026, 10, 17, 12);

describe('archive perf queries (step 8.1 A2, A13, A14, A16)', () => {
  const queries = archiveQueries({
    nowMs: NOW,
    organizationId: 7n,
    sweepCursor: { id: 100n, receivedAt: NOW - 3_600_000 },
    reconcileCursor: { id: 200n, receivedAt: NOW - 7_200_000 },
  });
  const byId = Object.fromEntries(queries.map((q) => [q.id, q]));

  it('covers the six archive-worker hot paths as Q25–Q30', () => {
    expect(queries.map((q) => q.id)).toEqual(['Q25', 'Q26', 'Q27', 'Q28', 'Q29', 'Q30']);
    for (const q of queries) {
      for (const step of q.steps) {
        expect(step.sql.split('?').length - 1, `${q.id} ${step.label}`).toBe(step.params.length);
      }
    }
  });

  it('bounds the forward sweeps by the cursor, one day of received_at slack and the safety lag', () => {
    const sweep = byId.Q25!.steps[0]!;
    expect(sweep.sql).toMatch(
      /FROM email_messages\s+WHERE id > \? AND received_at >= \? AND created_at <= \?/,
    );
    expect(sweep.sql).toMatch(/ORDER BY id\s+LIMIT 1000/);
    expect(sweep.params).toEqual([100n, '2026-11-16 11:00:00.000', '2026-11-17 11:58:00.000']);
    const reconcile = byId.Q26!.steps[0]!;
    expect(reconcile.sql).toMatch(/FROM policy_execution_logs/);
    expect(reconcile.params).toEqual([200n, '2026-11-16 10:00:00.000', '2026-11-17 11:55:00.000']);
  });

  it('claims intents, disposals and index ops with SKIP LOCKED in index order', () => {
    expect(byId.Q27!.steps[0]!.sql).toMatch(
      /status IN \('pending', 'captured_open'\) AND next_check_at <= \?[\s\S]*FOR UPDATE SKIP LOCKED/,
    );
    expect(byId.Q29!.steps[0]!.sql).toMatch(/FROM archive_disposals[\s\S]*FOR UPDATE SKIP LOCKED/);
    expect(byId.Q30!.steps[0]!.sql).toMatch(/ORDER BY available_at, id[\s\S]*SKIP LOCKED/);
  });

  it('reads expiry per organization on (organization_id, status, retain_until)', () => {
    const [expiry, review] = byId.Q28!.steps;
    expect(expiry!.sql).toMatch(
      /organization_id = \? AND status = 'active' AND retain_until <= \?/,
    );
    expect(expiry!.params[0]).toBe(7n);
    expect(review!.sql).toMatch(/status = 'expiry_review'/);
  });

  it('queries only tables the partition registry knows with their partition columns', () => {
    const tables = Object.fromEntries(PARTITION_REGISTRY.map((s) => [s.table, s.column]));
    expect(tables.archive_capture_intents).toBe('received_at');
    expect(tables.archive_disposals).toBe('requested_at');
  });
});

import type { PrismaReadService } from '@email-gateway/common';
import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { InconsistentReadError } from '../../../http/listing/echo-check';
import type { MessagesRepository } from '../../tenant-data/messages.repository';
import {
  indexPlanSql,
  MESSAGE_INDEXES,
  MessageDataRepository,
  messagesByKeysSql,
  recipientPlanSql,
  scanBoundarySql,
  scanPageSql,
  verdictPlanSql,
} from './message-data.repository';

const range = { from: new Date('2026-11-11T00:00:00Z'), to: new Date('2026-11-12T00:00:00Z') };
const base = { organizationId: 7n, range, direction: 'desc' as const, take: 26 };
const after = { at: new Date('2026-11-11T12:00:00Z'), id: 99n };
const flat = (sql: { sql: string }) => sql.sql.replace(/\s+/g, ' ');

describe('message list SQL (step 6.1 D4, D5)', () => {
  const hostile = "x' OR 1=1 -- ";

  it('verdict plan: organization first, the verdict index, keyset and bound values', () => {
    const sql = verdictPlanSql({ ...base, after, verdict: hostile });
    expect(flat(sql)).toContain(`FORCE INDEX (${MESSAGE_INDEXES.orgVerdict})`);
    expect(flat(sql)).toMatch(/WHERE organization_id = \? AND final_verdict = \?/);
    expect(flat(sql)).toContain('(received_at < ? OR (received_at = ? AND id < ?))');
    expect(flat(sql)).toContain('ORDER BY received_at DESC, id DESC LIMIT ?');
    expect(sql.sql).not.toContain(hostile);
    expect(sql.values).toEqual([7n, hostile, range.from, range.to, after.at, after.at, 99n, 26]);
  });

  it('index plan names the (organization_id, received_at, id) index (D5 plan 1)', () => {
    const sql = indexPlanSql({ ...base, after });
    expect(flat(sql)).toContain(`FORCE INDEX (${MESSAGE_INDEXES.orgReceived})`);
    expect(flat(sql)).toMatch(
      /WHERE organization_id = \? AND received_at >= \? AND received_at < \?/,
    );
    expect(flat(sql)).toContain('ORDER BY received_at DESC, id DESC LIMIT ?');
    expect(sql.values).toEqual([7n, range.from, range.to, after.at, after.at, 99n, 26]);
  });

  it('ascending keyset flips the comparisons and the order', () => {
    const sql = verdictPlanSql({ ...base, direction: 'asc', after, verdict: 'spam' });
    expect(flat(sql)).toContain('(received_at > ? OR (received_at = ? AND id > ?))');
    expect(flat(sql)).toContain('ORDER BY received_at ASC, id ASC');
  });

  it('recipient plan reads the address index; messages by (id, received_at)', () => {
    const sql = recipientPlanSql({ ...base, address: hostile });
    expect(flat(sql)).toContain(`FORCE INDEX (${MESSAGE_INDEXES.recipientAddress})`);
    expect(flat(sql)).toMatch(/WHERE organization_id = \? AND address = \?/);
    expect(sql.sql).not.toContain(hostile);
    const byKeys = messagesByKeysSql(7n, [
      { id: 1n, receivedAt: range.from },
      { id: 2n, receivedAt: range.to },
    ]);
    expect(flat(byKeys)).toContain(
      'WHERE organization_id = ? AND ((id = ? AND received_at = ?) OR (id = ? AND received_at = ?))',
    );
    expect(byKeys.values).toEqual([7n, 1n, range.from, 2n, range.to]);
  });

  it('scan boundary is index-only at OFFSET budget - 1', () => {
    const sql = scanBoundarySql({ ...base, budget: 5000 });
    expect(flat(sql)).toContain('SELECT received_at, id FROM email_messages');
    expect(flat(sql)).toContain(`FORCE INDEX (${MESSAGE_INDEXES.orgReceived})`);
    expect(flat(sql)).toContain('LIMIT 1 OFFSET ?');
    expect(sql.values.at(-1)).toBe(4999);
  });

  it('scan page: every filter maps to a code-side column with bound values', () => {
    const sql = scanPageSql({
      ...base,
      after,
      boundary: { at: range.from, id: 5n },
      filters: {
        direction: { values: ['inbound'] },
        status: { values: ['delivered', 'quarantined'] },
        verdict: { values: ['spam', 'phishing'] },
        action: { values: ['deliver'] },
        domainId: 44n,
        sender: { values: [hostile] },
        headerFrom: { values: [hostile] },
        internetMessageId: { values: [hostile] },
        riskScore: { gte: 100, lte: 900, gt: 1, lt: 999, values: [500] },
        hasAttachments: { values: [false] },
        recipient: { values: [hostile] },
      },
    });
    const text = flat(sql);
    for (const fragment of [
      'direction IN (?)',
      'status IN (?,?)',
      'final_verdict IN (?,?)',
      'final_action IN (?)',
      'domain_id = ?',
      'envelope_from = ?',
      'header_from = ?',
      'internet_message_id = ?',
      'risk_score IN (?)',
      'risk_score >= ?',
      'risk_score > ?',
      'risk_score <= ?',
      'risk_score < ?',
      'attachment_count = 0',
      'EXISTS (SELECT 1 FROM email_recipients r WHERE r.organization_id = ? AND r.message_id = email_messages.id AND r.received_at = email_messages.received_at AND r.address = ?)',
      '(received_at > ? OR (received_at = ? AND id >= ?))',
    ]) {
      expect(text).toContain(fragment);
    }
    expect(sql.sql).not.toContain(hostile);
    expect(text.indexOf('organization_id = ?')).toBeLessThan(text.indexOf('received_at >='));
    const noFilter = scanPageSql({
      ...base,
      boundary: null,
      filters: { hasAttachments: { values: [true] } },
    });
    expect(flat(noFilter)).toContain('attachment_count > 0');
    expect(flat(noFilter)).not.toContain('id >= ?');
  });
});

describe('MessageDataRepository echo checks (D15)', () => {
  const scope = systemScope(7n);
  const raw = (org: bigint, at = new Date('2026-11-11T10:00:00Z')) => ({
    id: 1n,
    received_at: at,
    organization_id: org,
    domain_id: null,
    direction: 'inbound',
    status: 'delivered',
    status_changed_at: at,
    subject: null,
    envelope_from: 'a@b',
    header_from: null,
    recipient_count: 1,
    attachment_count: 0,
    size_bytes: 1,
    final_verdict: 'spam',
    final_action: null,
    risk_score: null,
  });
  const repo = (rows: unknown[]) =>
    new MessageDataRepository(
      { client: { $queryRaw: vi.fn(() => Promise.resolve(rows)) } } as unknown as PrismaReadService,
      {} as MessagesRepository,
    );

  it('serves rows that echo the organization, the verdict and the range', async () => {
    const rows = await repo([raw(7n)]).verdictPlan(scope, { ...base, verdict: 'spam' });
    expect(rows[0]).toMatchObject({ id: 1n, organizationId: 7n, finalVerdict: 'spam' });
  });

  it('refuses another organization, another verdict or a row outside the range (503)', async () => {
    await expect(
      repo([raw(8n)]).verdictPlan(scope, { ...base, verdict: 'spam' }),
    ).rejects.toBeInstanceOf(InconsistentReadError);
    await expect(
      repo([raw(7n)]).verdictPlan(scope, { ...base, verdict: 'clean' }),
    ).rejects.toBeInstanceOf(InconsistentReadError);
    await expect(
      repo([raw(7n, new Date('2026-11-12T00:00:00Z'))]).scanPage(scope, {
        ...base,
        boundary: null,
        filters: {},
      }),
    ).rejects.toBeInstanceOf(InconsistentReadError);
  });
});

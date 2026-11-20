import { describe, expect, it } from 'vitest';
import {
  FOREIGN_DRIVERS,
  foreignBoundarySql,
  foreignKeysSql,
  foreignPageSql,
  MESSAGE_INDEXES,
  messagesBoundarySql,
  messagesByKeysSql,
  MESSAGES_DRIVERS,
  messagesPageSql,
  maxExecutionTime,
  prefixPageSql,
  prefixProbeSql,
  recipientBoundarySql,
  recipientPageSql,
  recipientRowsSql,
  residualSql,
} from './message-list-drivers';

const range = { from: new Date('2026-11-11T00:00:00Z'), to: new Date('2026-11-12T00:00:00Z') };
const nonce = 'nonce-1';
const base = { organizationId: 7n, range, direction: 'desc' as const, nonce };
const after = { at: new Date('2026-11-11T12:00:00Z'), id: 99n };
const flat = (sql: { sql: string }) => sql.sql.replace(/\s+/g, ' ');
const hostile = "x' OR 1=1 -- ";

describe('email_messages drivers (step 7.2 §3.2)', () => {
  it('none: the 6.1 index plan over (organization_id, received_at, id), nonce first', () => {
    const sql = messagesPageSql({ ...base, driver: 'none', take: 26, after });
    const text = flat(sql);
    expect(text).toContain(`FORCE INDEX (${MESSAGE_INDEXES.orgReceived})`);
    expect(text).toMatch(
      /WHERE m\.organization_id = \? AND m\.received_at >= \? AND m\.received_at < \?/,
    );
    expect(text).toContain('(m.received_at < ? OR (m.received_at = ? AND m.id < ?))');
    expect(text).toContain('ORDER BY m.received_at DESC, m.id DESC LIMIT ?');
    expect(text).toMatch(/^SELECT \? AS echo_nonce, m\.id, m\.received_at/);
    expect(sql.values).toEqual([nonce, 7n, range.from, range.to, after.at, after.at, 99n, 26]);
  });

  it.each([
    ['internetMessageId', MESSAGE_INDEXES.messageIdKey, 'm.message_id_key'],
    ['sender', MESSAGE_INDEXES.envelopeFrom, 'm.envelope_from'],
    ['headerFrom', MESSAGE_INDEXES.headerFrom, 'm.header_from'],
    ['subject', MESSAGE_INDEXES.subjectKey, 'm.subject_key'],
    ['senderDomain', MESSAGE_INDEXES.senderDomain, 'm.sender_domain'],
    ['verdict', MESSAGE_INDEXES.orgVerdict, 'm.final_verdict'],
  ] as const)(
    '%s: organization, key equality, range, keyset; values bound',
    (driver, index, key) => {
      expect(MESSAGES_DRIVERS[driver]).toEqual({ index, key });
      const sql = messagesPageSql({ ...base, driver, key: hostile, take: 26, after });
      const text = flat(sql);
      expect(text).toContain(`FORCE INDEX (${index})`);
      expect(text).toContain(`WHERE m.organization_id = ? AND ${key} = ? AND m.received_at >= ?`);
      expect(text).not.toContain('LIKE');
      expect(sql.sql).not.toContain(hostile);
      expect(sql.values).toEqual([
        nonce,
        7n,
        hostile,
        range.from,
        range.to,
        after.at,
        after.at,
        99n,
        26,
      ]);
    },
  );

  it('a key is required exactly for the keyed drivers (programming error otherwise)', () => {
    expect(() => messagesPageSql({ ...base, driver: 'sender', take: 2 })).toThrow(/key mismatch/);
    expect(() => messagesPageSql({ ...base, driver: 'scan', key: 'x', take: 2 })).toThrow();
  });

  it('ascending keyset flips the comparisons and the order', () => {
    const text = flat(
      messagesPageSql({
        ...base,
        direction: 'asc',
        driver: 'verdict',
        key: 'spam',
        after,
        take: 3,
      }),
    );
    expect(text).toContain('(m.received_at > ? OR (m.received_at = ? AND m.id > ?))');
    expect(text).toContain('ORDER BY m.received_at ASC, m.id ASC');
  });

  it('budgeted: boundary at OFFSET budget − 1 over the driver index; page up to the boundary with residuals', () => {
    const boundary = messagesBoundarySql({ ...base, driver: 'subject', key: 'k', budget: 5000 });
    const b = flat(boundary);
    expect(b).toContain('SELECT ? AS echo_nonce, m.organization_id, m.received_at, m.id FROM');
    expect(b).toContain(`FORCE INDEX (${MESSAGE_INDEXES.subjectKey})`);
    expect(b).toContain('LIMIT 1 OFFSET ?');
    expect(boundary.values.at(-1)).toBe(4999);
    const page = messagesPageSql({
      ...base,
      driver: 'scan',
      take: 26,
      boundary: { at: range.from, id: 5n },
      residuals: residualSql(7n, { direction: ['inbound'] }),
    });
    const text = flat(page);
    expect(text).toContain(`FORCE INDEX (${MESSAGE_INDEXES.orgReceived})`);
    expect(text).toContain('(m.received_at > ? OR (m.received_at = ? AND m.id >= ?))');
    expect(text).toContain('m.direction IN (?)');
    expect(text.indexOf('m.organization_id = ?')).toBeLessThan(text.indexOf('m.received_at >='));
  });
});

describe('residual predicates (step 7.2 §3.2)', () => {
  it('maps every residual to a fixed fragment with bound values', () => {
    const parts = residualSql(7n, {
      direction: ['inbound'],
      status: ['delivered', 'quarantined'],
      verdict: ['spam', 'phishing'],
      action: ['deliver'],
      domainId: 44n,
      sender: hostile,
      headerFrom: hostile,
      messageIdKey: hostile,
      subjectKey: hostile,
      subjectPrefixPattern: `${hostile}%`,
      senderDomain: hostile,
      riskScore: { gte: 100, lte: 900, gt: 1, lt: 999, values: [500] },
      hasAttachments: false,
      recipient: hostile,
      recipientDomain: hostile,
      deliveryStatus: 'bounced',
      quarantineStatus: 'held',
    });
    const text = parts.map(flat).join(' AND ');
    for (const fragment of [
      'm.direction IN (?)',
      'm.status IN (?,?)',
      'm.final_verdict IN (?,?)',
      'm.final_action IN (?)',
      'm.domain_id = ?',
      'm.envelope_from = ?',
      'm.header_from = ?',
      'm.message_id_key = ?',
      'm.subject_key = ?',
      "m.subject_key LIKE ? ESCAPE '!'",
      'm.sender_domain = ?',
      'm.risk_score IN (?)',
      'm.risk_score >= ?',
      'm.risk_score > ?',
      'm.risk_score <= ?',
      'm.risk_score < ?',
      'm.attachment_count = 0',
      'EXISTS (SELECT 1 FROM email_recipients r WHERE r.organization_id = ? AND r.message_id = m.id AND r.received_at = m.received_at AND r.address = ?)',
      'EXISTS (SELECT 1 FROM email_recipients r WHERE r.organization_id = ? AND r.message_id = m.id AND r.received_at = m.received_at AND r.address_domain = ?)',
      'EXISTS (SELECT 1 FROM email_deliveries d WHERE d.organization_id = ? AND d.message_id = m.id AND d.received_at = m.received_at AND d.status = ?)',
      'EXISTS (SELECT 1 FROM quarantine_messages q WHERE q.organization_id = ? AND q.message_id = m.id AND q.message_received_at = m.received_at AND q.status = ?)',
    ]) {
      expect(text).toContain(fragment);
    }
    expect(parts.map((p) => p.sql).join(' ')).not.toContain(hostile);
    expect(residualSql(7n, { hasAttachments: true }).map(flat)).toEqual(['m.attachment_count > 0']);
    expect(residualSql(7n, {})).toEqual([]);
  });
});

describe('recipient driver (step 6.1 plan 3; step 7.2 budgeted)', () => {
  it('exact: the address index, keyset (received_at, recipient id)', () => {
    const sql = recipientRowsSql({ ...base, address: hostile, take: 26 });
    const text = flat(sql);
    expect(text).toContain(`FORCE INDEX (${MESSAGE_INDEXES.recipientAddress})`);
    expect(text).toMatch(/WHERE r\.organization_id = \? AND r\.address = \?/);
    expect(text).toContain('ORDER BY r.received_at DESC, r.id DESC LIMIT ?');
    expect(sql.sql).not.toContain(hostile);
  });

  it('budgeted: boundary over the address index; page joins recipients first and orders by the recipient keyset', () => {
    const boundary = flat(recipientBoundarySql({ ...base, address: 'a@b', budget: 10 }));
    expect(boundary).toContain(`FORCE INDEX (${MESSAGE_INDEXES.recipientAddress})`);
    expect(boundary).toContain('LIMIT 1 OFFSET ?');
    const page = recipientPageSql({
      ...base,
      address: 'a@b',
      take: 26,
      after,
      boundary: { at: range.from, id: 5n },
      residuals: residualSql(7n, { verdict: ['spam'] }),
    });
    const text = flat(page);
    expect(text).toContain(', k.id AS rid FROM (SELECT r.id, r.received_at, r.message_id');
    expect(text).toContain(
      'STRAIGHT_JOIN email_messages m ON m.id = k.message_id AND m.received_at = k.received_at',
    );
    expect(text).toContain('(r.received_at > ? OR (r.received_at = ? AND r.id >= ?))');
    expect(text).toContain('m.final_verdict IN (?)');
    expect(text).toContain('ORDER BY k.received_at DESC, k.id DESC LIMIT ?');
  });

  it('messages by (id, received_at) as an OR of pairs', () => {
    const sql = messagesByKeysSql(7n, [
      { id: 1n, receivedAt: range.from },
      { id: 2n, receivedAt: range.to },
    ]);
    expect(flat(sql)).toContain(
      "WHERE m.organization_id = ? AND m.ingest_source = 'gateway' AND ((m.id = ? AND m.received_at = ?) OR (m.id = ? AND m.received_at = ?))",
    );
    expect(sql.values).toEqual([7n, 1n, range.from, 2n, range.to]);
    expect(() => messagesByKeysSql(7n, [])).toThrow();
  });
});

describe('foreign drivers (step 7.2 §3.2)', () => {
  it.each([
    [
      'recipientDomain',
      'email_recipients',
      MESSAGE_INDEXES.recipientDomain,
      't.address_domain',
      't.received_at',
    ],
    [
      'deliveryStatus',
      'email_deliveries',
      MESSAGE_INDEXES.deliveryStatus,
      't.status',
      't.received_at',
    ],
    [
      'quarantineStatus',
      'quarantine_messages',
      MESSAGE_INDEXES.quarantineStatus,
      't.status',
      't.message_received_at',
    ],
  ] as const)(
    '%s: grouped (time, message_id) keys in index order',
    (driver, table, index, key, time) => {
      expect(FOREIGN_DRIVERS[driver]).toMatchObject({ table, index, key, time });
      const sql = foreignKeysSql({ ...base, driver, key: hostile, take: 26, after });
      const text = flat(sql);
      expect(text).toContain(`FROM ${table} t FORCE INDEX (${index})`);
      expect(text).toContain(
        `WHERE t.organization_id = ? AND ${key} = ? AND ${time} >= ? AND ${time} < ?`,
      );
      expect(text).toContain(`(${time} < ? OR (${time} = ? AND t.message_id < ?))`);
      expect(text).toContain(`GROUP BY t.organization_id, ${key}, ${time}, t.message_id`);
      expect(text).toContain(`ORDER BY ${time} DESC, t.message_id DESC LIMIT ?`);
      expect(sql.sql).not.toContain(hostile);

      const boundary = flat(foreignBoundarySql({ ...base, driver, key: 'k', budget: 100 }));
      expect(boundary).toContain(`FORCE INDEX (${index})`);
      expect(boundary).not.toContain('GROUP BY');
      expect(boundary).toContain('LIMIT 1 OFFSET ?');

      const page = flat(
        foreignPageSql({
          ...base,
          driver,
          key: 'k',
          take: 26,
          boundary: { at: range.from, id: 5n },
          residuals: residualSql(7n, { direction: ['inbound'] }),
        }),
      );
      expect(page).toContain(`GROUP BY ${time}, t.message_id) k STRAIGHT_JOIN email_messages m`);
      expect(page).toContain(`(${time} > ? OR (${time} = ? AND t.message_id >= ?))`);
      expect(page).toContain('m.direction IN (?)');
      expect(page).toContain('ORDER BY m.received_at DESC, m.id DESC LIMIT ?');
    },
  );
});

describe('subject prefix driver (step 7.2 §2 E1)', () => {
  it('probe: MAX_EXECUTION_TIME, the subject-key index, LIKE with the ! escape, the (cap + 1)-th entry', () => {
    const sql = prefixProbeSql({ ...base, pattern: 'Inv!%%', cap: 5000, timeoutMs: 5000 });
    const text = flat(sql);
    expect(text).toMatch(
      /^SELECT \/\*\+ MAX_EXECUTION_TIME\(5000\) \*\/ \? AS echo_nonce, m\.organization_id, m\.received_at, m\.id/,
    );
    expect(text).toContain(`FORCE INDEX (${MESSAGE_INDEXES.subjectKey})`);
    expect(text).toContain("m.subject_key LIKE ? ESCAPE '!'");
    expect(text).not.toContain('ORDER BY');
    expect(text).toMatch(/LIMIT 1 OFFSET \?$/);
    expect(sql.values).toContain('Inv!%%');
    expect(sql.values.at(-1)).toBe(5000);
    expect(() => prefixProbeSql({ ...base, pattern: 'x%', cap: 0, timeoutMs: 1 })).toThrow();
  });

  it('page: the same predicate plus residuals, sorted, LIMIT limit + 1', () => {
    const text = flat(
      prefixPageSql({
        ...base,
        pattern: 'Inv%',
        take: 26,
        timeoutMs: 1234,
        residuals: residualSql(7n, { senderDomain: 'b.example' }),
      }),
    );
    expect(text).toMatch(/^SELECT \/\*\+ MAX_EXECUTION_TIME\(1234\) \*\//);
    expect(text).toContain("m.subject_key LIKE ? ESCAPE '!'");
    expect(text).toContain('m.sender_domain = ?');
    expect(text).toContain('ORDER BY m.received_at DESC, m.id DESC LIMIT ?');
  });

  it('refuses a non-integer timeout (programming error)', () => {
    expect(() => maxExecutionTime(0)).toThrow();
    expect(() => maxExecutionTime(1.5)).toThrow();
    expect(maxExecutionTime(5).sql).toBe('/*+ MAX_EXECUTION_TIME(5) */');
  });
});

describe('gateway views exclude journal intake messages (step 8.6 D5)', () => {
  const GATEWAY = "m.ingest_source = 'gateway'";
  const boundary = { at: new Date('2026-11-11T06:00:00Z'), id: 5n };

  it('every page and key read carries the gateway predicate (no bound value)', () => {
    const pages = [
      messagesPageSql({ ...base, driver: 'none', take: 26, after }),
      messagesPageSql({ ...base, driver: 'verdict', key: 'malicious', take: 26, boundary }),
      recipientPageSql({ ...base, address: 'a@example.com', take: 26, boundary, residuals: [] }),
      foreignPageSql({
        ...base,
        driver: Object.keys(FOREIGN_DRIVERS)[0] as keyof typeof FOREIGN_DRIVERS,
        key: 'k',
        take: 26,
        boundary,
        residuals: [],
      }),
      messagesByKeysSql(7n, [{ id: 1n, receivedAt: range.from }]),
      prefixPageSql({ ...base, pattern: 'abc%', take: 26, timeoutMs: 1000, residuals: [] }),
    ];
    for (const sql of pages) {
      expect(flat(sql)).toContain(GATEWAY);
      expect(sql.values).not.toContain('gateway');
    }
  });

  it('the index-only budget boundaries do not (they bound a scan, not the result)', () => {
    expect(flat(messagesBoundarySql({ ...base, driver: 'none', budget: 100 }))).not.toContain(
      GATEWAY,
    );
    expect(
      flat(recipientBoundarySql({ ...base, address: 'a@example.com', budget: 100 })),
    ).not.toContain(GATEWAY);
  });
});

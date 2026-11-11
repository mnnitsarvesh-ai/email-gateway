import { Prisma } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { FakeRiskDb, MESSAGE, ORG, RECEIVED, round, SCAN } from './fakes.test-support';
import { decimalText, InconsistentRiskReadError, jsonColumn, RiskRoundReader } from './risk-reader';

function withRows() {
  const db = new FakeRiskDb();
  db.addFinal({
    engine: 'rspamd',
    outcome: 'clean',
    reasonCodes: ['clean.below_threshold'],
    score: '1.500',
  });
  db.addFinal({ engine: 'bec', outcome: 'clean', reasonCodes: ['clean.below_threshold'] });
  db.addFinal({ engine: 'dlp', outcome: 'clean', reasonCodes: ['dlp.no_findings'] });
  db.addAuth();
  const scope = { scan_id: SCAN, received_at: RECEIVED, message_id: MESSAGE, organization_id: ORG };
  db.bec.push({
    ...scope,
    lifecycle_round: 0,
    deterministic_verdict: 'clean',
    verdict: 'clean',
    rules: '[]',
  });
  db.dlp.push({
    ...scope,
    lifecycle_round: 0,
    action: 'allow',
    verdict: 'clean',
    coverage: 'complete',
    categories: [],
  });
  return db;
}

const R = round({ requiredEngines: ['bec', 'dlp', 'rspamd'] });

describe('RiskRoundReader (step 5.1 R12, §6)', () => {
  it('assembles RoundRows from the round, the message, the finals and the child rows', async () => {
    const db = withRows();
    const reader = new RiskRoundReader();
    const finals = await reader.lockedFinals(db.tx(), R);
    expect(finals.map((f) => f.engine).sort()).toEqual(['bec', 'dlp', 'rspamd']);
    expect(finals.find((f) => f.engine === 'rspamd')).toMatchObject({
      score: '1.5',
      reasonCodes: ['clean.below_threshold'],
      completedAt: expect.any(Date) as Date,
    });
    const rows = await reader.read(db.tx(), R, 'completed', finals);
    expect(rows).toMatchObject({
      scan: { requiredEngines: ['bec', 'dlp', 'rspamd'], scanKind: 'initial', status: 'completed' },
      message: { direction: 'inbound', attachmentCount: 0, recipientCount: 1 },
      auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', arc: 'none' },
      bec: { deterministicVerdict: 'clean', verdict: 'clean', rules: [] },
      dlp: { action: 'allow', verdict: 'clean', coverage: 'complete', categories: [] },
    });
  });

  it('reads no child row for an engine without a final', async () => {
    const db = withRows();
    const reader = new RiskRoundReader();
    const rows = await reader.read(db.tx(), R, 'completed', []);
    expect(rows).toMatchObject({ auth: null, bec: null, dlp: null });
  });

  it('missing child rows stay null (the builder adds risk.input.<engine>_row_missing)', async () => {
    const db = withRows();
    db.auth = [];
    db.bec = [];
    db.dlp = [];
    const reader = new RiskRoundReader();
    const rows = await reader.read(db.tx(), R, 'completed', await reader.lockedFinals(db.tx(), R));
    expect(rows).toMatchObject({ auth: null, bec: null, dlp: null });
  });

  it('returns null when the message row is gone (nothing to score)', async () => {
    const db = withRows();
    db.messages = [];
    expect(await new RiskRoundReader().read(db.tx(), R, 'completed', [])).toBeNull();
  });

  it('every echo mismatch of a child row is a retryable wrong read, counted by read', async () => {
    const cases: Array<[string, string, Record<string, unknown>]> = [
      ['email_auth_results', 'auth', { organization_id: 8n }],
      ['email_auth_results', 'auth', { message_id: 12n }],
      ['email_auth_results', 'auth', { received_at: new Date(RECEIVED.getTime() + 1) }],
      ['email_auth_results', 'auth', { engine: 'other' }],
      ['bec_scan_results', 'bec', { scan_id: 99n }],
      ['bec_scan_results', 'bec', { lifecycle_round: 1 }],
      ['dlp_scan_results', 'dlp', { organization_id: 8n }],
      ['dlp_scan_results', 'dlp', { lifecycle_round: 3 }],
      ['scan_engine_results', 'finals', { scan_id: 99n }],
      ['scan_engine_results', 'finals', { message_id: 99n }],
    ];
    for (const [table, read, forged] of cases) {
      const db = withRows();
      db.tamper = (t, rows) => (t === table ? rows.map((r) => ({ ...r, ...forged })) : rows);
      const seen: string[] = [];
      const reader = new RiskRoundReader((r) => seen.push(r));
      const attempt = async () => {
        const finals =
          table === 'scan_engine_results'
            ? await reader.lockedFinals(db.tx(), R)
            : await new RiskRoundReader().lockedFinals(db.tx(), R);
        return reader.read(db.tx(), R, 'completed', finals);
      };
      await expect(attempt(), `${table} ${JSON.stringify(Object.keys(forged))}`).rejects.toThrow(
        InconsistentRiskReadError,
      );
      expect(seen).toEqual([read]);
    }
  });

  it('two rows for a unique child key are a wrong read', async () => {
    const db = withRows();
    db.dlp.push({ ...db.dlp[0]! });
    const reader = new RiskRoundReader();
    await expect(
      reader.read(db.tx(), R, 'completed', await reader.lockedFinals(db.tx(), R)),
    ).rejects.toMatchObject({
      read: 'dlp',
    });
  });

  it('a message row of another organization or time is a wrong read', async () => {
    for (const forged of [{ organizationId: 8n }, { receivedAt: new Date(0) }, { id: 99n }]) {
      const db = withRows();
      const tx = db.tx();
      (tx.emailMessage as unknown as { findFirst: unknown }).findFirst = () =>
        Promise.resolve({ ...db.messages[0], ...forged });
      await expect(new RiskRoundReader().read(tx, R, 'completed', [])).rejects.toMatchObject({
        read: 'message',
      });
    }
  });

  it('lockRound echoes the scan row and returns its snapshot and status', async () => {
    const db = withRows();
    db.scan.risk_profile_version_id = 501n;
    db.scan.status = 'completed';
    const reader = new RiskRoundReader();
    const ref = { scanId: SCAN, receivedAt: RECEIVED, organizationId: ORG, messageId: MESSAGE };
    expect(await reader.lockRound(db.tx(), ref)).toMatchObject({
      status: 'completed',
      riskProfileVersionId: 501n,
      requiredEngines: ['rspamd'],
      round: 0,
    });
    await expect(reader.lockRound(db.tx(), { ...ref, organizationId: 8n })).rejects.toMatchObject({
      read: 'scan',
    });
    db.scans = [];
    expect(await reader.lockRound(db.tx(), ref)).toBeNull();
  });

  it('normalizes decimals and JSON text so both read paths hash alike', () => {
    expect(decimalText('1.500')).toBe('1.5');
    expect(decimalText(12)).toBe('12');
    expect(decimalText(new Prisma.Decimal('0.100'))).toBe('0.1');
    expect(decimalText({ unrelated: true })).toBeNull();
    expect(decimalText(null)).toBeNull();
    expect(jsonColumn('["a"]')).toEqual(['a']);
    expect(jsonColumn(['a'])).toEqual(['a']);
    expect(jsonColumn('{oops')).toBe('{oops');
  });
});

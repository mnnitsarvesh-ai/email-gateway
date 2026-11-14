// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { createMockFetch, mergedFixtures } from '@/server/dev-mocks';
import { DEV_MOCK_MARKER } from '../types';
import { fixtureDataset, type FixtureMessage } from './message-dataset';
import * as detailsData from './message-details-data';
import { FIXTURE_REVEALS_PER_MINUTE } from './messages';

/** Step 7.2 WP4 dev fixtures: the Email Details operations (§2 E14, details part). */
const API = 'http://api.test:3000';
const fetchImpl = createMockFetch(mergedFixtures());
const ADDRESS = /[\p{L}\p{N}._%+-]{2,}@[a-z0-9-]+(?:\.[a-z0-9-]+)+/u;

async function login(email: string): Promise<string> {
  const response = await fetchImpl(`${API}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'any' }),
  });
  const body = (await response.json()) as { accessToken?: string; mfaToken?: string };
  if (body.accessToken) return body.accessToken;
  const verified = await fetchImpl(`${API}/api/v1/auth/mfa/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ mfaToken: body.mfaToken, code: '123456' }),
  });
  return ((await verified.json()) as { accessToken: string }).accessToken;
}
const as = (role: string) => login(`${role}@example.com`);

async function call(
  token: string,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
) {
  const response = await fetchImpl(`${API}/api/v1${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...headers },
    body: body === undefined ? null : JSON.stringify(body),
  });
  const text = await response.text();
  return {
    status: response.status,
    headers: response.headers,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in a test
    body: (text ? JSON.parse(text) : null) as Record<string, any>,
  };
}

const data = fixtureDataset();
function find(predicate: (m: FixtureMessage) => boolean, what: string): FixtureMessage {
  const message = data.find(predicate);
  if (!message) throw new Error(`no dataset message ${what}`);
  return message;
}
/** Messages that no other test of this file mutates (rescans change state). */
const quarantinedMulti = find(
  (m) =>
    m.detail.status === 'quarantined' &&
    m.recipientRows.length >= 2 &&
    m.attachments.length > 0 &&
    m.detail.lifecycleRound === 0 &&
    m.detail.subject !== null,
  'quarantined with recipients and attachments',
);
const delivered = find(
  (m) => m.detail.status === 'delivered' && m.recipientRows.some((r) => r.delivery === 'delivered'),
  'delivered',
);
const dlpViolation = find((m) => m.detail.finalVerdict === 'dlp_violation', 'with DLP findings');
const becMessage = find((m) => m.detail.finalVerdict === 'bec', 'BEC');
const phishing = find(
  (m) => m.detail.finalVerdict === 'phishing' && m.urls.length > 0,
  'phishing with URLs',
);
const malware = find(
  (m) => m.detail.finalVerdict === 'malware' && m.attachments.length > 0,
  'malware',
);

describe('Email Details fixtures: reads', () => {
  it('every fixture module exports the mock marker', () => {
    expect(detailsData.DEV_MOCK_MARKER).toBe(DEV_MOCK_MARKER);
  });

  it('detail masks the subject; lifecycle and history agree on the version (v0 cursor)', async () => {
    const token = await as('read_only_user');
    const id = quarantinedMulti.detail.id;
    const detail = await call(token, 'GET', `/messages/${id}`);
    expect(detail.status).toBe(200);
    expect(detail.body.subject).toBeNull();
    expect(detail.body.subjectMasked).toBe(true);
    const lifecycle = await call(token, 'GET', `/messages/${id}/lifecycle`);
    expect(lifecycle.body.version).toBe(detail.body.version);
    expect(lifecycle.body.state).toBe('quarantined');
    expect(lifecycle.body.recipients.total).toBe(quarantinedMulti.recipientRows.length);
    const first = await call(token, 'GET', `/messages/${id}/lifecycle/history?limit=4`);
    expect(first.body.data).toHaveLength(4);
    expect(first.body.data[0]).toMatchObject({ version: 1, fromState: null, toState: 'received' });
    const second = await call(
      token,
      'GET',
      `/messages/${id}/lifecycle/history?limit=4&cursor=${first.body.nextCursor}`,
    );
    const versions = [...first.body.data, ...second.body.data].map(
      (h: { version: number }) => h.version,
    );
    expect(versions.at(-1)).toBe(detail.body.version);
    expect(
      (await call(token, 'GET', '/messages/01933c3a-1b2c-7d4e-8f00-0000000000ff')).status,
    ).toBe(404);
  });

  it('recipients are masked with the matched user withheld; the v1 cursor is bound to the message', async () => {
    const token = await as('read_only_user');
    const id = quarantinedMulti.detail.id;
    const page = await call(token, 'GET', `/messages/${id}/recipients?limit=1`);
    expect(page.status).toBe(200);
    expect(page.body.data[0]).toMatchObject({ rcptSeq: 0, addressMasked: true, userId: null });
    expect(page.body.data[0].address).toMatch(/^.\*\*\*@/u);
    expect(page.body.nextCursor).toEqual(expect.any(String));
    const next = await call(
      token,
      'GET',
      `/messages/${id}/recipients?limit=1&cursor=${page.body.nextCursor}`,
    );
    expect(next.body.data[0].rcptSeq).toBe(1);
    const other = await call(
      token,
      'GET',
      `/messages/${delivered.detail.id}/recipients?cursor=${page.body.nextCursor}`,
    );
    expect(other.status).toBe(400);
    expect(other.body.code).toBe('cursor_invalid');
  });

  it('headers: safe subset in clear, To/Cc/Subject masked, every availability state in the dataset', async () => {
    const token = await as('read_only_user');
    const response = await call(token, 'GET', `/messages/${quarantinedMulti.detail.id}/headers`);
    const body = response.body;
    if (body.availability === 'available') {
      for (const header of body.headers as {
        name: string;
        value: string | null;
        masked: boolean;
      }[]) {
        if (['To', 'Cc', 'Subject'].includes(header.name)) {
          expect(header).toMatchObject({ value: null, masked: true });
        } else {
          expect(header.masked).toBe(false);
          expect(body.safeHeaderNames).toContain(header.name);
        }
      }
    }
    const states = new Set(data.map((m) => detailsData.headerAvailability(m)));
    expect([...states].sort()).toEqual([
      'available',
      'none_stored',
      'not_parsed',
      'retention_expired',
    ]);
  });

  it('scans carry every engine; dlp masked findings only with dlp:read; symbol options masked', async () => {
    const analyst = await as('security_analyst');
    const readOnly = await as('read_only_user');
    const engines = new Set<string>();
    for (const message of [quarantinedMulti, dlpViolation, becMessage, phishing, malware]) {
      const scans = await call(analyst, 'GET', `/messages/${message.detail.id}/scans`);
      expect(scans.status).toBe(200);
      for (const round of scans.body.data) {
        for (const engine of round.engines) {
          engines.add(engine.engine);
          if (engine.engine === 'rspamd') {
            for (const symbol of engine.symbols) {
              for (const option of symbol.options) {
                const match = ADDRESS.exec(option);
                expect(match, option).toBeNull();
              }
            }
          }
        }
      }
    }
    expect([...engines].sort()).toEqual(['attachment', 'bec', 'dlp', 'rspamd', 'sandbox', 'url']);
    const scans = await call(analyst, 'GET', `/messages/${dlpViolation.detail.id}/scans`);
    const dlp = scans.body.data[0].engines.find((e: { engine: string }) => e.engine === 'dlp');
    expect(dlp.dlp.findings.length).toBeGreaterThan(0);
    expect(dlp.dlp.findings[0].masked[0]).toContain('•');
    expect(dlp.dlp.evidence.status).toBe('stored');
    const hidden = await call(readOnly, 'GET', `/messages/${dlpViolation.detail.id}/scans`);
    expect(
      hidden.body.data[0].engines.find((e: { engine: string }) => e.engine === 'dlp').dlp,
    ).toBeNull();
    const bec = await call(analyst, 'GET', `/messages/${becMessage.detail.id}/scans`);
    const becEngine = bec.body.data[0].engines.find((e: { engine: string }) => e.engine === 'bec');
    expect(becEngine.bec.rules.length).toBeGreaterThan(0);
    const url = (
      await call(analyst, 'GET', `/messages/${phishing.detail.id}/scans`)
    ).body.data[0].engines.find((e: { engine: string }) => e.engine === 'url');
    expect(url.urls.length).toBe(phishing.urls.length);
    expect(url.rewrite.status).toBe('rewritten');
    const risk = (await call(analyst, 'GET', `/messages/${malware.detail.id}/scans`)).body.data[0]
      .risk[0];
    expect(risk.contributions.length).toBeGreaterThan(0);
  });

  it('deliveries and their events mask recipients and addresses in SMTP texts', async () => {
    const token = await as('read_only_user');
    const id = delivered.detail.id;
    const deliveries = await call(token, 'GET', `/messages/${id}/deliveries`);
    expect(deliveries.status).toBe(200);
    expect(deliveries.body.deliveries.length).toBeGreaterThan(0);
    for (const d of deliveries.body.deliveries) {
      expect(d.recipientMasked).toBe(true);
      expect(d.recipient).toMatch(/^.\*\*\*@/u);
      if (d.finalSmtpResponse) expect(ADDRESS.exec(d.finalSmtpResponse)).toBeNull();
    }
    const events = await call(token, 'GET', `/messages/${id}/deliveries/events?limit=100`);
    expect(events.body.data.length).toBeGreaterThan(0);
    for (const e of events.body.data) if (e.detail) expect(ADDRESS.exec(e.detail)).toBeNull();
    const one = await call(token, 'GET', `/messages/${id}/deliveries/events?rcptSeq=0&limit=100`);
    expect(one.body.data.every((e: { rcptSeq: number }) => e.rcptSeq === 0)).toBe(true);
    expect(
      (await as('mailbox_user').then((t) => call(t, 'GET', `/messages/${id}/deliveries`))).status,
    ).toBe(403);
  });

  it('quarantine entries of a message follow E8 (masked for read-only, clear for deciders)', async () => {
    const id = quarantinedMulti.detail.id;
    const from = new Date(Date.parse(quarantinedMulti.detail.receivedAt) - 60_000).toISOString();
    const to = new Date().toISOString();
    const query = `/quarantine/entries?messageId=${id}&from=${from}&to=${to}`;
    const masked = await call(await as('read_only_user'), 'GET', query);
    expect(masked.status).toBe(200);
    expect(masked.body.items.length).toBe(
      quarantinedMulti.recipientRows.filter((r) => r.quarantine).length,
    );
    expect(masked.body.items.every((e: { recipientMasked: boolean }) => e.recipientMasked)).toBe(
      true,
    );
    const clear = await call(await as('quarantine_reviewer'), 'GET', query);
    expect(clear.body.items.every((e: { recipientMasked: boolean }) => !e.recipientMasked)).toBe(
      true,
    );
    // By messageId the range may be left out (every entry of the message, as the api).
    const windowless = await call(
      await as('read_only_user'),
      'GET',
      `/quarantine/entries?messageId=${id}`,
    );
    expect(windowless.status).toBe(200);
    expect(windowless.body.items.length).toBe(masked.body.items.length);
    expect(
      (await call(await as('read_only_user'), 'GET', '/quarantine/entries?state=held')).body.code,
    ).toBe('quarantine_search_range_invalid');
    // A masked caller may not search by the exact recipient (ADR-0062); a decider may.
    const address = clear.body.items[0].recipient as string;
    const exact = `${query}&recipient=${encodeURIComponent(address)}`;
    const refused = await call(await as('read_only_user'), 'GET', exact);
    expect(refused.status).toBe(403);
    expect(refused.body).toMatchObject({
      code: 'quarantine_filter_forbidden',
      filter: 'recipient',
    });
    expect((await call(await as('quarantine_reviewer'), 'GET', exact)).status).toBe(200);
  });
});

describe('Email Details fixtures: reveal, evidence, rescan and audit', () => {
  it('the single reveal returns the values, writes an audit row without values and pages recipients', async () => {
    const token = await as('security_analyst');
    const id = quarantinedMulti.detail.id;
    expect(
      (
        await call(await as('read_only_user'), 'POST', `/messages/${id}/reveal`, {
          fields: ['subject'],
        })
      ).status,
    ).toBe(403);
    expect(
      (await call(token, 'POST', `/messages/${id}/reveal`, { fields: ['subject'], extra: 1 }))
        .status,
    ).toBe(400);
    expect(
      (
        await call(token, 'POST', `/messages/${id}/reveal`, {
          fields: ['subject'],
          recipientsLimit: 5,
        })
      ).status,
    ).toBe(400);
    const first = await call(token, 'POST', `/messages/${id}/reveal`, {
      fields: ['subject', 'headers', 'recipients'],
      recipientsLimit: 1,
    });
    expect(first.status).toBe(200);
    expect(first.headers.get('cache-control')).toBe('no-store');
    expect(first.body.subject).toBe(quarantinedMulti.detail.subject);
    expect(first.body.recipients.data).toEqual([
      expect.objectContaining({ rcptSeq: 0, address: quarantinedMulti.recipientRows[0]?.address }),
    ]);
    for (const header of first.body.headers) expect(['To', 'Cc', 'Subject']).toContain(header.name);
    const second = await call(token, 'POST', `/messages/${id}/reveal`, {
      fields: ['recipients'],
      recipientsCursor: first.body.recipients.nextCursor,
      recipientsLimit: 1,
    });
    expect(second.body.recipients.data[0].rcptSeq).toBe(1);
    expect(second.body.subject).toBeUndefined();
    const tampered = await call(token, 'POST', `/messages/${delivered.detail.id}/reveal`, {
      fields: ['recipients'],
      recipientsCursor: first.body.recipients.nextCursor,
    });
    expect(tampered.body.code).toBe('cursor_invalid');
    expect(
      (
        await call(token, 'POST', '/messages/01933c3a-1b2c-7d4e-8f00-0000000000ff/reveal', {
          fields: ['subject'],
        })
      ).status,
    ).toBe(404);
    const audit = await call(
      token,
      'GET',
      `/audit/logs?resourceType=message&resourceId=${id}&limit=100&from=${new Date(Date.now() - 86_400_000).toISOString()}&to=${new Date(Date.now() + 60_000).toISOString()}`,
    );
    const reveals = audit.body.data.filter(
      (row: { action: string }) => row.action === 'message.revealed',
    );
    expect(reveals.length).toBeGreaterThanOrEqual(2);
    expect(reveals[1].metadata).toMatchObject({ fields: ['subject', 'headers', 'recipients'] });
    expect(JSON.stringify(reveals)).not.toContain(
      quarantinedMulti.recipientRows[0]?.address ?? '#',
    );
  });

  it('the single and bulk reveals share the per-user limit', async () => {
    const token = await login('mfa.compliance_auditor@example.com');
    const id = quarantinedMulti.detail.id;
    for (let i = 0; i < FIXTURE_REVEALS_PER_MINUTE; i += 1) {
      const response = await call(token, 'POST', `/messages/${id}/reveal`, { fields: ['subject'] });
      expect(response.status).toBe(200);
    }
    const limited = await call(token, 'POST', '/messages/reveal', { messageIds: [id] });
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
  });

  it('DLP evidence needs dlp:evidence_read and an MFA session; reads are audited', async () => {
    const id = dlpViolation.detail.id;
    const scans = await call(await as('security_analyst'), 'GET', `/messages/${id}/scans`);
    const scanId = scans.body.data[0].scanId as string;
    const path = `/messages/${id}/scans/${scanId}/dlp-evidence`;
    expect((await call(await as('read_only_user'), 'GET', path)).status).toBe(403);
    const noMfa = await call(await as('security_analyst'), 'GET', path);
    expect(noMfa.status).toBe(403);
    expect(noMfa.body.code).toBe('mfa_required');
    const mfa = await login('mfa.security_analyst@example.com');
    const evidence = await call(mfa, 'GET', path);
    expect(evidence.status).toBe(200);
    expect(evidence.headers.get('cache-control')).toBe('no-store');
    expect(evidence.body.evidence.matches.length).toBeGreaterThan(0);
    expect((await call(mfa, 'GET', `/messages/${id}/scans/1/dlp-evidence`)).status).toBe(404);
    const clean = await call(mfa, 'GET', `/messages/${delivered.detail.id}/scans`);
    const cleanScan = clean.body.data[0]?.scanId;
    if (cleanScan) {
      const none = await call(
        mfa,
        'GET',
        `/messages/${delivered.detail.id}/scans/${cleanScan}/dlp-evidence`,
      );
      expect(none.body.code).toBe('dlp_evidence_not_found');
    }
    const audit = await call(
      mfa,
      'GET',
      `/audit/logs?resourceType=dlp_evidence&resourceId=${id}&from=${new Date(Date.now() - 86_400_000).toISOString()}&to=${new Date(Date.now() + 60_000).toISOString()}`,
    );
    expect(audit.body.data[0]).toMatchObject({ action: 'dlp_evidence.read', resourceId: id });
    expect(JSON.stringify(audit.body.data)).not.toContain(evidence.body.evidence.matches[0].value);
  });

  it('rescan: Idempotency-Key required, replayed, refused on reuse; version and state conflicts; new round', async () => {
    const token = await as('organization_admin');
    const target = find(
      (m) =>
        m.detail.status === 'quarantined' &&
        m.detail.lifecycleRound === 0 &&
        m !== quarantinedMulti,
      'another quarantined message',
    );
    const id = target.detail.id;
    const before = await call(token, 'GET', `/messages/${id}`);
    const body = { expectedVersion: before.body.version, reason: 'Re-check with the new feed' };
    expect((await call(token, 'POST', `/messages/${id}/rescan`, body)).body.code).toBe(
      'idempotency_key_required',
    );
    expect(
      (
        await call(
          token,
          'POST',
          `/messages/${id}/rescan`,
          { ...body, reason: 'short' },
          { 'idempotency-key': 'k-0' },
        )
      ).status,
    ).toBe(400);
    const stale = await call(
      token,
      'POST',
      `/messages/${id}/rescan`,
      { ...body, expectedVersion: 1 },
      { 'idempotency-key': 'k-1' },
    );
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({
      code: 'message_version_conflict',
      currentVersion: before.body.version,
    });
    const key = crypto.randomUUID();
    const started = await call(token, 'POST', `/messages/${id}/rescan`, body, {
      'idempotency-key': key,
    });
    expect(started.status).toBe(202);
    expect(started.body).toMatchObject({
      state: 'scanning',
      version: before.body.version + 1,
      lifecycleRound: before.body.lifecycleRound + 1,
    });
    const replay = await call(token, 'POST', `/messages/${id}/rescan`, body, {
      'idempotency-key': key,
    });
    expect(replay.status).toBe(202);
    expect(replay.headers.get('idempotency-replayed')).toBe('true');
    expect(replay.body).toEqual(started.body);
    const reused = await call(
      token,
      'POST',
      `/messages/${id}/rescan`,
      { ...body, reason: 'Another reason here' },
      { 'idempotency-key': key },
    );
    expect(reused.status).toBe(422);
    const after = await call(token, 'GET', `/messages/${id}`);
    expect(after.body).toMatchObject({ status: 'scanning', version: before.body.version + 1 });
    const scans = await call(token, 'GET', `/messages/${id}/scans`);
    expect(scans.body.data[0]).toMatchObject({
      round: before.body.lifecycleRound + 1,
      status: 'running',
    });
    const history = await call(token, 'GET', `/messages/${id}/lifecycle/history?limit=100`);
    expect(history.body.data.at(-1)).toMatchObject({
      toState: 'scanning',
      actor: { role: 'operator' },
    });
    const audit = await call(
      token,
      'GET',
      `/audit/logs?resourceType=message&resourceId=${id}&from=${new Date(Date.now() - 86_400_000).toISOString()}&to=${new Date(Date.now() + 60_000).toISOString()}`,
    );
    expect(audit.body.data[0].action).toBe('message.rescan_requested');
    const deliveredState = await call(
      token,
      'POST',
      `/messages/${delivered.detail.id}/rescan`,
      { expectedVersion: delivered.detail.version, reason: 'Re-check delivered mail' },
      { 'idempotency-key': crypto.randomUUID() },
    );
    expect(deliveredState.body.code).toBe('message_state_conflict');
    expect(
      (
        await call(await as('compliance_auditor'), 'POST', `/messages/${id}/rescan`, body, {
          'idempotency-key': 'k-2',
        })
      ).status,
    ).toBe(403);
  });
});

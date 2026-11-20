import { afterEach, describe, expect, it, vi } from 'vitest';
import { decodeCursor, initialCursor } from '../core/cursor';
import { ProviderCallError } from '../core/errors';
import { appIdHash } from '../core/hash';
import type { ProviderIngestPage } from '../port/ato-port';
import { GOOGLE_SCOPES } from '../requirements';
import { GS_ADMIN_EMAIL, GS_CLIENTS, GS_USERS, gsActivity } from '../testing/datasets/google';
import {
  createGoogleTestbed,
  TEST_GS_CONNECTION_ID,
  type GoogleTestbed,
  type GoogleTestbedOptions,
} from '../testing/google-harness';
import { InMemoryRateBudget } from '../testing/in-memory-stores';
import { GOOGLE_ADAPTER_VERSION, GOOGLE_DECLARED_CAPABILITIES } from './constants';

const signal = () => new AbortController().signal;
let testbed: GoogleTestbed | null = null;

async function bed(options: GoogleTestbedOptions = {}): Promise<GoogleTestbed> {
  testbed = await createGoogleTestbed(options);
  return testbed;
}

afterEach(async () => {
  await testbed?.stop();
  testbed = null;
});

const cursorOf = (page: ProviderIngestPage) => {
  const decoded = decodeCursor(page.cursor, GOOGLE_ADAPTER_VERSION);
  if (!decoded.ok) throw new Error('cursor_invalid');
  return decoded.cursor;
};

const reportsCalls = (tb: GoogleTestbed, application: 'login' | 'token') =>
  tb.sims.script.calls({
    simulator: 'google-admin',
    path: `/admin/reports/v1/activity/users/all/applications/${application}`,
  });

async function drain(
  tb: GoogleTestbed,
  stream: 'sign_ins' | 'oauth_consents',
  cursor: string | null,
) {
  const pages: ProviderIngestPage[] = [];
  let current = cursor;
  for (let i = 0; i < 30; i += 1) {
    const page = await tb.adapter.ingest(stream, current, signal());
    pages.push(page);
    current = page.cursor;
    if (!page.hasMore) break;
  }
  return { pages, events: pages.flatMap((p) => p.events), cursor: current };
}

describe('Google adapter: identity', () => {
  it('has kind and version and declares every stream and action of D3/§3.3', async () => {
    const tb = await bed();
    expect(tb.adapter.kind).toBe('google_workspace');
    expect(tb.adapter.version).toBe('gws-ato/1');
    expect(tb.adapter.declaredCapabilities()).toBe(GOOGLE_DECLARED_CAPABILITIES);
    expect(GOOGLE_DECLARED_CAPABILITIES.streams.session_events).toEqual({ supported: false });
    expect(GOOGLE_DECLARED_CAPABILITIES.actions).toMatchObject({
      revoke_sessions: { rollback: false, confirmation: 'synchronous' },
      require_password_reset: { rollback: false, confirmation: 'polling' },
      suspend_account: { rollback: true, confirmation: 'polling' },
      require_mfa: { rollback: true, confirmation: 'polling' },
      remove_forwarding_rule: { rollback: false, confirmation: 'polling' },
      revoke_oauth_grant: { rollback: false, confirmation: 'synchronous' },
    });
    // Never probed: every capability is unsupported until a probe proves it (D6).
    expect(tb.adapter.capabilities().streams.sign_ins?.supported).toBe(false);
    await tb.adapter.probe(signal());
    const capabilities = tb.adapter.capabilities();
    expect(capabilities.streams.sign_ins?.supported).toBe(true);
    expect(capabilities.streams.session_events?.supported).toBe(false);
    expect(capabilities.actions.suspend_account).toEqual({
      supported: true,
      rollback: true,
      confirmation: 'polling',
    });
  });
});

describe('Google adapter: sign_ins (Reports login) and its companion risk_events', () => {
  it('maps the window [now − 60 min, now − 5 min] as the delegated admin and moves the watermark', async () => {
    const events = vi.fn();
    const tb = await bed({ metrics: { events } });
    const page = await tb.adapter.ingest('sign_ins', null, signal());
    const [call] = reportsCalls(tb, 'login');
    const query = new URLSearchParams(call?.query ?? '');
    expect(query.get('startTime')).toBe('2026-11-10T11:00:00.000Z');
    expect(query.get('endTime')).toBe('2026-11-10T11:55:00.000Z');
    expect(query.get('maxResults')).toBe('200');
    expect(query.get('eventName')).toBeNull();
    expect(call?.subject).toBe(GS_ADMIN_EMAIL);
    expect(page.hasMore).toBe(false);
    expect(cursorOf(page)).toMatchObject({ seq: 1, wm: '2026-11-10T11:55:00.000Z' });
    expect(cursorOf(page).page).toBeUndefined();
    const summary = page.events.map((e) => [
      e.stream,
      e.identity.externalId,
      e.outcome ?? e.riskLevel,
    ]);
    expect(summary).toEqual([
      ['risk_events', GS_USERS.gale, 'medium'],
      ['risk_events', GS_USERS.root, 'high'],
      ['sign_ins', GS_USERS.erin, 'success'],
      ['risk_events', GS_USERS.erin, 'high'],
      ['risk_events', GS_USERS.alex, 'medium'],
      ['sign_ins', GS_USERS.blake, 'interrupted'],
      ['sign_ins', GS_USERS.blake, 'failure'],
      ['sign_ins', GS_USERS.alex, 'failure'],
      ['sign_ins', GS_USERS.alex, 'success'],
    ]);
    expect(
      page.events.find((e) => e.identity.externalId === GS_USERS.erin && e.stream === 'sign_ins')
        ?.ip,
    ).toBe('2001:db8::1');
    expect(events).toHaveBeenCalledWith(
      { provider: 'google_workspace', stream: 'sign_ins', result: 'dropped_operation' },
      2,
    );
    expect(events).toHaveBeenCalledWith(
      { provider: 'google_workspace', stream: 'sign_ins', result: 'invalid' },
      1,
    );
    expect(events).toHaveBeenCalledWith(
      { provider: 'google_workspace', stream: 'risk_events', result: 'emitted' },
      4,
    );
  });

  it('pages to completion through pageToken without losing or repeating events', async () => {
    const tb = await bed({ configEnv: { ATO_IDP_PAGE_MAX_EVENTS: '4' } });
    const { pages, events } = await drain(tb, 'sign_ins', null);
    expect(pages).toHaveLength(3);
    expect(pages.slice(0, 2).every((p) => p.hasMore && typeof cursorOf(p).page === 'string')).toBe(
      true,
    );
    expect(cursorOf(pages[1] as ProviderIngestPage)).toMatchObject({
      ws: '2026-11-10T11:00:00.000Z',
      we: '2026-11-10T11:55:00.000Z',
    });
    expect(events).toHaveLength(9);
    expect(new Set(events.map((e) => e.eventId)).size).toBe(9);
    expect(pages.map((p) => cursorOf(p).seq)).toEqual([1, 2, 3]);
    const queries = reportsCalls(tb, 'login').map((c) => new URLSearchParams(c.query ?? ''));
    expect(queries.map((q) => q.get('maxResults'))).toEqual(['4', '4', '4']);
    expect(queries[0]?.get('pageToken')).toBeNull();
    expect(queries[1]?.get('pageToken')).toBeTruthy();
  });

  it('re-reads the overlap (same event ids) and picks up late events; unchanged when nothing settled', async () => {
    const tb = await bed();
    const first = await tb.adapter.ingest('sign_ins', null, signal());
    const idle = await tb.adapter.ingest('sign_ins', first.cursor, signal());
    expect(idle).toEqual({ events: [], cursor: first.cursor, hasMore: false });
    tb.clock.advance(10 * 60_000);
    // A late activity: written by the provider after the first poll, timed inside the overlap.
    tb.customer.activities.push(
      gsActivity(tb.clock.now(), {
        user: 'blake',
        minutesAgo: 30,
        uniqueQualifier: '-777',
        events: [{ name: 'login_success' }],
      }),
    );
    const second = await tb.adapter.ingest('sign_ins', first.cursor, signal());
    const query = new URLSearchParams(reportsCalls(tb, 'login').at(-1)?.query ?? '');
    expect(query.get('startTime')).toBe('2026-11-10T10:55:00.000Z');
    expect(query.get('endTime')).toBe('2026-11-10T12:05:00.000Z');
    const firstIds = new Set(first.events.map((e) => e.eventId));
    expect(second.events.filter((e) => firstIds.has(e.eventId))).toHaveLength(9);
    expect(second.events.filter((e) => !firstIds.has(e.eventId)).map((e) => e.eventId)).toEqual([
      expect.stringMatching(/^gws:login:\d+:-777:0$/),
    ]);
  });

  it('backfills from a start cursor clamped to the Reports retention (180 days)', async () => {
    const tb = await bed();
    const start = new Date(tb.clock.ms() - 200 * 86_400_000);
    const page = await tb.adapter.ingest(
      'sign_ins',
      initialCursor(GOOGLE_ADAPTER_VERSION, start, 41),
      signal(),
    );
    const query = new URLSearchParams(reportsCalls(tb, 'login')[0]?.query ?? '');
    expect(query.get('startTime')).toBe(new Date(tb.clock.ms() - 180 * 86_400_000).toISOString());
    expect(page.events).toHaveLength(9);
    expect(cursorOf(page).seq).toBe(42);
  });

  it('restarts an invalid cursor at now − overlap, counted', async () => {
    const cursorReset = vi.fn();
    const tb = await bed({ metrics: { cursorReset } });
    const page = await tb.adapter.ingest('sign_ins', 'not-a-cursor', signal());
    expect(cursorReset).toHaveBeenCalledWith({ provider: 'google_workspace', stream: 'sign_ins' });
    expect(page.events).toHaveLength(9);
    expect(cursorOf(page).seq).toBe(Math.floor(tb.clock.ms() / 1000) + 1);
    // A Microsoft cursor is another adapter version: also reset.
    const other = initialCursor('msgraph-ato/1', tb.clock.now());
    await tb.adapter.ingest('sign_ins', other, signal());
    expect(cursorReset).toHaveBeenCalledTimes(2);
  });

  it.each([
    { status: 429, reason: undefined, retryAfter: '7', expected: 7_000 },
    { status: 403, reason: 'rateLimitExceeded', retryAfter: '3', expected: 3_000 },
    // No Retry-After: exponential backoff with full jitter (random fixed at 0.5 → 500 ms).
    { status: 403, reason: 'userRateLimitExceeded', retryAfter: undefined, expected: 500 },
    { status: 403, reason: 'dailyLimitExceeded', retryAfter: undefined, expected: 3_600_000 },
    { status: 403, reason: 'quotaExceeded', retryAfter: undefined, expected: 3_600_000 },
  ])(
    'ends a page early on $status $reason and resumes from the same cursor',
    async ({ status, reason, retryAfter, expected }) => {
      const throttled = vi.fn();
      const tb = await bed({ configEnv: { ATO_IDP_PAGE_MAX_EVENTS: '4' }, metrics: { throttled } });
      const first = await tb.adapter.ingest('sign_ins', null, signal());
      tb.sims.script.inject({
        simulator: 'google-admin',
        path: '/admin/reports/v1/activity',
        status,
        ...(reason ? { reason } : {}),
        ...(retryAfter ? { retryAfter } : {}),
      });
      const page = await tb.adapter.ingest('sign_ins', first.cursor, signal());
      expect(page).toEqual({
        events: [],
        cursor: first.cursor,
        hasMore: true,
        retryAfterMs: expected,
      });
      expect(throttled).toHaveBeenCalledWith({
        provider: 'google_workspace',
        family: 'google_reports',
      });
      const resumed = await tb.adapter.ingest('sign_ins', page.cursor, signal());
      expect(resumed.events.length).toBeGreaterThan(0);
      expect(cursorOf(resumed).seq).toBe(2);
    },
  );

  it('ends the page with retryAfterMs 1000 when the Reports rate budget stays exhausted', async () => {
    const budget = new InMemoryRateBudget({
      graph: 5,
      o365: 2,
      google_reports: 2,
      google_directory: 5,
      gmail: 10,
    });
    budget.exhaust('google_reports');
    const tb = await bed({ budget });
    const page = await tb.adapter.ingest('sign_ins', null, signal());
    expect(page).toMatchObject({ events: [], hasMore: true, retryAfterMs: 1_000 });
    expect(tb.sims.script.calls()).toHaveLength(0);
  });

  it('fails missing_permission without the Reports scope and classifies outages as retryable', async () => {
    const tb = await bed();
    tb.sims.script.revokePermission(GOOGLE_SCOPES.reportsAudit);
    const permission = await tb.adapter.ingest('sign_ins', null, signal()).catch((e: unknown) => e);
    expect(permission).toBeInstanceOf(ProviderCallError);
    expect(permission).toMatchObject({ code: 'missing_permission', retryable: false });
    tb.sims.script.inject({ path: '/admin/reports/v1/activity', status: 503 });
    const outage = await tb.adapter
      .ingest('oauth_consents', null, signal())
      .catch((e: unknown) => e);
    expect(outage).toMatchObject({ code: 'provider_unavailable', retryable: true });
  });

  it('retries once with a fresh token after a 401', async () => {
    const tb = await bed();
    await tb.adapter.ingest('sign_ins', null, signal());
    tb.sims.tokens.invalidateAll(); // the cached token is now rejected
    const page = await tb.adapter.ingest('sign_ins', null, signal());
    expect(page.events).toHaveLength(9);
    expect(reportsCalls(tb, 'login').map((c) => c.status)).toEqual([200, 401, 200]);
  });

  it('fails connection_inactive and refuses a connection of another organization (echo check)', async () => {
    const tb = await bed();
    tb.connections.update('1001', TEST_GS_CONNECTION_ID, { status: 'disabled' });
    await expect(tb.adapter.ingest('sign_ins', null, signal())).rejects.toMatchObject({
      code: 'connection_inactive',
    });
    const foreign = tb.newAdapter({ organizationId: '2002' });
    await expect(foreign.ingest('sign_ins', null, signal())).rejects.toMatchObject({
      code: 'connection_not_found',
      retryable: false,
    });
    expect(tb.sims.script.calls()).toHaveLength(0);
  });

  it('never polls companions or the unsupported session_events stream', async () => {
    const tb = await bed();
    expect(await tb.adapter.ingest('risk_events', null, signal())).toEqual({
      events: [],
      cursor: 'companion:v1:sign_ins',
      hasMore: false,
    });
    for (const stream of ['mailbox_audit', 'delegation_changes'] as const) {
      expect(await tb.adapter.ingest(stream, null, signal())).toEqual({
        events: [],
        cursor: 'companion:v1:forwarding_changes',
        hasMore: false,
      });
    }
    expect(await tb.adapter.ingest('session_events', null, signal())).toEqual({
      events: [],
      cursor: 'unsupported:v1:session_events',
      hasMore: false,
    });
    expect(tb.sims.script.calls()).toHaveLength(0);
  });

  it('drops events of a disabled companion before they leave the page (stream_disabled)', async () => {
    const events = vi.fn();
    const tb = await bed({
      metrics: { events },
      settings: (s) => ({ ...s, streams: { ...s.streams, risk_events: { enabled: false } } }),
    });
    const page = await tb.adapter.ingest('sign_ins', null, signal());
    expect(page.events.map((e) => e.stream)).toEqual(Array(5).fill('sign_ins'));
    expect(events).toHaveBeenCalledWith(
      { provider: 'google_workspace', stream: 'risk_events', result: 'stream_disabled' },
      4,
    );
  });
});

describe('Google adapter: oauth_consents (Reports token)', () => {
  it('reads authorize events only and hashes the client ids', async () => {
    const tb = await bed();
    const page = await tb.adapter.ingest('oauth_consents', null, signal());
    const query = new URLSearchParams(reportsCalls(tb, 'token')[0]?.query ?? '');
    expect(query.get('eventName')).toBe('authorize');
    expect(
      page.events.map((e) => [e.identity.externalId, e.oauth?.appIdHash, e.oauth?.appDisplayName]),
    ).toEqual([
      [GS_USERS.erin, appIdHash(GS_CLIENTS.notes), undefined],
      [GS_USERS.alex, appIdHash(GS_CLIENTS.mailSync), 'Mail Sync Pro (example)'],
    ]);
    expect(page.events.every((e) => e.oauth?.consentType === 'user')).toBe(true);
    expect(JSON.stringify(page.events)).not.toContain('googleusercontent');
    expect(cursorOf(page).wm).toBe('2026-11-10T11:55:00.000Z');
  });
});

describe('Google adapter: resolveIdentity (D9.2)', () => {
  it('resolves by primary address and alias; null when unknown or not an address', async () => {
    const tb = await bed();
    const expected = {
      provider: 'google_workspace',
      externalId: GS_USERS.erin,
      primaryEmail: 'erin@fabrikam-it.example',
    };
    expect(await tb.adapter.resolveIdentity('Erin@Fabrikam-IT.example', signal())).toEqual(
      expected,
    );
    expect(await tb.adapter.resolveIdentity('erin.alias@fabrikam-it.example', signal())).toEqual(
      expected,
    );
    expect(await tb.adapter.resolveIdentity('nobody@fabrikam-it.example', signal())).toBeNull();
    expect(await tb.adapter.resolveIdentity('not an address', signal())).toBeNull();
    const calls = tb.sims.script.calls({ simulator: 'google-admin' });
    expect(calls).toHaveLength(3);
    expect(calls.every((c) => c.subject === GS_ADMIN_EMAIL)).toBe(true);
  });

  it('propagates a missing directory scope as a classified error', async () => {
    const tb = await bed();
    tb.sims.script.revokePermission(GOOGLE_SCOPES.directoryUserReadonly);
    await expect(
      tb.adapter.resolveIdentity('alex@fabrikam-it.example', signal()),
    ).rejects.toMatchObject({ code: 'missing_permission' });
  });
});

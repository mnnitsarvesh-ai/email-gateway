import { afterEach, describe, expect, it, vi } from 'vitest';
import { decodeCursor } from '../core/cursor';
import { identityHash } from '../core/hash';
import type { ProviderEvent, ProviderIngestPage } from '../port/ato-port';
import { GOOGLE_PROFILES, GOOGLE_SCOPES } from '../requirements';
import { GS_ADMIN_EMAIL, GS_USERS, googleCustomer } from '../testing/datasets/google';
import {
  createGoogleTestbed,
  type GoogleTestbed,
  type GoogleTestbedOptions,
} from '../testing/google-harness';
import { InMemoryRateBudget } from '../testing/in-memory-stores';
import type { GsCustomer, GsUser } from '../testing/simulators/google-types';
import { GOOGLE_ADAPTER_VERSION } from './constants';

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

async function drain(tb: GoogleTestbed, cursor: string | null, max = 50) {
  const pages: ProviderIngestPage[] = [];
  let current = cursor;
  for (let i = 0; i < max; i += 1) {
    const page = await tb.adapter.ingest('forwarding_changes', current, signal());
    pages.push(page);
    current = page.cursor;
    if (!page.hasMore) break;
  }
  return { pages, events: pages.flatMap((p) => p.events), cursor: current as string };
}

const summary = (events: ProviderEvent[]) =>
  events.map((e) => [e.stream, e.identity.externalId, e.mailbox?.change]);

const DAY_MS = 86_400_000;

/** The default customer plus `extra` synthetic users without Gmail settings. */
function withExtraUsers(extra: number) {
  return (now: Date): GsCustomer => {
    const customer = googleCustomer(now);
    for (let i = 0; i < extra; i += 1) {
      const id = `2000000000000000${String(i).padStart(5, '0')}`;
      const user: GsUser = {
        id,
        primaryEmail: `user${i}@fabrikam-it.example`,
        aliases: [],
        suspended: false,
        orgUnitPath: '/Staff',
        changePasswordAtNextLogin: false,
        isAdmin: false,
        gmailEnabled: true,
      };
      customer.users.push(user);
    }
    return customer;
  };
}

describe('Google forwarding_changes: Gmail settings sweep (D8.3)', () => {
  it('sweeps every active user impersonated, emitting the companions from one feed', async () => {
    const snapshotItems = vi.fn();
    const events = vi.fn();
    const tb = await bed({ metrics: { snapshotItems, events } });
    const page = await tb.adapter.ingest('forwarding_changes', null, signal());
    expect(page.hasMore).toBe(false);
    expect(summary(page.events)).toEqual([
      ['forwarding_changes', GS_USERS.alex, 'inbox_rule_added'],
      ['mailbox_audit', GS_USERS.alex, 'inbox_rule_added'],
      ['forwarding_changes', GS_USERS.blake, 'forwarding_added'],
      ['mailbox_audit', GS_USERS.blake, 'inbox_rule_added'],
      ['delegation_changes', GS_USERS.erin, 'delegate_added'],
    ]);
    const blake = page.events.find((e) => e.mailbox?.change === 'forwarding_added');
    expect(blake?.mailbox).toEqual({
      change: 'forwarding_added',
      targetDomain: 'exfil-mail.example',
    });
    const alexRule = page.events[0];
    expect(alexRule?.mailbox?.ruleTraits).toEqual([
      'forwards',
      'forwards_external',
      'moves_to_folder',
      'moves_to_rarely_used_folder',
      'matches_finance_keywords',
    ]);
    expect(page.events.every((e) => e.eventId.startsWith('snap:'))).toBe(true);
    expect(JSON.stringify(page.events)).not.toMatch(/drop@|pay@|invoice|password reset/);
    expect(cursorOf(page)).toMatchObject({ seq: 1, sw: { at: '2026-11-10T12:00:00.000Z' } });
    expect(cursorOf(page).page).toBeUndefined();

    // Directory as the delegated admin; Gmail as each mailbox owner (R1).
    const [listing] = tb.sims.script.calls({
      simulator: 'google-admin',
      path: '/admin/directory/v1/users',
    });
    expect(Object.fromEntries(new URLSearchParams(listing?.query ?? ''))).toEqual({
      customer: 'my_customer',
      maxResults: '100',
      query: 'isSuspended=false',
    });
    expect(listing?.subject).toBe(GS_ADMIN_EMAIL);
    const gmail = tb.sims.script.calls({ simulator: 'gmail' });
    expect(gmail.every((c) => c.path.includes(encodeURIComponent(c.subject ?? '-')))).toBe(true);
    const subjects = [...new Set(gmail.map((c) => c.subject))];
    expect(subjects).toEqual([
      GS_ADMIN_EMAIL,
      'alex@fabrikam-it.example',
      'blake@fabrikam-it.example',
      'drew@fabrikam-it.example', // Gmail not enabled: 400, skipped
      'erin@fabrikam-it.example',
      'root@fabrikam-it.example',
      'gale@fabrikam-it.example',
    ]);
    expect(
      gmail.filter((c) => c.subject === 'drew@fabrikam-it.example').map((c) => c.status),
    ).toEqual([400]);
    expect(subjects).not.toContain('casey@fabrikam-it.example'); // suspended: not listed
    // frank's domain is linked but not provider-verified: never impersonated, nothing stored (inv. 4).
    expect(subjects).not.toContain('frank@fabrikam-labs.example');
    expect(
      tb.mailboxState
        .all(tb.integration.id)
        .some((r) => r.identityHash === identityHash('google_workspace', GS_USERS.frank)),
    ).toBe(false);
    expect(events).toHaveBeenCalledWith(
      { provider: 'google_workspace', stream: 'forwarding_changes', result: 'foreign_domain' },
      1,
    );
    expect(snapshotItems).toHaveBeenCalledWith(
      { provider: 'google_workspace', kind: 'delegate', change: 'added' },
      1,
    );
    expect(tb.mailboxState.all(tb.integration.id)).toHaveLength(5);
  });

  it('only reads with the telemetry profile (gmail.settings.basic never writes, PQ14)', async () => {
    const tb = await bed();
    await drain(tb, null);
    expect(tb.sims.script.writes()).toEqual([]);
    const gmailTokens = tb.connections.tokenRequests.filter(
      (r) => r.subject && r.subject !== GS_ADMIN_EMAIL,
    );
    expect(gmailTokens.length).toBeGreaterThan(0);
    expect(
      gmailTokens.every((r) => r.profile === GOOGLE_PROFILES.telemetry && r.resource === 'google'),
    ).toBe(true);
  });

  it('runs the next sweep only after the interval and reports changes and removals', async () => {
    const tb = await bed();
    const first = await drain(tb, null);
    const idle = await tb.adapter.ingest('forwarding_changes', first.cursor, signal());
    expect(idle).toEqual({ events: [], cursor: first.cursor, hasMore: false });
    tb.sims.script.clearCalls();
    tb.clock.advance(23 * 3_600_000);
    expect((await tb.adapter.ingest('forwarding_changes', first.cursor, signal())).events).toEqual(
      [],
    );
    expect(tb.sims.script.calls()).toEqual([]);

    tb.clock.advance(3_600_000);
    const gmail = tb.customer.gmail;
    const blake = gmail[GS_USERS.blake];
    const alex = gmail[GS_USERS.alex];
    const erin = gmail[GS_USERS.erin];
    if (!blake || !alex || !erin) throw new Error('dataset');
    blake.autoForwarding = { enabled: false };
    const forwardRule = alex.filters[0];
    if (forwardRule?.action) forwardRule.action.forward = 'pay@another-exfil.example';
    alex.filters.push({ id: 'ANe1BmgAlex0003', action: { removeLabelIds: ['INBOX'] } });
    erin.delegates = [];
    const second = await drain(tb, first.cursor);
    expect(summary(second.events)).toEqual([
      ['forwarding_changes', GS_USERS.alex, 'inbox_rule_changed'],
      ['mailbox_audit', GS_USERS.alex, 'inbox_rule_added'],
      ['forwarding_changes', GS_USERS.blake, 'forwarding_removed'],
    ]);
    expect(second.events[0]?.mailbox?.targetDomain).toBe('another-exfil.example');
    expect(cursorOf(second.pages[0] as ProviderIngestPage).sw?.at).toBe('2026-11-11T12:00:00.000Z');
    const removed = tb.mailboxState.all(tb.integration.id).filter((r) => r.state === 'removed');
    expect(removed.map((r) => r.kind).sort()).toEqual(['delegate', 'forwarding']);
  });

  it('honours snapshot.sweepIntervalHours from the binding settings', async () => {
    const tb = await bed({ settings: (s) => ({ ...s, snapshot: { sweepIntervalHours: 6 } }) });
    const first = await drain(tb, null);
    tb.clock.advance(6 * 3_600_000);
    tb.sims.script.clearCalls();
    await drain(tb, first.cursor);
    expect(tb.sims.script.calls({ simulator: 'google-admin' }).length).toBeGreaterThan(0);
  });

  it('pages users (100 per listing) with the position in the cursor, ≤ users per poll', async () => {
    // 138 listed users (8 default users without suspended casey, plus 130), 50 per poll; frank's
    // unverified domain is out of scope, so 137 mailboxes are read.
    const tb = await bed({
      customer: withExtraUsers(130),
      configEnv: { ATO_IDP_SNAPSHOT_MAX_USERS_PER_POLL: '50' },
    });
    const run = await drain(tb, null);
    expect(run.pages.map((p) => p.hasMore)).toEqual([true, true, false]);
    const [first, second, third] = run.pages.map((p) => cursorOf(p));
    // Offset inside the first users page: 50 mailboxes read plus frank (out of scope, not counted).
    expect(first?.page).toBe('u:51');
    expect(first?.sw?.next).toBeUndefined();
    // The first users page is done after 49 more mailboxes; the 50th is the first user of the
    // next listing page (its token and the offset in the cursor).
    expect(second?.page).toBe('u:1');
    expect(second?.sw?.next).toBeTruthy();
    expect(third?.sw).toEqual({ at: '2026-11-10T12:00:00.000Z' });
    expect(run.pages.map((p) => cursorOf(p).seq)).toEqual([1, 2, 3]);
    expect(summary(run.events)).toHaveLength(5);
    const subjects = tb.sims.script
      .calls({ simulator: 'gmail', path: /autoForwarding$/ })
      .map((c) => c.subject);
    expect(subjects).toHaveLength(137);
    expect(new Set(subjects).size).toBe(137); // every in-scope user exactly once
    const listings = tb.sims.script.calls({
      simulator: 'google-admin',
      path: '/admin/directory/v1/users',
    });
    expect(listings.map((c) => new URLSearchParams(c.query ?? '').has('pageToken'))).toEqual([
      false,
      false,
      true,
      true,
    ]);
  });

  it('ends a page at ATO_IDP_PAGE_MAX_EVENTS and continues with the next user', async () => {
    const tb = await bed({ configEnv: { ATO_IDP_PAGE_MAX_EVENTS: '2' } });
    const run = await drain(tb, null);
    expect(run.pages.map((p) => p.events.length)).toEqual([2, 2, 1]);
    expect(new Set(run.events.map((e) => e.eventId)).size).toBe(5);
  });

  it('returns the processed users’ events when throttled mid-sweep and resumes after them', async () => {
    const throttled = vi.fn();
    const tb = await bed({ metrics: { throttled } });
    tb.sims.script.inject({ simulator: 'gmail', path: /blake/, status: 429, retryAfter: '7' });
    const page = await tb.adapter.ingest('forwarding_changes', null, signal());
    expect(summary(page.events)).toEqual([
      ['forwarding_changes', GS_USERS.alex, 'inbox_rule_added'],
      ['mailbox_audit', GS_USERS.alex, 'inbox_rule_added'],
    ]);
    expect(page).toMatchObject({ hasMore: true, retryAfterMs: 7_000 });
    expect(cursorOf(page)).toMatchObject({ seq: 1, page: 'u:2' });
    expect(throttled).toHaveBeenCalledWith({ provider: 'google_workspace', family: 'gmail' });
    const rest = await drain(tb, page.cursor);
    expect(summary(rest.events).map((e) => e[1])).toEqual([
      GS_USERS.blake,
      GS_USERS.blake,
      GS_USERS.erin,
    ]);
  });

  it('ends the page on a Directory quota answer without advancing the sweep', async () => {
    const tb = await bed();
    tb.sims.script.inject({
      simulator: 'google-admin',
      path: '/admin/directory/v1/users',
      status: 403,
      reason: 'dailyLimitExceeded',
    });
    const page = await tb.adapter.ingest('forwarding_changes', null, signal());
    expect(page).toMatchObject({ events: [], hasMore: true, retryAfterMs: 3_600_000 });
    expect(cursorOf(page).sw).toBeUndefined();
    const next = await tb.adapter.ingest('forwarding_changes', page.cursor, signal());
    expect(next.events).toHaveLength(5);
  });

  it('ends the page with retryAfterMs 1000 when the Gmail rate budget stays exhausted', async () => {
    const budget = new InMemoryRateBudget({
      graph: 5,
      o365: 2,
      google_reports: 2,
      google_directory: 5,
      gmail: 10,
    });
    budget.exhaust('gmail');
    const tb = await bed({ budget });
    const page = await tb.adapter.ingest('forwarding_changes', null, signal());
    expect(page).toMatchObject({ events: [], hasMore: true, retryAfterMs: 1_000 });
    expect(tb.sims.script.calls({ simulator: 'gmail' })).toHaveLength(0);
  });

  it('fails missing_permission without gmail.settings.basic or the directory scope', async () => {
    const tb = await bed();
    tb.sims.script.revokePermission(GOOGLE_SCOPES.gmailSettingsBasic);
    await expect(tb.adapter.ingest('forwarding_changes', null, signal())).rejects.toMatchObject({
      code: 'missing_permission',
      retryable: false,
    });
    const tb2 = await createGoogleTestbed();
    try {
      tb2.sims.script.revokePermission(GOOGLE_SCOPES.directoryUserReadonly);
      await expect(tb2.adapter.ingest('forwarding_changes', null, signal())).rejects.toMatchObject({
        code: 'missing_permission',
      });
    } finally {
      await tb2.stop();
    }
  });

  it('drops events of a disabled companion (stream_disabled) while keeping the state', async () => {
    const events = vi.fn();
    const tb = await bed({
      metrics: { events },
      settings: (s) => ({
        ...s,
        streams: { ...s.streams, delegation_changes: { enabled: false } },
      }),
    });
    const page = await tb.adapter.ingest('forwarding_changes', null, signal());
    expect(page.events.map((e) => e.stream)).not.toContain('delegation_changes');
    expect(events).toHaveBeenCalledWith(
      { provider: 'google_workspace', stream: 'delegation_changes', result: 'stream_disabled' },
      1,
    );
    expect(tb.mailboxState.all(tb.integration.id).some((r) => r.kind === 'delegate')).toBe(true);
  });
});

describe('Google forwarding_changes: cursor-confirmed snapshots and priority refresh (D8.3)', () => {
  it('re-emits a sweep page after a crash with the same ids, and nothing after the commit', async () => {
    const tb = await bed();
    const page = await tb.adapter.ingest('forwarding_changes', null, signal());
    expect(page.events).toHaveLength(5);
    // Crash: the runner never committed `page.cursor`; the next poll runs from `null` again.
    const replay = await tb.adapter.ingest('forwarding_changes', null, signal());
    expect(replay.events.map((e) => e.eventId)).toEqual(page.events.map((e) => e.eventId));
    // Commit, a day later the next sweep: state confirmed, nothing re-emitted.
    tb.clock.advance(DAY_MS);
    const next = await drain(tb, replay.cursor);
    expect(next.events).toEqual([]);
  });

  it('processes priority identities first, re-emits them after a crash and never after the commit', async () => {
    const tb = await bed();
    const baseline = await drain(tb, null);
    const committed = baseline.cursor;
    const alexSettings = tb.customer.gmail[GS_USERS.alex];
    if (!alexSettings) throw new Error('dataset');
    alexSettings.autoForwarding = {
      enabled: true,
      emailAddress: 'grab@exfil-mail.example',
      disposition: 'leaveInInbox',
    };
    const alex = { provider: 'google_workspace' as const, externalId: GS_USERS.alex };
    tb.mailboxState.requestRefresh(tb.integration.id, alex);
    tb.sims.script.clearCalls();

    const page = await tb.adapter.ingest('forwarding_changes', committed, signal());
    expect(summary(page.events)).toEqual([
      ['forwarding_changes', GS_USERS.alex, 'forwarding_added'],
    ]);
    expect(page.hasMore).toBe(true);
    expect(cursorOf(page).pq).toEqual([identityHash('google_workspace', GS_USERS.alex)]);
    // The priority identity is re-read from the directory (fresh address and suspension).
    expect(tb.sims.script.calls({ simulator: 'google-admin' }).map((c) => c.path)).toEqual([
      `/admin/directory/v1/users/${GS_USERS.alex}`,
    ]);

    const replay = await tb.adapter.ingest('forwarding_changes', committed, signal());
    expect(replay.events.map((e) => e.eventId)).toEqual(page.events.map((e) => e.eventId));
    expect(tb.mailboxState.pendingPriority(tb.integration.id)).toBe(1);

    const next = await tb.adapter.ingest('forwarding_changes', replay.cursor, signal());
    expect(tb.mailboxState.pendingPriority(tb.integration.id)).toBe(0);
    expect(next.events).toEqual([]);
    expect(cursorOf(next).pq).toBeUndefined();
    expect(cursorOf(next).seq).toBeGreaterThan(cursorOf(replay).seq);
  });

  it('skips a priority identity that is gone or suspended (its flag is still cleared)', async () => {
    const tb = await bed();
    const baseline = await drain(tb, null);
    tb.mailboxState.requestRefresh(tb.integration.id, {
      provider: 'google_workspace',
      externalId: GS_USERS.casey,
    });
    tb.mailboxState.requestRefresh(tb.integration.id, {
      provider: 'google_workspace',
      externalId: '199999999999999999999',
    });
    const page = await tb.adapter.ingest('forwarding_changes', baseline.cursor, signal());
    expect(page.events).toEqual([]);
    expect(cursorOf(page).pq).toHaveLength(2);
    await tb.adapter.ingest('forwarding_changes', page.cursor, signal());
    expect(tb.mailboxState.pendingPriority(tb.integration.id)).toBe(0);
  });

  it('reports refresh support only with a probe proving the settings sweep', async () => {
    const tb = await bed();
    expect(tb.adapter.mailboxRefreshSupported()).toBe(false); // never probed
    await tb.adapter.probe(signal());
    expect(tb.adapter.mailboxRefreshSupported()).toBe(true);
    tb.sims.script.revokePermission(GOOGLE_SCOPES.gmailSettingsBasic);
    await tb.adapter.probe(signal());
    expect(tb.adapter.mailboxRefreshSupported()).toBe(false);
  });
});

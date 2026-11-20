import { afterEach, describe, expect, it, vi } from 'vitest';
import { decodeCursor, encodeCursor } from '../core/cursor';
import { identityHash } from '../core/hash';
import type { ProviderEvent, ProviderIngestPage } from '../port/ato-port';
import {
  MS_TENANT_ID,
  MS_USERS,
  msAuditBlob,
  msExchangeRecord,
} from '../testing/datasets/microsoft';
import {
  createMicrosoftTestbed,
  type MicrosoftTestbed,
  type MicrosoftTestbedOptions,
} from '../testing/harness';
import { MICROSOFT_ADAPTER_VERSION } from './constants';

const signal = () => new AbortController().signal;
let testbed: MicrosoftTestbed | null = null;

async function bed(options: MicrosoftTestbedOptions = {}): Promise<MicrosoftTestbed> {
  testbed = await createMicrosoftTestbed(options);
  return testbed;
}

afterEach(async () => {
  await testbed?.stop();
  testbed = null;
});

const cursorOf = (page: ProviderIngestPage) => {
  const decoded = decodeCursor(page.cursor, MICROSOFT_ADAPTER_VERSION);
  if (!decoded.ok) throw new Error('cursor_invalid');
  return decoded.cursor;
};

/** A cursor whose sweep just ran, so the next call pages the audit feed. */
function afterSweep(tb: MicrosoftTestbed, seq = 1): string {
  return encodeCursor({
    v: 1,
    a: MICROSOFT_ADAPTER_VERSION,
    seq,
    sw: { at: tb.clock.now().toISOString(), alt: true },
  });
}

async function drain(tb: MicrosoftTestbed, cursor: string | null, max = 30) {
  const pages: ProviderIngestPage[] = [];
  let current = cursor;
  for (let i = 0; i < max; i += 1) {
    const page = await tb.adapter.ingest('mailbox_audit', current, signal());
    pages.push(page);
    current = page.cursor;
    if (!page.hasMore) break;
  }
  return { pages, events: pages.flatMap((p) => p.events), cursor: current };
}

const changes = (events: ProviderEvent[]) => events.map((e) => [e.stream, e.mailbox?.change]);

describe('Microsoft mailbox_audit: sweep and audit feed', () => {
  it('sweeps inbox rules first, then pages Audit.Exchange with mapped companions', async () => {
    const tb = await bed();
    const sweep = await tb.adapter.ingest('mailbox_audit', null, signal());
    expect(sweep.hasMore).toBe(true);
    expect(changes(sweep.events)).toEqual([
      ['forwarding_changes', 'inbox_rule_added'],
      ['mailbox_audit', 'inbox_rule_added'],
    ]);
    expect(sweep.events[0]?.mailbox).toMatchObject({
      targetDomain: 'evil-mail.example',
      ruleTraits: ['forwards', 'forwards_external', 'stops_processing', 'matches_finance_keywords'],
    });
    // gale is disabled and frank is a guest (`#EXT#`, outside the linked domains, inv. 4): no
    // rules read for them and nothing stored for frank.
    const ruleReads = tb.sims.script.calls({ path: /\/messageRules$/ }).map((c) => c.path);
    expect(ruleReads).toHaveLength(5);
    expect(ruleReads.some((p) => p.includes(MS_USERS.gale))).toBe(false);
    expect(ruleReads.some((p) => p.includes(MS_USERS.frank))).toBe(false);

    const audit = await tb.adapter.ingest('mailbox_audit', sweep.cursor, signal());
    expect(changes(audit.events)).toEqual([
      ['mailbox_audit', 'access'],
      ['forwarding_changes', 'forwarding_added'],
      ['delegation_changes', 'permission_added'],
      ['delegation_changes', 'permission_added'],
      ['delegation_changes', 'delegate_added'],
    ]);
    expect(audit.events[0]).toMatchObject({
      ip: '203.0.113.30',
      mailbox: { change: 'access', clientType: 'owa' },
    });
    expect(audit.events[0]?.identity.externalId).toBe(MS_USERS.alex);
    expect(audit.events[1]?.mailbox).toEqual({
      change: 'forwarding_added',
      targetDomain: 'evil-mail.example',
    });
    expect(audit.events[4]?.mailbox).toEqual({
      change: 'delegate_added',
      targetDomain: 'contoso-it.example',
    });
    expect(audit.events.every((e) => e.eventId.startsWith('o365:'))).toBe(true);
    expect(cursorOf(audit).wm).toBe('2026-11-10T11:50:00.000Z');
    // Mailbox items were recorded (forwarding, permissions; rules from the sweep).
    const kinds = tb.mailboxState
      .all(tb.integration.id)
      .map((r) => r.kind)
      .sort();
    expect(kinds).toEqual([
      'delegate',
      'forwarding',
      'inbox_rule',
      'inbox_rule',
      'mailbox_permission',
      'send_as',
    ]);
    expect(
      JSON.stringify(tb.mailboxState.all(tb.integration.id), (_k, v: unknown) =>
        typeof v === 'bigint' ? v.toString() : v,
      ),
    ).not.toContain('collector@');
  });

  it('starts the Audit.Exchange subscription once after AF20022 (the only non-action write)', async () => {
    const tb = await bed();
    await drain(tb, afterSweep(tb));
    tb.clock.advance(30 * 60_000);
    await drain(tb, afterSweep(tb, 5));
    expect(tb.sims.script.writes()).toEqual([
      expect.objectContaining({
        simulator: 'o365',
        method: 'POST',
        path: `/api/v1.0/${MS_TENANT_ID}/activity/feed/subscriptions/start`,
      }),
    ]);
    expect(tb.directory.exchange.subscribed).toBe(true);
  });

  it('counts dropped operations and owner access', async () => {
    const events = vi.fn();
    const tb = await bed({ metrics: { events } });
    await tb.adapter.ingest('mailbox_audit', afterSweep(tb), signal());
    expect(events).toHaveBeenCalledWith(
      { provider: 'microsoft_entra', stream: 'mailbox_audit', result: 'dropped_operation' },
      2,
    );
  });

  it('derives rule traits from audit parameter names without MailboxSettings.Read', async () => {
    const tb = await bed();
    tb.sims.script.revokePermission('MailboxSettings.Read');
    const { events } = await drain(tb, null);
    const rule = events.find((e) => e.mailbox?.change === 'inbox_rule_added');
    expect(rule).toMatchObject({
      stream: 'forwarding_changes',
      eventId: expect.stringMatching(/^o365:/),
      mailbox: {
        targetDomain: 'evil-mail.example',
        ruleTraits: [
          'forwards',
          'forwards_external',
          'moves_to_folder',
          'moves_to_rarely_used_folder',
          'marks_read',
          'matches_finance_keywords',
        ],
      },
    });
    expect(tb.sims.script.calls({ path: /messageRules/ })).toHaveLength(0);
    expect(JSON.stringify(events)).not.toMatch(/invoice|payment|RSS|collector/i);
  });

  it('slices large blobs into pages of ≤ ATO_IDP_PAGE_MAX_EVENTS with the position in the cursor', async () => {
    const tb = await bed({ configEnv: { ATO_IDP_PAGE_MAX_EVENTS: '2' } });
    const now = tb.clock.now();
    const records = Array.from({ length: 5 }, () =>
      msExchangeRecord(now, { Operation: 'MailboxLogin', LogonType: 1 }),
    );
    tb.directory.exchange = {
      subscribed: true,
      blobs: [msAuditBlob(now, records, { contentId: 'EXAMPLEblob1' })],
    };
    const { pages, events } = await drain(tb, afterSweep(tb));
    expect(pages.map((p) => p.events.length)).toEqual([2, 2, 1]);
    expect(new Set(events.map((e) => e.eventId)).size).toBe(5);
    expect(cursorOf(pages[0] as ProviderIngestPage).page).toEqual({
      blob: { id: 'EXAMPLEblob1', offset: 2 },
    });
    expect(cursorOf(pages[1] as ProviderIngestPage).page).toEqual({
      blob: { id: 'EXAMPLEblob1', offset: 4 },
    });
    expect(tb.sims.script.calls({ path: /\/audit\// })).toHaveLength(3); // immutable blob re-fetched per slice
  });

  it('follows NextPageUri listing pages (same origin) to the end of the window', async () => {
    const tb = await bed();
    const now = tb.clock.now();
    tb.directory.exchange = {
      subscribed: true,
      listingPageSize: 1,
      blobs: [0, 1, 2].map((i) =>
        msAuditBlob(now, [msExchangeRecord(now, { Operation: 'MailboxLogin', LogonType: 2 })], {
          contentId: `EXAMPLElist${i}`,
          minutesAgo: 40 - i,
        }),
      ),
    };
    const { events } = await drain(tb, afterSweep(tb));
    expect(events.filter((e) => e.mailbox?.change === 'access')).toHaveLength(3);
    expect(
      tb.sims.script
        .calls({ path: /subscriptions\/content$/ })
        .map((c) => new URLSearchParams(c.query).get('nextPage')),
    ).toEqual([null, '1', '2']);
  });

  it('returns the events of processed records when throttled mid-page, resuming at the next blob', async () => {
    const tb = await bed();
    const now = tb.clock.now();
    const access = () => msExchangeRecord(now, { Operation: 'MailboxLogin', LogonType: 1 });
    tb.directory.exchange = {
      subscribed: true,
      blobs: [
        msAuditBlob(now, [access(), access()], { contentId: 'EXAMPLEa', minutesAgo: 41 }),
        msAuditBlob(now, [access(), access()], { contentId: 'EXAMPLEb', minutesAgo: 40 }),
      ],
    };
    tb.sims.script.inject({
      simulator: 'o365',
      path: /\/audit\/EXAMPLEb$/,
      status: 429,
      retryAfter: '30',
    });
    const throttled = await tb.adapter.ingest('mailbox_audit', afterSweep(tb), signal());
    expect(throttled.events).toHaveLength(2);
    expect(throttled).toMatchObject({ hasMore: true, retryAfterMs: 30_000 });
    expect(cursorOf(throttled).page).toEqual({ blob: { id: 'EXAMPLEb', offset: 0 } });
    const resumed = await tb.adapter.ingest('mailbox_audit', throttled.cursor, signal());
    expect(resumed.events).toHaveLength(2);
    expect(new Set([...throttled.events, ...resumed.events].map((e) => e.eventId)).size).toBe(4);
  });

  it('refuses a contentUri of another origin (blocked_host)', async () => {
    const tb = await bed();
    tb.directory.exchange.subscribed = true;
    tb.sims.script.inject({
      simulator: 'o365',
      path: /subscriptions\/content$/,
      status: 200,
      rawBody: JSON.stringify([
        {
          contentId: 'x',
          contentUri: 'https://attacker.example.invalid/blob',
          contentCreated: tb.clock.now().toISOString(),
        },
      ]),
    });
    await expect(
      tb.adapter.ingest('mailbox_audit', afterSweep(tb), signal()),
    ).rejects.toMatchObject({ code: 'blocked_host' });
  });

  it('fails missing_license without unified audit logging', async () => {
    const tb = await bed();
    tb.sims.script.setLicense(MS_TENANT_ID, 'unifiedAudit', false);
    await expect(
      tb.adapter.ingest('mailbox_audit', afterSweep(tb), signal()),
    ).rejects.toMatchObject({ code: 'missing_license' });
  });

  it('pages the weekly sweep through users and alternates with audit windows', async () => {
    const tb = await bed({ configEnv: { ATO_IDP_SNAPSHOT_MAX_USERS_PER_POLL: '2' } });
    const { pages } = await drain(tb, null);
    const userPages = tb.sims.script
      .calls({ path: '/v1.0/users', method: 'GET' })
      .filter((c) => c.path === '/v1.0/users');
    expect(userPages).toHaveLength(4); // 7 users, 2 per page
    expect(cursorOf(pages[0] as ProviderIngestPage).sw?.next).toEqual(expect.any(String));
    const last = cursorOf(pages[pages.length - 1] as ProviderIngestPage);
    expect(last.sw?.next).toBeUndefined();
    expect(last.wm).toBe('2026-11-10T11:50:00.000Z');
    // Not due again within the week.
    tb.sims.script.clearCalls();
    tb.clock.advance(60 * 60_000);
    await drain(tb, pages[pages.length - 1]?.cursor ?? null);
    expect(
      tb.sims.script.calls({ path: '/v1.0/users' }).filter((c) => c.path === '/v1.0/users'),
    ).toHaveLength(0);
  });

  it('only reads (telemetry never writes to Graph)', async () => {
    const tb = await bed();
    await drain(tb, null);
    expect(tb.sims.script.writes('graph')).toEqual([]);
  });
});

describe('Microsoft mailbox_audit: cursor-confirmed snapshots (D8.3)', () => {
  it('re-emits a priority refresh after a crash and never after the commit', async () => {
    const tb = await bed();
    const baseline = await drain(tb, null);
    const committed = baseline.cursor as string;
    // A new external forwarding rule appears; the api requests a refresh of alex's mailbox.
    tb.directory.messageRules[MS_USERS.alex]?.push({
      id: 'AQAAAJ5dZqC=',
      displayName: 'x',
      sequence: 3,
      isEnabled: true,
      actions: { redirectTo: [{ emailAddress: { address: 'drop@evil-mail.example' } }] },
    });
    const alex = { provider: 'microsoft_entra' as const, externalId: MS_USERS.alex };
    tb.mailboxState.requestRefresh(tb.integration.id, alex);

    const page = await tb.adapter.ingest('mailbox_audit', committed, signal());
    expect(changes(page.events)).toEqual([['forwarding_changes', 'inbox_rule_added']]);
    expect(cursorOf(page).pq).toEqual([identityHash('microsoft_entra', MS_USERS.alex)]);

    // Crash: the runner never committed `page.cursor`; the next poll runs from `committed` again.
    const replay = await tb.adapter.ingest('mailbox_audit', committed, signal());
    expect(replay.events.map((e) => e.eventId)).toEqual(page.events.map((e) => e.eventId));
    expect(tb.mailboxState.pendingPriority(tb.integration.id)).toBe(1);

    // Commit: the next poll runs from the new cursor; flags are cleared and nothing is re-emitted.
    const next = await tb.adapter.ingest('mailbox_audit', replay.cursor, signal());
    expect(tb.mailboxState.pendingPriority(tb.integration.id)).toBe(0);
    expect(next.events.map((e) => e.eventId)).not.toContain(page.events[0]?.eventId);
    expect(cursorOf(next).pq).toBeUndefined();
    expect(cursorOf(next).seq).toBeGreaterThan(cursorOf(replay).seq);
  });

  it('reports refresh support only with a probe proving inbox rule reads', async () => {
    const tb = await bed();
    expect(tb.adapter.mailboxRefreshSupported()).toBe(false); // never probed
    await tb.adapter.probe(signal());
    expect(tb.adapter.mailboxRefreshSupported()).toBe(true);
    tb.sims.script.revokePermission('MailboxSettings.Read');
    await tb.adapter.probe(signal());
    expect(tb.adapter.mailboxRefreshSupported()).toBe(false);
  });
});

describe('Microsoft mailbox_audit: identity scope (inv. 4, WP2-10)', () => {
  const UNLINKED = 'blake@contoso-labs.example';
  const FRANK_UPN = 'frank_partner-org.example#EXT#@contoso-it.example';

  it('neither reads rules nor stores items for users outside the provider-verified domains', async () => {
    const events = vi.fn();
    const tb = await bed({ metrics: { events } });
    // blake moved to a domain the organization never linked; frank is a guest (`#EXT#`).
    const blake = tb.directory.users.find((u) => u.id === MS_USERS.blake);
    if (!blake) throw new Error('dataset');
    blake.userPrincipalName = UNLINKED;
    blake.mail = UNLINKED;
    const now = tb.clock.now();
    const forwardingOf = (owner: string, id: string) =>
      msExchangeRecord(now, {
        Id: id,
        Operation: 'Set-Mailbox',
        UserId: owner,
        MailboxOwnerUPN: owner,
        Parameters: [
          { Name: 'Identity', Value: owner },
          { Name: 'ForwardingSmtpAddress', Value: 'smtp:collector@evil-mail.example' },
        ],
      });
    tb.directory.exchange = {
      subscribed: false,
      blobs: [
        msAuditBlob(now, [
          forwardingOf(UNLINKED, '00000000-0000-4000-8000-00000000a001'),
          forwardingOf(FRANK_UPN, '00000000-0000-4000-8000-00000000a002'),
          forwardingOf('alex@contoso-it.example', '00000000-0000-4000-8000-00000000a003'),
        ]),
      ],
    };
    const run = await drain(tb, null);

    const ruleReads = tb.sims.script.calls({ path: /\/messageRules$/ }).map((c) => c.path);
    expect(ruleReads.some((p) => p.includes(MS_USERS.blake))).toBe(false);
    expect(ruleReads.some((p) => p.includes(MS_USERS.frank))).toBe(false);
    expect(ruleReads.some((p) => p.includes(MS_USERS.alex))).toBe(true);

    const hashes = new Set(tb.mailboxState.all(tb.integration.id).map((r) => r.identityHash));
    expect(hashes.has(identityHash('microsoft_entra', MS_USERS.blake))).toBe(false);
    expect(hashes.has(identityHash('microsoft_entra', MS_USERS.frank))).toBe(false);
    expect(hashes.has(identityHash('microsoft_entra', MS_USERS.alex))).toBe(true);

    const owners = new Set(run.events.map((e) => e.identity.externalId));
    expect(owners.has(MS_USERS.blake)).toBe(false);
    expect(owners.has(MS_USERS.frank)).toBe(false);
    expect(
      run.events.some(
        (e) => e.identity.externalId === MS_USERS.alex && e.stream === 'forwarding_changes',
      ),
    ).toBe(true);
    expect(events).toHaveBeenCalledWith(
      { provider: 'microsoft_entra', stream: 'mailbox_audit', result: 'foreign_domain' },
      expect.any(Number),
    );
  });

  it('skips a priority refresh of an identity outside the linked domains', async () => {
    const tb = await bed();
    const baseline = await drain(tb, null);
    const blake = tb.directory.users.find((u) => u.id === MS_USERS.blake);
    if (!blake) throw new Error('dataset');
    blake.userPrincipalName = UNLINKED;
    blake.mail = UNLINKED;
    tb.sims.script.clearCalls();
    tb.mailboxState.requestRefresh(tb.integration.id, {
      provider: 'microsoft_entra',
      externalId: MS_USERS.blake,
      primaryEmail: 'blake@contoso-it.example', // stale stored address: Graph is authoritative
    });
    const page = await tb.adapter.ingest('mailbox_audit', baseline.cursor, signal());
    expect(page.events).toEqual([]);
    expect(tb.sims.script.calls({ path: /\/messageRules$/ })).toHaveLength(0);
  });
});

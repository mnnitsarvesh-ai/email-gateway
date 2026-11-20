import { afterEach, describe, expect, it, vi } from 'vitest';
import { decodeCursor } from '../core/cursor';
import { ProviderCallError } from '../core/errors';
import { appIdHash } from '../core/hash';
import {
  providerEventSchema,
  type ProviderIngestPage,
  type ProviderStream,
} from '../port/ato-port';
import { MS_SERVICE_PRINCIPALS, MS_USERS, msSignIn } from '../testing/datasets/microsoft';
import {
  createMicrosoftTestbed,
  type MicrosoftTestbed,
  type MicrosoftTestbedOptions,
} from '../testing/harness';
import { InMemoryRateBudget } from '../testing/in-memory-stores';
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

function cursorOf(page: ProviderIngestPage) {
  const decoded = decodeCursor(page.cursor, MICROSOFT_ADAPTER_VERSION);
  if (!decoded.ok) throw new Error('cursor_invalid');
  return decoded.cursor;
}

async function drain(
  tb: MicrosoftTestbed,
  stream: ProviderStream,
  cursor: string | null = null,
  max = 20,
) {
  const pages: ProviderIngestPage[] = [];
  let current = cursor;
  for (let i = 0; i < max; i += 1) {
    const page = await tb.adapter.ingest(stream, current, signal());
    pages.push(page);
    current = page.cursor;
    if (!page.hasMore) break;
  }
  return { pages, events: pages.flatMap((p) => p.events), cursor: current };
}

describe('Microsoft adapter: identity', () => {
  it('has kind and version and declares every stream and action', async () => {
    const tb = await bed();
    expect(tb.adapter.kind).toBe('microsoft_entra');
    expect(tb.adapter.version).toBe('msgraph-ato/1');
    const declared = tb.adapter.declaredCapabilities();
    expect(Object.keys(declared.streams)).toHaveLength(7);
    expect(Object.keys(declared.actions)).toHaveLength(6);
    expect(() => tb.newAdapter({ provider: 'google_workspace' })).toThrow(
      'adapter_provider_mismatch',
    );
  });
});

describe('Microsoft adapter: sign_ins', () => {
  it('maps the window [now − 15 min, now − 2 min] and moves the watermark to its end', async () => {
    const tb = await bed();
    const page = await tb.adapter.ingest('sign_ins', null, signal());
    expect(page.hasMore).toBe(false);
    expect(page.events.map((e) => [e.outcome, e.failureCode])).toEqual([
      ['success', undefined],
      ['failure', 'entra_50126'],
      ['interrupted', undefined],
    ]);
    for (const event of page.events)
      expect(providerEventSchema.safeParse(event).success).toBe(true);
    expect(cursorOf(page)).toEqual({
      v: 1,
      a: 'msgraph-ato/1',
      seq: 1,
      wm: '2026-11-10T11:58:00.000Z',
    });
    const call = tb.sims.script.calls({ path: '/v1.0/auditLogs/signIns' });
    expect(call).toHaveLength(1);
  });

  it('pages to completion through $skiptoken without losing or repeating events', async () => {
    const tb = await bed({ configEnv: { ATO_IDP_PAGE_MAX_EVENTS: '2' } });
    for (let i = 0; i < 5; i += 1)
      tb.directory.signIns.push(msSignIn(tb.clock.now(), { minutesAgo: 5 + i }));
    const { pages, events } = await drain(tb, 'sign_ins');
    expect(pages.map((p) => p.events.length)).toEqual([2, 2, 2, 2]);
    expect(new Set(events.map((e) => e.eventId)).size).toBe(8);
    const seqs = pages.map((p) => cursorOf(p).seq);
    expect(seqs).toEqual([1, 2, 3, 4]);
    expect(cursorOf(pages[0] as ProviderIngestPage).page).toEqual(expect.any(String));
    expect(cursorOf(pages[3] as ProviderIngestPage).wm).toBe('2026-11-10T11:58:00.000Z');
  });

  it('re-reads the overlap (duplicates by event id) and picks up late events', async () => {
    const tb = await bed();
    const first = await tb.adapter.ingest('sign_ins', null, signal());
    const late = msSignIn(tb.clock.now(), { minutesAgo: 4 }); // arrives after the first poll, before the watermark
    tb.directory.signIns.push(late);
    tb.clock.advance(5 * 60_000);
    const second = await tb.adapter.ingest('sign_ins', first.cursor, signal());
    const ids = second.events.map((e) => e.eventId);
    expect(ids).toEqual(
      expect.arrayContaining([...first.events.map((e) => e.eventId), `entra:${late.id}`]),
    );
    expect(cursorOf(second).seq).toBe(2);
  });

  it('returns an unchanged cursor when nothing new has settled', async () => {
    const tb = await bed();
    const first = await tb.adapter.ingest('sign_ins', null, signal());
    const again = await tb.adapter.ingest('sign_ins', first.cursor, signal());
    expect(again).toEqual({ events: [], cursor: first.cursor, hasMore: false });
  });

  it('backfills from a start cursor clamped to the provider retention (30 days for sign-ins)', async () => {
    const tb = await bed();
    const start = Buffer.from(
      JSON.stringify({
        v: 1,
        a: 'msgraph-ato/1',
        seq: 3,
        wm: new Date(tb.clock.ms() - 40 * 86_400_000).toISOString(),
      }),
    ).toString('base64url');
    const page = await tb.adapter.ingest('sign_ins', start, signal());
    expect(page.hasMore).toBe(false); // Graph windows are not sliced: one window up to now − settle
    const query = new URLSearchParams(
      tb.sims.script.calls({ path: '/v1.0/auditLogs/signIns' })[0]?.query ?? '',
    );
    const thirtyDaysAgo = new Date(tb.clock.ms() - 30 * 86_400_000).toISOString();
    expect(query.get('$filter')).toBe(
      `createdDateTime ge ${thirtyDaysAgo} and createdDateTime le 2026-11-10T11:58:00.000Z`,
    );
    expect(query.get('$top')).toBe('200');
    expect(cursorOf(page).seq).toBe(4);
  });

  it('restarts an invalid cursor at now − overlap, counted', async () => {
    const cursorReset = vi.fn();
    const tb = await bed({ metrics: { cursorReset } });
    const page = await tb.adapter.ingest('sign_ins', 'not-a-cursor', signal());
    expect(cursorReset).toHaveBeenCalledWith({ provider: 'microsoft_entra', stream: 'sign_ins' });
    expect(page.events).toHaveLength(3);
    expect(cursorOf(page).seq).toBe(Math.floor(tb.clock.ms() / 1000) + 1);
  });

  it('ends a page early on throttling and resumes from the same cursor', async () => {
    const tb = await bed({ configEnv: { ATO_IDP_PAGE_MAX_EVENTS: '2' } });
    const first = await tb.adapter.ingest('sign_ins', null, signal());
    expect(first.hasMore).toBe(true);
    tb.sims.script.inject({
      simulator: 'graph',
      path: '/v1.0/auditLogs/signIns',
      status: 429,
      retryAfter: '7',
    });
    const throttled = await tb.adapter.ingest('sign_ins', first.cursor, signal());
    expect(throttled).toEqual({
      events: [],
      cursor: first.cursor,
      hasMore: true,
      retryAfterMs: 7_000,
    });
    const resumed = await tb.adapter.ingest('sign_ins', throttled.cursor, signal());
    expect(resumed.events).toHaveLength(1);
    expect(resumed.hasMore).toBe(false);
  });

  it('ends the page with retryAfterMs 1000 when the rate budget stays exhausted', async () => {
    const budget = new InMemoryRateBudget({
      graph: 5,
      o365: 2,
      google_reports: 2,
      google_directory: 5,
      gmail: 10,
    });
    budget.exhaust('graph');
    const tb = await bed({ budget });
    const page = await tb.adapter.ingest('sign_ins', null, signal());
    expect(page).toMatchObject({ events: [], hasMore: true, retryAfterMs: 1_000 });
    expect(tb.sims.script.calls()).toHaveLength(0);
  });

  it('fails missing_permission and missing_license (not retryable)', async () => {
    const tb = await bed();
    tb.sims.script.revokePermission('AuditLog.Read.All');
    const permission = await tb.adapter.ingest('sign_ins', null, signal()).catch((e: unknown) => e);
    expect(permission).toBeInstanceOf(ProviderCallError);
    expect(permission).toMatchObject({ code: 'missing_permission', retryable: false });
    const tb2 = await createMicrosoftTestbed();
    try {
      tb2.sims.script.setLicense(tb2.directory.tenantId, 'entraP1', false);
      tb2.sims.script.setLicense(tb2.directory.tenantId, 'entraP2', false);
      await expect(tb2.adapter.ingest('sign_ins', null, signal())).rejects.toMatchObject({
        code: 'missing_license',
      });
    } finally {
      await tb2.stop();
    }
  });

  it('classifies an unavailable provider as retryable', async () => {
    const tb = await bed();
    tb.sims.script.inject({ path: '/v1.0/auditLogs/signIns', status: 503 });
    await expect(tb.adapter.ingest('sign_ins', null, signal())).rejects.toMatchObject({
      code: 'provider_unavailable',
      retryable: true,
    });
  });

  it('fails connection_inactive when the 8.2 connection is not active', async () => {
    const tb = await bed();
    tb.connections.update(tb.integration.organizationId, tb.integration.connectionPublicId, {
      status: 'disabled',
    });
    await expect(tb.adapter.ingest('sign_ins', null, signal())).rejects.toMatchObject({
      code: 'connection_inactive',
    });
  });

  it('refuses a connection of another organization (echo check)', async () => {
    const tb = await bed();
    const other = tb.newAdapter({ organizationId: '2002' });
    await expect(other.ingest('sign_ins', null, signal())).rejects.toMatchObject({
      code: 'connection_not_found',
    });
  });
});

describe('Microsoft adapter: risk_events and its companion session_events', () => {
  it('emits risk and token-risk events from one feed, dropping dismissed detections', async () => {
    const events = vi.fn();
    const tb = await bed({ metrics: { events } });
    const page = await tb.adapter.ingest('risk_events', null, signal());
    expect(page.events.map((e) => [e.stream, e.riskDetail, e.riskLevel])).toEqual([
      ['risk_events', 'unfamiliar_features', 'high'],
      ['session_events', 'token_anomaly', 'medium'],
    ]);
    expect(events).toHaveBeenCalledWith(
      { provider: 'microsoft_entra', stream: 'risk_events', result: 'dropped_operation' },
      1,
    );
  });

  it('never polls a companion', async () => {
    const tb = await bed();
    for (const stream of ['session_events', 'forwarding_changes', 'delegation_changes'] as const) {
      const page = await tb.adapter.ingest(stream, null, signal());
      expect(page.events).toEqual([]);
      expect(page.hasMore).toBe(false);
      expect(page.cursor).toMatch(/^companion:v1:(risk_events|mailbox_audit)$/);
    }
    expect(tb.sims.script.calls()).toHaveLength(0);
  });

  it('drops events of a disabled stream before they leave the page (stream_disabled)', async () => {
    const events = vi.fn();
    const tb = await bed({
      metrics: { events },
      settings: (s) => ({ ...s, streams: { ...s.streams, session_events: { enabled: false } } }),
    });
    const page = await tb.adapter.ingest('risk_events', null, signal());
    expect(page.events.map((e) => e.stream)).toEqual(['risk_events']);
    expect(events).toHaveBeenCalledWith(
      { provider: 'microsoft_entra', stream: 'session_events', result: 'stream_disabled' },
      1,
    );
  });

  it('omits hidden risk levels without Entra ID P2', async () => {
    const tb = await bed();
    tb.sims.script.setLicense(tb.directory.tenantId, 'entraP2', false);
    const page = await tb.adapter.ingest('risk_events', null, signal());
    expect(page.events.every((e) => e.riskLevel === undefined)).toBe(true);
  });
});

describe('Microsoft adapter: oauth_consents', () => {
  it('maps consent audits with publisher verification looked up and cached', async () => {
    const tb = await bed();
    const page = await tb.adapter.ingest('oauth_consents', null, signal());
    expect(page.events.map((e) => e.oauth)).toEqual([
      {
        appIdHash: appIdHash(MS_SERVICE_PRINCIPALS.unverified),
        appDisplayName: 'Mail Helper Example',
        scopes: ['mail_read', 'mail_send', 'offline_access'],
        consentType: 'user',
        publisherVerified: false,
      },
      {
        appIdHash: appIdHash(MS_SERVICE_PRINCIPALS.verified),
        appDisplayName: 'Verified Example App',
        scopes: ['user_read'],
        consentType: 'admin',
        publisherVerified: true,
      },
    ]);
    expect(page.events[0]?.identity.externalId).toBe(MS_USERS.alex);
    tb.clock.advance(60_000);
    await tb.adapter.ingest('oauth_consents', null, signal());
    expect(tb.sims.script.calls({ path: '/v1.0/servicePrincipals/' })).toHaveLength(2); // cached 24 h
    const query = tb.sims.script.calls({ path: '/v1.0/auditLogs/directoryAudits' });
    expect(query.length).toBeGreaterThan(0);
  });

  it('leaves publisherVerified undefined without a directory read permission', async () => {
    const tb = await bed();
    tb.sims.script.revokePermission('Directory.Read.All');
    const page = await tb.adapter.ingest('oauth_consents', null, signal());
    expect(page.events).toHaveLength(2);
    expect(page.events.every((e) => e.oauth?.publisherVerified === undefined)).toBe(true);
    expect(tb.sims.script.calls({ path: '/v1.0/servicePrincipals/' })).toHaveLength(0);
  });
});

describe('Microsoft adapter: resolveIdentity (D9.2)', () => {
  it('resolves by UPN, mail, proxy address and alias; null when unknown', async () => {
    const tb = await bed();
    const s = signal();
    expect(await tb.adapter.resolveIdentity('Alex@Contoso-IT.example', s)).toEqual({
      provider: 'microsoft_entra',
      externalId: MS_USERS.alex,
      userPrincipalName: 'alex@contoso-it.example',
      primaryEmail: 'alex@contoso-it.example',
    });
    expect((await tb.adapter.resolveIdentity('frank@partner-org.example', s))?.externalId).toBe(
      MS_USERS.frank,
    );
    expect((await tb.adapter.resolveIdentity('erin.alias@contoso-it.example', s))?.externalId).toBe(
      MS_USERS.erin,
    );
    expect((await tb.adapter.resolveIdentity('erin@contoso-it.example', s))?.primaryEmail).toBe(
      'erin@contoso-it.example',
    );
    expect(await tb.adapter.resolveIdentity('nobody@contoso-it.example', s)).toBeNull();
    expect(await tb.adapter.resolveIdentity('not an address', s)).toBeNull();
  });
});

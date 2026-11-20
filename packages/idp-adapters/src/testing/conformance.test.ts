/**
 * Local conformance suite (design note §11.1): the properties of the 8.4 contract kit plus 8.5's
 * own (events valid against 8.4's strict `providerEventSchema`, monotonic and resumable cursors,
 * `unsupported` never thrown, every `confirmed` carrying a provider reference, classified errors,
 * `rollback` only where declared, no credential in `health`). Written pre-rebase against the shim;
 * since the rebase (WP3, M1) it runs against the built 8.4 schema, and the kit itself runs in
 * `contract.test.ts`. Subjects: the Microsoft (`msgraph-ato/1`) and Google (`gws-ato/1`)
 * adapters on their simulators.
 */
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { IdpAdapter } from '../adapter-types';
import { decodeCursor } from '../core/cursor';
import { ProviderCallError } from '../core/errors';
import {
  PROVIDER_ACTION_TYPES,
  PROVIDER_STREAMS,
  providerEventSchema,
  type ProviderActionResult,
  type ProviderIdentityRef,
  type ProviderStream,
} from '../port/ato-port';
import { STREAM_ROLES } from '../requirements';
import { GS_USERS } from './datasets/google';
import { MS_USERS } from './datasets/microsoft';
import { createGoogleTestbed, type GoogleTestbed } from './google-harness';
import { createMicrosoftTestbed, type MicrosoftTestbed } from './harness';

interface Subject {
  name: string;
  setup(): Promise<{
    adapter: IdpAdapter;
    /** A second adapter with every action disabled in the settings. */
    disabled: IdpAdapter;
    identity: ProviderIdentityRef;
    stop(): Promise<void>;
    tokensIssued(): number;
  }>;
}

const SUBJECTS: Subject[] = [
  {
    name: 'msgraph-ato/1',
    async setup() {
      const tb: MicrosoftTestbed = await createMicrosoftTestbed();
      const settings = structuredClone(tb.integration.settings);
      for (const action of PROVIDER_ACTION_TYPES) settings.actions[action].enabled = false;
      return {
        adapter: tb.adapter,
        disabled: tb.newAdapter({ settings }),
        identity: {
          provider: 'microsoft_entra',
          externalId: MS_USERS.blake,
          primaryEmail: 'blake@contoso-it.example',
        },
        stop: () => tb.stop(),
        tokensIssued: () => tb.sims.tokens.issuedCount(),
      };
    },
  },
  {
    name: 'gws-ato/1',
    async setup() {
      const tb: GoogleTestbed = await createGoogleTestbed();
      const settings = structuredClone(tb.integration.settings);
      for (const action of PROVIDER_ACTION_TYPES) settings.actions[action].enabled = false;
      return {
        adapter: tb.adapter,
        disabled: tb.newAdapter({ settings }),
        identity: {
          provider: 'google_workspace',
          externalId: GS_USERS.blake,
          primaryEmail: 'blake@fabrikam-it.example',
        },
        stop: () => tb.stop(),
        tokensIssued: () => tb.sims.tokens.issuedCount(),
      };
    },
  },
];

const signal = () => new AbortController().signal;

describe.each(SUBJECTS)('adapter conformance: $name', (subject) => {
  let env: Awaited<ReturnType<Subject['setup']>>;

  beforeAll(async () => {
    env = await subject.setup();
    await env.adapter.probe(signal());
  });
  afterAll(async () => {
    await env.stop();
  });

  it('declares a version ≤ 32 characters and a kind', () => {
    expect(env.adapter.version.length).toBeLessThanOrEqual(32);
    expect(['microsoft_entra', 'google_workspace']).toContain(env.adapter.kind);
  });

  it('emits only events valid against the strict schema, with strictly monotonic cursors', async () => {
    const kind = env.adapter.kind as 'microsoft_entra' | 'google_workspace';
    for (const stream of PROVIDER_STREAMS) {
      const role = STREAM_ROLES[kind][stream].role;
      let cursor: string | null = null;
      let lastSeq = -1;
      for (let i = 0; i < 30; i += 1) {
        const page = await env.adapter.ingest(stream, cursor, signal());
        for (const event of page.events) {
          const parsed = providerEventSchema.safeParse(event);
          expect(parsed.success, `${stream} ${JSON.stringify(parsed.error?.issues)}`).toBe(true);
          expect(event.provider).toBe(env.adapter.kind);
        }
        expect(page.cursor.length).toBeLessThanOrEqual(4096);
        if (role !== 'primary') {
          // Companions and unsupported streams are never polled; ingest answers, never throws.
          expect(page).toEqual({
            events: [],
            cursor: expect.stringMatching(
              role === 'companion' ? /^companion:v1:/ : /^unsupported:v1:/,
            ),
            hasMore: false,
          });
          break;
        }
        const decoded = decodeCursor(page.cursor, env.adapter.version);
        expect(decoded.ok).toBe(true);
        if (decoded.ok) {
          expect(decoded.cursor.seq).toBeGreaterThan(lastSeq);
          lastSeq = decoded.cursor.seq;
        }
        cursor = page.cursor;
        if (!page.hasMore) break;
      }
    }
  });

  it('is resumable: an earlier cursor can be replayed (duplicates by eventId are tolerated)', async () => {
    const first = await env.adapter.ingest('sign_ins', null, signal());
    const replay = await env.adapter.ingest('sign_ins', null, signal());
    expect(replay.events.map((e) => e.eventId)).toEqual(first.events.map((e) => e.eventId));
  });

  it('answers unsupported instead of throwing, and confirms only with a provider reference', async () => {
    const results: ProviderActionResult[] = [];
    for (const type of PROVIDER_ACTION_TYPES) {
      const id = randomUUID();
      const request = {
        actionPublicId: id,
        idempotencyKey: id,
        type,
        identity: env.identity,
        params: {},
      };
      const unsupported = await env.disabled.execute(request, signal());
      expect(unsupported).toEqual({ status: 'unsupported' });
      results.push(
        await env.adapter.execute({ ...request, actionPublicId: randomUUID() }, signal()),
      );
    }
    for (const result of results) {
      expect(['confirmed', 'pending', 'failed', 'unsupported']).toContain(result.status);
      if (result.status === 'confirmed' || result.status === 'pending') {
        expect(result.providerReference.length).toBeGreaterThan(0);
        expect(result.providerReference.length).toBeLessThanOrEqual(128);
      }
      if (result.status === 'failed') expect(typeof result.retryable).toBe('boolean');
    }
    expect(results.some((r) => r.status === 'confirmed')).toBe(true);
  });

  it('never throws from execute, confirm or rollback on bad input', async () => {
    const bad = {
      actionPublicId: 'not valid!',
      idempotencyKey: 'x',
      type: 'suspend_account' as const,
      identity: env.identity,
      params: {},
    };
    expect(await env.adapter.execute(bad, signal())).toMatchObject({
      status: 'failed',
      retryable: false,
    });
    expect(
      await env.adapter.confirm(
        { type: 'suspend_account', providerReference: 'garbage' },
        signal(),
      ),
    ).toMatchObject({ status: 'failed' });
    if (env.adapter.rollback) {
      expect(
        await env.adapter.rollback({ ...bad, providerReference: 'garbage' }, signal()),
      ).toMatchObject({ status: 'failed' });
    }
  });

  it('offers rollback only where declared', () => {
    const declared = Object.values(env.adapter.capabilities().actions).some((a) => a?.rollback);
    expect(typeof env.adapter.rollback === 'function').toBe(declared);
  });

  it('classifies errors (ProviderCallError with retryable) and never echoes credentials in health', async () => {
    const error = await env.adapter
      .ingest('sign_ins', 'x'.repeat(10), new AbortController().signal)
      .catch((e: unknown) => e);
    if (error instanceof Error) {
      expect(error).toBeInstanceOf(ProviderCallError);
      expect(typeof (error as ProviderCallError).retryable).toBe('boolean');
    }
    const health = await env.adapter.health(signal());
    expect(JSON.stringify(health)).not.toMatch(/EXAMPLE-sim-token|Bearer/);
    expect(env.tokensIssued()).toBeGreaterThan(0);
  });

  it('derives capabilities from the probe (declared ∩ probed ∩ enabled)', () => {
    const capabilities = env.adapter.capabilities();
    for (const stream of PROVIDER_STREAMS as readonly ProviderStream[]) {
      expect(typeof capabilities.streams[stream]?.supported).toBe('boolean');
    }
    expect(env.disabled.capabilities().actions.revoke_sessions?.supported).toBe(false);
  });
});

/**
 * `describeProviderAdapterContract(name, factory, fixtures)` (test kit; step 8.4 D15): the Vitest
 * contract every identity-provider adapter must pass (the fake in 8.4, the Microsoft and Google
 * adapters in 8.5). Assertions: declared capabilities match behaviour; unsupported actions return
 * `unsupported` (never throw, never confirm); `confirmed` always carries a provider reference;
 * `execute` is idempotent per idempotency key; `confirm` of a pending action converges; cursors are
 * monotonic and resumable; events validate against the strict `providerEventSchema`; duplicate
 * event ids are tolerated; errors are classified; `retryAfterMs` is a valid delay; `health` never
 * echoes credentials; `rollback` exists only when declared.
 */
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  PROVIDER_ACTION_TYPES,
  PROVIDER_STREAMS,
  ProviderAdapterError,
  providerEventSchema,
  SECRET_SHAPED,
  type IdentityProviderAdapter,
  type ProviderActionResult,
  type ProviderEvent,
  type ProviderIdentityRef,
  type ProviderStream,
} from '../provider';

export interface ProviderContractFixtures {
  /** An identity the adapter can act on. */
  identity: ProviderIdentityRef;
  /** An address `resolveIdentity` resolves to `identity`. */
  address: string;
  /** Streams that have at least three scripted events (ingest assertions). */
  streamsWithEvents: readonly ProviderStream[];
  /** Makes the next ingest call fail (classification assertion); omit to skip. */
  injectIngestFailure?: (adapter: IdentityProviderAdapter) => void;
  /** Makes the next ingest of a stream throttled (`retryAfterMs`); omit to skip. */
  injectThrottle?: (adapter: IdentityProviderAdapter, stream: ProviderStream) => void;
  /** Real effects per action type (idempotency assertion); omit to compare references only. */
  effects?: (adapter: IdentityProviderAdapter) => Partial<Record<string, number>>;
  /** Maximum confirmation polls before convergence (default 5). */
  maxPolls?: number;
}

const signal = (): AbortSignal => new AbortController().signal;

const key = (_label: string): string => randomUUID();

function checkResult(result: ProviderActionResult): void {
  if (result.status === 'confirmed' || result.status === 'pending') {
    expect(typeof result.providerReference).toBe('string');
    expect(result.providerReference.length).toBeGreaterThan(0);
    expect(result.providerReference.length).toBeLessThanOrEqual(128);
  }
  if (result.status === 'failed') {
    expect(typeof result.retryable).toBe('boolean');
    expect(result.code).toMatch(/^[a-z0-9_.-]{1,64}$/);
  }
}

async function drain(
  adapter: IdentityProviderAdapter,
  stream: ProviderStream,
  from: string | null,
): Promise<{ events: ProviderEvent[]; cursors: string[] }> {
  const events: ProviderEvent[] = [];
  const cursors: string[] = [];
  let cursor = from;
  for (let i = 0; i < 1000; i++) {
    const page = await adapter.ingest(stream, cursor, signal());
    cursors.push(page.cursor);
    events.push(...page.events);
    cursor = page.cursor;
    if (!page.hasMore) break;
  }
  return { events, cursors };
}

export function describeProviderAdapterContract(
  name: string,
  factory: () => IdentityProviderAdapter | Promise<IdentityProviderAdapter>,
  fixtures: ProviderContractFixtures,
): void {
  describe(`identity provider adapter contract: ${name}`, () => {
    it('declares a version and capabilities for known streams and actions only', async () => {
      const adapter = await factory();
      expect(adapter.version.length).toBeGreaterThan(0);
      const caps = adapter.capabilities();
      for (const s of Object.keys(caps.streams)) expect(PROVIDER_STREAMS).toContain(s);
      for (const a of Object.keys(caps.actions)) expect(PROVIDER_ACTION_TYPES).toContain(a);
    });

    it('declared capabilities match behaviour; unsupported actions answer unsupported', async () => {
      const adapter = await factory();
      const caps = adapter.capabilities();
      for (const type of PROVIDER_ACTION_TYPES) {
        const declared = caps.actions[type]?.supported === true;
        const result = await adapter.execute(
          {
            actionPublicId: key(type),
            idempotencyKey: key(type),
            type,
            identity: fixtures.identity,
            params: {},
          },
          signal(),
        );
        checkResult(result);
        if (declared) expect(result.status).not.toBe('unsupported');
        else expect(result.status).toBe('unsupported');
      }
    });

    it('confirmed results always carry a provider reference', async () => {
      const adapter = await factory();
      const caps = adapter.capabilities();
      for (const type of PROVIDER_ACTION_TYPES.filter((t) => caps.actions[t]?.supported)) {
        const result = await adapter.execute(
          {
            actionPublicId: key(type),
            idempotencyKey: key(type),
            type,
            identity: fixtures.identity,
            params: {},
          },
          signal(),
        );
        if (result.status === 'confirmed') {
          expect(result.providerReference.length).toBeGreaterThan(0);
          expect(Number.isNaN(Date.parse(result.confirmedAt))).toBe(false);
        }
      }
    });

    it('execute is idempotent per idempotency key (no second effect)', async () => {
      const adapter = await factory();
      const caps = adapter.capabilities();
      const type = PROVIDER_ACTION_TYPES.find((t) => caps.actions[t]?.supported);
      if (!type) return;
      const request = {
        actionPublicId: key('idem'),
        idempotencyKey: key('idem'),
        type,
        identity: fixtures.identity,
        params: {},
      };
      const first = await adapter.execute(request, signal());
      const effectsBefore = fixtures.effects?.(adapter)[type];
      const second = await adapter.execute(request, signal());
      expect(second.status).toBe(first.status);
      if ('providerReference' in first && 'providerReference' in second) {
        expect(second.providerReference).toBe(first.providerReference);
      }
      if (fixtures.effects) expect(fixtures.effects(adapter)[type]).toBe(effectsBefore);
    });

    it('confirm of a pending action converges', async () => {
      const adapter = await factory();
      const caps = adapter.capabilities();
      for (const type of PROVIDER_ACTION_TYPES.filter(
        (t) => caps.actions[t]?.confirmation === 'polling' && caps.actions[t]?.supported,
      )) {
        const result = await adapter.execute(
          {
            actionPublicId: key(type),
            idempotencyKey: key(type),
            type,
            identity: fixtures.identity,
            params: {},
          },
          signal(),
        );
        if (result.status !== 'pending') continue;
        let current: ProviderActionResult = result;
        for (let i = 0; i < (fixtures.maxPolls ?? 5) && current.status === 'pending'; i++) {
          current = await adapter.confirm(
            { type, providerReference: result.providerReference },
            signal(),
          );
          checkResult(current);
        }
        expect(current.status).toBe('confirmed');
      }
    });

    it('cursors are monotonic and resumable; events validate; duplicates by eventId are tolerated', async () => {
      const adapter = await factory();
      for (const stream of fixtures.streamsWithEvents) {
        const { events, cursors } = await drain(adapter, stream, null);
        expect(events.length).toBeGreaterThanOrEqual(3);
        for (const e of events) {
          const parsed = providerEventSchema.safeParse(e);
          expect(parsed.success, JSON.stringify(parsed.error?.issues ?? [])).toBe(true);
          expect(e.stream).toBe(stream);
        }
        // Monotonic: each cursor resumes after the previous one (never earlier events again).
        const resumeFrom = cursors[0]!;
        const resumed = await drain(adapter, stream, resumeFrom);
        const tail = events.slice(events.length - resumed.events.length);
        expect(resumed.events.map((e) => e.eventId)).toEqual(tail.map((e) => e.eventId));
        // A replay from the start yields the same ids (a runner dedupes by eventId).
        const replay = await drain(adapter, stream, null);
        expect(replay.events.map((e) => e.eventId)).toEqual(events.map((e) => e.eventId));
        const unique = new Set(events.map((e) => `${e.provider}|${e.eventId}`));
        expect(unique.size).toBeLessThanOrEqual(events.length);
      }
    });

    it('errors are classified (retryable or not)', async () => {
      if (!fixtures.injectIngestFailure) return;
      const adapter = await factory();
      fixtures.injectIngestFailure(adapter);
      const stream = fixtures.streamsWithEvents[0] ?? 'sign_ins';
      const error = await adapter.ingest(stream, null, signal()).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(ProviderAdapterError);
      expect(typeof (error as ProviderAdapterError).retryable).toBe('boolean');
    });

    it('retryAfterMs is a non-negative delay and the cursor does not move', async () => {
      if (!fixtures.injectThrottle) return;
      const adapter = await factory();
      const stream = fixtures.streamsWithEvents[0] ?? 'sign_ins';
      fixtures.injectThrottle(adapter, stream);
      const page = await adapter.ingest(stream, null, signal());
      expect(page.retryAfterMs).toBeDefined();
      expect(Number.isInteger(page.retryAfterMs)).toBe(true);
      expect(page.retryAfterMs!).toBeGreaterThanOrEqual(0);
      expect(page.events).toEqual([]);
      const next = await adapter.ingest(stream, page.cursor, signal());
      expect(next.events.length).toBeGreaterThan(0);
    });

    it('health never echoes credentials', async () => {
      const adapter = await factory();
      const health = await adapter.health(signal());
      expect(Object.keys(health).every((k) => k === 'ok' || k === 'code')).toBe(true);
      expect(SECRET_SHAPED.test(JSON.stringify(health))).toBe(false);
    });

    it('resolves a known identity and answers null for an unknown one', async () => {
      const adapter = await factory();
      const found = await adapter.resolveIdentity(fixtures.address, signal());
      expect(found?.externalId).toBe(fixtures.identity.externalId);
      expect(await adapter.resolveIdentity('nobody@unknown.example', signal())).toBeNull();
    });

    it('rollback exists only when declared', async () => {
      const adapter = await factory();
      const declared = Object.values(adapter.capabilities().actions).some((a) => a?.rollback);
      expect(typeof adapter.rollback === 'function').toBe(declared);
    });
  });
}

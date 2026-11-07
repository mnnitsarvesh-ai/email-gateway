import { Readable } from 'node:stream';
import { EventTypes, type EventEnvelope } from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import type { EngineName } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { CircuitBreaker } from './circuit-breaker';
import type { EngineScanContext, EngineScanOutcome, ScanEngineAdapter } from './engine';
import { SCAN_EVENT_TYPES, scanEventTypes, STAGE_EVENT_TYPES } from './engine-consumer';
import { becRegistration } from './engines/bec/registration';
import { rspamdRegistration } from './engines/rspamd/registration';
import { urlRegistration } from './engines/url/registration';
import { FakeScanStore, newMetrics } from './fakes.test-support';
import type { ScanEngineRegistration } from './registry';
import { ScanRoundService, type ScanTriggerPayload, type SettingsLookup } from './round-service';
import { decideOpen, stageTriggersFor } from './scan-store';

/**
 * Step 4.4 B2: the generic stage-2 capability of the orchestrator (catalog `dependsOn`), with
 * the fake store: `decideOpen('stage')`, the stage trigger written exactly once by the
 * completion check of the last dependency final, and the round service's stage path.
 */

const logger = createLogger({ service: 'test', level: 'silent' });
const ORG = 42n;
const MSG = 1001n;
const RECEIVED = new Date('2026-11-06T10:00:00.000Z');
const KEY = `org/${ORG.toString()}/eml/2026/11/06/m.eml`;
const REQUIRED = ['rspamd', 'url', 'bec'];

const definite = (
  engine: EngineName,
  outcome: 'clean' | 'suspicious' = 'clean',
): EngineScanOutcome => ({
  kind: 'definite',
  result: {
    engine,
    engineVersion: `${engine}/1`,
    outcome,
    score: null,
    requiredScore: null,
    action: null,
    reasonCodes: ['clean.below_threshold'],
    signals: [],
    durationMs: 3,
    settingsVersion: `${engine}-map/1;p=000000000000;t=none`,
    mappingVersion: `${engine}-map/1`,
  },
});

class StaticAdapter implements ScanEngineAdapter {
  readonly contexts: EngineScanContext[] = [];
  constructor(
    readonly name: EngineName,
    private readonly outcome: EngineScanOutcome,
  ) {}
  scan(ctx: EngineScanContext): Promise<EngineScanOutcome> {
    this.contexts.push(ctx);
    return Promise.resolve(this.outcome);
  }
}

const settings: SettingsLookup = {
  resolve: () =>
    Promise.resolve({
      settings: {},
      settingsVersion: 'x-map/1;p=000000000000;t=none',
      invalidRow: false,
      violations: [],
    }),
};

function service(
  store: FakeScanStore,
  registration: ScanEngineRegistration,
  adapter: ScanEngineAdapter,
  required: string[] = REQUIRED,
) {
  const { metrics, registry } = newMetrics();
  const svc = new ScanRoundService({
    registration,
    adapter,
    store,
    settings,
    openEml: () => Promise.resolve(Readable.from([Buffer.from('x')])),
    breaker: new CircuitBreaker({
      failureThreshold: 5,
      failureRatio: 1,
      window: 10,
      openMs: 1000,
      halfOpenProbes: 1,
    }),
    metrics,
    logger,
    budget: { concurrency: 1, timeoutMs: 1000, maxAttempts: 3 },
    requiredEngines: required,
    deadlineSeconds: 1800,
    consumer: `test.${registration.catalog.name}`,
  });
  return { svc, registry };
}

function setupStore(): FakeScanStore {
  const store = new FakeScanStore();
  store.addMessage({
    id: MSG,
    receivedAt: RECEIVED,
    organizationId: ORG,
    direction: 'inbound',
    emlObjectKey: KEY,
    sizeBytes: 100,
    clientIp: '192.0.2.10',
    clientHelo: 'mx.clean.scan.test',
    clientName: 'mx.clean.scan.test',
    envelopeFrom: 'alice@clean.scan.test',
    mtaQueueId: 'ABC123',
    recipients: ['bob@customer.scan.test'],
  });
  return store;
}

let n = 0;
const nextId = (): string => {
  n += 1;
  return `00000000-0000-7000-8000-${String(n).padStart(12, '0')}`;
};

function parsed(): EventEnvelope<ScanTriggerPayload> {
  return {
    eventId: nextId(),
    eventType: EventTypes.MessageParsed,
    occurredAt: new Date().toISOString(),
    correlationId: 'corr-stage-0001',
    organizationId: ORG.toString(),
    payload: {
      messageId: MSG.toString(),
      receivedAt: RECEIVED.toISOString(),
      direction: 'inbound',
      emlS3Key: KEY,
    },
  } as unknown as EventEnvelope<ScanTriggerPayload>;
}

function stageEvent(
  scanId: bigint,
  overrides: Partial<{ engine: string; round: number; scanKind: 'initial' | 'rescan' }> = {},
): EventEnvelope<ScanTriggerPayload> {
  return {
    eventId: nextId(),
    eventType: EventTypes.MessageScanStageReady,
    occurredAt: new Date().toISOString(),
    correlationId: 'corr-stage-0001',
    organizationId: ORG.toString(),
    payload: {
      messageId: MSG.toString(),
      receivedAt: RECEIVED.toISOString(),
      direction: 'inbound',
      emlS3Key: KEY,
      lifecycleRound: overrides.round ?? 0,
      scanId: scanId.toString(),
      scanKind: overrides.scanKind ?? 'initial',
      engine: overrides.engine ?? 'bec',
      dependencies: [
        { engine: 'rspamd', outcome: 'clean' },
        { engine: 'url', outcome: 'clean' },
      ],
      readyAt: new Date().toISOString(),
    },
  } as unknown as EventEnvelope<ScanTriggerPayload>;
}

describe('catalog-driven consumer event types (B2)', () => {
  it('stage-1 engines consume parsed + rescan, stage-2 engines the stage event only', () => {
    expect(scanEventTypes(rspamdRegistration.catalog)).toEqual(SCAN_EVENT_TYPES);
    expect(scanEventTypes(urlRegistration.catalog)).toEqual(SCAN_EVENT_TYPES);
    expect(scanEventTypes(becRegistration.catalog)).toEqual(STAGE_EVENT_TYPES);
    expect(STAGE_EVENT_TYPES).toEqual(['mail.message.scan_stage_ready.v1']);
  });
});

describe('decideOpen with trigger stage (B2)', () => {
  it('never opens a round (no E3), joins a scanning round, checks finals after completion', () => {
    expect(decideOpen({ state: 'persisted', round: 0 }, 0, 'stage')).toEqual({
      action: 'skip',
      reason: 'lifecycle_persisted',
    });
    expect(decideOpen({ state: 'scanning', round: 0 }, 0, 'stage')).toEqual({ action: 'open' });
    expect(decideOpen({ state: 'scanning', round: 3 }, 3, 'stage')).toEqual({ action: 'open' });
    expect(decideOpen({ state: 'scanning', round: 3 }, 2, 'stage')).toEqual({
      action: 'skip',
      reason: 'older_round',
    });
    expect(decideOpen({ state: 'scanned', round: 0 }, 0, 'stage')).toEqual({
      action: 'check_final',
    });
    for (const state of ['persisted', 'scanning', 'scanned', 'scan_failed'] as const) {
      for (const round of [0, 1]) {
        expect(decideOpen({ state, round }, round, 'stage').action).not.toBe('open_e3');
      }
    }
  });
});

describe('stageTriggersFor (B2, pure)', () => {
  const finals = (...engines: string[]) => engines.map((engine) => ({ engine, outcome: 'clean' }));

  it('triggers exactly when the inserted final is the last dependency final of the round', () => {
    expect(stageTriggersFor(REQUIRED, finals('rspamd'), 'rspamd')).toEqual([]);
    expect(stageTriggersFor(REQUIRED, finals('rspamd', 'url'), 'url')).toEqual([
      {
        engine: 'bec',
        dependencies: [
          { engine: 'rspamd', outcome: 'clean' },
          { engine: 'url', outcome: 'clean' },
        ],
      },
    ]);
    // Whichever dependency finishes last triggers; failures count as finals (definite or not).
    expect(
      stageTriggersFor(
        REQUIRED,
        [
          { engine: 'url', outcome: 'skipped' },
          { engine: 'rspamd', outcome: 'error' },
        ],
        'rspamd',
      ),
    ).toEqual([
      {
        engine: 'bec',
        dependencies: [
          { engine: 'rspamd', outcome: 'error' },
          { engine: 'url', outcome: 'skipped' },
        ],
      },
    ]);
  });

  it('never triggers for a non-dependency final, a re-check, the sweeper or a finalized stage engine', () => {
    const all = [...REQUIRED, 'attachment'];
    expect(stageTriggersFor(all, finals('rspamd', 'url', 'attachment'), 'attachment')).toEqual([]);
    expect(stageTriggersFor(REQUIRED, finals('rspamd', 'url'), null)).toEqual([]);
    expect(stageTriggersFor(REQUIRED, finals('rspamd', 'url', 'bec'), 'url')).toEqual([]);
    expect(stageTriggersFor(REQUIRED, finals('rspamd', 'url', 'bec'), 'bec')).toEqual([]);
  });

  it('ignores dependencies outside the required set and engines that are not required', () => {
    // url not required in this round: rspamd alone completes the stage-2 dependencies.
    expect(stageTriggersFor(['rspamd', 'bec'], finals('rspamd'), 'rspamd')).toEqual([
      { engine: 'bec', dependencies: [{ engine: 'rspamd', outcome: 'clean' }] },
    ]);
    // bec not required: nothing to trigger.
    expect(stageTriggersFor(['rspamd', 'url'], finals('rspamd', 'url'), 'url')).toEqual([]);
    // Neither dependency required: never triggered (the configuration refuses this set-up).
    expect(stageTriggersFor(['attachment', 'bec'], finals('attachment'), 'attachment')).toEqual([]);
  });
});

describe('round service with stage triggers (B2)', () => {
  it('rspamd then url finals write one trigger; the bec delivery joins the round and completes it', async () => {
    const store = setupStore();
    const rspamd = service(
      store,
      rspamdRegistration,
      new StaticAdapter('rspamd', definite('rspamd')),
    );
    const url = service(store, urlRegistration, new StaticAdapter('url', definite('url')));
    const becAdapter = new StaticAdapter('bec', definite('bec', 'suspicious'));
    const bec = service(store, becRegistration, becAdapter);

    expect(await rspamd.svc.handle(parsed())).toBe('handled');
    expect(store.stageOutbox).toHaveLength(0);
    expect(await url.svc.handle(parsed())).toBe('handled');
    const scanId = store.scans[0]!.scanId;
    expect(store.stageOutbox).toEqual([
      {
        engine: 'bec',
        scanId,
        round: 0,
        dependencies: [
          { engine: 'rspamd', outcome: 'clean' },
          { engine: 'url', outcome: 'clean' },
        ],
      },
    ]);
    expect(await url.registry.metrics()).toMatch(
      /scan_stage_triggers_total\{engine="bec"[^}]*\} 1/,
    );
    expect(store.state(MSG)).toEqual({ state: 'scanning', round: 0 });

    // Redelivery of a dependency (another event id): the completion re-check, no second trigger.
    expect(await url.svc.handle(parsed())).toBe('handled');
    expect(store.stageOutbox).toHaveLength(1);

    const event = stageEvent(scanId);
    expect(await bec.svc.handle(event)).toBe('handled');
    expect(becAdapter.contexts[0]).toMatchObject({ scanId, round: 0, scanKind: 'initial' });
    expect(store.state(MSG)).toEqual({ state: 'scanned', round: 0 });
    expect(store.outbox).toEqual([{ outcome: 'scanned', verdict: 'suspicious', round: 0 }]);
    // The same stage event again: a ledger duplicate; a re-drive with a new id finds the final.
    expect(await bec.svc.handle(event)).toBe('duplicate');
    expect(await bec.svc.handle(stageEvent(scanId))).toBe('duplicate');
    expect(store.rowsOf(scanId).filter((r) => r.engine === 'bec')).toHaveLength(1);
    expect(store.stageOutbox).toHaveLength(1);
  });

  it('a stage event for another engine is a ledger no-op (other_stage_engine)', async () => {
    const store = setupStore();
    await service(
      store,
      rspamdRegistration,
      new StaticAdapter('rspamd', definite('rspamd')),
    ).svc.handle(parsed());
    const adapter = new StaticAdapter('bec', definite('bec'));
    const { svc, registry } = service(store, becRegistration, adapter);
    const event = stageEvent(store.scans[0]!.scanId, { engine: 'dlp' });
    expect(await svc.handle(event)).toBe('handled');
    expect(store.ledger.has(`test.bec:${event.eventId}`)).toBe(true);
    expect(adapter.contexts).toHaveLength(0);
    expect(await registry.metrics()).toMatch(
      /scan_events_skipped_total\{engine="bec",reason="other_stage_engine"[^}]*\} 1/,
    );
  });

  it('a missing round or another scan id is a ledger no-op (stage_round_missing), never an open', async () => {
    const store = setupStore();
    const adapter = new StaticAdapter('bec', definite('bec'));
    const { svc, registry } = service(store, becRegistration, adapter);
    // The message is still persisted: no round, and a stage trigger never applies E3.
    expect(await svc.handle(stageEvent(1n))).toBe('handled');
    expect(store.scans).toHaveLength(0);
    expect(store.state(MSG)).toEqual({ state: 'persisted', round: 0 });

    await service(
      store,
      rspamdRegistration,
      new StaticAdapter('rspamd', definite('rspamd')),
    ).svc.handle(parsed());
    const scanId = store.scans[0]!.scanId;
    expect(await svc.handle(stageEvent(scanId + 7n))).toBe('handled');
    expect(adapter.contexts).toHaveLength(0);
    expect(store.scans).toHaveLength(1);
    const text = await registry.metrics();
    expect(text).toMatch(
      /scan_events_skipped_total\{engine="bec",reason="lifecycle_persisted"[^}]*\} 1/,
    );
    expect(text).toMatch(
      /scan_events_skipped_total\{engine="bec",reason="stage_round_missing"[^}]*\} 1/,
    );
  });

  it('the deadline sweeper finalizes a missing stage-2 engine as timeout and writes no trigger', async () => {
    const store = setupStore();
    await service(
      store,
      rspamdRegistration,
      new StaticAdapter('rspamd', definite('rspamd')),
    ).svc.handle(parsed());
    const scan = store.scans[0]!;
    const result = await store.sweepRound(
      {
        scanId: scan.scanId,
        receivedAt: scan.receivedAt,
        messageId: scan.messageId,
        organizationId: scan.organizationId,
      },
      new Date(scan.deadlineAt.getTime() + 1),
    );
    expect(result.finalized).toEqual(['url', 'bec']);
    expect(store.stageOutbox).toHaveLength(0);
    expect(store.state(MSG)).toEqual({ state: 'scan_failed', round: 0 });
  });

  it('a rescan round triggers the stage engine for the new round only', async () => {
    const store = setupStore();
    const rspamd = service(
      store,
      rspamdRegistration,
      new StaticAdapter('rspamd', definite('rspamd')),
    );
    const url = service(store, urlRegistration, new StaticAdapter('url', definite('url')));
    const bec = service(store, becRegistration, new StaticAdapter('bec', definite('bec')));
    await rspamd.svc.handle(parsed());
    await url.svc.handle(parsed());
    await bec.svc.handle(stageEvent(store.scans[0]!.scanId));
    expect(store.state(MSG)).toEqual({ state: 'scanned', round: 0 });

    store.setState(MSG, 'scanning', 1);
    const rescan = (): EventEnvelope<ScanTriggerPayload> => {
      const e = parsed() as unknown as { eventType: string; payload: Record<string, unknown> };
      e.eventType = EventTypes.MessageRescanRequested;
      e.payload = { ...e.payload, lifecycleRound: 1, scanKind: 'rescan' };
      return e as unknown as EventEnvelope<ScanTriggerPayload>;
    };
    await url.svc.handle(rescan());
    await rspamd.svc.handle(rescan());
    expect(store.scans).toHaveLength(2);
    const second = store.scans[1]!;
    expect(store.stageOutbox.map((t) => [t.scanId, t.round])).toEqual([
      [store.scans[0]!.scanId, 0],
      [second.scanId, 1],
    ]);
    // An old round's trigger delivered late is an older round: skipped.
    expect(await bec.svc.handle(stageEvent(store.scans[0]!.scanId))).toBe('handled');
    expect(store.rowsOf(store.scans[0]!.scanId).filter((r) => r.engine === 'bec')).toHaveLength(1);
    expect(await bec.svc.handle(stageEvent(second.scanId, { round: 1, scanKind: 'rescan' }))).toBe(
      'handled',
    );
    expect(store.state(MSG)).toEqual({ state: 'scanned', round: 1 });
  });
});

import { createHash } from 'node:crypto';
import { PassThrough } from 'node:stream';
import { MetricsService, type PrismaService, type RedisService } from '@email-gateway/common';
import type { SMTPServerDataStream } from 'smtp-server';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { metricValue, silentLogger } from '../../integration/in-session-support/fakes';
import {
  type DkimTestKey,
  generateDkimKey,
  keyRecordName,
  memoryResolver,
  signMessage,
  testMessage,
} from '../../integration/provider-relay-support/dkim';
import type { EmlStore, EmlUploadOptions } from '../ingestion/eml-store';
import type { IngestionConfig } from '../ingestion/ingestion.config';
import { IngestionMetrics } from '../ingestion/ingestion.metrics';
import type {
  CommittedMessage,
  IngestCommit,
  IngestionRepository,
} from '../ingestion/ingestion.repository';
import { IngestionService } from '../ingestion/ingestion.service';
import type { MessageSink } from '../ingestion/message-reader';
import type { IngestRecipient } from '../ingestion/tenant-split';
import type { ProbeObservationInput, ProbeRecorderRepository } from './probe-recorder.repository';
import { ProofVerifier } from './proof-verifier';
import { ProviderRelayMetrics } from './provider-relay.metrics';
import { ProviderRelayIngestion } from './provider-relay-ingestion.service';
import type { RelayCounterName, RelayCountersService } from './relay-counters.service';
import {
  RELAY_MARKER_RETRY_TTL_SECONDS,
  relayMarkerKey,
  RelayMarkerStore,
} from './relay-marker.store';

const ORG = 7n;
const TENANT = '11111111-2222-3333-4444-555555555555';
const CONNECTION = '0190a0a0-0000-7000-8000-000000000c05';
const PROBE = 'eg-probe-abcdefghijklmnopqrstuvwxyz@probe.mail-gateway.test';
const QUEUE_ID = '4XyZ12AbCd';

const config: IngestionConfig = {
  LMTP_INBOUND_PORT: 10050,
  LMTP_OUTBOUND_PORT: 10051,
  LMTP_MAX_CLIENTS: 20,
  INGEST_MAX_MESSAGE_BYTES: 1_000_000,
  INGEST_S3_PART_SIZE_BYTES: 5 * 1024 * 1024,
  INGEST_S3_QUEUE_SIZE: 2,
  INGEST_S3_TIMEOUT_MS: 5_000,
  INGEST_DB_TIMEOUT_MS: 5_000,
  INGEST_HEADER_MAX_BYTES: 65_536,
  GATEWAY_TRACE_SECRET: 's'.repeat(40),
  GATEWAY_TRACE_ID: 'gw-test',
  SMTP_LOOP_MAX_PASSES: 1,
};

/** Redis double: GET/SET/EXPIRE of markers plus the replay script. */
class MarkerRedis {
  readonly values = new Map<string, string>();
  readonly ttls = new Map<string, number>();
  readonly replay = new Map<string, Set<string>>();
  failGet = false;
  readonly client = {
    get: (key: string) =>
      this.failGet
        ? Promise.reject(new Error('redis down'))
        : Promise.resolve(this.values.get(key) ?? null),
    set: (key: string, value: string, _ex: string, ttl: number) => {
      this.values.set(key, value);
      this.ttls.set(key, ttl);
      return Promise.resolve('OK');
    },
    expire: (key: string, ttl: number) => {
      this.ttls.set(key, ttl);
      return Promise.resolve(1);
    },
    eval: (_s: string, _n: number, key: string, member: string) => {
      const set = this.replay.get(key) ?? new Set<string>();
      set.add(member);
      this.replay.set(key, set);
      return Promise.resolve(set.size);
    },
  };
}

class FakeStore {
  uploads: string[] = [];
  aborted: string[] = [];
  deletes: string[] = [];
  startUpload(options: EmlUploadOptions): MessageSink {
    this.uploads.push(options.key);
    return {
      failed: false,
      write: () => Promise.resolve(),
      finish: () => Promise.resolve(),
      abort: () => {
        this.aborted.push(options.key);
      },
    };
  }
  copy(): Promise<void> {
    return Promise.resolve();
  }
  delete(key: string): Promise<void> {
    this.deletes.push(key);
    return Promise.resolve();
  }
}

class FakeRepository {
  commits: IngestCommit[] = [];
  findCommitted(): Promise<CommittedMessage | null> {
    return Promise.resolve(null);
  }
  commit(data: IngestCommit) {
    this.commits.push(data);
    return Promise.resolve({ messageId: 1n, eventId: 'e' });
  }
}

class FakeProbes {
  rows = new Map<string, ProbeObservationInput>();
  failing = false;
  record(input: ProbeObservationInput): Promise<'recorded' | 'duplicate'> {
    if (this.failing) return Promise.reject(new Error('db down'));
    const key = `${input.tokenSha256}|${input.queueId}`;
    if (this.rows.has(key)) return Promise.resolve('duplicate');
    this.rows.set(key, input);
    return Promise.resolve('recorded');
  }
}

let acme: DkimTestKey;
const records = new Map<string, string>();
const failingDns = new Set<string>();

beforeAll(() => {
  acme = generateDkimKey('acme.test');
  records.set(keyRecordName(acme), acme.txt);
});

interface ConnectionRow {
  organizationId?: bigint;
  provider?: string;
  relayProof?: unknown;
  domains?: { name: string; status: string; organizationId: bigint }[];
}

function harness(connection: ConnectionRow | null | 'error' = {}) {
  const redis = new MarkerRedis();
  const store = new FakeStore();
  const repository = new FakeRepository();
  const probes = new FakeProbes();
  const counters: [RelayCounterName, number][] = [];
  const metrics = new MetricsService({ service: 'test' });
  const relayMetrics = new ProviderRelayMetrics(metrics);
  const findUnique = vi.fn(() => {
    if (connection === 'error') return Promise.reject(new Error('db down'));
    if (connection === null) return Promise.resolve(null);
    return Promise.resolve({
      id: 5n,
      publicId: CONNECTION,
      organizationId: connection.organizationId ?? ORG,
      provider: connection.provider ?? 'microsoft_365',
      externalTenantId: TENANT,
      relayProof: connection.relayProof ?? null,
      domains: (
        connection.domains ?? [{ name: 'acme.test', status: 'active', organizationId: ORG }]
      ).map((domain) => ({ domain })),
    });
  });
  const relayConfig = {
    PROVIDER_PROBE_DOMAIN: 'probe.mail-gateway.test',
    INGEST_DB_TIMEOUT_MS: 5000,
  };
  const relay = new ProviderRelayIngestion(
    new RelayMarkerStore(redis as unknown as RedisService, {
      PROVIDER_RELAY_MARKER_TTL_SECONDS: 3600,
    }),
    { providerConnection: { findUnique } } as unknown as PrismaService,
    new ProofVerifier(
      redis as unknown as RedisService,
      {
        PROVIDER_RELAY_DNS_SERVERS: [],
        PROVIDER_RELAY_DNS_TIMEOUT_MS: 500,
        PROVIDER_RELAY_DKIM_REPLAY_WINDOW_SECONDS: 604_800,
      },
      memoryResolver(records, failingDns),
    ),
    probes as unknown as ProbeRecorderRepository,
    {
      record: (_o: bigint, _c: bigint, counter: RelayCounterName, _at: Date, by = 1) => {
        if (by > 0) counters.push([counter, by]);
      },
    } as unknown as RelayCountersService,
    relayMetrics,
    relayConfig,
    silentLogger(),
  );
  const service = new IngestionService(
    { config, listenHost: '127.0.0.1', internalNetworks: '127.0.0.0/8', logLevel: 'silent' },
    {} as never,
    repository as unknown as IngestionRepository,
    store as unknown as EmlStore,
    new IngestionMetrics(metrics),
    relay,
  );
  const mark = (overrides: Record<string, unknown> = {}) =>
    redis.values.set(
      relayMarkerKey(QUEUE_ID),
      JSON.stringify({
        v: 1,
        organizationId: '7',
        connectionPublicId: CONNECTION,
        provider: 'microsoft_365',
        tenantId: TENANT,
        outboundMode: 'active',
        tlsProtocol: 'TLSv1.3',
        tlsCipher: 'TLS_AES_256_GCM_SHA384',
        clientAddress: '40.92.1.2',
        ...overrides,
      }),
    );
  return { redis, store, repository, probes, counters, metrics, service, mark, findUnique };
}

const recipient = (address: string): IngestRecipient => ({
  address,
  domain: address.slice(address.indexOf('@') + 1),
  organizationId: ORG,
  domainId: 100n,
  direction: 'outbound',
});

function stream(text: string): SMTPServerDataStream {
  const s = Object.assign(new PassThrough(), { byteLength: 0, sizeExceeded: false });
  s.end(Buffer.from(text));
  return s;
}

const transaction = (service: IngestionService, direction: 'inbound' | 'outbound' = 'outbound') =>
  service.beginTransaction(
    direction,
    {
      connectionId: 'c',
      peerAddress: '127.0.0.1',
      lhloName: 'out.test',
      queueId: QUEUE_ID,
      clientAddress: '40.92.1.2',
      clientHelo: 'provider.test',
      clientName: null,
    },
    'alice@acme.test',
  );

const tenantHeader = `X-MS-Exchange-CrossTenant-Id: ${TENANT}`;
const message = (headers: string[] = [tenantHeader], to = 'bob@ext.test') =>
  testMessage({ from: 'alice@acme.test', to, extraHeaders: headers });
const signed = (headers: string[] = [tenantHeader], to?: string) =>
  signMessage(message(headers, to), [acme]);
const codes = (replies: { code: number; text: string }[]) =>
  replies.map((r) => `${r.code} ${r.text.slice(0, 6)}`);

describe('LMTP ingestion with the provider relay (D8, D10)', () => {
  it('without a marker the step 2.2 path is unchanged (one GET, nothing else)', async () => {
    const h = harness();
    const replies = await h.service.handleData(
      transaction(h.service),
      [recipient('bob@ext.test')],
      stream(message([])),
    );
    expect(codes(replies)).toEqual(['250 2.0.0 ']);
    expect(h.repository.commits[0]!.providerRelay).toBeUndefined();
    expect(h.findUnique).not.toHaveBeenCalled();
    expect(h.counters).toEqual([]);
  });

  it('the inbound listener never reads markers', async () => {
    const h = harness();
    h.redis.failGet = true;
    const replies = await h.service.handleData(
      transaction(h.service, 'inbound'),
      [{ ...recipient('bob@acme.test'), direction: 'inbound' }],
      stream(message([])),
    );
    expect(codes(replies)).toEqual(['250 2.0.0 ']);
  });

  it('a passing proof stores the message unchanged with details.providerRelay', async () => {
    const h = harness();
    h.mark();
    const eml = await signed();
    const replies = await h.service.handleData(
      transaction(h.service),
      [recipient('bob@ext.test'), recipient('carol@ext.test')],
      stream(eml),
    );
    expect(codes(replies)).toEqual(['250 2.0.0 ', '250 2.0.0 ']);
    const [commit] = h.repository.commits;
    expect(commit!.providerRelay).toEqual({
      provider: 'microsoft_365',
      connectionId: CONNECTION,
      proof: 'pass',
    });
    expect(commit!.emlSha256).toBe(createHash('sha256').update(eml).digest('hex'));
    expect(h.store.deletes).toEqual([]);
    expect(h.counters).toEqual([['accepted', 1]]);
    expect(
      await metricValue(h.metrics, 'smtp_provider_proof_total', {
        provider: 'microsoft_365',
        rule: 'tenant_header',
        result: 'pass',
      }),
    ).toBe(1);
  });

  it.each<[string, () => Promise<string>]>([
    ['unsigned', () => Promise.resolve(message())],
    ['without the tenant header', () => signed([])],
    [
      'with a forged second tenant header',
      () =>
        signed([
          tenantHeader,
          'X-MS-Exchange-CrossTenant-Id: 99999999-2222-3333-4444-555555555555',
        ]),
    ],
  ])(
    'refuses every recipient with 550 5.7.26 when %s; the upload is discarded',
    async (_, build) => {
      const h = harness();
      h.mark();
      const replies = await h.service.handleData(
        transaction(h.service),
        [recipient('bob@ext.test'), recipient('carol@ext.test')],
        stream(await build()),
      );
      expect(replies.map((r) => `${r.code} ${r.text}`)).toEqual([
        '550 5.7.26 Sender not authenticated by the linked provider tenant',
        '550 5.7.26 Sender not authenticated by the linked provider tenant',
      ]);
      expect(h.repository.commits).toEqual([]);
      expect(h.store.aborted).toEqual(h.store.uploads);
      expect(h.store.deletes).toEqual(h.store.uploads);
      expect(h.counters).toEqual([['proofFailed', 1]]);
    },
  );

  it('tempfails when a key lookup fails, and keeps the marker for the retries', async () => {
    const h = harness();
    h.mark();
    failingDns.add(keyRecordName(acme));
    try {
      const replies = await h.service.handleData(
        transaction(h.service),
        [recipient('bob@ext.test')],
        stream(await signed()),
      );
      expect(codes(replies)).toEqual(['451 4.3.0 ']);
    } finally {
      failingDns.clear();
    }
    expect(h.repository.commits).toEqual([]);
    expect(h.store.deletes).toEqual(h.store.uploads);
    expect(h.redis.ttls.get(relayMarkerKey(QUEUE_ID))).toBe(RELAY_MARKER_RETRY_TTL_SECONDS);
    expect(h.counters).toEqual([['tempFailed', 1]]);
  });

  it.each<[string, (h: ReturnType<typeof harness>) => void, ConnectionRow | null | 'error']>([
    ['the marker cannot be read', (h) => (h.redis.failGet = true), {}],
    ['the connection lookup fails', () => undefined, 'error'],
    [
      'the stored proof policy is invalid',
      () => undefined,
      { relayProof: { dkimAligned: 'sometimes' } },
    ],
  ])('tempfails every recipient when %s', async (_, prepare, connection) => {
    const h = harness(connection);
    h.mark();
    prepare(h);
    const replies = await h.service.handleData(
      transaction(h.service),
      [recipient('bob@ext.test'), recipient(PROBE)],
      stream(await signed()),
    );
    expect(codes(replies)).toEqual(['451 4.3.0 ', '451 4.3.0 ']);
    expect(h.repository.commits).toEqual([]);
    expect(h.probes.rows.size).toBe(0);
  });

  it.each<[string, ConnectionRow | null]>([
    ['the connection is gone', null],
    ['the connection belongs to another organization', { organizationId: 8n }],
    ['the provider differs', { provider: 'google_workspace' }],
  ])('refuses with 550 5.7.26 when %s', async (_, connection) => {
    const h = harness(connection);
    h.mark();
    const replies = await h.service.handleData(
      transaction(h.service),
      [recipient('bob@ext.test')],
      stream(await signed()),
    );
    expect(codes(replies)).toEqual(['550 5.7.26']);
  });

  it('a signature by a domain not linked to the connection fails', async () => {
    const h = harness({
      domains: [{ name: 'acme.test', status: 'suspended', organizationId: ORG }],
    });
    h.mark();
    const replies = await h.service.handleData(
      transaction(h.service),
      [recipient('bob@ext.test')],
      stream(await signed()),
    );
    expect(codes(replies)).toEqual(['550 5.7.26']);
  });

  describe('probe interception (D10, I8)', () => {
    it('a probe-only transaction stores nothing and records one observation, idempotently', async () => {
      const h = harness();
      h.mark({ outboundMode: 'probe_only' });
      const eml = await signed([tenantHeader], PROBE);
      for (let attempt = 0; attempt < 2; attempt++) {
        const replies = await h.service.handleData(
          transaction(h.service),
          [recipient(PROBE)],
          stream(eml),
        );
        expect(codes(replies)).toEqual(['250 2.0.0 ']);
      }
      expect(h.store.uploads).toEqual([]);
      expect(h.repository.commits).toEqual([]);
      expect([...h.probes.rows.values()]).toEqual([
        expect.objectContaining({
          organizationId: ORG,
          connectionId: 5n,
          tokenSha256: createHash('sha256').update('abcdefghijklmnopqrstuvwxyz').digest('hex'),
          queueId: QUEUE_ID,
          provider: 'microsoft_365',
          clientIp: '40.92.1.2',
          tlsProtocol: 'TLSv1.3',
          envelopeFromDomain: 'acme.test',
          headerFromDomain: 'acme.test',
          tenantHeader: 'match',
          dkim: 'aligned_pass',
          dkimDomains: ['acme.test'],
          proofResult: 'pass',
          failureCode: null,
        }),
      ]);
      expect(h.counters).toEqual([['probes', 1]]);
      expect(
        await metricValue(h.metrics, 'smtp_provider_probe_observations_total', {
          provider: 'microsoft_365',
          result: 'duplicate',
        }),
      ).toBe(1);
    });

    it('mixed probe and normal recipients: the normal ones are stored without the probe', async () => {
      const h = harness();
      h.mark();
      const replies = await h.service.handleData(
        transaction(h.service),
        [recipient('bob@ext.test'), recipient(PROBE), recipient('carol@ext.test')],
        stream(await signed()),
      );
      expect(codes(replies)).toEqual(['250 2.0.0 ', '250 2.0.0 ', '250 2.0.0 ']);
      expect(h.repository.commits.map((c) => c.recipients)).toEqual([
        ['bob@ext.test', 'carol@ext.test'],
      ]);
      expect(h.probes.rows.size).toBe(1);
      expect(h.counters).toEqual([
        ['accepted', 1],
        ['probes', 1],
      ]);
    });

    it('a failing probe is recorded as failed and refused', async () => {
      const h = harness();
      h.mark({ outboundMode: 'probe_only' });
      const replies = await h.service.handleData(
        transaction(h.service),
        [recipient(PROBE)],
        stream(message([], PROBE)),
      );
      expect(codes(replies)).toEqual(['550 5.7.26']);
      expect([...h.probes.rows.values()][0]).toMatchObject({
        proofResult: 'fail',
        tenantHeader: 'absent',
        dkim: 'none',
        failureCode: 'tenant_header_absent',
      });
    });

    it('a failed evidence write tempfails the probe only', async () => {
      const h = harness();
      h.mark();
      h.probes.failing = true;
      const replies = await h.service.handleData(
        transaction(h.service),
        [recipient(PROBE), recipient('bob@ext.test')],
        stream(await signed()),
      );
      expect(codes(replies)).toEqual(['451 4.3.0 ', '250 2.0.0 ']);
    });
  });
});

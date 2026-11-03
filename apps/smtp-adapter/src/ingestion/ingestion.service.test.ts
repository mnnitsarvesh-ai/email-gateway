import { MetricsService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { PassThrough } from 'node:stream';
import type { SMTPServerDataStream } from 'smtp-server';
import { describe, expect, it } from 'vitest';
import type { MessageSink } from './message-reader';
import type { EmlStore, EmlUploadOptions } from './eml-store';
import type { IngestionConfig } from './ingestion.config';
import { IngestionMetrics } from './ingestion.metrics';
import type { CommittedMessage, IngestCommit, IngestionRepository } from './ingestion.repository';
import { IngestionService } from './ingestion.service';
import type { IngestRecipient } from './tenant-split';

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

class FakeStore {
  uploads: string[] = [];
  copies: [string, string][] = [];
  deletes: string[] = [];
  failCopyTo = new Set<string>();
  failUpload = false;
  startUpload(options: EmlUploadOptions): MessageSink {
    this.uploads.push(options.key);
    const fail = this.failUpload;
    return {
      failed: false,
      write: () => Promise.resolve(),
      finish: () => (fail ? Promise.reject(new Error('s3 down')) : Promise.resolve()),
      abort: () => undefined,
    };
  }
  copy(source: string, target: string): Promise<void> {
    if ([...this.failCopyTo].some((prefix) => target.startsWith(prefix))) {
      return Promise.reject(new Error('copy failed'));
    }
    this.copies.push([source, target]);
    return Promise.resolve();
  }
  delete(key: string): Promise<void> {
    this.deletes.push(key);
    return Promise.resolve();
  }
}

class FakeRepository {
  committed = new Map<string, CommittedMessage>();
  commits: IngestCommit[] = [];
  raceFor = new Map<bigint, string>();
  failFor = new Set<bigint>();
  private nextId = 100n;
  findCommitted(organizationId: bigint, ingestKey: string): Promise<CommittedMessage | null> {
    return Promise.resolve(this.committed.get(`${organizationId}|${ingestKey}`) ?? null);
  }
  commit(data: IngestCommit): Promise<{ messageId: bigint; eventId: string }> {
    const raceKey = this.raceFor.get(data.organizationId);
    if (raceKey !== undefined) {
      this.committed.set(`${data.organizationId}|${data.ingestKey}`, {
        messageId: 1n,
        receivedAt: new Date(),
        emlObjectKey: raceKey,
      });
      return Promise.reject(
        new Prisma.PrismaClientKnownRequestError('dup', { code: 'P2002', clientVersion: 'test' }),
      );
    }
    if (this.failFor.has(data.organizationId)) return Promise.reject(new Error('db down'));
    this.commits.push(data);
    this.nextId += 1n;
    return Promise.resolve({ messageId: this.nextId, eventId: 'e' });
  }
}

function setup() {
  const store = new FakeStore();
  const repository = new FakeRepository();
  const service = new IngestionService(
    { config, listenHost: '127.0.0.1', internalNetworks: '127.0.0.0/8', logLevel: 'silent' },
    {} as never,
    repository as unknown as IngestionRepository,
    store as unknown as EmlStore,
    new IngestionMetrics(new MetricsService({ service: 'test' })),
  );
  return { store, repository, service };
}

const recipients: IngestRecipient[] = [
  { address: 'a@one.test', domain: 'one.test', organizationId: 1n, domainId: 10n },
  { address: 'b@two.test', domain: 'two.test', organizationId: 2n, domainId: 20n },
];

function stream(text: string): SMTPServerDataStream {
  const s = Object.assign(new PassThrough(), { byteLength: 0, sizeExceeded: false });
  s.end(Buffer.from(text));
  return s;
}

const transaction = (service: IngestionService) =>
  service.beginTransaction(
    'inbound',
    {
      connectionId: 'c',
      peerAddress: '127.0.0.1',
      lhloName: 'mx.test',
      queueId: 'Q1',
      clientAddress: null,
      clientHelo: null,
    },
    'sender@external.test',
  );

const codes = (replies: { code: number }[]) => replies.map((r) => r.code);
const MESSAGE = 'From: x@external.test\r\nSubject: s\r\n\r\nbody\r\n';

describe('IngestionService.handleData', () => {
  it('uploads once under the first organization and copies for the second', async () => {
    const { store, repository, service } = setup();
    const replies = await service.handleData(transaction(service), recipients, stream(MESSAGE));
    expect(codes(replies)).toEqual([250, 250]);
    expect(store.uploads).toHaveLength(1);
    expect(store.uploads[0]).toMatch(/^org\/1\/eml\//);
    expect(store.copies).toEqual([[store.uploads[0], expect.stringMatching(/^org\/2\/eml\//)]]);
    expect(repository.commits.map((c) => [c.organizationId, c.recipients])).toEqual([
      [1n, ['a@one.test']],
      [2n, ['b@two.test']],
    ]);
  });

  it('isolates a copy failure and a DB failure to their organization', async () => {
    const { store, repository, service } = setup();
    store.failCopyTo.add('org/2/');
    expect(
      codes(await service.handleData(transaction(service), recipients, stream(MESSAGE))),
    ).toEqual([250, 451]);
    const second = setup();
    second.repository.failFor.add(1n);
    expect(
      codes(
        await second.service.handleData(transaction(second.service), recipients, stream(MESSAGE)),
      ),
    ).toEqual([451, 250]);
    expect(repository.commits).toHaveLength(1);
  });

  it('answers 451 for every organization when the upload fails, and commits nothing', async () => {
    const { store, repository, service } = setup();
    store.failUpload = true;
    expect(
      codes(await service.handleData(transaction(service), recipients, stream(MESSAGE))),
    ).toEqual([451, 451]);
    expect(repository.commits).toHaveLength(0);
    expect(store.copies).toHaveLength(0);
  });

  it('treats a committed ingest key as duplicate and deletes only a superseded object', async () => {
    const { store, repository, service } = setup();
    // First delivery commits both organizations.
    await service.handleData(transaction(service), recipients, stream(MESSAGE));
    const [first] = repository.commits;
    for (const commit of repository.commits) {
      repository.committed.set(`${commit.organizationId}|${commit.ingestKey}`, {
        messageId: 1n,
        receivedAt: commit.receivedAt,
        emlObjectKey:
          commit.organizationId === 1n ? 'org/1/eml/2020/01/01/old.eml' : commit.emlObjectKey,
      });
    }
    store.uploads = [];
    store.copies = [];
    const replies = await service.handleData(transaction(service), recipients, stream(MESSAGE));
    expect(codes(replies)).toEqual([250, 250]);
    expect(repository.commits).toHaveLength(2);
    // Org 1's committed object has another key (an earlier day): the new one is removed.
    expect(store.deletes).toEqual([first!.emlObjectKey]);
    // Org 2 was a duplicate before any copy.
    expect(store.copies).toHaveLength(0);
  });

  it('counts a concurrent commit (P2002) as duplicate and removes its own copy if superseded', async () => {
    const { store, repository, service } = setup();
    repository.raceFor.set(2n, 'org/2/eml/2020/01/01/winner.eml');
    const replies = await service.handleData(transaction(service), recipients, stream(MESSAGE));
    expect(codes(replies)).toEqual([250, 250]);
    expect(store.deletes).toEqual([store.copies[0]![1]]);
  });

  it('refuses outbound mail whose From does not match the envelope sender domain', async () => {
    const { store, service } = setup();
    const tx = service.beginTransaction(
      'outbound',
      {
        connectionId: 'c',
        peerAddress: '127.0.0.1',
        lhloName: 'out.test',
        queueId: 'Q2',
        clientAddress: null,
        clientHelo: null,
      },
      'alice@one.test',
    );
    const replies = await service.handleData(
      tx,
      [{ address: 'x@sink.test', domain: 'sink.test', organizationId: 1n, domainId: 10n }],
      stream('From: boss@evil.test\r\n\r\nbody\r\n'),
    );
    expect(replies.map((r) => `${r.code} ${r.text}`)).toEqual([
      '550 5.7.1 From header does not match the authenticated sender domain',
    ]);
    expect(store.uploads).toHaveLength(0);
  });

  it('requires XFORWARD IDENT and the LHLO name', () => {
    const { service } = setup();
    const base = {
      connectionId: 'c',
      peerAddress: '127.0.0.1',
      lhloName: 'mx.test',
      queueId: 'Q1',
      clientAddress: null,
      clientHelo: null,
    };
    expect(() => service.beginTransaction('inbound', { ...base, queueId: null }, '')).toThrow();
    expect(() => service.beginTransaction('inbound', { ...base, lhloName: null }, '')).toThrow();
  });
});

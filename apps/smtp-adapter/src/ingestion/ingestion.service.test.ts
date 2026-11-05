import { MetricsService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { createHash } from 'node:crypto';
import { PassThrough } from 'node:stream';
import type { SMTPServerDataStream } from 'smtp-server';
import { describe, expect, it } from 'vitest';
import type { MessageSink } from './message-reader';
import type { EmlStore, EmlUploadOptions } from './eml-store';
import type { IngestionConfig } from './ingestion.config';
import { ingestKey, objectRef } from './ingestion-keys';
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

/** `domains` rows by verified name, as resolveDomainOwner reads them. */
interface DomainRow {
  id: bigint;
  organizationId: bigint;
  status: 'active' | 'suspended';
  organizationStatus?: 'active' | 'suspended';
}

function fakePrisma(domains: Record<string, DomainRow>, failFor = new Set<string>()) {
  const lookups: string[] = [];
  return {
    lookups,
    domain: {
      findUnique: ({ where }: { where: { verifiedName: string } }) => {
        lookups.push(where.verifiedName);
        if (failFor.has(where.verifiedName)) return Promise.reject(new Error('db down'));
        const row = domains[where.verifiedName];
        return Promise.resolve(
          row
            ? {
                id: row.id,
                publicId: `p-${row.id}`,
                organizationId: row.organizationId,
                name: where.verifiedName,
                status: row.status,
                inboundEnabled: true,
                outboundEnabled: true,
                organization: { status: row.organizationStatus ?? 'active' },
              }
            : null,
        );
      },
    },
  };
}

function setup(prisma: unknown = {}) {
  const store = new FakeStore();
  const repository = new FakeRepository();
  const service = new IngestionService(
    { config, listenHost: '127.0.0.1', internalNetworks: '127.0.0.0/8', logLevel: 'silent' },
    prisma as never,
    repository as unknown as IngestionRepository,
    store as unknown as EmlStore,
    new IngestionMetrics(new MetricsService({ service: 'test' })),
  );
  return { store, repository, service };
}

const recipients: IngestRecipient[] = [
  {
    address: 'a@one.test',
    domain: 'one.test',
    organizationId: 1n,
    domainId: 10n,
    direction: 'inbound',
  },
  {
    address: 'b@two.test',
    domain: 'two.test',
    organizationId: 2n,
    domainId: 20n,
    direction: 'inbound',
  },
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
      clientName: null,
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
        clientName: null,
      },
      'alice@one.test',
    );
    const replies = await service.handleData(
      tx,
      [
        {
          address: 'x@sink.test',
          domain: 'sink.test',
          organizationId: 1n,
          domainId: 10n,
          direction: 'outbound',
        },
      ],
      stream('From: boss@evil.test\r\n\r\nbody\r\n'),
    );
    expect(replies.map((r) => `${r.code} ${r.text}`)).toEqual([
      '550 5.7.1 From header does not match the authenticated sender domain',
    ]);
    expect(store.uploads).toHaveLength(0);
  });

  it('stores the XFORWARD client host name (step 4.1), truncated to 255 characters', async () => {
    const { repository, service } = setup();
    const client = {
      connectionId: 'c',
      peerAddress: '127.0.0.1',
      lhloName: 'mx.test',
      queueId: 'Q1',
      clientAddress: '203.0.113.7',
      clientHelo: 'helo.example',
    };
    const named = service.beginTransaction(
      'inbound',
      { ...client, clientName: 'mail.example' },
      'sender@external.test',
    );
    expect(named.clientName).toBe('mail.example');
    await service.handleData(named, recipients, stream(MESSAGE));
    expect(repository.commits.map((c) => c.clientName)).toEqual(['mail.example', 'mail.example']);
    expect(
      service.beginTransaction('inbound', { ...client, clientName: 'unknown' }, '').clientName,
    ).toBe('unknown');
    expect(
      service.beginTransaction('inbound', { ...client, clientName: null }, '').clientName,
    ).toBeNull();
    const long = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(80)}`;
    expect(
      service.beginTransaction('inbound', { ...client, clientName: long }, '').clientName,
    ).toBe(long.slice(0, 255));
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
      clientName: null,
    };
    expect(() => service.beginTransaction('inbound', { ...base, queueId: null }, '')).toThrow();
    expect(() => service.beginTransaction('inbound', { ...base, lhloName: null }, '')).toThrow();
  });
});

describe('IngestionService classification at ingestion (step 2.3 R1)', () => {
  const client = {
    connectionId: 'c',
    peerAddress: '127.0.0.1',
    lhloName: 'out.test',
    queueId: 'Q9',
    clientAddress: null,
    clientHelo: null,
    clientName: null,
  };
  const domains: Record<string, DomainRow> = {
    'one.test': { id: 10n, organizationId: 1n, status: 'active' },
    'second.test': { id: 11n, organizationId: 1n, status: 'active' },
    'paused.test': { id: 12n, organizationId: 1n, status: 'suspended' },
    'other.test': { id: 20n, organizationId: 2n, status: 'active' },
  };

  it('outbound: own active domain → internal; another tenant, unknown or inactive → outbound', async () => {
    const prisma = fakePrisma(domains);
    const { service } = setup(prisma);
    const tx = service.beginTransaction('outbound', client, 'alice@one.test');
    const accepted = await Promise.all(
      [
        'a@second.test',
        'b@SECOND.test',
        'c@other.test',
        'd@external.example',
        'e@paused.test',
        'f@one.test',
      ].map((address) => service.acceptRecipient(tx, address)),
    );
    expect(accepted.map((r) => [r.address, r.organizationId, r.direction])).toEqual([
      ['a@second.test', 1n, 'internal'],
      ['b@second.test', 1n, 'internal'],
      ['c@other.test', 1n, 'outbound'],
      ['d@external.example', 1n, 'outbound'],
      ['e@paused.test', 1n, 'outbound'],
      ['f@one.test', 1n, 'internal'],
    ]);
    // One lookup per distinct domain per transaction (the sender's shared with its recipients).
    expect([...prisma.lookups].sort()).toEqual(
      ['external.example', 'one.test', 'other.test', 'paused.test', 'second.test'].sort(),
    );
  });

  it('outbound: a suspended organization owning the recipient domain → outbound', async () => {
    const { service } = setup(
      fakePrisma({
        ...domains,
        'second.test': {
          id: 11n,
          organizationId: 1n,
          status: 'active',
          organizationStatus: 'suspended',
        },
      }),
    );
    const tx = service.beginTransaction('outbound', client, 'alice@one.test');
    expect((await service.acceptRecipient(tx, 'a@second.test')).direction).toBe('outbound');
  });

  it('outbound: a recipient-domain lookup error tempfails that recipient (and is retried)', async () => {
    const prisma = fakePrisma(domains, new Set(['other.test']));
    const { service } = setup(prisma);
    const tx = service.beginTransaction('outbound', client, 'alice@one.test');
    await expect(service.acceptRecipient(tx, 'c@other.test')).rejects.toThrow('db down');
    expect((await service.acceptRecipient(tx, 'a@second.test')).direction).toBe('internal');
  });

  it('inbound: every recipient is inbound, even with a same-organization sender', async () => {
    const prisma = fakePrisma(domains);
    const { service } = setup(prisma);
    const tx = service.beginTransaction(
      'inbound',
      { ...client, lhloName: 'mx.test' },
      'boss@second.test',
    );
    const accepted = await service.acceptRecipient(tx, 'a@one.test');
    expect(accepted.direction).toBe('inbound');
    expect(prisma.lookups).toEqual(['one.test']);
  });

  it('stores the message direction and recipient directions, keeping the listener keys', async () => {
    const { repository, store, service } = setup(fakePrisma(domains));
    const tx = service.beginTransaction('outbound', client, 'alice@one.test');
    const internalOnly = [
      await service.acceptRecipient(tx, 'a@second.test'),
      await service.acceptRecipient(tx, 'f@one.test'),
    ];
    const message = 'From: alice@one.test\r\nSubject: s\r\n\r\nbody\r\n';
    expect(codes(await service.handleData(tx, internalOnly, stream(message)))).toEqual([250, 250]);
    const [commit] = repository.commits;
    expect(commit!.direction).toBe('outbound');
    expect(commit!.messageDirection).toBe('internal');
    expect(commit!.recipientDirections).toEqual(['internal', 'internal']);
    // 2.2 D7/D8 contracts unchanged: both keys are built from the LISTENER direction.
    const ref = { mtaId: 'out.test', queueId: 'Q9', direction: 'outbound' as const };
    const sha = createHash('sha256').update(message).digest('hex');
    expect(commit!.ingestKey).toBe(ingestKey(ref, sha, ['a@second.test', 'f@one.test']));
    expect(store.uploads[0]).toContain(`/${objectRef(ref, 1n)}.eml`);
    expect(commit!.emlObjectKey).toBe(store.uploads[0]);

    const mixed = setup(fakePrisma(domains));
    const tx2 = mixed.service.beginTransaction(
      'outbound',
      { ...client, queueId: 'Q10' },
      'alice@one.test',
    );
    const recipients = [
      await mixed.service.acceptRecipient(tx2, 'a@second.test'),
      await mixed.service.acceptRecipient(tx2, 'c@other.test'),
    ];
    await mixed.service.handleData(tx2, recipients, stream(message));
    expect(mixed.repository.commits[0]!.messageDirection).toBe('outbound');
    expect(mixed.repository.commits[0]!.recipientDirections).toEqual(['internal', 'outbound']);
  });
});

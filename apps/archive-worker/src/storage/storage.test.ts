import { createHash, randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import { S3Client } from '@aws-sdk/client-s3';
import {
  ARCHIVE_JOURNAL_EXAMPLE,
  encryptArchiveObject,
  generateDataKey,
  wrapRecordKey,
} from '@email-gateway/archive';
import { describe, expect, it } from 'vitest';
import { FakeStorage } from '../archive.test-support';
import { parseReindexArgs } from '../cli/reindex';
import type { TenantKeyService } from '../keys/tenant-keys';
import { ArchiveStorage, isLockRefusal, isMissing, ObjectLockState } from './archive-storage';
import { RecordObjects, RecordShreddedError } from './record-objects';

const ORG = 42n;
const PUBLIC = '0190a5d0-0000-7000-8000-0000000000aa';
const CAPTURE = '0190a5d0-0000-7000-8000-0000000000bb';
const tenantKey = randomBytes(32);
const keys = {
  version: () => Promise.resolve({ organizationId: ORG, version: 1, key: tenantKey }),
} as unknown as TenantKeyService;

/** A fake S3 client recording the commands it receives. */
function client(answer: (name: string, input: Record<string, unknown>) => unknown) {
  const sent: Array<{ name: string; input: Record<string, unknown> }> = [];
  return {
    sent,
    send: (command: { constructor: { name: string }; input: Record<string, unknown> }) => {
      sent.push({ name: command.constructor.name, input: command.input });
      try {
        return Promise.resolve(answer(command.constructor.name, command.input));
      } catch (error) {
        return Promise.reject(error instanceof Error ? error : new Error('send failed'));
      }
    },
    config: {},
  };
}

describe('ArchiveStorage (A10)', () => {
  it('probes Object Lock and classifies missing / locked errors', async () => {
    const enabled = new ArchiveStorage(
      client(() => ({ ObjectLockConfiguration: { ObjectLockEnabled: 'Enabled' } })) as never,
      { mail: 'm', archive: 'a' },
      { timeoutMs: 1_000, partSizeBytes: 5_242_880 },
    );
    expect(await enabled.probeObjectLock()).toBe(true);
    const missing = new ArchiveStorage(
      client(() => {
        throw Object.assign(new Error('x'), {
          name: 'ObjectLockConfigurationNotFoundError',
          $metadata: { httpStatusCode: 404 },
        });
      }) as never,
      { mail: 'm', archive: 'a' },
      { timeoutMs: 1_000, partSizeBytes: 5_242_880 },
    );
    expect(await missing.probeObjectLock()).toBe(false);
    expect(isMissing({ name: 'NoSuchVersion' })).toBe(true);
    expect(isLockRefusal({ name: 'InvalidRequest', $metadata: { httpStatusCode: 400 } })).toBe(
      true,
    );
    expect(isLockRefusal({ name: 'AccessDenied', $metadata: { httpStatusCode: 403 } })).toBe(true);
    const state = new ObjectLockState('auto');
    expect([state.available, state.probed]).toEqual([null, false]);
    state.set(true);
    expect(state.available).toBe(true);
    expect(new ObjectLockState('disabled').available).toBe(false);
  });

  it('puts objects with the Object Lock headers of locked tenants and deletes versions (bypass only when asked)', async () => {
    const c = client((name) =>
      name === 'DeleteObjectCommand'
        ? (() => {
            throw Object.assign(new Error('worm'), {
              name: 'InvalidRequest',
              $metadata: { httpStatusCode: 400 },
            });
          })()
        : { VersionId: 'v1' },
    );
    const s = new ArchiveStorage(
      c as never,
      { mail: 'm', archive: 'a' },
      { timeoutMs: 1_000, partSizeBytes: 5_242_880 },
    );
    const until = new Date('2030-01-01T00:00:00Z');
    expect(
      await s.putBuffer({
        key: 'org/42/archive/x',
        body: Buffer.from('x'),
        lock: { mode: 'compliance', until },
      }),
    ).toEqual({ key: 'org/42/archive/x', versionId: 'v1' });
    expect(c.sent[0]!.input).toMatchObject({
      Bucket: 'a',
      ObjectLockMode: 'COMPLIANCE',
      ObjectLockRetainUntilDate: until,
      ContentType: 'application/octet-stream',
    });
    expect(await s.deleteVersion('a', 'k', 'v', { bypassGovernance: true })).toBe('locked');
    expect(c.sent[1]!.input).toMatchObject({ VersionId: 'v', BypassGovernanceRetention: true });
    await s.putRetention('a', 'k', 'v', { mode: 'governance', until });
    expect(c.sent[2]).toMatchObject({
      name: 'PutObjectRetentionCommand',
      input: { Retention: { Mode: 'GOVERNANCE', RetainUntilDate: until } },
    });
    expect(c.sent[2]!.input.BypassGovernanceRetention).toBeUndefined();
  });

  it('streams small uploads through lib-storage with the lock headers and tags', async () => {
    const c = client(() => ({ VersionId: 'v9', ETag: '"e"' }));
    // lib-storage reads the real client's configuration; only `send` is replaced.
    const real = new S3Client({
      region: 'us-east-1',
      endpoint: 'http://127.0.0.1:9',
      forcePathStyle: true,
      credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
    });
    real.send = c.send as never;
    const s = new ArchiveStorage(
      real,
      { mail: 'm', archive: 'a' },
      { timeoutMs: 5_000, partSizeBytes: 5_242_880 },
    );
    const out = await s.uploadStream({
      key: 'org/42/exports/x.bin',
      body: Readable.from([Buffer.from('abc')]),
      tagging: 'eg-object=archive-export',
    });
    expect(out).toEqual({ key: 'org/42/exports/x.bin', versionId: 'v9' });
    expect(c.sent.find((x) => x.name === 'PutObjectCommand')!.input).toMatchObject({
      Tagging: 'eg-object=archive-export',
      Key: 'org/42/exports/x.bin',
    });
  });
});

describe('RecordObjects (A6, A8)', () => {
  function sealedRecord(storage: FakeStorage, eml: Buffer) {
    const dek = generateDataKey();
    const k = (n: string) => `org/${ORG}/archive/2026/11/16/${PUBLIC}/${CAPTURE}/${n}`;
    const e = encryptArchiveObject(eml, {
      dek,
      kind: 'eml',
      organizationId: ORG,
      subjectId: PUBLIC,
    });
    const j = encryptArchiveObject(
      Buffer.from(
        JSON.stringify({ ...ARCHIVE_JOURNAL_EXAMPLE, organizationId: '42', messageId: PUBLIC }),
      ),
      { dek, kind: 'journal', organizationId: ORG, subjectId: PUBLIC },
    );
    const ev = storage.seed('archive', k('eml.bin'), e.object);
    const jv = storage.seed('archive', k('journal.bin'), j.object);
    return {
      organizationId: ORG,
      messagePublicId: PUBLIC,
      keyVersion: 1,
      wrappedDek: wrapRecordKey(
        tenantKey,
        { organizationId: ORG, messagePublicId: PUBLIC, captureId: CAPTURE, keyVersion: 1 },
        dek,
      ) as string | null,
      sha256: createHash('sha256').update(eml).digest('hex'),
      objects: {
        captureId: CAPTURE,
        eml: {
          key: k('eml.bin'),
          versionId: ev,
          sha256: e.summary.ciphertextSha256,
          bytes: e.object.length,
        },
        journal: {
          key: k('journal.bin'),
          versionId: jv,
          sha256: j.summary.ciphertextSha256,
          bytes: j.object.length,
        },
        scans: [],
      },
    };
  }

  it('decrypts the journal and the original (hash verified while streaming); shredded records have no content', async () => {
    const storage = new FakeStorage();
    const eml = randomBytes(70_000);
    const record = sealedRecord(storage, eml);
    const objects = new RecordObjects(storage.asStorage(), keys);
    expect((await objects.journal(record)).messageId).toBe(PUBLIC);
    const chunks: Buffer[] = [];
    for await (const c of await objects.emlStream(record)) chunks.push(c as Buffer);
    expect(Buffer.concat(chunks).equals(eml)).toBe(true);
    const tampered = { ...record, sha256: 'f'.repeat(64) };
    await expect(async () => {
      for await (const c of await objects.emlStream(tampered)) void c;
    }).rejects.toMatchObject({ reason: 'integrity' });
    await expect(objects.journal({ ...record, wrappedDek: null })).rejects.toBeInstanceOf(
      RecordShreddedError,
    );
    // A key outside the record's organization is never read.
    await expect(objects.journal({ ...record, organizationId: 43n })).rejects.toThrow();
  });
});

describe('reindex CLI arguments', () => {
  it('accepts exactly one mode; --version only with --all', () => {
    expect(parseReindexArgs(['--all'])).toEqual({
      organization: null,
      all: true,
      version: null,
      batch: 500,
    });
    expect(parseReindexArgs(['--organization', PUBLIC, '--batch', '50'])).toMatchObject({
      organization: PUBLIC,
      batch: 50,
    });
    expect(parseReindexArgs(['--all', '--version', '3']).version).toBe(3);
    for (const bad of [
      [],
      ['--all', '--organization', PUBLIC],
      ['--organization', PUBLIC, '--version', 'v2'],
      ['--organization', 'x'],
      ['--all', '--version', 'v0'],
      ['--bogus'],
    ]) {
      expect(() => parseReindexArgs(bad)).toThrow();
    }
  });
});

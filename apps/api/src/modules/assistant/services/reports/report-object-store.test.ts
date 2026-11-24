import { Readable } from 'node:stream';
import type { S3Service } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import {
  isReportKeyOf,
  ReportObjectError,
  ReportObjectStore,
  reportObjectKey,
  sha256Hex,
} from './report-object-store';

const ORG = 7001n;
const ID = '0193d000-0000-7000-8000-00000000a001';
const KEY = `org/7001/assistant/report/2026/11/23/${ID}.html`;

/** An S3 client double: records the commands' names and inputs; answers per command. */
function s3Double(answer: (name: string, input: Record<string, unknown>) => unknown) {
  const sent: Array<{ name: string; input: Record<string, unknown> }> = [];
  const service = {
    mailBucket: 'test-mail',
    client: {
      send: (command: { constructor: { name: string }; input: Record<string, unknown> }) => {
        sent.push({ name: command.constructor.name, input: command.input });
        try {
          return Promise.resolve(answer(command.constructor.name, command.input));
        } catch (error) {
          return Promise.reject(error instanceof Error ? error : new Error(String(error)));
        }
      },
    },
  } as unknown as S3Service;
  return { service, sent };
}

const notFound = () => Object.assign(new Error('missing'), { name: 'NoSuchKey' });

describe('report object keys (step AI-R D6)', () => {
  it('builds org/<org>/assistant/report/<yyyy>/<mm>/<dd>/<id>.html from the UTC date', () => {
    expect(reportObjectKey(ORG, ID, new Date('2026-11-23T23:59:59.000Z'))).toBe(KEY);
    expect(() => reportObjectKey(ORG, '../x', new Date())).toThrow();
  });

  it('accepts only keys under the organization’s report prefix without dot segments', () => {
    expect(isReportKeyOf(KEY, ORG)).toBe(true);
    expect(isReportKeyOf(KEY, 7002n)).toBe(false);
    expect(isReportKeyOf('org/7001/part/x.html', ORG)).toBe(false);
    expect(isReportKeyOf('org/7001/assistant/report/../part/x', ORG)).toBe(false);
    expect(isReportKeyOf('org/7001/assistant/report//x', ORG)).toBe(false);
    expect(isReportKeyOf('org/70011/assistant/report/x', ORG)).toBe(false);
  });
});

describe('ReportObjectStore', () => {
  const bytes = Buffer.from('<!doctype html><html></html>', 'utf8');
  const sha = sha256Hex(bytes);

  it('puts the HTML with its content type and the SHA-256 checksum into the mail bucket', async () => {
    const { service, sent } = s3Double(() => ({}));
    await new ReportObjectStore(service).put(ORG, KEY, bytes, sha);
    expect(sent).toEqual([
      {
        name: 'PutObjectCommand',
        input: {
          Bucket: 'test-mail',
          Key: KEY,
          Body: bytes,
          ContentType: 'text/html; charset=utf-8',
          ChecksumSHA256: Buffer.from(sha, 'hex').toString('base64'),
        },
      },
    ]);
  });

  it('refuses a foreign key before any request', async () => {
    const { service, sent } = s3Double(() => ({}));
    const store = new ReportObjectStore(service);
    const foreign = `org/7002/assistant/report/2026/11/23/${ID}.html`;
    await expect(store.put(ORG, foreign, bytes, sha)).rejects.toMatchObject({ why: 'foreign_key' });
    await expect(store.get(ORG, foreign, 100, sha)).rejects.toMatchObject({ why: 'foreign_key' });
    await expect(store.delete(ORG, foreign)).rejects.toMatchObject({ why: 'foreign_key' });
    expect(sent).toHaveLength(0);
  });

  it('gets bounded bytes and verifies the SHA-256', async () => {
    const answer = (body: Buffer, length?: number) => () => ({
      Body: Readable.from([body]),
      ...(length !== undefined ? { ContentLength: length } : {}),
    });
    expect(
      await new ReportObjectStore(s3Double(answer(bytes, bytes.length)).service).get(
        ORG,
        KEY,
        1024,
        sha,
      ),
    ).toEqual(bytes);
    await expect(
      new ReportObjectStore(s3Double(answer(bytes)).service).get(ORG, KEY, 10, sha),
    ).rejects.toMatchObject({ why: 'too_large' });
    await expect(
      new ReportObjectStore(s3Double(answer(bytes, 5000)).service).get(ORG, KEY, 1024, sha),
    ).rejects.toMatchObject({ why: 'too_large' });
    await expect(
      new ReportObjectStore(s3Double(answer(Buffer.from('tampered'))).service).get(
        ORG,
        KEY,
        1024,
        sha,
      ),
    ).rejects.toMatchObject({ why: 'integrity' });
    await expect(
      new ReportObjectStore(
        s3Double(() => {
          throw notFound();
        }).service,
      ).get(ORG, KEY, 1024, sha),
    ).rejects.toBeInstanceOf(ReportObjectError);
  });

  it('deletes every version and delete marker of exactly the key (versioned bucket, D7)', async () => {
    const pages = [
      {
        Versions: [
          { Key: KEY, VersionId: 'v2' },
          { Key: `${KEY}.other`, VersionId: 'x1' },
        ],
        DeleteMarkers: [{ Key: KEY, VersionId: 'm1' }],
        IsTruncated: true,
        NextKeyMarker: KEY,
        NextVersionIdMarker: 'm1',
      },
      { Versions: [{ Key: KEY, VersionId: 'v1' }], IsTruncated: false },
    ];
    let listed = 0;
    const { service, sent } = s3Double((name) =>
      name === 'ListObjectVersionsCommand' ? pages[listed++] : {},
    );
    await expect(new ReportObjectStore(service).delete(ORG, KEY)).resolves.toBe(3);
    expect(sent).toEqual([
      { name: 'ListObjectVersionsCommand', input: { Bucket: 'test-mail', Prefix: KEY } },
      { name: 'DeleteObjectCommand', input: { Bucket: 'test-mail', Key: KEY, VersionId: 'v2' } },
      { name: 'DeleteObjectCommand', input: { Bucket: 'test-mail', Key: KEY, VersionId: 'm1' } },
      {
        name: 'ListObjectVersionsCommand',
        input: { Bucket: 'test-mail', Prefix: KEY, KeyMarker: KEY, VersionIdMarker: 'm1' },
      },
      { name: 'DeleteObjectCommand', input: { Bucket: 'test-mail', Key: KEY, VersionId: 'v1' } },
    ]);
  });

  it('deletes idempotently: a missing object counts as deleted; other errors propagate', async () => {
    const none = s3Double(() => ({ Versions: [], IsTruncated: false }));
    await expect(new ReportObjectStore(none.service).delete(ORG, KEY)).resolves.toBe(0);
    expect(none.sent).toEqual([
      { name: 'ListObjectVersionsCommand', input: { Bucket: 'test-mail', Prefix: KEY } },
    ]);
    const gone = s3Double((name) => {
      if (name === 'ListObjectVersionsCommand') {
        return { Versions: [{ Key: KEY, VersionId: 'v1' }], IsTruncated: false };
      }
      throw notFound();
    });
    await expect(new ReportObjectStore(gone.service).delete(ORG, KEY)).resolves.toBe(1);
    const down = s3Double(() => {
      throw Object.assign(new Error('down'), { name: 'ServiceUnavailable' });
    });
    await expect(new ReportObjectStore(down.service).delete(ORG, KEY)).rejects.toThrow('down');
  });
});

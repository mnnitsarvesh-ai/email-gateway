import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';
import {
  AssistantReportReads,
  isReportKeyOf,
  S3ReportObjectReader,
} from './assistant-report-reads';
import { InconsistentNotificationReadError } from './notification-reads';

const KEY = 'org/7/assistant/report/2026/11/23/0193a1b2-4f50-7a61-8b72-9c8d7e6f5a41.html';
const HTML = Buffer.from('<!doctype html><html><body><h1>Report</h1></body></html>', 'utf8');
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

describe('isReportKeyOf (step AI-R D6)', () => {
  it.each([
    [KEY, 7n, true],
    [KEY, 8n, false],
    ['org/7/assistant/report/x.html', 7n, true],
    ['org/70/assistant/report/x.html', 7n, false],
    ['org/7/eml/2026/x.eml', 7n, false],
    ['org/7/assistant/reports/x.html', 7n, false],
    ['org/7/assistant/report/../../8/assistant/report/x.html', 7n, false],
    ['org/7/assistant/report/./x.html', 7n, false],
    ['org/7/assistant/report//x.html', 7n, false],
    ['/org/7/assistant/report/x.html', 7n, false],
  ])('%s of organization %s → %s', (key, org, expected) => {
    expect(isReportKeyOf(key, org)).toBe(expected);
  });
});

function fakeS3(behaviour: { body?: Buffer; error?: Error; chunk?: number }) {
  const inputs: Array<{ Bucket: string; Key: string; Range?: string }> = [];
  const client = {
    send: vi.fn((command: { input: { Bucket: string; Key: string; Range?: string } }) => {
      inputs.push(command.input);
      if (behaviour.error) return Promise.reject(behaviour.error);
      const body = behaviour.body ?? Buffer.alloc(0);
      const range = /bytes=0-(\d+)/.exec(command.input.Range ?? '');
      const served = range ? body.subarray(0, Number(range[1]) + 1) : body;
      const size = behaviour.chunk ?? 16;
      const chunks: Buffer[] = [];
      for (let i = 0; i < served.length; i += size) chunks.push(served.subarray(i, i + size));
      return Promise.resolve({ Body: Readable.from(chunks) });
    }),
  };
  return { s3: { client, mailBucket: 'gateway-mail' } as never, inputs };
}

describe('S3ReportObjectReader (bounded read, SHA-256 verified)', () => {
  const expected = { sizeBytes: HTML.length, sha256: sha(HTML) };

  it('reads at most size + 1 bytes of the mail bucket and returns verified bytes', async () => {
    const { s3, inputs } = fakeS3({ body: HTML });
    const read = await new S3ReportObjectReader(s3).read(7n, KEY, expected, 1_000_000);
    expect(read).toEqual({ kind: 'ok', bytes: HTML });
    expect(inputs).toEqual([
      { Bucket: 'gateway-mail', Key: KEY, Range: `bytes=0-${String(HTML.length)}` },
    ]);
  });

  it('accepts an upper-case stored SHA-256', async () => {
    const { s3 } = fakeS3({ body: HTML });
    const read = await new S3ReportObjectReader(s3).read(
      7n,
      KEY,
      { ...expected, sha256: expected.sha256.toUpperCase() },
      1_000_000,
    );
    expect(read.kind).toBe('ok');
  });

  it('never reads a key outside org/<organizationId>/assistant/report/', async () => {
    const { s3, inputs } = fakeS3({ body: HTML });
    const reader = new S3ReportObjectReader(s3);
    expect(await reader.read(8n, KEY, expected, 1_000_000)).toEqual({ kind: 'foreign_key' });
    expect(await reader.read(7n, 'org/7/eml/x.eml', expected, 1_000_000)).toEqual({
      kind: 'foreign_key',
    });
    expect(inputs).toHaveLength(0);
  });

  it('cuts a larger object at the bound (too_large) and never buffers it whole', async () => {
    const big = Buffer.concat([HTML, Buffer.alloc(10_000, 0x61)]);
    const { s3, inputs } = fakeS3({ body: big, chunk: 8 });
    expect(await new S3ReportObjectReader(s3).read(7n, KEY, expected, 1_000_000)).toEqual({
      kind: 'too_large',
    });
    // The configured maximum bounds the request even when the row claims more.
    await new S3ReportObjectReader(s3).read(7n, KEY, { ...expected, sizeBytes: 5000 }, 100);
    expect(inputs[1]!.Range).toBe('bytes=0-100');
  });

  it('reports a different hash or a shorter object as sha_mismatch', async () => {
    const tampered = Buffer.from(HTML);
    tampered[20] = 0x58;
    expect(
      await new S3ReportObjectReader(fakeS3({ body: tampered }).s3).read(
        7n,
        KEY,
        expected,
        1_000_000,
      ),
    ).toEqual({ kind: 'sha_mismatch' });
    expect(
      await new S3ReportObjectReader(fakeS3({ body: HTML.subarray(0, 10) }).s3).read(
        7n,
        KEY,
        expected,
        1_000_000,
      ),
    ).toEqual({ kind: 'sha_mismatch' });
    const empty = Object.assign(new Error('range'), { $metadata: { httpStatusCode: 416 } });
    expect(
      await new S3ReportObjectReader(fakeS3({ error: empty }).s3).read(
        7n,
        KEY,
        expected,
        1_000_000,
      ),
    ).toEqual({ kind: 'sha_mismatch' });
  });

  it('maps NoSuchKey / 404 to missing and lets other errors propagate (retried)', async () => {
    const noSuchKey = Object.assign(new Error('nope'), { name: 'NoSuchKey' });
    expect(
      await new S3ReportObjectReader(fakeS3({ error: noSuchKey }).s3).read(7n, KEY, expected, 10),
    ).toEqual({ kind: 'missing' });
    const notFound = Object.assign(new Error('nf'), { $metadata: { httpStatusCode: 404 } });
    expect(
      await new S3ReportObjectReader(fakeS3({ error: notFound }).s3).read(7n, KEY, expected, 10),
    ).toEqual({ kind: 'missing' });
    const down = Object.assign(new Error('503'), { $metadata: { httpStatusCode: 503 } });
    await expect(
      new S3ReportObjectReader(fakeS3({ error: down }).s3).read(7n, KEY, expected, 10),
    ).rejects.toBe(down);
  });
});

describe('AssistantReportReads (scoped to the envelope organization)', () => {
  const row = (org: bigint, reportOrg = org) => ({
    id: 11n,
    publicId: 'd',
    organizationId: org,
    status: 'queued',
    recipientAddress: 'owner@acme.example',
    organization: { id: org, name: 'Acme' },
    report: { id: 5n, publicId: 'r', organizationId: reportOrg, status: 'available' },
  });

  it('filters the delivery by public id and organization and echo-checks the rows', async () => {
    const findFirst = vi.fn((_args: unknown) => Promise.resolve(row(7n) as unknown));
    const tx = { aiChatReportDelivery: { findFirst } } as never;
    const reads = new AssistantReportReads();
    const got = await reads.delivery(tx, 7n, 'd');
    expect(findFirst.mock.calls[0]![0]).toMatchObject({
      where: { publicId: 'd', organizationId: 7n },
    });
    expect(got).toMatchObject({ organizationName: 'Acme', report: { id: 5n, publicId: 'r' } });
    expect(got!.report).not.toHaveProperty('organizationId');
    findFirst.mockResolvedValueOnce(null);
    expect(await reads.delivery(tx, 7n, 'd')).toBeNull();
    findFirst.mockResolvedValueOnce(row(7n, 8n));
    await expect(reads.delivery(tx, 7n, 'd')).rejects.toBeInstanceOf(
      InconsistentNotificationReadError,
    );
    findFirst.mockResolvedValueOnce(row(8n));
    await expect(reads.delivery(tx, 7n, 'd')).rejects.toBeInstanceOf(
      InconsistentNotificationReadError,
    );
  });

  it('updates only a queued delivery of the organization', async () => {
    const updateMany = vi.fn((_args: unknown) => Promise.resolve({ count: 1 }));
    const tx = { aiChatReportDelivery: { updateMany } } as never;
    const reads = new AssistantReportReads();
    const at = new Date('2026-11-23T10:00:00.000Z');
    expect(await reads.markSent(tx, 7n, 11n, '<m@gw.example>', at)).toBe(true);
    expect(updateMany.mock.calls[0]![0]).toEqual({
      where: { id: 11n, organizationId: 7n, status: 'queued' },
      data: { status: 'sent', sentAt: at, messageId: '<m@gw.example>', errorCode: null },
    });
    updateMany.mockResolvedValueOnce({ count: 0 });
    expect(await reads.markFailed(tx, 7n, 11n, 'assistant_report_missing')).toBe(false);
    expect(updateMany.mock.calls[1]![0]).toEqual({
      where: { id: 11n, organizationId: 7n, status: 'queued' },
      data: { status: 'failed', errorCode: 'assistant_report_missing' },
    });
  });
});

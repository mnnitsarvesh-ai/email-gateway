import { S3Client } from '@aws-sdk/client-s3';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { PART_CONTENT_DISPOSITION, PART_CONTENT_TYPES, S3PartSink } from './s3-part-sink';

interface Seen {
  method: string;
  path: string;
  query: Record<string, unknown>;
  headers: Record<string, string>;
  bodyBytes: number;
}

/**
 * A real S3Client whose HTTP handler is an in-memory S3: it records every request and answers
 * like S3 (PutObject, the multipart calls, ranged GetObject, DeleteObject). No network.
 */
function mockS3(options: { failUploadPart?: boolean; hangPut?: boolean } = {}) {
  const seen: Seen[] = [];
  const objects = new Map<string, Buffer>();
  const handler = {
    metadata: { handlerProtocol: 'http/1.1' },
    async handle(
      request: {
        method: string;
        path: string;
        query?: Record<string, unknown>;
        headers: Record<string, string>;
        body?: unknown;
      },
      handlerOptions: { abortSignal?: AbortSignal } = {},
    ) {
      const body = await readBody(request.body);
      if (options.hangPut && request.method === 'PUT') {
        // S3 accepts the connection and never answers (until the request is aborted).
        return new Promise<never>((_resolve, reject) => {
          handlerOptions.abortSignal?.addEventListener('abort', () =>
            reject(Object.assign(new Error('aborted'), { name: 'AbortError' })),
          );
        });
      }
      const query = request.query ?? {};
      seen.push({
        method: request.method,
        path: request.path,
        query,
        headers: request.headers,
        bodyBytes: body.length,
      });
      const key = decodeURIComponent(request.path.replace(/^\/bucket\//, ''));
      const respond = (statusCode: number, xml = '', headers: Record<string, string> = {}) => ({
        response: {
          statusCode,
          reason: '',
          headers: { 'content-type': 'application/xml', ...headers },
          body: Readable.from(xml ? [Buffer.from(xml)] : []),
        },
      });
      if (request.method === 'PUT' && query.uploadId === undefined) {
        objects.set(key, body);
        return respond(200, '', { etag: '"e"' });
      }
      if (request.method === 'POST' && 'uploads' in query) {
        return respond(
          200,
          `<?xml version="1.0"?><InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>${key}</Key><UploadId>u1</UploadId></InitiateMultipartUploadResult>`,
        );
      }
      if (request.method === 'PUT') {
        if (options.failUploadPart) {
          return respond(500, '<?xml version="1.0"?><Error><Code>InternalError</Code></Error>');
        }
        return respond(200, '', { etag: `"p${String(query.partNumber)}"` });
      }
      if (request.method === 'DELETE' && query.uploadId !== undefined) return respond(204);
      if (request.method === 'DELETE') {
        objects.delete(key);
        return respond(204);
      }
      if (request.method === 'GET') {
        const data = objects.get(key);
        if (!data)
          return respond(404, '<?xml version="1.0"?><Error><Code>NoSuchKey</Code></Error>');
        const range = /bytes=(\d+)-(\d+)/.exec(request.headers.range ?? '');
        const slice = range ? data.subarray(Number(range[1]), Number(range[2]) + 1) : data;
        return {
          response: {
            statusCode: range ? 206 : 200,
            reason: '',
            headers: { 'content-length': String(slice.length) },
            body: Readable.from([slice]),
          },
        };
      }
      return respond(400);
    },
    updateHttpClientConfig: () => undefined,
    httpHandlerConfigs: () => ({}),
    destroy: () => undefined,
  };
  const client = new S3Client({
    region: 'us-east-1',
    endpoint: 'http://s3.test',
    forcePathStyle: true,
    credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
    requestHandler: handler,
  });
  return { client, seen, objects };
}

async function readBody(body: unknown): Promise<Buffer> {
  if (body === undefined || body === null) return Buffer.alloc(0);
  if (typeof body === 'string') return Buffer.from(body);
  if (Buffer.isBuffer(body) || body instanceof Uint8Array) return Buffer.from(body);
  if (typeof (body as AsyncIterable<unknown>)[Symbol.asyncIterator] === 'function') {
    const chunks: Buffer[] = [];
    for await (const chunk of body as AsyncIterable<Buffer | string>)
      chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks);
  }
  return Buffer.alloc(0);
}

const target = { organizationId: 5n, messageId: 77n, receivedAt: new Date('2026-11-03T08:00:00Z') };
const sinkOn = (client: S3Client, timeoutMs = 10_000) =>
  new S3PartSink({
    client,
    bucket: 'bucket',
    target,
    partSizeBytes: 5 * 1024 * 1024,
    queueSize: 1,
    timeoutMs,
  });

describe('S3PartSink (design M11)', () => {
  it('stores a part at its deterministic key with safe object headers and serves ranges', async () => {
    const s3 = mockS3();
    const sink = sinkOn(s3.client);
    const writer = await sink.open({ partIndex: 1, partPath: '0.1', depth: 1, kind: 'text' });
    await writer.write(Buffer.from('hello '));
    await writer.write(Buffer.from('world'));
    const stored = await writer.finish();

    expect(stored.key).toBe('org/5/part/2026/11/03/77/1.text');
    expect(s3.objects.get(stored.key)?.toString()).toBe('hello world');
    const put = s3.seen.find((r) => r.method === 'PUT')!;
    expect(put.headers['content-type']).toBe(PART_CONTENT_TYPES.text);
    expect(put.headers['content-disposition']).toBe(PART_CONTENT_DISPOSITION);
    // No filename or header value in the object metadata.
    expect(Object.keys(put.headers).filter((h) => h.startsWith('x-amz-meta-'))).toEqual([]);
    expect(sink.writtenKeys).toEqual([stored.key]);

    const range = await stored.readRange(6, 10, new AbortController().signal);
    expect(range.toString()).toBe('world');
    expect(s3.seen.at(-1)?.headers.range).toBe('bytes=6-10');
  });

  it('uses application/octet-stream for html and attachment parts', async () => {
    const s3 = mockS3();
    const sink = sinkOn(s3.client);
    for (const kind of ['html', 'attachment'] as const) {
      const writer = await sink.open({ partIndex: 3, partPath: '0.3', depth: 1, kind });
      await writer.write(Buffer.from('<b>x</b>'));
      await writer.finish();
    }
    const puts = s3.seen.filter((r) => r.method === 'PUT');
    expect(puts.map((p) => p.headers['content-type'])).toEqual([
      'application/octet-stream',
      'application/octet-stream',
    ]);
    expect([...s3.objects.keys()].sort()).toEqual([
      'org/5/part/2026/11/03/77/3.att',
      'org/5/part/2026/11/03/77/3.html',
    ]);
  });

  it('abort before finish sends no object (single-part upload)', async () => {
    const s3 = mockS3();
    const sink = sinkOn(s3.client);
    const writer = await sink.open({ partIndex: 2, partPath: '0.2', depth: 1, kind: 'attachment' });
    await writer.write(Buffer.alloc(1024, 1));
    await writer.abort();
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(s3.seen.filter((r) => r.method === 'PUT')).toHaveLength(0);
    expect(s3.objects.size).toBe(0);
    expect(sink.writtenKeys).toEqual([]);
  });

  it('abort of a started multipart upload aborts it and never completes it', async () => {
    const s3 = mockS3();
    const sink = sinkOn(s3.client);
    const writer = await sink.open({ partIndex: 2, partPath: '0.2', depth: 1, kind: 'attachment' });
    // More than one part: lib-storage starts a multipart upload.
    for (let i = 0; i < 6; i += 1) await writer.write(Buffer.alloc(1024 * 1024, i));
    await new Promise((resolve) => setTimeout(resolve, 50));
    await writer.abort();
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(s3.seen.some((r) => r.method === 'POST' && 'uploads' in r.query)).toBe(true);
    const completes = s3.seen.filter((r) => r.method === 'POST' && r.query.uploadId !== undefined);
    expect(completes).toHaveLength(0);
    // leavePartsOnError: false → AbortMultipartUpload.
    expect(s3.seen.some((r) => r.method === 'DELETE' && r.query.uploadId !== undefined)).toBe(true);
    expect(s3.objects.size).toBe(0);
    expect(sink.writtenKeys).toEqual([]);
  });

  it('a failed upload rejects write or finish (infrastructure) and leaves no object', async () => {
    const s3 = mockS3({ failUploadPart: true });
    const sink = sinkOn(s3.client);
    const writer = await sink.open({ partIndex: 4, partPath: '0.4', depth: 1, kind: 'attachment' });
    let failure: unknown;
    try {
      for (let i = 0; i < 12; i += 1) await writer.write(Buffer.alloc(1024 * 1024, i));
      await writer.finish();
    } catch (err) {
      failure = err;
    }
    expect(failure).toBeInstanceOf(Error);
    expect(s3.objects.size).toBe(0);
    expect(s3.seen.some((r) => r.method === 'DELETE' && r.query.uploadId !== undefined)).toBe(true);
  });

  it('bounds each wait on S3, not the life of the part (MIME_S3_TIMEOUT_MS per wait)', async () => {
    const s3 = mockS3({ hangPut: true });
    const sink = sinkOn(s3.client, 100);
    const writer = await sink.open({ partIndex: 5, partPath: '0.5', depth: 1, kind: 'attachment' });
    // The parser feeds the part slowly: idle time is not S3 time, so nothing fails yet.
    await writer.write(Buffer.from('slow '));
    await new Promise((resolve) => setTimeout(resolve, 250));
    await writer.write(Buffer.from('part'));
    // Finishing waits on S3, which never answers: an infrastructure timeout after ~100 ms.
    const started = Date.now();
    await expect(writer.finish()).rejects.toMatchObject({
      name: 'UploadTimedOut',
      code: 'ETIMEDOUT',
    });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(s3.objects.size).toBe(0);
    expect(sink.writtenKeys).toEqual([]);
  });

  it('deletes the objects of this attempt (integrity-mismatch cleanup)', async () => {
    const s3 = mockS3();
    const sink = sinkOn(s3.client);
    for (const partIndex of [1, 2]) {
      const writer = await sink.open({
        partIndex,
        partPath: `0.${partIndex}`,
        depth: 1,
        kind: 'attachment',
      });
      await writer.write(Buffer.from('x'));
      await writer.finish();
    }
    expect(s3.objects.size).toBe(2);
    await expect(sink.deleteWritten()).resolves.toBe(0);
    expect(s3.objects.size).toBe(0);
  });
});

import {
  CompleteMultipartUploadCommand,
  CreateMultipartUploadCommand,
  DeleteObjectCommand,
  PutObjectCommand,
  PutObjectTaggingCommand,
  S3Client,
  UploadPartCommand,
} from '@aws-sdk/client-s3';
import type { Writable } from 'node:stream';
import type { RewriteResult } from '@email-gateway/url-security';
import { describe, expect, it, vi } from 'vitest';
import { REWRITE_OBJECT_TAGGING, S3RewriteStore } from './rewrite-store';

const MiB = 1024 * 1024;

const rewritten: RewriteResult = {
  status: 'rewritten',
  skipReason: null,
  linksRewritten: 1,
  linksUnmapped: 0,
  partsRewritten: 1,
  partsSkipped: 0,
  partSkipReasons: {},
  linksByPart: { text: 0, html: 1 },
  dkimSigned: false,
  rewrittenSeqs: [0],
  sha256: 'a'.repeat(64),
  sizeBytes: 10,
};

type Sent = { name: string; input: Record<string, unknown> };

/** A real S3Client whose `send` is scripted per command (no network). */
function client(fail: Partial<Record<string, Error>> = {}): { client: S3Client; sent: Sent[] } {
  const s3 = new S3Client({
    region: 'us-east-1',
    endpoint: 'http://s3.test',
    forcePathStyle: true,
    credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
  });
  const sent: Sent[] = [];
  const reply = (command: { constructor: { name: string }; input: Record<string, unknown> }) => {
    const name = command.constructor.name;
    sent.push({ name, input: command.input });
    const error = fail[name];
    if (error) return Promise.reject(error);
    if (name === CreateMultipartUploadCommand.name)
      return Promise.resolve({ UploadId: 'upload-1' });
    if (name === UploadPartCommand.name)
      return Promise.resolve({ ETag: `"etag-${String(command.input.PartNumber)}"` });
    return Promise.resolve({});
  };
  vi.spyOn(s3, 'send').mockImplementation(reply as never);
  return { client: s3, sent };
}

const store = (s3: S3Client): S3RewriteStore =>
  new S3RewriteStore(s3, 'mail', { partSizeBytes: 5 * MiB, queueSize: 1 });

const writeBytes =
  (bytes: number) =>
  async (sink: Writable): Promise<RewriteResult> => {
    const chunk = Buffer.alloc(MiB, 0x61);
    for (let left = bytes; left > 0; left -= MiB) {
      const piece = left >= MiB ? chunk : chunk.subarray(0, left);
      if (!sink.write(piece)) await new Promise((r) => sink.once('drain', r));
    }
    sink.end();
    return rewritten;
  };

const names = (sent: Sent[]): string[] => sent.map((s) => s.name);

describe('S3RewriteStore (step 4.3 U11): the tag is set atomically with the object', () => {
  it('single part: PutObject carries Tagging eg-object=rewrite; no separate PutObjectTagging', async () => {
    const { client: s3, sent } = client();
    const result = await store(s3).write(
      'org/1/rewrite/k.eml',
      writeBytes(1000),
      new AbortController().signal,
    );
    expect(result.status).toBe('rewritten');
    expect(names(sent)).toEqual([PutObjectCommand.name]);
    expect(sent[0]?.input).toMatchObject({
      Bucket: 'mail',
      Key: 'org/1/rewrite/k.eml',
      ContentType: 'message/rfc822',
      ContentDisposition: 'attachment',
      Tagging: REWRITE_OBJECT_TAGGING,
    });
    expect(REWRITE_OBJECT_TAGGING).toBe('eg-object=rewrite');
  });

  it('multipart: CreateMultipartUpload carries the tag; no PutObjectTagging after completion', async () => {
    const { client: s3, sent } = client();
    await store(s3).write(
      'org/1/rewrite/big.eml',
      writeBytes(11 * MiB),
      new AbortController().signal,
    );
    expect(names(sent)[0]).toBe(CreateMultipartUploadCommand.name);
    expect(sent[0]?.input).toMatchObject({ Tagging: REWRITE_OBJECT_TAGGING });
    expect(names(sent).filter((n) => n === UploadPartCommand.name)).toHaveLength(3);
    expect(names(sent).at(-1)).toBe(CompleteMultipartUploadCommand.name);
    expect(names(sent)).not.toContain(PutObjectTaggingCommand.name);
  });

  it('an upload failure after a successful rewrite deletes the key and is thrown (transient)', async () => {
    const { client: s3, sent } = client({ [PutObjectCommand.name]: new Error('s3 timeout') });
    await expect(
      store(s3).write('org/1/rewrite/f.eml', writeBytes(1000), new AbortController().signal),
    ).rejects.toThrow('s3 timeout');
    expect(names(sent)).toEqual([PutObjectCommand.name, DeleteObjectCommand.name]);
    expect(sent[1]?.input).toEqual({ Bucket: 'mail', Key: 'org/1/rewrite/f.eml' });
  });

  it('a failed multipart completion deletes the key too', async () => {
    const { client: s3, sent } = client({
      [CompleteMultipartUploadCommand.name]: new Error('complete lost'),
    });
    await expect(
      store(s3).write('org/1/rewrite/m.eml', writeBytes(11 * MiB), new AbortController().signal),
    ).rejects.toThrow('complete lost');
    expect(sent.at(-1)).toEqual({
      name: DeleteObjectCommand.name,
      input: { Bucket: 'mail', Key: 'org/1/rewrite/m.eml' },
    });
  });

  it('a skipped rewrite aborts and deletes a completed single-part object', async () => {
    const { client: s3, sent } = client();
    const result = await store(s3).write(
      'org/1/rewrite/s.eml',
      async (sink) => {
        sink.end('x');
        await new Promise((r) => setTimeout(r, 20));
        return {
          ...rewritten,
          status: 'skipped',
          skipReason: 'no_urls',
          sha256: null,
          sizeBytes: null,
        };
      },
      new AbortController().signal,
    );
    expect(result.status).toBe('skipped');
    expect(names(sent)).not.toContain(PutObjectTaggingCommand.name);
    if (names(sent).includes(PutObjectCommand.name))
      expect(names(sent).at(-1)).toBe(DeleteObjectCommand.name);
  });
});

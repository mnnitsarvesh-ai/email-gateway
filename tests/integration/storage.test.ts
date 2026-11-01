import { randomUUID } from 'node:crypto';
import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { afterAll, describe, expect, it } from 'vitest';
import { stack } from './support/env';

const cfg = stack.s3();
const s3 = new S3Client({
  endpoint: cfg.endpoint,
  region: cfg.region,
  forcePathStyle: true,
  credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey },
});

afterAll(() => s3.destroy());

describe('S3-compatible storage (MinIO)', () => {
  it('has the mail and archive buckets', async () => {
    for (const bucket of [cfg.mailBucket, cfg.archiveBucket]) {
      await expect(s3.send(new HeadBucketCommand({ Bucket: bucket }))).resolves.toBeDefined();
    }
  });

  it('round-trips an EML under a tenant-prefixed key', async () => {
    const key = `org/${randomUUID()}/eml/2026/11/01/${randomUUID()}.eml`;
    const body = 'From: a@example.test\r\nTo: b@gateway.test\r\nSubject: it\r\n\r\nhello\r\n';
    try {
      await s3.send(new PutObjectCommand({ Bucket: cfg.mailBucket, Key: key, Body: body }));
      const got = await s3.send(new GetObjectCommand({ Bucket: cfg.mailBucket, Key: key }));
      expect(await got.Body?.transformToString()).toBe(body);
    } finally {
      await s3.send(new DeleteObjectCommand({ Bucket: cfg.mailBucket, Key: key }));
    }
  });

  it('denies anonymous reads', async () => {
    const res = await fetch(`${cfg.endpoint}/${cfg.mailBucket}/`);
    expect(res.status).toBe(403);
  });
});

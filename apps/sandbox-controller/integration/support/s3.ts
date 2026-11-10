import { createHash } from 'node:crypto';
import {
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { sampleObjectKey, sealSample } from '@email-gateway/sandbox';
import { MINIO_ENDPOINT, required } from './env';

/**
 * Test-side MinIO access. `root()` (MinIO root user, test setup and cleanup only) stages sealed
 * samples into `samples/` exactly as the email-worker's dispatcher does and removes every object
 * a test created; `controllerUser()` is the controller's own restricted user (least-privilege
 * checks). Values are never printed.
 */

export const SANDBOX_BUCKET = process.env.SANDBOX_S3_BUCKET ?? 'email-gateway-sandbox';

function client(accessKeyId: string, secretAccessKey: string): S3Client {
  return new S3Client({
    region: process.env.SANDBOX_S3_REGION ?? 'ap-south-1',
    endpoint: MINIO_ENDPOINT,
    forcePathStyle: true,
    credentials: { accessKeyId, secretAccessKey },
    maxAttempts: 1,
  });
}

export const root = (): S3Client =>
  client(required('MINIO_ROOT_USER'), required('MINIO_ROOT_PASSWORD'));
export const controllerUser = (): S3Client =>
  client(required('SANDBOX_S3_ACCESS_KEY_ID'), required('SANDBOX_S3_SECRET_ACCESS_KEY'));

export const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');

/** Seals `bytes` with `SANDBOX_SAMPLE_KEY` and puts it at the task's sample key (root user). */
export async function stageSample(
  s3: S3Client,
  taskId: string,
  bytes: Buffer,
  at = new Date(),
): Promise<string> {
  const key = sampleObjectKey(taskId, at);
  const sealed = sealSample({ current: required('SANDBOX_SAMPLE_KEY') }, bytes, {
    taskId,
    sha256: sha256(bytes),
  });
  await s3.send(new PutObjectCommand({ Bucket: SANDBOX_BUCKET, Key: key, Body: sealed.object }));
  return key;
}

export async function getObject(
  s3: S3Client,
  key: string,
  bucket = SANDBOX_BUCKET,
): Promise<Buffer> {
  const response = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  return Buffer.from(
    await (response.Body as { transformToByteArray(): Promise<Uint8Array> }).transformToByteArray(),
  );
}

/** Deletes the sample and every artifact of the given tasks (root user); returns the count. */
export async function removeTaskObjects(s3: S3Client, taskIds: Iterable<string>): Promise<number> {
  let removed = 0;
  const ids = new Set(taskIds);
  for (const prefix of ['samples/', 'artifacts/']) {
    let token: string | undefined;
    do {
      const page = await s3.send(
        new ListObjectsV2Command({
          Bucket: SANDBOX_BUCKET,
          Prefix: prefix,
          ContinuationToken: token,
        }),
      );
      for (const object of page.Contents ?? []) {
        const key = object.Key ?? '';
        if ([...ids].some((id) => key.includes(id))) {
          await s3.send(new DeleteObjectCommand({ Bucket: SANDBOX_BUCKET, Key: key }));
          removed += 1;
        }
      }
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token);
  }
  return removed;
}

import { randomUUID } from 'node:crypto';
import {
  GetObjectCommand,
  HeadBucketCommand,
  ListObjectsV2Command,
  PutObjectCommand,
} from '@aws-sdk/client-s3';
import { type Channel, connect, type ChannelModel } from 'amqplib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { required, vhostUrl } from './support/env';
import {
  controllerUser,
  getObject,
  removeTaskObjects,
  root,
  SANDBOX_BUCKET,
  stageSample,
} from './support/s3';

/**
 * Least privilege of the controller's credentials (step 4.6 §9.2, threat model §9): the
 * `eg-sandbox` broker user cannot consume other queues, publish other routing keys or declare
 * anything; the `eg-sandbox-controller` S3 user cannot read the mail bucket, list the sandbox
 * bucket, read `artifacts/` or write `samples/` — and can read `samples/` and write
 * `artifacts/`. Every object created is removed (root user).
 */

const s3Root = root();
const s3Controller = controllerUser();
const taskId = randomUUID();
let sandbox: ChannelModel;

beforeAll(async () => {
  sandbox = await connect(vhostUrl(required('RABBITMQ_SANDBOX_URL')));
});

afterAll(async () => {
  await sandbox?.close().catch(() => undefined);
  await removeTaskObjects(s3Root, [taskId]);
  s3Root.destroy();
  s3Controller.destroy();
});

/** Runs `op` on a fresh channel; resolves with the AMQP reply code that closed it (or 0). */
async function replyCode(op: (channel: Channel) => Promise<unknown>): Promise<number> {
  const channel = await sandbox.createChannel();
  const closed = new Promise<number>((resolve) => {
    channel.on('error', (error: { code?: number }) => resolve(error.code ?? -1));
    channel.on('close', () => resolve(0));
  });
  try {
    await op(channel);
    // A publish refusal arrives asynchronously as a channel close.
    await new Promise((r) => setTimeout(r, 500));
    await channel.close().catch(() => undefined);
  } catch (error) {
    return (error as { code?: number }).code ?? (await closed);
  }
  return closed;
}

describe('eg-sandbox broker user', () => {
  it('cannot consume any queue but scan.sandbox', async () => {
    for (const queue of [
      'scan.sandbox.results',
      'scan.sandbox.submissions',
      'scan.spam',
      'email.delivery.pending',
      'email.dead-letter',
    ]) {
      expect(await replyCode((c) => c.consume(queue, () => undefined)), queue).toBe(403);
    }
  });

  it('cannot publish other routing keys or to other exchanges', async () => {
    const body = Buffer.from('{}');
    const cases: [string, string][] = [
      ['email.security', 'org.1.mail.sandbox.task_requested.v1'],
      ['email.security', 'org.1.mail.attachment.sandbox_completed.v1'],
      ['email.security', 'retry.scan.sandbox.results.org.1.x'],
      ['email.events', 'dead-letter.scan.spam.org.1.x'],
      ['email.ingestion', 'org.1.mail.received.v1'],
    ];
    for (const [exchange, key] of cases) {
      expect(
        await replyCode((c) => Promise.resolve(c.publish(exchange, key, body))),
        `${exchange} ${key}`,
      ).toBe(403);
    }
  });

  it('cannot declare or delete anything', async () => {
    expect(
      await replyCode((c) =>
        c.assertQueue(`wp2-probe-${randomUUID()}`, { durable: false, autoDelete: true }),
      ),
    ).toBe(403);
    expect(await replyCode((c) => c.deleteQueue('scan.sandbox'))).toBe(403);
  });
});

describe('eg-sandbox-controller S3 user', () => {
  const denied = async (op: Promise<unknown>): Promise<number | undefined> =>
    op.then(
      () => 200,
      (error: { $metadata?: { httpStatusCode?: number } }) => error.$metadata?.httpStatusCode,
    );

  it('reads samples/ and writes artifacts/ only', async () => {
    const sampleKey = await stageSample(s3Root, taskId, Buffer.from('least privilege sample'));
    expect((await getObject(s3Controller, sampleKey)).length).toBeGreaterThan(0);
    const artifactKey = `artifacts/2026/11/${taskId}/0123456789abcdef/0-static_report.bin`;
    await s3Controller.send(
      new PutObjectCommand({
        Bucket: SANDBOX_BUCKET,
        Key: artifactKey,
        Body: Buffer.from('sealed'),
      }),
    );

    expect(
      await denied(
        s3Controller.send(new GetObjectCommand({ Bucket: SANDBOX_BUCKET, Key: artifactKey })),
      ),
    ).toBe(403);
    expect(
      await denied(
        s3Controller.send(
          new PutObjectCommand({
            Bucket: SANDBOX_BUCKET,
            Key: `samples/2026/11/${taskId}.bin`,
            Body: Buffer.from('x'),
          }),
        ),
      ),
    ).toBe(403);
    expect(
      await denied(s3Controller.send(new ListObjectsV2Command({ Bucket: SANDBOX_BUCKET }))),
    ).toBe(403);
    expect(
      await denied(
        s3Controller.send(new ListObjectsV2Command({ Bucket: SANDBOX_BUCKET, Prefix: 'samples/' })),
      ),
    ).toBe(403);
    expect(await denied(s3Controller.send(new HeadBucketCommand({ Bucket: SANDBOX_BUCKET })))).toBe(
      403,
    );
    expect(
      await denied(
        s3Controller.send(
          new PutObjectCommand({
            Bucket: SANDBOX_BUCKET,
            Key: `other/${taskId}`,
            Body: Buffer.from('x'),
          }),
        ),
      ),
    ).toBe(403);
  });

  it('cannot touch the mail bucket', async () => {
    const mail = required('S3_BUCKET_MAIL');
    expect(
      await denied(s3Controller.send(new ListObjectsV2Command({ Bucket: mail, MaxKeys: 1 }))),
    ).toBe(403);
    expect(
      await denied(s3Controller.send(new GetObjectCommand({ Bucket: mail, Key: 'org/1/part/x' }))),
    ).toBe(403);
    expect(
      await denied(
        s3Controller.send(
          new PutObjectCommand({
            Bucket: mail,
            Key: `org/1/part/${taskId}`,
            Body: Buffer.from('x'),
          }),
        ),
      ),
    ).toBe(403);
  });
});

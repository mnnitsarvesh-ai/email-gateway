import type { S3Client } from '@aws-sdk/client-s3';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { EML_MISSING, S3EmlSource } from './eml-source';
import {
  S3Stalled,
  S3WaitTracker,
  stalledOnS3,
  stallThresholdMs,
  trackedInput,
  withStallTimeout,
} from './s3-waits';

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function readAll(stream: Readable, pauseMs = 0): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    chunks.push(Buffer.from(chunk));
    if (pauseMs > 0) await delay(pauseMs);
  }
  return Buffer.concat(chunks);
}

/** A body that sends `first`, then never sends anything again. */
const stallingBody = (first: string) => {
  let sent = false;
  return new Readable({
    read() {
      if (!sent) {
        sent = true;
        this.push(Buffer.from(first));
      }
    },
  });
};

describe('S3WaitTracker and stalledOnS3 (design M5)', () => {
  it('counts overlapping waits once and reports the pending one', async () => {
    let now = 0;
    const tracker = new S3WaitTracker(() => now);
    let release!: () => void;
    const a = tracker.track(new Promise<void>((resolve) => (release = resolve)));
    const b = tracker.track(Promise.resolve());
    now = 40;
    expect(tracker.snapshot()).toEqual({ inFlightMs: 40, waitedMs: 40 });
    release();
    await Promise.all([a, b]);
    now = 100;
    expect(tracker.snapshot()).toEqual({ inFlightMs: 0, waitedMs: 40 });
  });

  it('settles like the tracked promise', async () => {
    const tracker = new S3WaitTracker();
    await expect(tracker.track(Promise.resolve(7))).resolves.toBe(7);
    const failure = new Error('down');
    await expect(tracker.track(Promise.reject(failure))).rejects.toBe(failure);
    expect(tracker.snapshot().inFlightMs).toBe(0);
  });

  it('blames S3 for a long pending call or a budget spent mostly waiting', () => {
    expect(stallThresholdMs(120_000)).toBe(1000);
    expect(stallThresholdMs(200)).toBe(50);
    expect(stalledOnS3({ inFlightMs: 1000, waitedMs: 1000 }, 120_000)).toBe(true);
    expect(stalledOnS3({ inFlightMs: 0, waitedMs: 60_000 }, 120_000)).toBe(true);
    // A parse that is slow on its own: brief waits for the next socket read only.
    expect(stalledOnS3({ inFlightMs: 3, waitedMs: 5_000 }, 120_000)).toBe(false);
    expect(stalledOnS3({ inFlightMs: 0, waitedMs: 0 }, 120_000)).toBe(false);
  });
});

describe('trackedInput and withStallTimeout', () => {
  it('passes every byte through and counts the waits for chunks', async () => {
    let now = 0;
    const tracker = new S3WaitTracker(() => now);
    const source = Readable.from(
      (async function* () {
        yield Buffer.from('ab');
        now += 10;
        await delay(1);
        yield Buffer.from('cd');
      })(),
    );
    expect((await readAll(trackedInput(source, tracker))).toString()).toBe('abcd');
    expect(tracker.snapshot().waitedMs).toBe(10);
  });

  it('destroying the wrapper destroys a source with a read pending', async () => {
    const source = stallingBody('x');
    const wrapped = trackedInput(source, new S3WaitTracker());
    const iterator = (wrapped as AsyncIterable<Buffer>)[Symbol.asyncIterator]();
    await iterator.next();
    const pending = iterator.next().catch(() => ({ done: true }));
    await delay(5);
    wrapped.destroy();
    await pending;
    expect(source.destroyed).toBe(true);
  });

  it('fails a body that stalls longer than the timeout with S3Stalled', async () => {
    const source = stallingBody('first bytes');
    const started = Date.now();
    await expect(readAll(withStallTimeout(source, 60))).rejects.toBeInstanceOf(S3Stalled);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(source.destroyed).toBe(true);
  });

  it('never times out while only the consumer is slow (backpressure is not S3 time)', async () => {
    const source = Readable.from(
      Array.from({ length: 4 }, (_, i) => Buffer.alloc(32 * 1024, i)),
      { objectMode: false },
    );
    const data = await readAll(withStallTimeout(source, 50), 80);
    expect(data).toHaveLength(4 * 32 * 1024);
  });
});

describe('S3EmlSource (design M3.6)', () => {
  type Send = (command: unknown, options: { abortSignal: AbortSignal }) => Promise<unknown>;
  const sourceWith = (send: Send, timeoutMs = 60) =>
    new S3EmlSource({ send } as unknown as S3Client, 'mail', timeoutMs);
  const hanging: Send = (_command, { abortSignal }) =>
    new Promise((_resolve, reject) => {
      abortSignal.addEventListener('abort', () =>
        reject(Object.assign(new Error('aborted'), { name: 'AbortError' })),
      );
    });

  it('fails with S3Stalled when GetObject does not answer within MIME_S3_TIMEOUT_MS', async () => {
    await expect(
      sourceWith(hanging).open('org/1/eml/x.eml', new AbortController().signal),
    ).rejects.toBeInstanceOf(S3Stalled);
  });

  it('passes the caller abort through as it is (the parse budget decides)', async () => {
    const caller = new AbortController();
    const opening = sourceWith(hanging, 10_000).open('org/1/eml/x.eml', caller.signal);
    caller.abort();
    await expect(opening).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('maps NoSuchKey to EML_MISSING', async () => {
    const missing: Send = () =>
      Promise.reject(Object.assign(new Error('no'), { name: 'NoSuchKey', $metadata: {} }));
    await expect(
      sourceWith(missing).open('org/1/eml/x.eml', new AbortController().signal),
    ).resolves.toBe(EML_MISSING);
  });

  it('streams the body and fails a body that stalls mid-stream', async () => {
    const ok: Send = () => Promise.resolve({ Body: Readable.from([Buffer.from('From: a\r\n')]) });
    const opened = await sourceWith(ok).open('org/1/eml/x.eml', new AbortController().signal);
    expect(opened).not.toBe(EML_MISSING);
    expect((await readAll(opened as Readable)).toString()).toBe('From: a\r\n');

    const body = stallingBody('From: a\r\n');
    const stalls: Send = () => Promise.resolve({ Body: body });
    const stalled = await sourceWith(stalls).open('org/1/eml/x.eml', new AbortController().signal);
    await expect(readAll(stalled as Readable)).rejects.toBeInstanceOf(S3Stalled);
    expect(body.destroyed).toBe(true);
  });
});

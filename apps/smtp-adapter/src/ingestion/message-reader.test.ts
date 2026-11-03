import { createHash } from 'node:crypto';
import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import type { HeaderMetadata } from './header-scanner';
import { type MessageSink, readMessage } from './message-reader';

class FakeSink implements MessageSink {
  chunks: Buffer[] = [];
  aborted: unknown = null;
  constructor(private readonly failAfter = Infinity) {}
  get failed(): boolean {
    return this.aborted !== null || this.chunks.length >= this.failAfter;
  }
  write(chunk: Buffer): Promise<void> {
    if (!this.failed) this.chunks.push(chunk);
    return Promise.resolve();
  }
  finish(): Promise<void> {
    return this.failed ? Promise.reject(new Error('failed')) : Promise.resolve();
  }
  abort(reason: unknown): void {
    this.aborted = reason;
  }
}

function streamOf(
  chunks: (string | Buffer)[],
  options: { sizeExceeded?: boolean; destroyAfter?: number } = {},
) {
  const stream = Object.assign(new PassThrough(), { sizeExceeded: false });
  void (async () => {
    let i = 0;
    for (const chunk of chunks) {
      if (options.destroyAfter !== undefined && i === options.destroyAfter) {
        stream.destroy(new Error('Connection closed'));
        return;
      }
      stream.write(chunk);
      i += 1;
      await new Promise((resolve) => setImmediate(resolve));
    }
    if (options.sizeExceeded) stream.sizeExceeded = true;
    stream.end();
  })();
  return stream;
}

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

describe('readMessage', () => {
  it('hashes and counts every byte and sends the whole message to the sink chosen at the headers', async () => {
    const parts = ['From: a@b.test\r\nSub', 'ject: x\r\n\r\nbody ', 'line 1\r\n', 'line 2\r\n'];
    const sink = new FakeSink();
    let seen: HeaderMetadata | null = null;
    const result = await readMessage(streamOf(parts), {
      headerMaxBytes: 1024,
      onHeaders: (headers) => {
        seen = headers;
        return sink;
      },
    });
    const all = Buffer.from(parts.join(''));
    expect(result.outcome).toBe('complete');
    expect(result.sha256).toBe(sha(all));
    expect(result.bytes).toBe(all.length);
    expect(Buffer.concat(sink.chunks).equals(all)).toBe(true);
    expect(seen!.subject).toBe('x');
    expect(result.headers?.from).toBe('a@b.test');
  });

  it('decides at the end of a message without an empty line', async () => {
    const sink = new FakeSink();
    const result = await readMessage(streamOf(['Subject: only headers']), {
      headerMaxBytes: 1024,
      onHeaders: () => sink,
    });
    expect(result.headers?.subject).toBe('only headers');
    expect(Buffer.concat(sink.chunks).toString()).toBe('Subject: only headers');
  });

  it('discards (but still hashes and drains) when nothing is to be stored', async () => {
    const result = await readMessage(streamOf(['Subject: x\r\n\r\n', 'body']), {
      headerMaxBytes: 1024,
      onHeaders: () => null,
    });
    expect(result.outcome).toBe('complete');
    expect(result.sink).toBeNull();
    expect(result.bytes).toBe(18);
  });

  it('stops writing after the sink failed and keeps draining', async () => {
    const sink = new FakeSink(1);
    const result = await readMessage(streamOf(['Subject: x\r\n\r\n', 'a', 'b', 'c']), {
      headerMaxBytes: 1024,
      onHeaders: () => sink,
    });
    expect(result.outcome).toBe('complete');
    expect(result.bytes).toBe(17);
    expect(sink.chunks).toHaveLength(1);
  });

  it('reports a client that disconnects mid-DATA as aborted and aborts the sink', async () => {
    const sink = new FakeSink();
    const result = await readMessage(
      streamOf(['Subject: x\r\n\r\n', 'a', 'b'], { destroyAfter: 2 }),
      { headerMaxBytes: 1024, onHeaders: () => sink },
    );
    expect(result.outcome).toBe('aborted');
    expect(sink.aborted).not.toBeNull();
  });

  it('reports an oversized message (smtp-server sizeExceeded) and aborts the sink', async () => {
    const sink = new FakeSink();
    const result = await readMessage(
      streamOf(['Subject: x\r\n\r\n', 'a'], { sizeExceeded: true }),
      {
        headerMaxBytes: 1024,
        onHeaders: () => sink,
      },
    );
    expect(result.outcome).toBe('too_large');
    expect(sink.aborted).not.toBeNull();
  });

  it('turns a throwing decision into a failed read without stopping the stream', async () => {
    const result = await readMessage(streamOf(['Subject: x\r\n\r\n', 'a', 'b']), {
      headerMaxBytes: 1024,
      onHeaders: () => {
        throw new Error('bad config');
      },
    });
    expect(result.outcome).toBe('failed');
    expect(result.bytes).toBe(16);
  });
});

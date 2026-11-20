import { afterEach, describe, expect, it, vi } from 'vitest';
import { SSE_HEADERS, SseWriter, wantsEventStream } from './sse-writer';

class FakeResponse {
  statusCode = 0;
  headers: Record<string, string> = {};
  chunks: string[] = [];
  flushed = 0;
  writableEnded = false;
  destroyed = false;
  status(code: number): this {
    this.statusCode = code;
    return this;
  }
  setHeader(name: string, value: string): this {
    this.headers[name] = value;
    return this;
  }
  flushHeaders(): void {
    this.flushed += 1;
  }
  write(chunk: string): boolean {
    this.chunks.push(chunk);
    return true;
  }
  end(): this {
    this.writableEnded = true;
    return this;
  }
}

afterEach(() => vi.useRealTimers());

describe('SseWriter (assistant-stream/1, §4.2)', () => {
  it('flushes the headers at start and writes events as event + one data line, in order', () => {
    const res = new FakeResponse();
    const sse = new SseWriter(res as never);
    sse.start();
    expect(res.statusCode).toBe(200);
    expect(res.flushed).toBe(1);
    expect(res.headers).toEqual({
      'content-type': 'text/event-stream',
      'cache-control': 'no-store',
      'x-accel-buffering': 'no',
    });
    expect(SSE_HEADERS['x-accel-buffering']).toBe('no');
    sse.emit({ type: 'turn.started', turnId: 't', conversationId: 'c', seq: 1 });
    sse.emit({ type: 'text.delta', text: 'line one\nline "two"' });
    sse.emit({
      type: 'turn.completed',
      turnId: 't',
      status: 'completed',
      usage: { inputTokens: 1, outputTokens: 2 },
      messageId: 'm',
    });
    sse.end();
    expect(res.chunks).toEqual([
      'event: turn.started\ndata: {"turnId":"t","conversationId":"c","seq":1}\n\n',
      'event: text.delta\ndata: {"text":"line one\\nline \\"two\\""}\n\n',
      'event: turn.completed\ndata: {"turnId":"t","status":"completed","usage":{"inputTokens":1,"outputTokens":2},"messageId":"m"}\n\n',
    ]);
    // Nothing after the end.
    sse.emit({ type: 'text.delta', text: 'late' });
    expect(res.chunks).toHaveLength(3);
  });

  it('writes a comment heartbeat every interval until the end', () => {
    vi.useFakeTimers();
    const res = new FakeResponse();
    const sse = new SseWriter(res as never, 15_000);
    sse.start();
    vi.advanceTimersByTime(45_000);
    expect(res.chunks).toEqual([': heartbeat\n\n', ': heartbeat\n\n', ': heartbeat\n\n']);
    sse.end();
    vi.advanceTimersByTime(30_000);
    expect(res.chunks).toHaveLength(3);
  });

  it('writes nothing to a destroyed response', () => {
    const res = new FakeResponse();
    const sse = new SseWriter(res as never);
    sse.start();
    res.destroyed = true;
    sse.emit({ type: 'text.delta', text: 'x' });
    sse.end();
    expect(res.chunks).toEqual([]);
    expect(res.writableEnded).toBe(false);
  });

  it('recognizes accept: text/event-stream among other media types', () => {
    expect(wantsEventStream('text/event-stream')).toBe(true);
    expect(wantsEventStream('application/json, Text/Event-Stream;q=0.9')).toBe(true);
    expect(wantsEventStream('application/json')).toBe(false);
    expect(wantsEventStream(undefined)).toBe(false);
  });
});

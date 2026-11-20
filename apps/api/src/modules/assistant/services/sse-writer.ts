import {
  type AssistantStreamEvent,
  serializeStreamEvent,
  STREAM_HEARTBEAT,
  STREAM_HEARTBEAT_MS,
} from '@email-gateway/assistant';
import type { Response } from 'express';

/** Receives the events of a turn (the SSE writer, or a no-op for JSON answers). */
export interface TurnSink {
  emit(event: AssistantStreamEvent): void;
}

export const NULL_SINK: TurnSink = { emit: () => undefined };

/** The headers of an `assistant-stream/1` response (§4.2). */
export const SSE_HEADERS: Readonly<Record<string, string>> = {
  'content-type': 'text/event-stream',
  'cache-control': 'no-store',
  'x-accel-buffering': 'no',
};

/** Whether the client asked for the event stream (`accept: text/event-stream`). */
export function wantsEventStream(accept: string | string[] | undefined): boolean {
  const value = Array.isArray(accept) ? accept.join(',') : (accept ?? '');
  return value
    .split(',')
    .map((part) => part.split(';')[0]!.trim().toLowerCase())
    .includes('text/event-stream');
}

/**
 * Server-Sent Events writer of a turn (`assistant-stream/1`, design §4.2): `start()` writes the
 * status and headers and flushes them (the BFF timeout covers headers only), every event is one
 * `event:` + `data:` block, a comment heartbeat keeps proxies from timing out, and nothing is
 * written after `end()` or after the client went away.
 */
export class SseWriter implements TurnSink {
  private heartbeat: NodeJS.Timeout | undefined;
  private ended = false;

  constructor(
    private readonly res: Pick<
      Response,
      'status' | 'setHeader' | 'flushHeaders' | 'write' | 'end' | 'writableEnded' | 'destroyed'
    >,
    private readonly heartbeatMs: number = STREAM_HEARTBEAT_MS,
  ) {}

  start(): void {
    this.res.status(200);
    for (const [name, value] of Object.entries(SSE_HEADERS)) this.res.setHeader(name, value);
    this.res.flushHeaders();
    this.heartbeat = setInterval(() => this.write(STREAM_HEARTBEAT), this.heartbeatMs);
    this.heartbeat.unref();
  }

  emit(event: AssistantStreamEvent): void {
    this.write(serializeStreamEvent(event));
  }

  end(): void {
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = undefined;
    if (this.ended) return;
    this.ended = true;
    if (!this.res.writableEnded && !this.res.destroyed) this.res.end();
  }

  private write(chunk: string): void {
    if (this.ended || this.res.writableEnded || this.res.destroyed) return;
    this.res.write(chunk);
  }
}

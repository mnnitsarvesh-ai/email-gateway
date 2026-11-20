import type { AssistantStreamEvent } from './types';

/**
 * `assistant-stream/1` serialization (design §4.2): `event: <type>` + one `data:` line with the
 * JSON of the remaining fields, blank-line terminated. JSON never contains a raw newline, so one
 * `data:` line always suffices. Heartbeats are SSE comments.
 */

export function serializeStreamEvent(event: AssistantStreamEvent): string {
  const { type, ...data } = event;
  return `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
}

export const STREAM_HEARTBEAT = ': heartbeat\n\n';

/** Interval of the heartbeat comment (§4.2). */
export const STREAM_HEARTBEAT_MS = 15_000;

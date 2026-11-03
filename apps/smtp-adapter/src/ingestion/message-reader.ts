import { createHash } from 'node:crypto';
import { type HeaderMetadata, HeaderScanner } from './header-scanner';

/** Where the message bytes go once the header block is known (the S3 upload). */
export interface MessageSink {
  readonly failed: boolean;
  write(chunk: Buffer): Promise<void>;
  /** Completes the write; rejects when the sink failed. */
  finish(): Promise<void>;
  abort(reason: unknown): void;
}

export interface ReadMessageOptions {
  headerMaxBytes: number;
  /**
   * Called once, when the header block is complete (or the limit / the end of the message is
   * reached): decide where the message goes. Null discards the bytes (nothing to store).
   */
  onHeaders(headers: HeaderMetadata): MessageSink | null;
}

export type ReadOutcome = 'complete' | 'aborted' | 'too_large' | 'failed';

export interface ReadMessageResult {
  outcome: ReadOutcome;
  /** Lower-case hex SHA-256 of every byte of the message. */
  sha256: string;
  bytes: number;
  headers: HeaderMetadata | null;
  sink: MessageSink | null;
  /** The internal error behind outcome `failed`. */
  failure: unknown;
}

interface DataStream extends AsyncIterable<unknown> {
  readonly sizeExceeded?: boolean;
}

const toBuffer = (chunk: unknown): Buffer =>
  Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');

/**
 * Streams one LMTP DATA payload (D7 step 2): header scanner (bounded), SHA-256 and byte count,
 * then into the sink. Only the header block (≤ `headerMaxBytes` + one chunk) is buffered, until
 * `onHeaders` picks the sink. The stream is always read to its end, so smtp-server can answer;
 * a failed sink stops receiving data, the rest is drained and counted.
 */
export async function readMessage(
  stream: DataStream,
  options: ReadMessageOptions,
): Promise<ReadMessageResult> {
  const hash = createHash('sha256');
  const scanner = new HeaderScanner(options.headerMaxBytes);
  let bytes = 0;
  let pending: Buffer[] = [];
  let decided = false;
  let headers: HeaderMetadata | null = null;
  let sink: MessageSink | null = null;
  let outcome: ReadOutcome = 'complete';
  let failure: unknown = null;

  const decide = async (): Promise<[HeaderMetadata, MessageSink | null]> => {
    decided = true;
    const scanned = scanner.result();
    const chosen = options.onHeaders(scanned);
    const buffered = pending;
    pending = [];
    if (chosen) for (const chunk of buffered) await chosen.write(chunk);
    return [scanned, chosen];
  };

  try {
    for await (const raw of stream) {
      const chunk = toBuffer(raw);
      hash.update(chunk);
      bytes += chunk.length;
      if (outcome !== 'complete') continue;
      if (stream.sizeExceeded === true) {
        outcome = 'too_large';
        sink?.abort(new Error('message exceeds INGEST_MAX_MESSAGE_BYTES'));
        pending = [];
        continue;
      }
      // The loop body never throws: leaving a for-await early would destroy smtp-server's stream.
      try {
        if (!decided) {
          scanner.push(chunk);
          pending.push(chunk);
          if (scanner.done) [headers, sink] = await decide();
        } else if (sink !== null && !sink.failed) {
          await sink.write(chunk);
        }
      } catch (err) {
        outcome = 'failed';
        failure = err;
        pending = [];
      }
    }
  } catch {
    // The client went away mid-DATA (smtp-server destroys the stream): nothing is committed.
    outcome = 'aborted';
  }
  if (stream.sizeExceeded === true && outcome === 'complete') outcome = 'too_large';
  if (outcome !== 'complete') {
    sink?.abort(new Error(`message ${outcome}`));
  } else if (!decided) {
    try {
      scanner.finish();
      [headers, sink] = await decide();
    } catch (err) {
      outcome = 'failed';
      failure = err;
    }
  }
  return { outcome, sha256: hash.digest('hex'), bytes, headers, sink, failure };
}

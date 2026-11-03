import { open, stat } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { repoRoot, waitFor } from './compose';

/**
 * postfix-outbound's delivery log (step 2.3 R9: `maillog_file`), read from the Compose bind
 * mount `${POSTFIX_OUTBOUND_LOG_DIR}` on the host, exactly the file the delivery-worker's status
 * tailer reads. Readers remember a byte offset, so a test only sees lines written after it began.
 */
export function maillogPath(): string {
  const dir = process.env.POSTFIX_OUTBOUND_LOG_DIR || './.local/postfix-outbound-log';
  return join(isAbsolute(dir) ? dir : join(repoRoot, dir), 'maillog');
}

/** Current size of the log (the offset of the next line Postfix writes). */
export async function maillogOffset(): Promise<number> {
  try {
    return (await stat(maillogPath())).size;
  } catch {
    return 0;
  }
}

/** Lines appended since `offset` (all lines when the file was rotated and is now shorter). */
export async function maillogSince(offset: number): Promise<string[]> {
  const path = maillogPath();
  const handle = await open(path, 'r');
  try {
    const { size } = await handle.stat();
    const start = size < offset ? 0 : offset;
    const length = size - start;
    if (length <= 0) return [];
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, start);
    return buffer.toString('utf8').split('\n').filter(Boolean);
  } finally {
    await handle.close();
  }
}

/** Waits for a log line (since `offset`) matching `pattern`; returns it. */
export function waitForMaillog(offset: number, pattern: RegExp, timeoutMs = 90_000) {
  return waitFor(
    `postfix-outbound maillog line ${pattern}`,
    async () => (await maillogSince(offset)).find((line) => pattern.test(line)),
    { timeoutMs, intervalMs: 1_000 },
  );
}

/** Every line of one Postfix queue id since `offset`. */
export async function maillogForQueueId(offset: number, queueId: string): Promise<string[]> {
  if (!/^[A-Za-z0-9]+$/.test(queueId)) throw new Error(`invalid queue id ${queueId}`);
  return (await maillogSince(offset)).filter((line) => line.includes(` ${queueId}: `));
}

export const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

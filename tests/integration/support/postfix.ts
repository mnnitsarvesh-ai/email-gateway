import { compose, composeExec, waitFor } from './compose';

/** The Postfix services of the mail plane (Compose service names). */
export type PostfixService = 'postfix' | 'postfix-outbound';

export interface QueuedRecipient {
  address: string;
  delay_reason?: string;
}

/** One entry of `postqueue -j` (Postfix 3.1+ JSON queue listing). */
export interface QueuedMessage {
  queue_name: 'maildrop' | 'incoming' | 'active' | 'deferred' | 'hold' | 'corrupt';
  queue_id: string;
  arrival_time: number;
  message_size: number;
  sender: string;
  recipients: QueuedRecipient[];
}

/** Parses `postqueue -j` output: one JSON object per line. */
export function parseQueue(output: string): QueuedMessage[] {
  return output
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as QueuedMessage);
}

export async function listQueue(service: PostfixService): Promise<QueuedMessage[]> {
  const result = await composeExec(service, ['postqueue', '-j'], { timeoutMs: 30_000 });
  if (result.exitCode !== 0) throw new Error(`postqueue -j failed: ${result.stderr}`);
  return parseQueue(result.stdout);
}

/** `postqueue -f`: attempt delivery of every queued message now. */
export async function flushQueue(service: PostfixService): Promise<void> {
  const result = await composeExec(service, ['postqueue', '-f'], { timeoutMs: 30_000 });
  if (result.exitCode !== 0) throw new Error(`postqueue -f failed: ${result.stderr}`);
}

/** Deletes the given queue ids (`postsuper -d`); unknown ids are ignored. */
export async function deleteQueued(service: PostfixService, ids: readonly string[]) {
  for (const id of ids) {
    if (!/^[A-Za-z0-9]+$/.test(id)) throw new Error(`invalid queue id ${id}`);
    await composeExec(service, ['postsuper', '-d', id], { timeoutMs: 30_000 });
  }
}

/** Messages whose sender or any recipient ends with one of `domains`. */
export function involving(queue: QueuedMessage[], domains: readonly string[]): QueuedMessage[] {
  const hit = (address: string) =>
    domains.some((d) => address.toLowerCase().endsWith(`@${d.toLowerCase()}`));
  return queue.filter((m) => hit(m.sender) || m.recipients.some((r) => hit(r.address)));
}

/** Waits until no queued message involves `domains` (flushing between polls). */
export async function waitForQueueDrained(
  service: PostfixService,
  domains: readonly string[],
  timeoutMs = 120_000,
): Promise<void> {
  let polls = 0;
  await waitFor(
    `${service} queue to drain for ${domains.join(', ')}`,
    async () => {
      const left = involving(await listQueue(service), domains);
      if (left.length === 0) return true;
      polls += 1;
      if (polls % 10 === 0) await flushQueue(service);
      return false;
    },
    { timeoutMs, intervalMs: 500 },
  );
}

/** Log lines of a Compose service since `since` (ISO time). */
export async function logsSince(service: string, since: Date): Promise<string> {
  const result = await compose(
    ['logs', '--no-color', '--no-log-prefix', '--since', since.toISOString(), service],
    {
      timeoutMs: 30_000,
    },
  );
  return `${result.stdout}${result.stderr}`;
}

/** Waits for a log line of `service` (since `since`) that matches `pattern`; returns it. */
export async function waitForLog(
  service: string,
  since: Date,
  pattern: RegExp,
  timeoutMs = 60_000,
): Promise<string> {
  return waitFor(
    `${service} log line ${pattern}`,
    async () => {
      const lines = (await logsSince(service, since)).split('\n');
      return lines.find((line) => pattern.test(line));
    },
    { timeoutMs, intervalMs: 1_000 },
  );
}

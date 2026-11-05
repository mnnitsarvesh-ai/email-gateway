import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { PrismaClient } from '@email-gateway/database';
import { compose, composeExec, composeOk, run, waitFor } from './compose';
import { stack } from './env';
import type { MessageKey } from './lifecycle';
import { routingStackGate } from './routing-stack';
import type { SmtpStackGate } from './smtp-stack';
import { swaks, type SwaksResult } from './smtp-tools';

export { PASSTHROUGH_CONSUMER, RSPAMD_LEDGER, scanStageProblems } from './scan-stage';

async function ready(service: 'event-relay' | 'api'): Promise<boolean> {
  try {
    const res = await fetch(`http://${stack.host}:${stack.ports.services[service]}/health/ready`, {
      signal: AbortSignal.timeout(3_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

let cached: Promise<SmtpStackGate> | undefined;

/**
 * Gate of the step 4.1 scan stack suites (tests/integration/scan-*.test.ts): the routing stack
 * gate (which includes the scan stage) plus a ready event-relay and api (administrative
 * rescan). The services may run as containers or on the host; only Rspamd itself must be the
 * Compose container (the resilience suite stops and starts it).
 */
export function scanStackGate(): Promise<SmtpStackGate> {
  cached ??= detect();
  return cached;
}

async function detect(): Promise<SmtpStackGate> {
  const base = await routingStackGate();
  if (base.skip) return base;
  const problems: string[] = base.problem ? [base.problem] : [];
  if (!(await ready('event-relay'))) problems.push('event-relay is not ready');
  if (!(await ready('api'))) problems.push('api is not ready');
  return {
    ...base,
    problem: problems.length > 0 ? problems.join('\n') : undefined,
  };
}

// --- Readers (MySQL writer) ---------------------------------------------------------------------

export function scanRoundsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.emailScan.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { lifecycleRound: 'asc' },
  });
}

export function engineResultsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.scanEngineResult.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: [{ scanId: 'asc' }, { attempt: 'asc' }],
  });
}

export function authResultsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.emailAuthResult.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { scanId: 'asc' },
  });
}

/** `mail.message.scanned.v1` outbox rows of a message, oldest first. */
export function scannedEventsOf(prisma: PrismaClient, organizationId: bigint, message: MessageKey) {
  return prisma.messageOutbox.findMany({
    where: {
      organizationId,
      aggregateId: message.id.toString(),
      eventType: 'mail.message.scanned.v1',
    },
    orderBy: { id: 'asc' },
  });
}

/** Waits until the message's round `round` is no longer `running` (or `pending`); returns it. */
export async function waitForRoundComplete(
  prisma: PrismaClient,
  message: MessageKey,
  round: number,
  timeoutMs = 120_000,
) {
  return waitFor(
    `scan round ${round} of message ${message.id} completed`,
    async () => {
      const row = (await scanRoundsOf(prisma, message)).find((r) => r.lifecycleRound === round);
      return row && row.status !== 'running' && row.status !== 'pending' ? row : undefined;
    },
    { timeoutMs, intervalMs: 500 },
  );
}

/** Waits until the message has at least `n` engine result rows (attempts and finals). */
export async function waitForEngineRows(
  prisma: PrismaClient,
  message: MessageKey,
  n: number,
  timeoutMs = 120_000,
) {
  return waitFor(
    `${n} engine result rows of message ${message.id}`,
    async () => {
      const rows = await engineResultsOf(prisma, message);
      return rows.length >= n ? rows : undefined;
    },
    { timeoutMs, intervalMs: 250 },
  );
}

// --- Rspamd container control -------------------------------------------------------------------

/** `docker compose stop rspamd` (the inbound Rspamd: milter and /checkv2). */
export async function stopRspamd(): Promise<void> {
  await composeOk(['stop', '--timeout', '10', 'rspamd'], { timeoutMs: 60_000 });
}

/**
 * Starts the stopped Rspamd container (`docker start`, not `docker compose start`, so nothing
 * else is started) and waits until its health check passes. Returns the seconds it took.
 */
export async function startRspamd(): Promise<number> {
  const started = Date.now();
  const id = (await composeOk(['ps', '--all', '--quiet', 'rspamd'], { timeoutMs: 20_000 })).stdout
    .trim()
    .split('\n')[0];
  if (!id || !/^[0-9a-f]{12,64}$/.test(id)) throw new Error('rspamd container not found');
  const result = await run('docker', ['start', id], { timeoutMs: 60_000 });
  if (result.exitCode !== 0) throw new Error(`docker start rspamd: ${result.stderr.trim()}`);
  await waitForRspamdHealthy(180_000);
  return (Date.now() - started) / 1000;
}

export async function waitForRspamdHealthy(timeoutMs = 180_000): Promise<void> {
  await waitFor(
    'rspamd healthy',
    async () => {
      const id = (await compose(['ps', '--quiet', 'rspamd'], { timeoutMs: 20_000 })).stdout.trim();
      if (!/^[0-9a-f]{12,64}$/.test(id)) return false;
      const state = await run('docker', ['inspect', '--format', '{{.State.Health.Status}}', id], {
        timeoutMs: 20_000,
      });
      return state.stdout.trim() === 'healthy';
    },
    { timeoutMs, intervalMs: 1_000 },
  );
}

/** Postfix's `myhostname`: the authserv-id of the Authentication-Results Rspamd adds (S11). */
export async function gatewayAuthservId(): Promise<string> {
  const result = await composeExec('postfix', ['postconf', '-h', 'myhostname']);
  const value = result.stdout.trim();
  if (result.exitCode !== 0 || !value) throw new Error('postconf myhostname failed');
  return value;
}

/** One `<name>: <value>` header field per entry (unfolded), of the header block of `eml`. */
export function headerFieldsOf(eml: string): { name: string; value: string }[] {
  const block = eml.replace(/\r\n/g, '\n').split('\n\n')[0] ?? '';
  const unfolded = block.replace(/\n[ \t]+/g, ' ');
  return unfolded
    .split('\n')
    .filter((line) => line.includes(':'))
    .map((line) => {
      const colon = line.indexOf(':');
      return { name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() };
    });
}

// --- Mail through the inbound MX ----------------------------------------------------------------

/** One file of the step 4.1 scan corpus (tests/fixtures/scan-corpus), as text. */
export function corpusEml(file: string): string {
  return readFileSync(
    fileURLToPath(new URL(`../../fixtures/scan-corpus/${file}`, import.meta.url)),
    'utf8',
  );
}

/**
 * Inserts header lines at the top of `eml` (before the existing header fields). Header fields
 * that a DKIM signature does not cover can be added without breaking it.
 */
export function withLeadingHeaders(eml: string, headers: readonly string[]): string {
  return `${headers.join('\r\n')}\r\n${eml.replace(/\r?\n/g, '\r\n')}`;
}

/**
 * The inbound Postfix's fixed address on the `mailtest` network (docker-compose.yml). The scan
 * suites connect to it, not to the service name: `postfix` resolves to its address on the
 * default network, so the client would be smtp-tools' default-network address, which is not in
 * the `scan.test` SPF records (172.31.250.0/24 is, S12).
 */
export const POSTFIX_MAILTEST_ADDRESS = '172.31.250.10';

/** Sends `data` from smtp-tools to the gateway MX (postfix:25 on mailtest) with the envelope. */
export function sendToMx(options: {
  from: string;
  to: readonly string[];
  data: string;
  helo?: string;
}): Promise<SwaksResult> {
  return swaks({
    server: POSTFIX_MAILTEST_ADDRESS,
    port: 25,
    from: options.from,
    to: options.to,
    helo: options.helo,
    data: options.data,
  });
}

/** Starts Rspamd when its container is not running, then waits for its health check. */
export async function ensureRspamdRunning(): Promise<void> {
  const running = await compose(['ps', '--status', 'running', '--quiet', 'rspamd'], {
    timeoutMs: 20_000,
  });
  if (!running.stdout.trim()) {
    await startRspamd();
    return;
  }
  await waitForRspamdHealthy();
}

/** The public id of a message (`message_identities.public_id`, what the api addresses). */
export async function messagePublicId(prisma: PrismaClient, message: MessageKey): Promise<string> {
  const identity = await prisma.messageIdentity.findFirstOrThrow({
    where: { id: message.id },
    select: { publicId: true },
  });
  return identity.publicId;
}

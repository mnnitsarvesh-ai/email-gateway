import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { PrismaClient } from '@email-gateway/database';
import { compose, composeExec, composeOk, run, waitFor } from './compose';
import { stack } from './env';
import type { MessageKey } from './lifecycle';
import { routingStackGate } from './routing-stack';
import type { SmtpStackGate } from './smtp-stack';
import { swaks, type SwaksResult } from './smtp-tools';

export {
  ATTACHMENT_LEDGER,
  BEC_LEDGER,
  DLP_LEDGER,
  POLICY_QUEUE,
  REQUIRED_ENGINES,
  RSPAMD_LEDGER,
  SCAN_CONSUMED_QUEUES,
  scanStageProblems,
  URL_LEDGER,
} from './scan-stage';

/**
 * The stage-1 engines of the stack (consume `parsed.v1`/`rescan_requested.v1`, step 4.4 B2;
 * `dlp` since step 4.5 D1).
 */
export const STAGE1_ENGINES = ['rspamd', 'attachment', 'url', 'dlp'] as const;

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

/**
 * The engines of a round's final rows WITHOUT the asynchronous `sandbox` engine (step 4.6 X10):
 * its final may be written before or after the round completes (an attachment submitted to the
 * sandbox), never counts for the round and is asserted by the sandbox suites, so round-level
 * assertions compare the synchronous engines only. Sorted.
 */
export function roundFinalEngines(rows: readonly { engine: string; isFinal: boolean }[]): string[] {
  return rows
    .filter((r) => r.isFinal && r.engine !== 'sandbox')
    .map((r) => r.engine)
    .sort();
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

export function attachmentResultsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.attachmentScanResult.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: [{ scanId: 'asc' }, { partIndex: 'asc' }],
  });
}

export function sandboxSubmissionsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.sandboxSubmission.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: [{ scanId: 'asc' }, { partIndex: 'asc' }],
  });
}

/** `bec_scan_results` rows of a message (step 4.4 B14), oldest round first. */
export function becResultsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.becScanResult.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { scanId: 'asc' },
  });
}

/** `dlp_scan_results` rows of a message (step 4.5 D19), oldest round first. */
export function dlpResultsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.dlpScanResult.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { scanId: 'asc' },
  });
}

/** `dlp_evidence` rows of a message (step 4.5 D16), oldest round first. */
export function dlpEvidenceOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.dlpEvidence.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { scanId: 'asc' },
  });
}

/** `mail.message.dlp_incident.v1` outbox rows of a message (step 4.5 D14), oldest first. */
export function dlpIncidentEventsOf(
  prisma: PrismaClient,
  organizationId: bigint,
  message: MessageKey,
) {
  return prisma.messageOutbox.findMany({
    where: {
      organizationId,
      aggregateId: message.id.toString(),
      eventType: 'mail.message.dlp_incident.v1',
    },
    orderBy: { id: 'asc' },
  });
}

/** The detector/coverage codes of a stored `dlp_scan_results.findings` JSON (masked only). */
export function dlpFindingCodes(findings: unknown): string[] {
  return Array.isArray(findings)
    ? findings
        .map((f) => (f && typeof f === 'object' ? (f as { code?: unknown }).code : undefined))
        .filter((c): c is string => typeof c === 'string')
    : [];
}

/**
 * `mail.message.scan_stage_ready.v1` outbox rows of a message (step 4.4 B2: the trigger of a
 * stage-2 engine, written once per round by the transaction that inserts the last dependency
 * final), oldest first.
 */
export function stageReadyEventsOf(
  prisma: PrismaClient,
  organizationId: bigint,
  message: MessageKey,
) {
  return prisma.messageOutbox.findMany({
    where: {
      organizationId,
      aggregateId: message.id.toString(),
      eventType: 'mail.message.scan_stage_ready.v1',
    },
    orderBy: { id: 'asc' },
  });
}

/** The fired rule codes of a stored `bec_scan_results.rules` JSON (never evidence content). */
export function becRuleCodes(rules: unknown): string[] {
  return Array.isArray(rules)
    ? rules
        .map((r) => (r && typeof r === 'object' ? (r as { code?: unknown }).code : undefined))
        .filter((c): c is string => typeof c === 'string')
    : [];
}

// --- Engine container control (Rspamd, ClamAV) --------------------------------------------------

/** The engine containers the resilience suites stop and start (Compose services). */
export type EngineService = 'rspamd' | 'clamav';

/** `docker compose stop <service>` (only that container). */
export async function stopEngineService(service: EngineService): Promise<void> {
  await composeOk(['stop', '--timeout', '10', service], { timeoutMs: 60_000 });
}

/**
 * Starts a stopped engine container (`docker start`, not `docker compose start`, so nothing else
 * is started) and waits until its health check passes. Returns the seconds it took.
 */
export async function startEngineService(
  service: EngineService,
  timeoutMs = 180_000,
): Promise<number> {
  const started = Date.now();
  const id = (await composeOk(['ps', '--all', '--quiet', service], { timeoutMs: 20_000 })).stdout
    .trim()
    .split('\n')[0];
  if (!id || !/^[0-9a-f]{12,64}$/.test(id)) throw new Error(`${service} container not found`);
  const result = await run('docker', ['start', id], { timeoutMs: 60_000 });
  if (result.exitCode !== 0) throw new Error(`docker start ${service}: ${result.stderr.trim()}`);
  await waitForEngineHealthy(service, timeoutMs);
  return (Date.now() - started) / 1000;
}

export async function waitForEngineHealthy(
  service: EngineService,
  timeoutMs = 180_000,
): Promise<void> {
  await waitFor(
    `${service} healthy`,
    async () => {
      const id = (await compose(['ps', '--quiet', service], { timeoutMs: 20_000 })).stdout.trim();
      if (!/^[0-9a-f]{12,64}$/.test(id)) return false;
      const state = await run('docker', ['inspect', '--format', '{{.State.Health.Status}}', id], {
        timeoutMs: 20_000,
      });
      return state.stdout.trim() === 'healthy';
    },
    { timeoutMs, intervalMs: 1_000 },
  );
}

/** Starts the engine container when it is not running, then waits for its health check. */
export async function ensureEngineRunning(
  service: EngineService,
  timeoutMs = 180_000,
): Promise<void> {
  const running = await compose(['ps', '--status', 'running', '--quiet', service], {
    timeoutMs: 20_000,
  });
  if (!running.stdout.trim()) {
    await startEngineService(service, timeoutMs);
    return;
  }
  await waitForEngineHealthy(service, timeoutMs);
}

/** `docker compose stop rspamd` (the inbound Rspamd: milter and /checkv2). */
export function stopRspamd(): Promise<void> {
  return stopEngineService('rspamd');
}

/** Starts the stopped Rspamd container and waits for its health check (seconds it took). */
export function startRspamd(): Promise<number> {
  return startEngineService('rspamd');
}

export function waitForRspamdHealthy(timeoutMs = 180_000): Promise<void> {
  return waitForEngineHealthy('rspamd', timeoutMs);
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
export function ensureRspamdRunning(): Promise<void> {
  return ensureEngineRunning('rspamd');
}

/** The public id of a message (`message_identities.public_id`, what the api addresses). */
export async function messagePublicId(prisma: PrismaClient, message: MessageKey): Promise<string> {
  const identity = await prisma.messageIdentity.findFirstOrThrow({
    where: { id: message.id },
    select: { publicId: true },
  });
  return identity.publicId;
}

import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import { expect } from 'vitest';
import type { ApiSession } from './api-client';
import { attachmentMessage, type MessageAttachment } from './attachment-stack';
import { compose, composeExec, run, waitFor } from './compose';
import { waitForMessage } from './deliveries';
import type { MessageKey } from './lifecycle';
import {
  engineResultsOf,
  sandboxSubmissionsOf,
  sendToMx,
  waitForRoundComplete,
} from './scan-stack';
import { reply } from './smtp-tools';

/**
 * Helpers of the step 4.6 sandbox stack suites (tests/integration/sandbox-*.test.ts,
 * docs/plan/steps/14-sandbox.md §9.5). The sandbox-controller runs as the Compose container of
 * the `apps` profile (backend `disabled` by default; the suites switch it to `static` or, with
 * the LOCAL/CI-only exec override, to `hardened-container` and restore it afterwards). Every
 * sample is a synthetic benign script/HTML written by the test (no real malware; EICAR only as
 * the runtime-built test string).
 */

export type ControllerBackend = 'disabled' | 'static' | 'hardened-container';

/** The plan feature the sandbox opt-in needs (FEATURE_KEYS). */
export const SANDBOX_FEATURE = 'attachment_sandbox';

/**
 * The controller's HTTP port inside its container. Its only network (`sandbox-control`) is
 * `internal`, so Docker does not publish the port to the host: health and metrics are read from
 * inside the container (`docker compose exec … node -e fetch(…)`), like the url-browser-worker.
 */
const CONTROLLER_PORT = 3092;

/** GET `path` on the controller from inside its container: `{ status, body }` (status 0 = down). */
async function controllerGet(path: string): Promise<{ status: number; body: string }> {
  const script =
    `fetch('http://127.0.0.1:${CONTROLLER_PORT}${path}',{signal:AbortSignal.timeout(5000)})` +
    ".then(async r=>process.stdout.write(r.status+'\\n'+await r.text()))" +
    ".catch(()=>process.stdout.write('0\\n'))";
  const result = await composeExec('sandbox-controller', ['node', '-e', script], {
    timeoutMs: 20_000,
  }).catch(() => ({ exitCode: 1, stdout: '', stderr: '' }));
  if (result.exitCode !== 0) return { status: 0, body: '' };
  const newline = result.stdout.indexOf('\n');
  return {
    status: Number(result.stdout.slice(0, newline === -1 ? undefined : newline)) || 0,
    body: newline === -1 ? '' : result.stdout.slice(newline + 1),
  };
}

/** Compose files of the LOCAL/CI-only execution override (`hardened-container`, NOT a VM). */
export const EXEC_COMPOSE_FILES = [
  '-f',
  'docker-compose.yml',
  '-f',
  'infrastructure/sandbox/compose.exec.yml',
] as const;

/** `/health/ready` of the controller: `{ ok, backend }` (backend from the readiness details). */
export async function controllerHealth(): Promise<{ ok: boolean; backend: string | null }> {
  const { status, body } = await controllerGet('/health/ready');
  const match = /"backend"\s*:\s*"([a-z-]+)"/.exec(body);
  return { ok: status === 200, backend: match ? match[1]! : null };
}

/** A counter/gauge of the controller's `/metrics`, summed over the series matching `labels`. */
export async function controllerMetric(
  name: string,
  labels: Record<string, string> = {},
): Promise<number> {
  const { status, body } = await controllerGet('/metrics');
  if (status !== 200) throw new Error(`sandbox-controller /metrics answered ${status}`);
  let total = 0;
  for (const line of body.split('\n')) {
    if (!line.startsWith(`${name}{`) && !line.startsWith(`${name} `)) continue;
    const match = /^[^{ ]+(?:\{([^}]*)\})? ([0-9.eE+-]+)$/.exec(line);
    if (!match) continue;
    const present = new Map(
      [...(match[1] ?? '').matchAll(/(\w+)="([^"]*)"/g)].map((m) => [m[1]!, m[2]!]),
    );
    if (Object.entries(labels).every(([k, v]) => present.get(k) === v)) total += Number(match[2]);
  }
  return total;
}

/**
 * (Re)creates the controller container with `backend` unless it already runs it and is ready.
 * `exec` adds the LOCAL/CI-only execution override (Docker socket, sinkhole, hardened runner).
 */
export async function ensureController(
  backend: ControllerBackend,
  options: { exec?: boolean } = {},
): Promise<void> {
  const health = await controllerHealth();
  if (health.ok && health.backend === backend) return;
  const files = options.exec ? [...EXEC_COMPOSE_FILES] : [];
  if (options.exec) {
    // The recording sinkhole first (the runner self-test requires it); `--no-deps` below keeps
    // every other running service (rabbitmq, minio, postfix …) untouched.
    const sinkhole = await compose(
      [...files, '--profile', 'sandbox', 'up', '-d', '--no-deps', '--wait', 'sandbox-sinkhole'],
      { timeoutMs: 180_000 },
    );
    if (sinkhole.exitCode !== 0) {
      throw new Error(`sandbox-sinkhole did not start: ${sinkhole.stderr.trim()}`);
    }
  }
  const profiles = options.exec
    ? ['--profile', 'apps', '--profile', 'sandbox']
    : ['--profile', 'apps'];
  const result = await compose(
    [...files, ...profiles, 'up', '-d', '--no-deps', '--wait', 'sandbox-controller'],
    {
      timeoutMs: 240_000,
      env: options.exec
        ? {}
        : { SANDBOX_BACKEND: backend, SANDBOX_ALLOW_NON_VM_EXECUTION: 'false' },
    },
  );
  if (result.exitCode !== 0) {
    throw new Error(`sandbox-controller (${backend}) did not start: ${result.stderr.trim()}`);
  }
  await waitFor(
    `sandbox-controller ready with backend ${backend}`,
    async () => {
      const h = await controllerHealth();
      return h.ok && h.backend === backend;
    },
    { timeoutMs: 120_000, intervalMs: 1_000 },
  );
}

/** Restores the default controller of the apps profile (backend `disabled`, no Docker socket). */
export async function restoreDefaultController(): Promise<void> {
  const result = await compose(
    [
      '--profile',
      'apps',
      'up',
      '-d',
      '--no-deps',
      '--wait',
      '--force-recreate',
      'sandbox-controller',
    ],
    {
      timeoutMs: 240_000,
      env: { SANDBOX_BACKEND: 'disabled', SANDBOX_ALLOW_NON_VM_EXECUTION: 'false' },
    },
  );
  if (result.exitCode !== 0) {
    throw new Error(`sandbox-controller could not be restored: ${result.stderr.trim()}`);
  }
}

/** `docker compose stop|start|kill sandbox-controller`. */
export async function controllerService(action: 'stop' | 'start' | 'kill'): Promise<void> {
  const result = await compose([action, 'sandbox-controller'], { timeoutMs: 120_000 });
  if (result.exitCode !== 0) {
    throw new Error(`docker compose ${action} sandbox-controller: ${result.stderr.trim()}`);
  }
}

/** Entries of the controller's scratch tmpfs (must be empty between tasks). */
export async function controllerScratch(): Promise<string[]> {
  const result = await composeExec('sandbox-controller', ['ls', '-A', '/scratch'], {
    timeoutMs: 20_000,
  });
  if (result.exitCode !== 0) throw new Error(`ls /scratch failed: ${result.stderr.trim()}`);
  return result.stdout
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

/** Containers labelled as sandbox runners (any controller). */
export async function runnerContainers(): Promise<string[]> {
  const result = await run('docker', ['ps', '-aq', '--filter', 'label=eg.sandbox.runner=1'], {
    timeoutMs: 20_000,
  });
  return result.stdout
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

/**
 * Opts the organization in through the api (X17): `enabled: true` is `409 feature_not_enabled`
 * until the plan feature exists; the caller grants it first (fixtures) and passes `expectRefusal`
 * to prove the gate.
 */
export async function optIn(session: ApiSession, settings: Record<string, unknown> = {}) {
  const res = await session.put('/scan-settings/sandbox', {
    expectedVersion: 0,
    settings: { enabled: true, ...settings },
  });
  return res;
}

/** A synthetic benign JavaScript sample (denied type `script_js` → attachment `suspicious`). */
export function benignScript(label: string, body = ''): Buffer {
  const nonce = randomBytes(8).toString('hex');
  return Buffer.from(
    [
      `// synthetic benign sandbox fixture ${label} ${nonce} (step 4.6 stack suite)`,
      "var note = 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA';",
      body,
      "console.log('fixture done', note.length);",
      '',
    ].join('\n'),
    'utf8',
  );
}

export interface SentMessage {
  rcpt: string;
  message: MessageKey;
  round: Awaited<ReturnType<typeof waitForRoundComplete>>;
}

/** Sends one message with `attachments` through the inbound MX; waits for round 0. */
export async function sendAttachmentMessage(
  prisma: PrismaClient,
  organizationId: bigint,
  rcpt: string,
  subject: string,
  attachments: readonly MessageAttachment[],
): Promise<SentMessage> {
  const built = attachmentMessage({
    from: 'alice@clean.scan.test',
    to: [rcpt],
    subject,
    attachments,
  });
  const sent = await sendToMx({
    from: 'alice@clean.scan.test',
    to: [rcpt],
    helo: 'mx.clean.scan.test',
    data: built.text,
  });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  const message = await waitForMessage(prisma, organizationId, { mtaQueueId: sent.queueId! });
  const round = await waitForRoundComplete(prisma, message, 0, 180_000);
  return { rcpt, message, round };
}

/** The message's submission once it reached one of `statuses`. */
export function waitForSubmission(
  prisma: PrismaClient,
  message: MessageKey,
  statuses: readonly string[],
  timeoutMs = 120_000,
) {
  return waitFor(
    `a sandbox submission of message ${message.id} in ${statuses.join('|')}`,
    async () => {
      const [s] = await sandboxSubmissionsOf(prisma, message);
      return s && statuses.includes(s.status) ? s : undefined;
    },
    { timeoutMs, intervalMs: 500 },
  );
}

/** The round-0 `sandbox` final row of the message. */
export function waitForSandboxFinal(
  prisma: PrismaClient,
  message: MessageKey,
  timeoutMs = 120_000,
) {
  return waitFor(
    `the sandbox final of message ${message.id}`,
    async () =>
      (await engineResultsOf(prisma, message)).find((r) => r.engine === 'sandbox' && r.isFinal),
    { timeoutMs, intervalMs: 500 },
  );
}

/** Every `sandbox` engine row of the message (finals and attempts). */
export async function sandboxRowsOf(prisma: PrismaClient, message: MessageKey) {
  return (await engineResultsOf(prisma, message)).filter((r) => r.engine === 'sandbox');
}

/** `mail.sandbox.task_requested.v1` outbox rows of an analysis (one per dispatched task). */
export function taskRowsOf(prisma: PrismaClient, organizationId: bigint, analysisId: bigint) {
  return prisma.messageOutbox.findMany({
    where: {
      organizationId,
      eventType: 'mail.sandbox.task_requested.v1',
      aggregateId: analysisId.toString(),
    },
    orderBy: { id: 'asc' },
  });
}

/** The scans read API (replica) of a message until `ready(body)`; returns the body. */
export async function scansView<T>(
  session: ApiSession,
  publicId: string,
  ready: (body: T) => boolean,
): Promise<T> {
  return waitFor(
    `GET /messages/${publicId}/scans`,
    async () => {
      const res = await session.get(`/messages/${publicId}/scans`);
      if (res.status !== 200) return undefined;
      const body = res.body as T;
      return ready(body) ? body : undefined;
    },
    { timeoutMs: 60_000, intervalMs: 1_000 },
  );
}

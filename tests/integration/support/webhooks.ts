import { X509Certificate } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
// The stack suites verify signatures with the PUBLISHED algorithm of @email-gateway/webhooks.
// `tests/package.json` does not declare that workspace package (step 6.2 WP5 changes no
// dependency), so the self-contained module (node:crypto only) is imported by path.
import {
  verifyWebhookSignature,
  type WebhookVerificationResult,
} from '../../../packages/webhooks/src/signing';
import { idempotencyKey, type ApiResponse, type ApiSession } from './api-client';
import { compose, composeExec, composeOk, runningServices, waitFor } from './compose';
import { stack } from './env';
import { scanStackGate } from './scan-stack';
import type { SmtpStackGate } from './smtp-stack';

/**
 * Step 6.2 stack helpers (docs/plan/steps/19-webhooks-notifications.md §4.5, §10.4): the
 * TEST-ONLY `webhook-receiver` (profile smtp-test; HTTPS on 203.0.113.20 for
 * `hooks.receiver.test`, admin API on 127.0.0.1:WEBHOOK_RECEIVER_ADMIN_HOST_PORT), webhook
 * subscriptions created through the live api, the no-content assertion every received payload
 * must pass, and the postfix-notify / webhook-worker recreations of the notification suite.
 * Secrets are registered with the receiver and kept in memory only; nothing here prints one.
 */

export const RECEIVER_HOST = 'hooks.receiver.test';
/** notify-relay-sink's fixed address on `mailtest` (docker-compose.yml). */
export const NOTIFY_RELAY_SINK_ADDRESS = '172.31.250.31';
/** Largest envelope the platform sends (W2 `WEBHOOK_MAX_PAYLOAD_BYTES`). */
export const MAX_PAYLOAD_BYTES = 16_384;

/** The ten subscribable public event types (§5.2), in catalogue order. */
export const ALL_EVENT_TYPES = [
  'email.received',
  'email.scanned',
  'email.delivered',
  'email.rejected',
  'email.quarantined',
  'email.released',
  'email.threat.detected',
  'email.policy.triggered',
  'domain.verified',
  'domain.dns.failed',
] as const;
export type WebhookEventType = (typeof ALL_EVENT_TYPES)[number];

const receiverAdmin = () =>
  `http://${stack.host}:${Number(process.env.WEBHOOK_RECEIVER_ADMIN_HOST_PORT ?? 18_091)}`;
const workerPort = () => Number(process.env.WEBHOOK_WORKER_HOST_PORT ?? 3_075);

async function ok(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(3_000) });
    return res.ok;
  } catch {
    return false;
  }
}

let cached: Promise<SmtpStackGate> | undefined;

/**
 * Gate of the webhook stack suites: the scan stack gate (Postfix, adapter, engines, relay, api)
 * plus a ready webhook-worker and the running webhook-receiver.
 */
export function webhooksStackGate(): Promise<SmtpStackGate> {
  cached ??= (async () => {
    const base = await scanStackGate();
    if (base.skip) return base;
    const problems: string[] = base.problem ? [base.problem] : [];
    if (!(await ok(`http://${stack.host}:${workerPort()}/health/ready`))) {
      problems.push(
        `webhook-worker is not ready on ${stack.host}:${workerPort()} ` +
          '(docker compose --profile apps up -d --wait webhook-worker)',
      );
    }
    const services = await runningServices();
    if (!services.has('webhook-receiver') || !(await ok(`${receiverAdmin()}/health`))) {
      problems.push(
        'webhook-receiver is not running (docker compose --profile smtp-test up -d --wait webhook-receiver)',
      );
    }
    return { ...base, problem: problems.length > 0 ? problems.join('\n') : undefined };
  })();
  return cached;
}

// --- webhook-receiver admin API ------------------------------------------------------------------

/** One request recorded by the receiver (headers lower-case, raw body bytes). */
export interface ReceivedRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: Buffer;
  receivedAt: Date;
  /** The receiver's own verification against the registered secrets (null: none registered). */
  signatureValid: boolean | null;
  eventId: string;
  eventType: string;
  deliveryId: string;
  attempt: number;
  envelope: WebhookEnvelope;
}

export interface WebhookEnvelope {
  id: string;
  type: string;
  version: number;
  occurredAt: string;
  organizationId: string;
  data: Record<string, unknown> & {
    message?: Record<string, unknown> & { id?: string; internetMessageId?: string | null };
  };
}

async function admin(method: 'GET' | 'PUT', route: string, body?: unknown): Promise<unknown> {
  const res = await fetch(`${receiverAdmin()}${route}`, {
    method,
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`webhook-receiver ${method} ${route.split('/')[1]} → ${res.status}`);
  return res.json();
}

/** Registers the signing secret(s) of `path` (the receiver then records `signatureValid`). */
export async function registerReceiverSecrets(path: string, secrets: readonly string[]) {
  await admin('PUT', `/secrets/${path}`, { secrets });
}

/** Programs the next answers of `path` (then `then`, default 200). */
export async function programReceiver(
  path: string,
  responses: readonly { status: number; retryAfter?: number | string; body?: string }[],
  then = 200,
) {
  await admin('PUT', `/program/${path}`, { responses, then });
}

/** Every request recorded for `path`, oldest first, parsed. */
export async function receivedRequests(path: string): Promise<ReceivedRequest[]> {
  const doc = (await admin('GET', `/requests/${path}`)) as {
    requests: {
      method: string;
      path: string;
      headers: Record<string, string | string[]>;
      bodyBase64: string;
      receivedAt: string;
      signatureValid: boolean | null;
    }[];
  };
  return doc.requests.map((r) => {
    const headers = Object.fromEntries(
      Object.entries(r.headers).map(([k, v]) => [
        k.toLowerCase(),
        Array.isArray(v) ? v.join(', ') : v,
      ]),
    );
    const body = Buffer.from(r.bodyBase64, 'base64');
    return {
      method: r.method,
      path: r.path,
      headers,
      body,
      receivedAt: new Date(r.receivedAt),
      signatureValid: r.signatureValid,
      eventId: headers['eg-event-id'] ?? '',
      eventType: headers['eg-event-type'] ?? '',
      deliveryId: headers['eg-delivery-id'] ?? '',
      attempt: Number(headers['eg-delivery-attempt'] ?? 0),
      envelope: JSON.parse(body.toString('utf8')) as WebhookEnvelope,
    };
  });
}

/** Polls `path` until `predicate` holds for the recorded requests; returns them. */
export function waitForRequests(
  path: string,
  description: string,
  predicate: (requests: ReceivedRequest[]) => boolean,
  timeoutMs = 180_000,
): Promise<ReceivedRequest[]> {
  return waitFor(
    `${description} at the webhook receiver`,
    async () => {
      const requests = await receivedRequests(path);
      return predicate(requests) ? requests : undefined;
    },
    { timeoutMs, intervalMs: 1_000 },
  );
}

/** The requests of `path` whose envelope concerns message `messagePublicId`. */
export const ofMessage = (requests: readonly ReceivedRequest[], messagePublicId: string) =>
  requests.filter((r) => r.envelope.data.message?.id === messagePublicId);

/** First-attempt requests (one per delivery) of `type`. */
export const ofType = (requests: readonly ReceivedRequest[], type: string) =>
  requests.filter((r) => r.eventType === type);

// --- Subscriptions through the api ---------------------------------------------------------------

export interface CreatedWebhook {
  id: string;
  path: string;
  url: string;
  secret: string;
  rowVersion: number;
  response: ApiResponse;
  idempotencyKey: string;
}

/**
 * Creates a subscription on `https://hooks.receiver.test/<path>` through the api (POST /webhooks
 * with an Idempotency-Key, step 6.2 §6.1) and registers its secret with the receiver.
 */
export async function createWebhook(
  session: ApiSession,
  options: {
    name: string;
    path: string;
    eventTypes: readonly string[];
    filters?: Record<string, unknown>;
  },
): Promise<CreatedWebhook> {
  const key = idempotencyKey();
  const url = `https://${RECEIVER_HOST}/${options.path}`;
  const res = await session.post(
    '/webhooks',
    {
      name: options.name,
      url,
      eventTypes: options.eventTypes,
      ...(options.filters ? { filters: options.filters } : {}),
    },
    key,
  );
  if (res.status !== 201) {
    throw new Error(`POST /webhooks answered ${res.status}: ${JSON.stringify(res.body)}`);
  }
  const body = res.body as { id: string; secret: string; rowVersion: number };
  if (!/^whsec_[A-Za-z0-9_-]{43}$/.test(body.secret ?? '')) {
    throw new Error('POST /webhooks returned no well-formed secret');
  }
  await registerReceiverSecrets(options.path, [body.secret]);
  return {
    id: body.id,
    path: options.path,
    url,
    secret: body.secret,
    rowVersion: body.rowVersion,
    response: res,
    idempotencyKey: key['Idempotency-Key'],
  };
}

/**
 * Re-verifies a received request with `verifyWebhookSignature` (the receiver's clock = the time
 * it recorded the request, so a later check is not `stale`).
 */
export function verifyReceived(
  request: ReceivedRequest,
  secrets: readonly string[],
): WebhookVerificationResult {
  return verifyWebhookSignature({
    header: request.headers['eg-signature'],
    rawBody: request.body,
    secrets,
    now: request.receivedAt,
  });
}

/**
 * The exact header contract of §4.2 for one request of subscription `webhookId`; returns the
 * problems (empty when it holds).
 */
export function headerProblems(request: ReceivedRequest, webhookId: string): string[] {
  const h = request.headers;
  const problems: string[] = [];
  const expect = (name: string, ok: boolean) => {
    if (!ok) problems.push(name);
  };
  expect('method', request.method === 'POST');
  expect('content-type', h['content-type'] === 'application/json');
  expect('user-agent', h['user-agent'] === 'EmailGateway-Webhooks/1');
  expect(
    'eg-signature',
    /^t=\d+,v1=[0-9a-f]{64}(,v1=[0-9a-f]{64})?$/.test(h['eg-signature'] ?? ''),
  );
  expect('eg-event-id', h['eg-event-id'] === request.envelope.id);
  expect('eg-event-type', h['eg-event-type'] === request.envelope.type);
  expect('idempotency-key', h['idempotency-key'] === request.envelope.id);
  expect('eg-subscription-id', h['eg-subscription-id'] === webhookId);
  expect('eg-delivery-id', /^[0-9a-f-]{36}$/.test(h['eg-delivery-id'] ?? ''));
  expect('eg-delivery-attempt', request.attempt >= 1);
  expect('content-length', Number(h['content-length']) === request.body.length);
  expect('no cookie', h.cookie === undefined);
  return problems;
}

/**
 * The no-content assertion (§2.0 invariant 1, §10.4) on the RAW received body: at most 16 KiB,
 * JSON, envelope `organizationId` = the organization's public id, no `@` (the documented
 * `data.message.internetMessageId` is the one field allowed to carry one, §5.1 and WP1
 * deviation 4), no `://`, no `org/` (object key prefix), no signing secret, none of the
 * `forbidden` strings (subjects, local parts, file names, body phrases of the fixtures) anywhere
 * — `internetMessageId` included. Returns the problems (empty when the payload is clean).
 */
export function payloadProblems(
  request: ReceivedRequest,
  organizationPublicId: string,
  forbidden: readonly string[],
): string[] {
  const problems: string[] = [];
  const raw = request.body.toString('utf8');
  if (request.body.length > MAX_PAYLOAD_BYTES) problems.push(`size ${request.body.length}`);
  const env = request.envelope;
  if (env.organizationId !== organizationPublicId) problems.push('organizationId');
  if (env.version !== 1) problems.push('version');
  const message = env.data.message;
  const withoutMessageId = JSON.stringify(
    message
      ? { ...env, data: { ...env.data, message: { ...message, internetMessageId: null } } }
      : env,
  );
  if (withoutMessageId.includes('@')) problems.push(`'@' outside internetMessageId`);
  if (raw.includes('://')) problems.push(`'://'`);
  if (raw.includes('org/')) problems.push(`'org/'`);
  if (raw.includes('whsec_')) problems.push('secret');
  const lower = raw.toLowerCase();
  for (const value of forbidden) {
    if (value && lower.includes(value.toLowerCase())) problems.push(`forbidden '${value}'`);
  }
  return problems;
}

// --- api reads ---------------------------------------------------------------------------------

export interface DeliveryDetail {
  id: string;
  eventId: string;
  eventType: string;
  status: string;
  trigger: string;
  deliverySeq: number;
  attemptCount: number;
  lastResponseCode: number | null;
  attempts: {
    attemptNo: number;
    outcome: string;
    httpStatus: number | null;
    retryAfterSeconds: number | null;
    errorCode: string | null;
    signatureCount: number;
    responseSnippet: string | null;
  }[];
  event: WebhookEnvelope | null;
}

export async function deliveryDetail(
  session: ApiSession,
  webhookId: string,
  deliveryId: string,
): Promise<DeliveryDetail> {
  const res = await session.get(`/webhooks/${webhookId}/deliveries/${deliveryId}`);
  if (res.status !== 200) {
    throw new Error(`GET delivery answered ${res.status}: ${JSON.stringify(res.body)}`);
  }
  return res.body as DeliveryDetail;
}

/** Notification settings of the caller's organization merged with `alerts` (PUT with CAS). */
export async function putAlertSettings(session: ApiSession, alerts: Record<string, unknown>) {
  const current = await session.get('/notifications/settings');
  if (current.status !== 200) {
    throw new Error(`GET /notifications/settings answered ${current.status}`);
  }
  const { rowVersion } = current.body as { rowVersion: number };
  const res = await session.put('/notifications/settings', {
    settings: { alerts },
    expectedRowVersion: rowVersion,
  });
  if (res.status !== 200) {
    throw new Error(
      `PUT /notifications/settings answered ${res.status}: ${JSON.stringify(res.body)}`,
    );
  }
  return res.body;
}

/** Webhook rows of the fixture organizations (for the end-of-suite assertions). */
export async function webhookRowCounts(prisma: PrismaClient, organizationIds: readonly bigint[]) {
  const where = { organizationId: { in: [...organizationIds] } };
  return {
    subscriptions: await prisma.webhookSubscription.count({ where }),
    events: await prisma.webhookEvent.count({ where }),
    deliveries: await prisma.webhookDelivery.count({ where }),
    attempts: await prisma.webhookDeliveryAttempt.count({ where }),
    replays: await prisma.webhookReplay.count({ where }),
    alertWindows: await prisma.notificationAlertWindow.count({ where }),
    settings: await prisma.notificationSettings.count({ where }),
  };
}

// --- Container recreations (notification suite) ---------------------------------------------------

/**
 * SHA-256 fingerprint (`AA:BB:…`, the format of `smtp_tls_fingerprint_cert_match`) of the
 * TEST-ONLY notify-relay-sink certificate in the test-pki volume.
 */
export async function notifyRelaySinkFingerprint(): Promise<string> {
  const pem = await composeExec('notify-relay-sink', ['cat', '/pki/notify-relay-sink/cert.pem'], {
    timeoutMs: 20_000,
  });
  if (pem.exitCode !== 0) throw new Error('cannot read the notify-relay-sink certificate');
  return new X509Certificate(pem.stdout).fingerprint256;
}

/**
 * Recreates postfix-notify with its upstream relay = notify-relay-sink (172.31.250.31:587, the
 * test SASL pair NOTIFY_RELAY_SINK_USER/_PASSWORD, the pinned sink certificate). Compose
 * interpolation: the child environment wins over `.env`, which is never written.
 */
export async function pointPostfixNotifyAtRelaySink(): Promise<void> {
  const user = process.env.NOTIFY_RELAY_SINK_USER;
  const password = process.env.NOTIFY_RELAY_SINK_PASSWORD;
  if (!user || !password) throw new Error('NOTIFY_RELAY_SINK_USER/_PASSWORD missing in .env');
  await composeOk(['up', '-d', '--no-deps', '--force-recreate', '--wait', 'postfix-notify'], {
    timeoutMs: 240_000,
    env: {
      NOTIFY_RELAY_HOST: NOTIFY_RELAY_SINK_ADDRESS,
      NOTIFY_RELAY_PORT: '587',
      NOTIFY_RELAY_USER: user,
      NOTIFY_RELAY_PASSWORD: password,
      NOTIFY_RELAY_TLS_FINGERPRINT: await notifyRelaySinkFingerprint(),
    },
  });
}

/** Recreates postfix-notify from `.env` again (the developer's own relay settings). */
export async function restorePostfixNotify(): Promise<void> {
  await composeOk(['up', '-d', '--no-deps', '--force-recreate', '--wait', 'postfix-notify'], {
    timeoutMs: 240_000,
  });
}

/** The relay settings postfix-notify runs with now (`relayhost`), no secret. */
export async function postfixNotifyRelayhost(): Promise<string> {
  const res = await composeExec('postfix-notify', ['postconf', '-h', 'relayhost'], {
    timeoutMs: 20_000,
  });
  return res.stdout.trim();
}

/** Queue ids in postfix-notify (empty when the queue is empty). */
export async function postfixNotifyQueue(): Promise<string[]> {
  const res = await composeExec('postfix-notify', ['postqueue', '-j'], { timeoutMs: 20_000 });
  return res.stdout
    .split('\n')
    .filter((l) => l.trim().startsWith('{'))
    .map((l) => (JSON.parse(l) as { queue_id: string }).queue_id);
}

/** Recreates the webhook-worker with Compose overrides (shell environment over `.env`). */
export async function recreateWebhookWorker(overrides: Record<string, string> = {}) {
  await composeOk(['up', '-d', '--no-deps', '--force-recreate', '--wait', 'webhook-worker'], {
    timeoutMs: 240_000,
    env: overrides,
  });
}

/** The webhook-worker's effective value of `key` inside the container. */
export async function webhookWorkerEnv(key: string): Promise<string> {
  const res = await compose(['exec', '-T', 'webhook-worker', 'printenv', key], {
    timeoutMs: 20_000,
  });
  return res.stdout.trim();
}

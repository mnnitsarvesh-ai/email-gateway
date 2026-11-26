/**
 * Simulator registry, in-process start helper and the standalone entry (design note D12).
 *
 * Standalone (`node dist/testing/simulators/main.js`, Compose service `idp-simulator`): every
 * registered simulator on `IDP_SIM_PORT` (8080) under its prefix (`/graph`, `/o365`,
 * `/google-admin`, `/gmail`), `/health`, and an admin API on
 * `IDP_SIM_ADMIN_PORT` (8081; published only on 127.0.0.1) to load a dataset, script failures,
 * revoke permissions, set licences and read the call log. Step API-1 (D13) adds mailboxes:
 * `POST /admin/mailboxes/{user}/messages` (deliver a synthetic EML; Graph change notifications are
 * pushed to active subscriptions), `DELETE /admin/mailboxes/{user}/messages/{id}`,
 * `POST /admin/mailboxes/{user}/expire-cursors`, `GET /admin/subscriptions`,
 * `POST /admin/subscriptions/{id}/lifecycle`, `GET /admin/notifications`, `family` on
 * `/admin/inject` and filters on `/admin/calls`. Tokens: any non-empty bearer token
 * (tokens come from 8.2's provider-fake in the stack); permissions per directory via the admin API.
 */
import { readFileSync } from 'node:fs';
import { GOOGLE_SIMULATORS } from './google';
import { createGraphSimulator } from './graph';
import { createO365Simulator } from './o365';
import {
  deliverMessage,
  expireCursors,
  LIFECYCLE_EVENTS,
  pushLifecycle,
  removeMessage,
  SimMailboxNotFoundError,
  type DeliverMessageInput,
  type DeliverMessageResult,
  type LifecycleEvent,
} from './mail';
import { SimScript, type SimInjection } from './script';
import {
  json,
  SimulatorServer,
  type SimRequest,
  type SimResponse,
  type SimulatorFactory,
} from './server';
import { SimTokenRegistry } from './tokens';
import type { SimDataset, SimLicense } from './types';

/** Every simulator (Graph, Office 365 Management, Google Admin SDK and Gmail settings). */
export const ALL_SIMULATORS: readonly SimulatorFactory[] = [
  createGraphSimulator,
  createO365Simulator,
  ...GOOGLE_SIMULATORS,
];

/** Directory used for permissive (stack) tokens: the first Microsoft tenant or Google customer. */
function defaultDirectoryOf(dataset: SimDataset): string | undefined {
  return dataset.microsoft?.directories[0]?.tenantId ?? dataset.google?.customers[0]?.customerId;
}

export interface RunningSimulators {
  server: SimulatorServer;
  script: SimScript;
  tokens: SimTokenRegistry;
  /** Base URL per mounted prefix (`graph` → `http://127.0.0.1:<port>/graph`). */
  baseUrl(name: string): string;
  /** Step API-1: delivers a synthetic EML into a simulated mailbox (`deliverMessage`). */
  deliver(input: DeliverMessageInput): Promise<DeliverMessageResult>;
  stop(): Promise<void>;
}

/** Starts the simulators in-process on 127.0.0.1:0. */
export async function startSimulators(options: {
  dataset: SimDataset;
  tokens?: SimTokenRegistry;
  now?: () => number;
  factories?: readonly SimulatorFactory[];
}): Promise<RunningSimulators> {
  const tokens = options.tokens ?? new SimTokenRegistry({ now: options.now });
  const script = new SimScript(options.dataset, tokens, options.now ?? Date.now);
  const simulators = (options.factories ?? ALL_SIMULATORS).map((factory) => factory(script));
  const server = new SimulatorServer(simulators, script);
  await server.start();
  return {
    server,
    script,
    tokens,
    baseUrl: (name) => {
      const simulator = simulators.find((s) => s.name === name);
      if (!simulator) throw new Error(`simulator_not_registered: ${name}`);
      return server.url(simulator.prefix);
    },
    deliver: (input) => deliverMessage(script, input),
    stop: () => server.stop(),
  };
}

/**
 * Simulator and path prefix of an API family for scripted failures (step API-1 D13): `graph`,
 * `gmail`, `google_directory` (Admin SDK Directory), `google_reports`, `o365`.
 */
const FAMILY_TARGETS: Readonly<Record<string, { simulator: string; path: string }>> = {
  graph: { simulator: 'graph', path: '/' },
  o365: { simulator: 'o365', path: '/' },
  gmail: { simulator: 'gmail', path: '/' },
  google_directory: { simulator: 'google-admin', path: '/admin/directory/' },
  google_reports: { simulator: 'google-admin', path: '/admin/reports/' },
};

/** Step API-1 admin routes: mailboxes, subscriptions and notifications (D13). */
async function mailAdmin(
  script: SimScript,
  request: SimRequest,
  body: Record<string, unknown>,
): Promise<SimResponse | null> {
  const p = request.path;
  const m = request.method;
  let match: RegExpExecArray | null;
  if ((match = /^\/admin\/mailboxes\/([^/]+)\/messages$/.exec(p)) && m === 'POST') {
    const eml =
      typeof body.eml === 'string'
        ? body.eml
        : typeof body.emlBase64 === 'string'
          ? Buffer.from(body.emlBase64, 'base64')
          : null;
    if (eml === null) return json(400, { error: 'eml or emlBase64 required' });
    try {
      const result = await deliverMessage(script, {
        user: decodeURIComponent(match[1] as string),
        eml,
        ...(typeof body.receivedAt === 'string' ? { receivedAt: body.receivedAt } : {}),
        ...(Array.isArray(body.labelIds)
          ? { labelIds: body.labelIds.filter((l): l is string => typeof l === 'string') }
          : {}),
        ...(body.isDraft === true ? { isDraft: true } : {}),
      });
      return json(201, result);
    } catch (error) {
      if (error instanceof SimMailboxNotFoundError)
        return json(404, { error: 'mailbox not found' });
      throw error;
    }
  }
  if ((match = /^\/admin\/mailboxes\/([^/]+)\/messages\/([^/]+)$/.exec(p)) && m === 'DELETE') {
    const removed = removeMessage(
      script,
      decodeURIComponent(match[1] as string),
      decodeURIComponent(match[2] as string),
    );
    return json(removed ? 204 : 404);
  }
  if ((match = /^\/admin\/mailboxes\/([^/]+)\/expire-cursors$/.exec(p)) && m === 'POST') {
    return json(expireCursors(script, decodeURIComponent(match[1] as string)) ? 204 : 404);
  }
  if (p === '/admin/subscriptions' && m === 'GET') {
    const subscriptions = (script.dataset.microsoft?.directories ?? []).flatMap((d) =>
      (d.subscriptions ?? []).map((s) => ({
        id: s.id,
        directoryId: d.tenantId,
        userId: s.userId,
        resource: s.resource,
        changeType: s.changeType,
        notificationUrl: s.notificationUrl,
        lifecycleNotificationUrl: s.lifecycleNotificationUrl,
        expirationDateTime: s.expirationDateTime,
        // The client state itself is never echoed by the admin API.
        hasClientState: s.clientState !== null,
      })),
    );
    return json(200, { subscriptions });
  }
  if ((match = /^\/admin\/subscriptions\/([^/]+)\/lifecycle$/.exec(p)) && m === 'POST') {
    const event = body.event;
    if (typeof event !== 'string' || !(LIFECYCLE_EVENTS as readonly string[]).includes(event)) {
      return json(400, { error: `event must be one of ${LIFECYCLE_EVENTS.join(', ')}` });
    }
    const notification = await pushLifecycle(
      script,
      decodeURIComponent(match[1] as string),
      event as LifecycleEvent,
    );
    return notification ? json(200, notification) : json(404, { error: 'subscription not found' });
  }
  if (p === '/admin/notifications' && m === 'GET') {
    return json(200, { notifications: script.notifications });
  }
  return null;
}

function adminApi(script: SimScript, tokens: SimTokenRegistry) {
  return async (request: SimRequest): Promise<SimResponse | null> => {
    if (!request.path.startsWith('/admin/')) return null;
    const body = (request.body ?? {}) as Record<string, unknown>;
    const mail = await mailAdmin(script, request, body);
    if (mail) return mail;
    const route = `${request.method} ${request.path}`;
    switch (route) {
      case 'POST /admin/dataset': {
        script.reset(body);
        const first = defaultDirectoryOf(body);
        if (first) tokens.setDefaultDirectory(first);
        return json(204);
      }
      case 'POST /admin/reset':
        script.reset({});
        tokens.reset();
        return json(204);
      case 'POST /admin/inject': {
        // `family` (step API-1) selects the simulator and a default path prefix of an API family.
        const family =
          typeof body.family === 'string' ? (FAMILY_TARGETS[body.family] ?? null) : undefined;
        if (family === null) return json(400, { error: 'unknown family' });
        const path = typeof body.path === 'string' ? body.path : (family?.path ?? null);
        const status = typeof body.status === 'number' ? body.status : null;
        if (path === null || status === null)
          return json(400, { error: 'path and status required' });
        const injection: SimInjection = { path, status };
        if (family) injection.simulator = family.simulator;
        if (typeof body.simulator === 'string') injection.simulator = body.simulator;
        if (typeof body.method === 'string') injection.method = body.method;
        if (typeof body.retryAfter === 'string') injection.retryAfter = body.retryAfter;
        if (typeof body.code === 'string') injection.code = body.code;
        if (typeof body.reason === 'string') injection.reason = body.reason;
        if (typeof body.times === 'number') injection.times = body.times;
        script.inject(injection);
        return json(204);
      }
      case 'POST /admin/delay-read-back':
        script.delayReadBack(typeof body.reads === 'number' ? body.reads : 1);
        return json(204);
      case 'POST /admin/permissions': {
        if (typeof body.directoryId !== 'string' || !Array.isArray(body.permissions)) {
          return json(400, { error: 'directoryId and permissions required' });
        }
        tokens.setDirectoryPermissions(
          body.directoryId,
          body.permissions.filter((p): p is string => typeof p === 'string'),
        );
        return json(204);
      }
      case 'POST /admin/revoke-permission':
        if (typeof body.name !== 'string') return json(400, { error: 'name required' });
        script.revokePermission(
          body.name,
          typeof body.directoryId === 'string' ? body.directoryId : undefined,
        );
        return json(204);
      case 'POST /admin/license':
        if (
          typeof body.directoryId !== 'string' ||
          typeof body.license !== 'string' ||
          typeof body.value !== 'boolean'
        ) {
          return json(400, { error: 'directoryId, license and value required' });
        }
        try {
          script.setLicense(body.directoryId, body.license as SimLicense, body.value);
        } catch {
          return json(404, { error: 'directory not found' });
        }
        return json(204);
      case 'GET /admin/calls': {
        const simulator = request.query.get('simulator');
        const path = request.query.get('path');
        const method = request.query.get('method');
        return json(200, {
          calls: script.calls({
            ...(simulator ? { simulator } : {}),
            ...(path ? { path } : {}),
            ...(method ? { method } : {}),
          }),
        });
      }
      default:
        return json(404, { error: 'unknown admin route' });
    }
  };
}

/** Standalone entry: data server and admin server. */
export async function runStandalone(
  env: NodeJS.ProcessEnv,
): Promise<{ dataPort: number; adminPort: number; stop(): Promise<void> }> {
  const tokens = new SimTokenRegistry({ permissive: true });
  let dataset: SimDataset = {};
  if (env.IDP_SIM_DATASET_FILE) {
    dataset = JSON.parse(readFileSync(env.IDP_SIM_DATASET_FILE, 'utf8')) as SimDataset;
    const first = defaultDirectoryOf(dataset);
    if (first) tokens.setDefaultDirectory(first);
  }
  const script = new SimScript(dataset, tokens);
  const simulators = ALL_SIMULATORS.map((factory) => factory(script));
  const host = env.IDP_SIM_HOST ?? '0.0.0.0';
  const data = new SimulatorServer(simulators, script, {
    host,
    port: Number(env.IDP_SIM_PORT ?? 8080),
  });
  const admin = new SimulatorServer([], script, {
    host,
    port: Number(env.IDP_SIM_ADMIN_PORT ?? 8081),
    admin: adminApi(script, tokens),
  });
  const dataPort = await data.start();
  const adminPort = await admin.start();
  if (env.IDP_SIM_QUIET !== 'true') {
    process.stdout.write(`idp-simulator listening on ${dataPort} (admin ${adminPort})\n`);
  }
  return {
    dataPort,
    adminPort,
    stop: async () => {
      await data.stop();
      await admin.stop();
    },
  };
}

if (require.main === module) {
  runStandalone(process.env).then(
    (running) => {
      const shutdown = () => {
        void running.stop().then(() => process.exit(0));
      };
      process.on('SIGTERM', shutdown);
      process.on('SIGINT', shutdown);
    },
    (error: unknown) => {
      process.stderr.write(
        `idp-simulator failed to start: ${error instanceof Error ? error.message : 'unknown'}\n`,
      );
      process.exit(1);
    },
  );
}

/**
 * Simulator registry, in-process start helper and the standalone entry (design note D12).
 *
 * Standalone (`node dist/testing/simulators/main.js`, Compose service `idp-simulator`): every
 * registered simulator on `IDP_SIM_PORT` (8080) under its prefix (`/graph`, `/o365`,
 * `/google-admin`, `/gmail`), `/health`, and an admin API on
 * `IDP_SIM_ADMIN_PORT` (8081; published only on 127.0.0.1) to load a dataset, script failures,
 * revoke permissions, set licences and read the call log. Tokens: any non-empty bearer token
 * (tokens come from 8.2's provider-fake in the stack); permissions per directory via the admin API.
 */
import { readFileSync } from 'node:fs';
import { GOOGLE_SIMULATORS } from './google';
import { createGraphSimulator } from './graph';
import { createO365Simulator } from './o365';
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
    stop: () => server.stop(),
  };
}

function adminApi(script: SimScript, tokens: SimTokenRegistry) {
  return (request: SimRequest): SimResponse | null => {
    if (!request.path.startsWith('/admin/')) return null;
    const body = (request.body ?? {}) as Record<string, unknown>;
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
        const path = typeof body.path === 'string' ? body.path : null;
        const status = typeof body.status === 'number' ? body.status : null;
        if (path === null || status === null)
          return json(400, { error: 'path and status required' });
        const injection: SimInjection = { path, status };
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
      case 'GET /admin/calls':
        return json(200, { calls: script.calls() });
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

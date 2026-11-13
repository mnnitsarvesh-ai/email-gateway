import 'server-only';
import { matchOperation, splitRawPath } from '@/lib/api/operations';
import type { UpstreamFetch } from '@/server/upstream';
import { fixtures as attachments } from './fixtures/attachments';
import { fixtures as audit } from './fixtures/audit';
import { fixtures as billing } from './fixtures/billing';
import { fixtures as dashboard } from './fixtures/dashboard';
import { fixtures as domains } from './fixtures/domains';
import { fixtures as integrations } from './fixtures/integrations';
import { fixtures as mailServers } from './fixtures/mail-servers';
import { fixtures as messages } from './fixtures/messages';
import { fixtures as organizations } from './fixtures/organizations';
import { fixtures as policies } from './fixtures/policies';
import { fixtures as quarantine } from './fixtures/quarantine';
import { fixtures as reports } from './fixtures/reports';
import { fixtures as roles } from './fixtures/roles';
import { fixtures as session } from './fixtures/session';
import { fixtures as settings } from './fixtures/settings';
import { fixtures as threatIntel } from './fixtures/threat-intel';
import { fixtures as urlProtection } from './fixtures/url-protection';
import { fixtures as users } from './fixtures/users';
import {
  DEV_MOCK_MARKER,
  apiError,
  type FixtureHandler,
  type FixtureHandlers,
  type FixtureResponse,
} from './types';

export { DEV_MOCK_MARKER };
export type { FixtureHandler, FixtureHandlers };

/**
 * Dev fixture mode (design P9): a `fetch` replacement for the BFF's upstream calls that answers
 * from typed fixture handlers keyed by OperationId. Loaded only through the guarded dynamic
 * import in `src/server/bff/deps.ts`; never part of a production build (asserted after build).
 *
 * Order matters: the session fixtures come first, so a feature package may replace one of them
 * (e.g. `OrganizationsController_list_v1`) in its own file.
 */
export const FEATURE_FIXTURES: Readonly<Record<string, FixtureHandlers>> = {
  session,
  dashboard,
  reports,
  billing,
  audit,
  organizations,
  settings,
  'threat-intel': threatIntel,
  'url-protection': urlProtection,
  attachments,
  domains,
  'mail-servers': mailServers,
  users,
  roles,
  integrations,
  messages,
  quarantine,
  policies,
};

export function mergedFixtures(): FixtureHandlers {
  return Object.assign({}, ...Object.values(FEATURE_FIXTURES)) as FixtureHandlers;
}

function toResponse(result: FixtureResponse, correlationId: string): Response {
  const headers = new Headers({
    'x-request-id': crypto.randomUUID(),
    'x-correlation-id': correlationId,
    ...(result.headers ?? {}),
  });
  if (result.body === undefined || result.status === 204) {
    return new Response(null, { status: result.status, headers });
  }
  headers.set('content-type', headers.get('content-type') ?? 'application/json');
  const payload = typeof result.body === 'string' ? result.body : JSON.stringify(result.body);
  return new Response(payload, { status: result.status, headers });
}

async function readBody(init: RequestInit): Promise<unknown> {
  if (init.body === null || init.body === undefined) return null;
  const text = typeof init.body === 'string' ? init.body : await new Response(init.body).text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

export function createMockFetch(handlers: FixtureHandlers = mergedFixtures()): UpstreamFetch {
  return async (url, init) => {
    const target = new URL(url);
    const headers = new Headers(init.headers);
    const correlationId = headers.get('x-correlation-id') ?? crypto.randomUUID();
    const method = (init.method ?? 'GET').toUpperCase();

    if (target.pathname === '/health/ready') {
      return toResponse(
        {
          status: 200,
          body: {
            service: 'api',
            status: 'ok',
            version: '0.0.0-dev-fixtures',
            uptimeSeconds: 1,
            checks: [
              { name: 'mysql', status: 'ok', latencyMs: 3 },
              { name: 'redis', status: 'ok', latencyMs: 1 },
              { name: 'rabbitmq', status: 'ok', latencyMs: 4 },
            ],
          },
        },
        correlationId,
      );
    }

    const prefix = '/api/v1/';
    const segments = target.pathname.startsWith(prefix)
      ? splitRawPath(target.pathname.slice(prefix.length))
      : null;
    const match = segments ? matchOperation(method, segments) : null;
    if (!match)
      return toResponse(apiError(404, 'route_not_found', 'Route not found'), correlationId);

    const handler = handlers[match.operationId];
    if (!handler) {
      return toResponse(
        apiError(501, 'mock_not_implemented', `No dev fixture for ${match.operationId}`),
        correlationId,
      );
    }
    const authorization = headers.get('authorization');
    const result = await handler({
      operationId: match.operationId,
      method,
      params: match.params,
      query: target.searchParams,
      body: await readBody(init),
      token: authorization?.startsWith('Bearer ') ? authorization.slice('Bearer '.length) : null,
      headers,
    });
    return toResponse(result, correlationId);
  };
}

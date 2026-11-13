import { http, HttpResponse, type JsonBodyType } from 'msw';
import { setupServer } from 'msw/node';
import { operations } from '@/lib/api/operations.gen';
import type { OperationId } from '@/lib/api/types';

/** The MSW server of the test kit (node mode). Unhandled requests fail the test. */
export const server = setupServer();

export const TEST_ORIGIN = 'http://localhost:3000';

export interface MockRequestContext {
  readonly request: Request;
  readonly params: Readonly<Record<string, string>>;
  readonly url: URL;
  /** Parsed JSON body (`null` when none). */
  readonly body: unknown;
}

export type MockHandler = (context: MockRequestContext) => Response | Promise<Response>;

/** `/api/v1/domains/{id}` → MSW path `/bff/api/v1/domains/:id`. */
export function mswPathFor(operationId: OperationId): string {
  return `${TEST_ORIGIN}/bff${operations[operationId].path.replace(/\{([^}]+)\}/g, ':$1')}`;
}

/**
 * Registers handlers keyed by OperationId; requests from the typed client go to
 * `/bff/api/v1/...` and are resolved through operations.gen.ts.
 */
export function mockApi(handlers: Partial<Record<OperationId, MockHandler>>): void {
  server.use(
    ...Object.entries(handlers).map(([operationId, handler]) => {
      const op = operations[operationId as OperationId];
      if (!op)
        throw new Error(`mockApi: unknown operationId ${operationId} (not in operations.gen.ts)`);
      const method = op.method.toLowerCase() as 'get' | 'post' | 'put' | 'patch' | 'delete';
      return http[method](mswPathFor(operationId as OperationId), async ({ request, params }) => {
        const text = await request.clone().text();
        let body: unknown = null;
        if (text) {
          try {
            body = JSON.parse(text) as unknown;
          } catch {
            body = text;
          }
        }
        return handler({
          request,
          params: params as Record<string, string>,
          url: new URL(request.url),
          body,
        });
      });
    }),
  );
}

/** Registers raw handlers for BFF session routes (`/bff/session/...`). */
export function mockBff(
  method: 'get' | 'post' | 'delete',
  path: string,
  handler: (context: { request: Request; body: unknown }) => Response | Promise<Response>,
): void {
  server.use(
    http[method](`${TEST_ORIGIN}${path}`, async ({ request }) => {
      const text = await request.clone().text();
      return handler({ request, body: text ? (JSON.parse(text) as unknown) : null });
    }),
  );
}

export function okJson(
  body: JsonBodyType,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return HttpResponse.json(body, {
    status,
    headers: { 'x-request-id': 'req-test-0001', ...headers },
  });
}

export function noContentResponse(headers: Record<string, string> = {}): Response {
  return new HttpResponse(null, {
    status: 204,
    headers: { 'x-request-id': 'req-test-0001', ...headers },
  });
}

/** An error in the api envelope. */
export function apiErrorJson(
  status: number,
  code: string,
  message: string | string[] = code,
  options: {
    requestId?: string;
    headers?: Record<string, string>;
    extra?: Record<string, unknown>;
  } = {},
): Response {
  const requestId = options.requestId ?? 'req-test-err-0001';
  return HttpResponse.json(
    {
      statusCode: status,
      error: code.toUpperCase(),
      code,
      message,
      requestId,
      ...(options.extra ?? {}),
    },
    { status, headers: { 'x-request-id': requestId, ...(options.headers ?? {}) } },
  );
}

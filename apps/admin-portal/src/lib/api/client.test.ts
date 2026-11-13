import { http, HttpResponse } from 'msw';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { onSessionEvent } from '@/lib/session/events';
import { resetRefreshCoordinatorForTests } from '@/lib/session/refresh';
import { TEST_ORIGIN, apiErrorJson, mockApi, okJson, server } from '@/test';
import { callOperation, callOperationRaw } from './call';
import { api } from './client';
import { ApiError, mapValidationErrors, parseRetryAfter, toApiError } from './errors';

afterEach(() => resetRefreshCoordinatorForTests());

function setCsrf(value: string) {
  document.cookie = `eg_csrf=${value}; path=/`;
}

describe('typed client (design P7)', () => {
  it('calls /bff/api/v1/... with typed params and comma-joined arrays', async () => {
    let url = '';
    mockApi({
      DomainsController_list_v1: ({ url: u }) => {
        url = u.pathname + u.search;
        return okJson({ data: [], nextCursor: null });
      },
    });
    const { data } = await api.GET('/api/v1/domains', {
      params: { query: { status: 'active', limit: 10 } },
    });
    expect(data).toEqual({ data: [], nextCursor: null });
    expect(url).toBe('/bff/api/v1/domains?status=active&limit=10');
  });

  it('adds X-CSRF-Token on mutations only, from the eg_csrf cookie', async () => {
    setCsrf('csrf-123');
    const seen: Record<string, string | null> = {};
    mockApi({
      DomainsController_list_v1: ({ request }) => {
        seen.get = request.headers.get('x-csrf-token');
        return okJson({ data: [], nextCursor: null });
      },
      DomainsController_create_v1: ({ request }) => {
        seen.post = request.headers.get('x-csrf-token');
        return okJson({}, 201);
      },
    });
    await callOperation('DomainsController_list_v1');
    await callOperation('DomainsController_create_v1', { body: { name: 'a.example.test' } });
    expect(seen).toEqual({ get: null, post: 'csrf-123' });
  });

  it('sends Idempotency-Key only for operations with x-eg-idempotency', async () => {
    const keys: (string | null)[] = [];
    mockApi({
      MessageLifecycleController_rescan_v1: ({ request }) => {
        keys.push(request.headers.get('idempotency-key'));
        return okJson({}, 202);
      },
      DomainsController_create_v1: ({ request }) => {
        keys.push(request.headers.get('idempotency-key'));
        return okJson({}, 201);
      },
    });
    await callOperation(
      'MessageLifecycleController_rescan_v1',
      { path: { messageId: '01930000-0000-7000-8000-000000000001' }, body: {} as never },
      { idempotencyKey: 'intent-1' },
    );
    await callOperation('MessageLifecycleController_rescan_v1', {
      path: { messageId: '01930000-0000-7000-8000-000000000001' },
      body: {} as never,
    });
    await callOperation(
      'DomainsController_create_v1',
      { body: { name: 'a.example.test' } },
      { idempotencyKey: 'ignored' },
    );
    expect(keys[0]).toBe('intent-1');
    expect(keys[1]).toMatch(/^[0-9a-f-]{36}$/);
    expect(keys[2]).toBeNull();
  });

  it('normalizes errors into ApiError', async () => {
    mockApi({
      DomainsController_list_v1: () =>
        apiErrorJson(429, 'rate_limited', 'Too many requests', {
          requestId: 'rq-9',
          headers: { 'retry-after': '17' },
          extra: { scope: 'tenant' },
        }),
    });
    const error = await callOperation('DomainsController_list_v1').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      status: 429,
      code: 'rate_limited',
      apiMessage: 'Too many requests',
      requestId: 'rq-9',
      retryAfterSeconds: 17,
      details: { scope: 'tenant' },
      operationId: 'DomainsController_list_v1',
    });
  });

  it('turns network failures into network_error (status 0)', async () => {
    server.use(http.get(`${TEST_ORIGIN}/bff/api/v1/domains`, () => HttpResponse.error()));
    await expect(callOperation('DomainsController_list_v1')).rejects.toMatchObject({
      status: 0,
      code: 'network_error',
    });
  });

  it('refreshes once and retries once on 401 access_token_expired', async () => {
    setCsrf('before');
    let refreshes = 0;
    let calls = 0;
    const csrfSeen: (string | null)[] = [];
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/refresh`, () => {
        refreshes += 1;
        document.cookie = 'eg_csrf=after; path=/';
        return HttpResponse.json({
          authenticated: true,
          accessExpiresAt: null,
          refreshExpiresAt: null,
          mfaEnrollmentRequired: false,
          override: null,
          devFixtures: false,
        });
      }),
    );
    mockApi({
      DomainsController_create_v1: ({ request }) => {
        calls += 1;
        csrfSeen.push(request.headers.get('x-csrf-token'));
        return calls === 1 ? apiErrorJson(401, 'access_token_expired') : okJson({ id: 'd1' }, 201);
      },
    });
    const result = await callOperationRaw('DomainsController_create_v1', {
      body: { name: 'a.example.test' },
    });
    expect(result.data).toEqual({ id: 'd1' });
    expect(refreshes).toBe(1);
    expect(calls).toBe(2);
    expect(csrfSeen).toEqual(['before', 'after']);
  });

  it('does not loop: a second 401 after the refresh is returned', async () => {
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/refresh`, () =>
        HttpResponse.json({ authenticated: true }),
      ),
    );
    let calls = 0;
    mockApi({
      DomainsController_list_v1: () => {
        calls += 1;
        return apiErrorJson(401, 'unauthorized');
      },
    });
    await expect(callOperation('DomainsController_list_v1')).rejects.toMatchObject({ status: 401 });
    expect(calls).toBe(2);
  });

  it('runs a single refresh for 5 concurrent 401s', async () => {
    let refreshes = 0;
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/refresh`, async () => {
        refreshes += 1;
        await new Promise((r) => setTimeout(r, 20));
        return HttpResponse.json({ authenticated: true });
      }),
    );
    const seen = new Map<string, number>();
    mockApi({
      DomainsController_get_v1: ({ params }) => {
        const n = (seen.get(params.id ?? '') ?? 0) + 1;
        seen.set(params.id ?? '', n);
        return n === 1
          ? apiErrorJson(401, 'access_token_expired')
          : okJson({ id: params.id ?? '' });
      },
    });
    const ids = ['1', '2', '3', '4', '5'];
    const results = await Promise.all(
      ids.map((id) => callOperation('DomainsController_get_v1', { path: { id } })),
    );
    expect(results.map((r) => (r as { id: string }).id)).toEqual(ids);
    expect(refreshes).toBe(1);
  });

  it('emits session-expired when the refresh fails and does not retry', async () => {
    const events: string[] = [];
    const off = onSessionEvent((e) => events.push(e.type));
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/refresh`, () =>
        HttpResponse.json(
          { statusCode: 401, code: 'session_expired', message: 'x' },
          { status: 401 },
        ),
      ),
    );
    mockApi({ DomainsController_list_v1: () => apiErrorJson(401, 'access_token_expired') });
    await expect(callOperation('DomainsController_list_v1')).rejects.toMatchObject({ status: 401 });
    expect(events).toContain('session-expired');
    off();
  });

  it('forces the refresh after an api 401 unauthorized, so a revoked session ends (session-expired)', async () => {
    const events: string[] = [];
    const off = onSessionEvent((e) => events.push(e.type));
    const bodies: unknown[] = [];
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/refresh`, async ({ request }) => {
        const body = (await request.json()) as { force?: boolean };
        bodies.push(body);
        // The BFF's "fresh enough" short-circuit answers 200 unless forced; forced, the api
        // refuses the revoked session's refresh token.
        return body.force
          ? HttpResponse.json(
              { statusCode: 401, code: 'session_expired', message: 'x' },
              { status: 401 },
            )
          : HttpResponse.json({ authenticated: true });
      }),
    );
    let calls = 0;
    mockApi({
      DomainsController_list_v1: () => {
        calls += 1;
        return apiErrorJson(401, 'unauthorized');
      },
    });
    await expect(callOperation('DomainsController_list_v1')).rejects.toMatchObject({ status: 401 });
    expect(bodies).toEqual([{ force: true }]);
    expect(calls).toBe(1);
    expect(events).toContain('session-expired');
    off();
  });

  it('does not force the refresh after the BFF-coded access_token_expired', async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/refresh`, async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({ authenticated: true });
      }),
    );
    let calls = 0;
    mockApi({
      DomainsController_list_v1: () => {
        calls += 1;
        return calls === 1
          ? apiErrorJson(401, 'access_token_expired')
          : okJson({ data: [], nextCursor: null });
      },
    });
    await callOperation('DomainsController_list_v1');
    expect(bodies).toEqual([{}]);
  });

  it('emits override-expired without refreshing', async () => {
    const events: string[] = [];
    const off = onSessionEvent((e) => events.push(e.type));
    const refresh = vi.fn(() => HttpResponse.json({}));
    server.use(http.post(`${TEST_ORIGIN}/bff/session/refresh`, refresh));
    mockApi({ DomainsController_list_v1: () => apiErrorJson(401, 'override_expired') });
    await expect(callOperation('DomainsController_list_v1')).rejects.toMatchObject({
      code: 'override_expired',
    });
    expect(events).toEqual(['override-expired']);
    expect(refresh).not.toHaveBeenCalled();
    off();
  });
});

describe('error helpers', () => {
  it('maps validation messages to fields and keeps the rest at form level', () => {
    const error = toApiError(new Response(null, { status: 400 }), {
      statusCode: 400,
      code: 'validation_failed',
      message: ['name: Required', 'settings.mode: Invalid enum value', 'colour: Unrecognized key'],
    });
    expect(mapValidationErrors(error, ['name', 'settings'])).toEqual({
      fieldErrors: { name: 'Required', settings: 'Invalid enum value' },
      formErrors: ['colour: Unrecognized key'],
    });
  });

  it('parses Retry-After seconds and dates', () => {
    expect(parseRetryAfter('5')).toBe(5);
    expect(parseRetryAfter(null)).toBeNull();
    expect(parseRetryAfter(new Date(Date.now() + 3000).toUTCString())).toBeGreaterThanOrEqual(2);
  });

  it('falls back to default codes and headers', () => {
    const error = toApiError(
      new Response(null, { status: 503, headers: { 'x-request-id': 'h-1' } }),
      null,
    );
    expect(error).toMatchObject({ code: 'service_unavailable', requestId: 'h-1' });
  });
});

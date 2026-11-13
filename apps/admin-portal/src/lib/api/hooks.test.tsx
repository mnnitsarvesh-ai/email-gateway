import { QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { toast } from 'sonner';
import { describe, expect, it, vi } from 'vitest';
import { onSessionEvent } from '@/lib/session/events';
import { apiErrorJson, createTestQueryClient, mockApi, okJson } from '@/test';
import { useApiMutation, useApiQuery, useCursorList } from './hooks';

function wrapper() {
  const client = createTestQueryClient();
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
}

const MSG = '01930000-0000-7000-8000-000000000001';
const rescanInput = { path: { messageId: MSG }, body: {} } as never;

describe('useApiMutation (design P8)', () => {
  it('uses one Idempotency-Key per intent and reuses it on retry', async () => {
    const keys: (string | null)[] = [];
    let n = 0;
    mockApi({
      MessageLifecycleController_rescan_v1: ({ request }) => {
        keys.push(request.headers.get('idempotency-key'));
        n += 1;
        return n === 1 ? apiErrorJson(503, 'service_unavailable') : okJson({ messageId: MSG }, 202);
      },
    });
    const { result } = renderHook(() => useApiMutation('MessageLifecycleController_rescan_v1'), {
      wrapper: wrapper(),
    });
    let outcome = await act(() => result.current.submit(rescanInput));
    expect(outcome.ok).toBe(false);
    outcome = await act(() => result.current.retry());
    expect(outcome.ok).toBe(true);
    await act(() => result.current.submit(rescanInput));
    expect(keys[0]).toBeTruthy();
    expect(keys[1]).toBe(keys[0]);
    expect(keys[2]).not.toBe(keys[0]);
  });

  it('waits Retry-After on 409 idempotency_request_in_progress and retries with the same key (twice at most)', async () => {
    const keys: (string | null)[] = [];
    mockApi({
      MessageLifecycleController_rescan_v1: ({ request }) => {
        keys.push(request.headers.get('idempotency-key'));
        return keys.length < 3
          ? apiErrorJson(409, 'idempotency_request_in_progress', 'busy', {
              headers: { 'retry-after': '3' },
            })
          : okJson({ messageId: MSG }, 202);
      },
    });
    const sleep = vi.fn(() => Promise.resolve());
    const { result } = renderHook(
      () => useApiMutation('MessageLifecycleController_rescan_v1', { sleep }),
      { wrapper: wrapper() },
    );
    const outcome = await act(() => result.current.submit(rescanInput));
    expect(outcome.ok).toBe(true);
    expect(sleep).toHaveBeenCalledWith(3000);
    expect(new Set(keys).size).toBe(1);
    expect(keys).toHaveLength(3);
  });

  it('gives up after two in-progress retries', async () => {
    let calls = 0;
    mockApi({
      MessageLifecycleController_rescan_v1: () => {
        calls += 1;
        return apiErrorJson(409, 'idempotency_request_in_progress', 'busy', {
          headers: { 'retry-after': '60' },
        });
      },
    });
    const sleep = vi.fn(() => Promise.resolve());
    const { result } = renderHook(
      () => useApiMutation('MessageLifecycleController_rescan_v1', { sleep }),
      { wrapper: wrapper() },
    );
    const outcome = await act(() => result.current.submit(rescanInput));
    expect(outcome.ok).toBe(false);
    expect(calls).toBe(3);
    expect(sleep).toHaveBeenCalledWith(10_000);
  });

  it('treats Idempotency-Replayed as success with "Already applied"', async () => {
    const success = vi.spyOn(toast, 'success');
    mockApi({
      MessageLifecycleController_rescan_v1: () =>
        okJson({ messageId: MSG }, 202, { 'idempotency-replayed': 'true' }),
    });
    const onSuccess = vi.fn();
    const { result } = renderHook(
      () => useApiMutation('MessageLifecycleController_rescan_v1', { onSuccess }),
      { wrapper: wrapper() },
    );
    await act(() => result.current.submit(rescanInput));
    expect(success).toHaveBeenCalledWith('Already applied');
    expect(onSuccess).toHaveBeenCalledWith({ messageId: MSG }, { replayed: true });
  });

  it('starts a 429 countdown', async () => {
    mockApi({
      MessageLifecycleController_rescan_v1: () =>
        apiErrorJson(429, 'rate_limited', 'Too many', { headers: { 'retry-after': '7' } }),
    });
    const { result } = renderHook(() => useApiMutation('MessageLifecycleController_rescan_v1'), {
      wrapper: wrapper(),
    });
    await act(() => result.current.submit(rescanInput));
    await waitFor(() => expect(result.current.retryAfterSeconds).toBe(7));
  });

  it('raises the MFA dialog event on 403 mfa_required', async () => {
    const events: string[] = [];
    const off = onSessionEvent((e) => events.push(e.type));
    mockApi({ MessageLifecycleController_rescan_v1: () => apiErrorJson(403, 'mfa_required') });
    const { result } = renderHook(() => useApiMutation('MessageLifecycleController_rescan_v1'), {
      wrapper: wrapper(),
    });
    await act(() => result.current.submit(rescanInput));
    expect(events).toContain('mfa-required');
    off();
  });

  it('reports 422 idempotency_key_reused with the request id and maps 400 to fields', async () => {
    const error = vi.spyOn(toast, 'error');
    mockApi({
      MessageLifecycleController_rescan_v1: () =>
        apiErrorJson(422, 'idempotency_key_reused', 'reused', { requestId: 'rq-422' }),
    });
    const { result } = renderHook(() => useApiMutation('MessageLifecycleController_rescan_v1'), {
      wrapper: wrapper(),
    });
    await act(() => result.current.submit(rescanInput));
    expect(error).toHaveBeenCalledWith(expect.stringContaining('rq-422'));
    mockApi({
      DomainsController_create_v1: () =>
        apiErrorJson(400, 'validation_failed', ['name: Invalid domain', 'foo: Unrecognized key']),
    });
    const create = renderHook(() => useApiMutation('DomainsController_create_v1'), {
      wrapper: wrapper(),
    });
    await act(() => create.result.current.submit({ body: { name: 'x' } }));
    await waitFor(() => expect(create.result.current.error).not.toBeNull());
    expect(create.result.current.formErrors(['name'])).toEqual({
      fieldErrors: { name: 'Invalid domain' },
      formErrors: ['foo: Unrecognized key'],
    });
  });

  it('sends no Idempotency-Key for operations without x-eg-idempotency', async () => {
    let key: string | null = 'unset';
    mockApi({
      DomainsController_create_v1: ({ request }) => (
        (key = request.headers.get('idempotency-key')),
        okJson({}, 201)
      ),
    });
    const { result } = renderHook(() => useApiMutation('DomainsController_create_v1'), {
      wrapper: wrapper(),
    });
    await act(() => result.current.submit({ body: { name: 'a.example.test' } }));
    expect(key).toBeNull();
  });
});

describe('useApiQuery', () => {
  it('fetches with [operationId, params] and exposes ApiError', async () => {
    mockApi({
      DomainsController_get_v1: ({ params }) =>
        params.id === 'missing' ? apiErrorJson(404, 'not_found') : okJson({ id: params.id ?? '' }),
    });
    const ok = renderHook(() => useApiQuery('DomainsController_get_v1', { path: { id: 'd1' } }), {
      wrapper: wrapper(),
    });
    await waitFor(() => expect(ok.result.current.data).toEqual({ id: 'd1' }));
    const missing = renderHook(
      () => useApiQuery('DomainsController_get_v1', { path: { id: 'missing' } }),
      { wrapper: wrapper() },
    );
    await waitFor(() => expect(missing.result.current.error?.code).toBe('not_found'));
  });
});

describe('useCursorList', () => {
  it('walks pages with a cursor stack, reads items lists and resets on filter change', async () => {
    const requests: string[] = [];
    mockApi({
      QuarantineEntriesController_search_v1: ({ url }) => {
        requests.push(url.search);
        const cursor = url.searchParams.get('cursor');
        return okJson({ items: [{ id: cursor ?? 'first' }], nextCursor: cursor ? null : 'c2' });
      },
    });
    let filters = { state: 'held' };
    const { result, rerender } = renderHook(
      () => useCursorList('QuarantineEntriesController_search_v1', filters as never, { limit: 1 }),
      { wrapper: wrapper() },
    );
    await waitFor(() => expect(result.current.rows).toEqual([{ id: 'first' }]));
    expect(result.current).toMatchObject({ page: 1, hasNext: true, hasPrevious: false });
    act(() => result.current.next());
    await waitFor(() => expect(result.current.rows).toEqual([{ id: 'c2' }]));
    expect(result.current).toMatchObject({ page: 2, hasNext: false, hasPrevious: true });
    act(() => result.current.previous());
    await waitFor(() => expect(result.current.page).toBe(1));
    act(() => result.current.next());
    await waitFor(() => expect(result.current.page).toBe(2));
    filters = { state: 'released' };
    rerender();
    await waitFor(() => expect(result.current.page).toBe(1));
    expect(requests.at(-1)).toContain('state=released');
    expect(requests.at(-1)).not.toContain('cursor');
  });

  it('flags a short page that still has a next cursor', async () => {
    mockApi({
      MessagesController_list_v1: () => okJson({ data: [{ id: 'm1' }], nextCursor: 'next' }),
    });
    const { result } = renderHook(
      () => useCursorList('MessagesController_list_v1', {}, { limit: 25 }),
      { wrapper: wrapper() },
    );
    await waitFor(() => expect(result.current.isShortPage).toBe(true));
  });
});

import { act, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/lib/api/errors';
import {
  AUTO_VALIDATE_DEBOUNCE_MS,
  AUTO_VALIDATE_MIN_INTERVAL_MS,
  useServerValidation,
  type ServerValidation,
  type ValidateRequest,
} from './use-server-validation';
import { validateResponse } from './test-data';

/**
 * The automatic validation schedule of design B4 with fake timers: 2 s after the last edit when
 * the document changed, at most once per 10 s, only while the tab is visible, paused for
 * `Retry-After` after a `429`.
 */

let latest: ServerValidation | null = null;

function Harness({
  doc,
  request,
  auto = true,
}: {
  doc: Record<string, unknown>;
  request: ValidateRequest;
  auto?: boolean;
}) {
  latest = useServerValidation(doc, { auto, request });
  return null;
}

const docOf = (n: number) => ({ dslVersion: 'policy-dsl/1', priority: n });

function setVisibility(state: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { value: state, configurable: true });
  document.dispatchEvent(new Event('visibilitychange'));
}

async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

describe('useServerValidation (design B4 automatic schedule)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    setVisibility('visible');
    latest = null;
  });
  afterEach(() => {
    vi.useRealTimers();
    setVisibility('visible');
  });

  it('does not validate the document the page opened with; validates 2 s after the last edit', async () => {
    const request = vi.fn<ValidateRequest>(() => Promise.resolve(validateResponse()));
    const { rerender } = render(<Harness doc={docOf(1)} request={request} />);
    await advance(30_000);
    expect(request).not.toHaveBeenCalled();
    rerender(<Harness doc={docOf(2)} request={request} />);
    await advance(AUTO_VALIDATE_DEBOUNCE_MS - 100);
    rerender(<Harness doc={docOf(3)} request={request} />); // still typing: the 2 s restart
    await advance(AUTO_VALIDATE_DEBOUNCE_MS - 100);
    expect(request).not.toHaveBeenCalled();
    await advance(100);
    expect(request).toHaveBeenCalledTimes(1);
    expect(request.mock.calls[0]?.[0]).toEqual(docOf(3));
    expect(latest?.outcome?.response.valid).toBe(true);
    // No change since the last validation: nothing more.
    await advance(60_000);
    expect(request).toHaveBeenCalledTimes(1);
  });

  it('runs at most once per 10 s however often the document changes', async () => {
    const request = vi.fn<ValidateRequest>(() => Promise.resolve(validateResponse()));
    const { rerender } = render(<Harness doc={docOf(1)} request={request} />);
    rerender(<Harness doc={docOf(2)} request={request} />);
    await advance(AUTO_VALIDATE_DEBOUNCE_MS);
    expect(request).toHaveBeenCalledTimes(1); // t = 2 s
    rerender(<Harness doc={docOf(3)} request={request} />);
    await advance(AUTO_VALIDATE_DEBOUNCE_MS); // t = 4 s: debounce over, interval not
    expect(request).toHaveBeenCalledTimes(1);
    // The first run started at t = 2 s: the next one is due at t = 12 s.
    await advance(
      AUTO_VALIDATE_DEBOUNCE_MS + AUTO_VALIDATE_MIN_INTERVAL_MS - 2 * AUTO_VALIDATE_DEBOUNCE_MS - 1,
    );
    expect(request).toHaveBeenCalledTimes(1);
    await advance(1); // t = 12 s = 2 s + 10 s
    expect(request).toHaveBeenCalledTimes(2);
    expect(request.mock.calls[1]?.[0]).toEqual(docOf(3));
  });

  it('never validates while the tab is hidden; catches up when it becomes visible', async () => {
    const request = vi.fn<ValidateRequest>(() => Promise.resolve(validateResponse()));
    const { rerender } = render(<Harness doc={docOf(1)} request={request} />);
    setVisibility('hidden');
    rerender(<Harness doc={docOf(2)} request={request} />);
    await advance(60_000);
    expect(request).not.toHaveBeenCalled();
    act(() => {
      setVisibility('visible');
    });
    await advance(0);
    expect(request).toHaveBeenCalledTimes(1);
  });

  it('pauses for Retry-After after a 429, then retries the same document', async () => {
    const tooMany = new ApiError({
      status: 429,
      code: 'rate_limited',
      message: 'Too many requests',
      retryAfterSeconds: 30,
    });
    const request = vi
      .fn<ValidateRequest>()
      .mockRejectedValueOnce(tooMany)
      .mockResolvedValue(validateResponse());
    const { rerender } = render(<Harness doc={docOf(1)} request={request} />);
    rerender(<Harness doc={docOf(2)} request={request} />);
    await advance(AUTO_VALIDATE_DEBOUNCE_MS);
    expect(request).toHaveBeenCalledTimes(1);
    expect(latest?.pausedUntil).not.toBeNull();
    rerender(<Harness doc={docOf(3)} request={request} />);
    await advance(29_000);
    expect(request).toHaveBeenCalledTimes(1);
    await advance(1_100);
    expect(request).toHaveBeenCalledTimes(2);
    expect(request.mock.calls[1]?.[0]).toEqual(docOf(3));
    expect(latest?.pausedUntil).toBeNull();
  });

  it('after another failure only an edit or an explicit run validates again', async () => {
    const request = vi
      .fn<ValidateRequest>()
      .mockRejectedValueOnce(new ApiError({ status: 500, code: 'internal_error', message: 'x' }))
      .mockResolvedValue(validateResponse({ valid: false, violations: [] }));
    const { rerender } = render(<Harness doc={docOf(1)} request={request} />);
    rerender(<Harness doc={docOf(2)} request={request} />);
    await advance(AUTO_VALIDATE_DEBOUNCE_MS);
    expect(request).toHaveBeenCalledTimes(1);
    expect(latest?.error?.code).toBe('internal_error');
    await advance(60_000);
    expect(request).toHaveBeenCalledTimes(1);
    await act(async () => {
      await latest?.validateNow();
    });
    expect(request).toHaveBeenCalledTimes(2);
    expect(latest?.outcome?.origin).toBe('manual');
    expect(latest?.error).toBeNull();
  });

  it('is off in view mode (auto false); the explicit run still works', async () => {
    const request = vi.fn<ValidateRequest>(() => Promise.resolve(validateResponse()));
    const { rerender } = render(<Harness doc={docOf(1)} request={request} auto={false} />);
    rerender(<Harness doc={docOf(2)} request={request} auto={false} />);
    await advance(60_000);
    expect(request).not.toHaveBeenCalled();
    await act(async () => {
      await latest?.validateNow();
    });
    expect(request).toHaveBeenCalledTimes(1);
  });
});

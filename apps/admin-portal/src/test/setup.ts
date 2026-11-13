import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterAll, afterEach, beforeAll, vi } from 'vitest';
import { server } from './msw';
import { resetTestRouter, testRouter, useTestPathname, useTestSearchParams } from './router';

vi.mock('next/navigation', () => ({
  useRouter: () => testRouter,
  usePathname: () => useTestPathname(),
  useSearchParams: () => useTestSearchParams(),
  redirect: vi.fn(),
  notFound: vi.fn(),
}));

if (typeof window !== 'undefined') {
  // jsdom gaps used by Radix, Recharts and the media-query hook.
  window.matchMedia ??= ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
  globalThis.ResizeObserver ??= class {
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
  } as unknown as typeof ResizeObserver;
  Element.prototype.scrollIntoView ??= function scrollIntoView() {};
  Element.prototype.hasPointerCapture ??= () => false;
  Element.prototype.releasePointerCapture ??= () => undefined;
  if (!navigator.clipboard) {
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: vi.fn(() => Promise.resolve()) },
      configurable: true,
    });
  }
}

/** Requests no handler answered: they fail the test that made them (design-system.md "Testing pages"). */
const unhandled: string[] = [];
beforeAll(() =>
  server.listen({
    onUnhandledRequest(request) {
      const url = new URL(request.url);
      unhandled.push(`${request.method} ${url.pathname}`);
    },
  }),
);
afterEach(() => {
  cleanup();
  if (unhandled.length > 0) {
    const list = unhandled.splice(0).join(', ');
    throw new Error(
      `Unhandled API request(s) in this test: ${list}. Add a mockApi/mockBff handler.`,
    );
  }
  server.resetHandlers();
  resetTestRouter();
  if (typeof window !== 'undefined') {
    document.cookie.split(';').forEach((c) => {
      const name = c.split('=')[0]?.trim();
      if (name) document.cookie = `${name}=; Max-Age=0; path=/`;
    });
    try {
      window.localStorage.clear();
    } catch {
      // ignore
    }
  }
});
afterAll(() => server.close());

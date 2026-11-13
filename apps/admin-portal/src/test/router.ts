import { useSyncExternalStore } from 'react';
import { vi } from 'vitest';

/**
 * In-memory Next router for tests: `useRouter`, `usePathname`, `useSearchParams` reflect the
 * current URL; `push`/`replace` change it (and are spies).
 */
type Listener = () => void;
const listeners = new Set<Listener>();
let current = new URL('http://localhost:3000/');
let searchParamsSnapshot = new URLSearchParams();

function emit(): void {
  searchParamsSnapshot = new URLSearchParams(current.search);
  for (const listener of listeners) listener();
}

export function setTestRoute(path: string): void {
  current = new URL(path, 'http://localhost:3000');
  emit();
}

export function currentTestUrl(): string {
  return `${current.pathname}${current.search}`;
}

const navigate = (href: string) => setTestRoute(href);

export const testRouter = {
  push: vi.fn(navigate),
  replace: vi.fn(navigate),
  back: vi.fn(),
  forward: vi.fn(),
  refresh: vi.fn(),
  prefetch: vi.fn(() => Promise.resolve()),
};

export function resetTestRouter(): void {
  setTestRoute('/');
  for (const fn of Object.values(testRouter)) fn.mockClear();
  testRouter.push.mockImplementation(navigate);
  testRouter.replace.mockImplementation(navigate);
}

function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useTestPathname(): string {
  return useSyncExternalStore(
    subscribe,
    () => current.pathname,
    () => current.pathname,
  );
}

export function useTestSearchParams(): URLSearchParams {
  return useSyncExternalStore(
    subscribe,
    () => searchParamsSnapshot,
    () => searchParamsSnapshot,
  );
}

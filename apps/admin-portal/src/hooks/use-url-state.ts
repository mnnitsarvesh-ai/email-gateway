'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useMemo, useRef } from 'react';
import type { z } from 'zod';

type Shape = Record<string, z.ZodType>;

/**
 * Parses search params against a zod object shape. Each key is parsed on its own, so one invalid
 * value (a hand-edited URL) falls back to that key's default instead of discarding all state.
 * Repeated keys and comma lists are passed as arrays only when the field schema wants an array.
 */
export function parseSearchParams<S extends Shape>(
  shape: S,
  params: URLSearchParams,
): { [K in keyof S]: z.output<S[K]> } {
  const out: Record<string, unknown> = {};
  for (const [key, schema] of Object.entries(shape)) {
    const all = params.getAll(key);
    const raw: unknown = all.length === 0 ? undefined : all.length === 1 ? all[0] : all;
    // Array fields: `a=x,y` or repeated keys; use the array reading when the schema yields one.
    const list =
      all.length === 0 ? undefined : all.flatMap((value) => value.split(',')).filter(Boolean);
    const asArray = list ? schema.safeParse(list) : null;
    if (asArray?.success && Array.isArray(asArray.data)) {
      out[key] = asArray.data;
      continue;
    }
    const parsed = schema.safeParse(raw);
    if (parsed.success && !Array.isArray(parsed.data)) out[key] = parsed.data;
    else {
      const fallback = schema.safeParse(undefined);
      out[key] = fallback.success ? fallback.data : undefined;
    }
  }
  return out as { [K in keyof S]: z.output<S[K]> };
}

/** Writes values into search params; `undefined`, `null`, `''` and defaults are removed. */
export function serializeSearchParams<S extends Shape>(
  shape: S,
  current: URLSearchParams,
  patch: Partial<{ [K in keyof S]: z.output<S[K]> | undefined }>,
): URLSearchParams {
  const next = new URLSearchParams(current);
  for (const [key, value] of Object.entries(patch)) {
    next.delete(key);
    const schema = shape[key];
    const fallback = schema?.safeParse(undefined);
    const isDefault = fallback?.success && JSON.stringify(fallback.data) === JSON.stringify(value);
    if (value === undefined || value === null || value === '' || isDefault) continue;
    if (Array.isArray(value)) {
      if (value.length > 0) next.set(key, value.map(String).join(','));
    } else if (value instanceof Date) {
      next.set(key, value.toISOString());
    } else {
      next.set(key, String(value));
    }
  }
  return next;
}

/**
 * Typed URL state (filters, search, sort, range, tab live in the URL: shareable and back-button
 * safe, design P8). `set` replaces history by default; pass `{ push: true }` for a new entry.
 */
export function useUrlState<S extends Shape>(shape: S) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const key = searchParams.toString();
  const state = useMemo(
    () => parseSearchParams(shape, new URLSearchParams(key)),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- shape is a module constant
    [key],
  );
  // Writes made before the router has applied the previous one (two debounced filters
  // committing together) must build on that write, not on the URL of the last render, or the
  // later write silently restores what the earlier one removed. `written` holds the query strings
  // this hook wrote since the URL last caught up; it is dropped once the URL reaches the latest
  // write, or moves somewhere this hook did not write (back button, another link).
  const written = useRef<{ pathname: string; queries: string[] } | null>(null);
  useEffect(() => {
    const pending = written.current;
    if (!pending) return;
    if (
      pending.pathname !== pathname ||
      !pending.queries.includes(key) ||
      pending.queries.at(-1) === key
    ) {
      written.current = null;
    }
  }, [key, pathname]);
  const set = useCallback(
    (
      patch: Partial<{ [K in keyof S]: z.output<S[K]> | undefined }>,
      options: { push?: boolean } = {},
    ) => {
      const pending = written.current?.pathname === pathname ? written.current : null;
      const base = pending?.queries.at(-1) ?? key;
      const next = serializeSearchParams(shape, new URLSearchParams(base), patch).toString();
      written.current = { pathname, queries: [...(pending ? pending.queries : [key]), next] };
      const url = next ? `${pathname}?${next}` : pathname;
      if (options.push) router.push(url, { scroll: false });
      else router.replace(url, { scroll: false });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps -- shape is a module constant
    [key, pathname, router],
  );
  return [state, set] as const;
}

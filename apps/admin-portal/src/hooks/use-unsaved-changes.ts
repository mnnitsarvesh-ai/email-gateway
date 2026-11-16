'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

export const UNSAVED_CHANGES_MESSAGE =
  'You have unsaved changes. Leave this page and discard them?';

export interface UnsavedChangesGuard {
  /** Runs `proceed` now when nothing is unsaved; otherwise asks first (see `pending`). */
  readonly guard: (proceed: () => void) => void;
  /** A navigation waits for the user's answer (render a confirmation while true). */
  readonly pending: boolean;
  /** "Discard and leave": runs the waiting navigation. */
  readonly confirm: () => void;
  /** "Stay": forgets the waiting navigation. */
  readonly cancel: () => void;
}

const sameDocumentTarget = (anchor: HTMLAnchorElement): boolean =>
  (!anchor.target || anchor.target === '_self') && !anchor.hasAttribute('download');

/**
 * Protects unsaved work (step 7.3 design B6): while `dirty`, the browser's `beforeunload` prompt
 * (reload, tab close, external navigation) and a confirmation before an in-app navigation, both
 * for the page's own controls (`guard(() => router.push(…))` for Cancel and Back buttons) and
 * for every same-origin link the user clicks (breadcrumbs, the sidebar): such clicks are held
 * and replayed through `navigate` after "Discard and leave". Modified clicks (new tab or
 * window), downloads and in-page anchors are left alone. Nothing is written to browser storage
 * (definitions are tenant configuration).
 */
export function useUnsavedChanges(
  dirty: boolean,
  navigate: (href: string) => void,
): UnsavedChangesGuard {
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;
  const navigateRef = useRef(navigate);
  navigateRef.current = navigate;
  const waiting = useRef<(() => void) | null>(null);
  const [pending, setPending] = useState(false);

  const ask = useCallback((proceed: () => void) => {
    waiting.current = proceed;
    setPending(true);
  }, []);

  useEffect(() => {
    if (!dirty) return undefined;
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      // Older browsers need returnValue set to show the prompt.
      event.returnValue = '';
    };
    const onClick = (event: MouseEvent) => {
      if (event.defaultPrevented || event.button !== 0) return;
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const target = event.target instanceof Element ? event.target : null;
      const anchor = target?.closest('a[href]');
      if (!(anchor instanceof HTMLAnchorElement) || !sameDocumentTarget(anchor)) return;
      const url = new URL(anchor.href, window.location.href);
      if (url.origin !== window.location.origin) return; // beforeunload covers it
      const here = window.location;
      if (url.pathname === here.pathname && url.search === here.search) return;
      event.preventDefault();
      event.stopPropagation();
      ask(() => navigateRef.current(`${url.pathname}${url.search}${url.hash}`));
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    document.addEventListener('click', onClick, true);
    return () => {
      window.removeEventListener('beforeunload', onBeforeUnload);
      document.removeEventListener('click', onClick, true);
    };
  }, [dirty, ask]);

  const guard = useCallback(
    (proceed: () => void) => {
      if (!dirtyRef.current) proceed();
      else ask(proceed);
    },
    [ask],
  );

  const confirm = useCallback(() => {
    const proceed = waiting.current;
    waiting.current = null;
    setPending(false);
    proceed?.();
  }, []);

  const cancel = useCallback(() => {
    waiting.current = null;
    setPending(false);
  }, []);

  return { guard, pending, confirm, cancel };
}

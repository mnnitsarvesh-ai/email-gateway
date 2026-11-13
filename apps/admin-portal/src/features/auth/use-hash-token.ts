'use client';

import { useEffect, useState } from 'react';

export type HashTokenState =
  { status: 'reading' } | { status: 'missing' } | { status: 'present'; token: string };

/**
 * Reads `#token=<token>` of an emailed link once and removes it from the address bar at once
 * (history.replaceState), so the token is not kept in history, bookmarks or screenshots.
 */
export function readAndClearHashToken(win: Window = window): string | null {
  const hash = win.location.hash.startsWith('#') ? win.location.hash.slice(1) : win.location.hash;
  const token = new URLSearchParams(hash).get('token');
  if (win.location.hash) {
    win.history.replaceState(
      win.history.state,
      '',
      `${win.location.pathname}${win.location.search}`,
    );
  }
  return token && token.length > 0 && token.length <= 128 ? token : null;
}

export function useHashToken(): HashTokenState {
  const [state, setState] = useState<HashTokenState>({ status: 'reading' });
  useEffect(() => {
    const token = readAndClearHashToken();
    setState(token ? { status: 'present', token } : { status: 'missing' });
  }, []);
  return state;
}

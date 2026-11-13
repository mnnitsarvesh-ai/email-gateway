/** In-memory session event bus (browser only); the providers subscribe once. */
export type SessionEvent =
  | { type: 'session-expired' }
  | { type: 'override-expired' }
  | { type: 'mfa-required' }
  | { type: 'session-refreshed' };

type Listener = (event: SessionEvent) => void;
const listeners = new Set<Listener>();

export function onSessionEvent(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function emitSessionEvent(event: SessionEvent): void {
  for (const listener of [...listeners]) listener(event);
}

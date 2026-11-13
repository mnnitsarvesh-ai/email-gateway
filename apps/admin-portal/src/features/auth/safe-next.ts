/**
 * Validates a `next` redirect target: only same-origin relative paths (`/x`), never `//host`,
 * `/\host`, schemes, or the auth pages themselves. Anything else → `/`.
 */
export function safeNextPath(next: string | null | undefined): string {
  if (!next || typeof next !== 'string' || next.length > 2048) return '/';
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\')) return '/';
  for (let i = 0; i < next.length; i += 1) if (next.charCodeAt(i) < 0x20) return '/';
  try {
    const url = new URL(next, 'http://portal.invalid');
    if (url.origin !== 'http://portal.invalid') return '/';
    if (
      url.pathname === '/login' ||
      url.pathname.startsWith('/login/') ||
      url.pathname.startsWith('/auth/')
    )
      return '/';
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return '/';
  }
}

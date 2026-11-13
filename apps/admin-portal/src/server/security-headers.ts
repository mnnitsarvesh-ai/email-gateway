import 'server-only';

/** Content-Security-Policy of design P10 for one request nonce. */
export function buildCsp(
  nonce: string,
  options: { development: boolean; secure: boolean },
): string {
  const script = [`'self'`, `'nonce-${nonce}'`, `'strict-dynamic'`];
  if (options.development) script.push(`'unsafe-eval'`);
  const connect = [`'self'`];
  if (options.development) connect.push('ws:');
  const directives = [
    `default-src 'self'`,
    `script-src ${script.join(' ')}`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data: blob:`,
    `font-src 'self'`,
    `connect-src ${connect.join(' ')}`,
    `frame-ancestors 'none'`,
    `form-action 'self'`,
    `base-uri 'none'`,
    `object-src 'none'`,
    `manifest-src 'self'`,
  ];
  if (options.secure) directives.push('upgrade-insecure-requests');
  return directives.join('; ');
}

/** Pages reachable without a session (design §3.1). */
const PUBLIC_PREFIXES = ['/login', '/forgot-password', '/auth/'];

export function isPublicPath(pathname: string): boolean {
  if (pathname === '/login' || pathname === '/forgot-password') return true;
  return PUBLIC_PREFIXES.some((prefix) =>
    pathname.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`),
  );
}

/** `/login?next=<path>`; only same-origin relative paths are kept (open-redirect safe). */
export function loginRedirectPath(next: string): string {
  const safe =
    next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/';
  return safe === '/' ? '/login' : `/login?next=${encodeURIComponent(safe)}`;
}

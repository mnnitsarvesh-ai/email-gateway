import path from 'node:path';
import type { NextConfig } from 'next';

// Design P9: the dev fixture layer never runs in a production build or server.
if (process.env.PORTAL_DEV_MOCKS === 'enabled' && process.env.NODE_ENV === 'production') {
  throw new Error(
    'PORTAL_DEV_MOCKS=enabled is refused with NODE_ENV=production (dev fixture mode is development-only)',
  );
}

// Static security headers (design P10). The CSP (per-request nonce) and HSTS (only when the
// runtime PORTAL_PUBLIC_URL is https; next.config is evaluated at build time) come from middleware.
const securityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'same-origin' },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
];

const nextConfig: NextConfig = {
  output: 'standalone',
  // Trace files from the monorepo root so workspace packages are included in the standalone build.
  outputFileTracingRoot: path.join(__dirname, '../../'),
  // The file tracer follows the guarded dynamic import statically; keep the fixture sources out
  // of every traced function and of the standalone copy (design P9).
  outputFileTracingExcludes: { '*': ['src/server/dev-*/**'] },
  poweredByHeader: false,
  reactStrictMode: true,
  // `pnpm lint` runs ESLint (root flat config); the build does not lint a second time.
  eslint: { ignoreDuringBuilds: true },
  webpack(config: { resolve: { alias: Record<string, string> } }, { dev }: { dev: boolean }) {
    // Design P9: outside `next dev` the fixture layer is replaced by a stub that only throws,
    // so production output (bundle and file trace) never contains it.
    if (!dev) {
      config.resolve.alias['@/server/dev-mocks$'] = path.join(
        __dirname,
        'src/server/no-fixtures.ts',
      );
    }
    return config;
  },
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

export default nextConfig;

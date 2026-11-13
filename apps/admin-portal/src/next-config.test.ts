// @vitest-environment node
import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe('next.config.ts (design P9, P10)', () => {
  it('throws when PORTAL_DEV_MOCKS=enabled with NODE_ENV=production', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('PORTAL_DEV_MOCKS', 'enabled');
    await expect(import('../next.config')).rejects.toThrow(/PORTAL_DEV_MOCKS=enabled is refused/);
  });

  it('keeps standalone output, no powered-by header and the static security headers', async () => {
    vi.stubEnv('PORTAL_DEV_MOCKS', 'disabled');
    const { default: config } = await import('../next.config');
    expect(config.output).toBe('standalone');
    expect(config.poweredByHeader).toBe(false);
    const headers = await config.headers!();
    const values = Object.fromEntries(headers[0]!.headers.map((h) => [h.key, h.value]));
    expect(values).toMatchObject({
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
    });
  });
});

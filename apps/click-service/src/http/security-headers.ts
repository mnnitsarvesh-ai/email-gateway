import type { IncomingMessage, ServerResponse } from 'node:http';
import helmet from 'helmet';

/** `Content-Security-Policy` of every public response (U14). */
export const CONTENT_SECURITY_POLICY =
  "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

/** Deny-all `Permissions-Policy` (U14). */
export const PERMISSIONS_POLICY = [
  'accelerometer',
  'autoplay',
  'camera',
  'clipboard-read',
  'clipboard-write',
  'display-capture',
  'encrypted-media',
  'fullscreen',
  'geolocation',
  'gyroscope',
  'hid',
  'idle-detection',
  'magnetometer',
  'microphone',
  'midi',
  'payment',
  'picture-in-picture',
  'publickey-credentials-get',
  'screen-wake-lock',
  'serial',
  'usb',
  'xr-spatial-tracking',
]
  .map((feature) => `${feature}=()`)
  .join(', ');

type Middleware = (
  req: IncomingMessage,
  res: ServerResponse,
  next: (err?: unknown) => void,
) => void;

/**
 * The U14 header set on EVERY public response (pages, redirects, 404s, errors): CSP, no
 * referrer, nosniff, frame denial, COOP/CORP same-origin, deny-all permissions, no caching, HSTS
 * only in production. `X-Powered-By` is disabled on the Express instance by the bootstrap.
 */
export function securityHeaders(options: { hsts: boolean }): Middleware[] {
  const base = helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'no-referrer' },
    strictTransportSecurity: options.hsts ? { maxAge: 31_536_000, includeSubDomains: true } : false,
    xContentTypeOptions: true,
    xFrameOptions: { action: 'deny' },
    xPoweredBy: true,
  });
  const extra: Middleware = (_req, res, next) => {
    // The exact policy string of U14 (helmet would add its own defaults).
    res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
    res.setHeader('Permissions-Policy', PERMISSIONS_POLICY);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    next();
  };
  return [base, extra];
}

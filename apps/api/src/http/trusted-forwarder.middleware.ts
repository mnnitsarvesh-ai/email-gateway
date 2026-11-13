import { createHash, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { Logger } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';

/** The browser's address, sent by the admin portal BFF (step 7.1 §3.4, ADR-0060). */
export const CLIENT_IP_HEADER = 'x-eg-client-ip';
/** The shared secret `API_TRUSTED_FORWARDER_TOKEN`, sent by the admin portal BFF. */
export const FORWARDER_TOKEN_HEADER = 'x-eg-forwarder-token';

/** `outcome` of `api_trusted_forwarder_total`. */
export type TrustedForwarderOutcome = 'accepted' | 'rejected' | 'invalid_ip' | 'disabled';

/** `login_audit_logs.ip_address`, `audit_logs.source_ip` and friends are VARCHAR(45). */
const MAX_IP_LENGTH = 45;

const digest = (value: string): Buffer => createHash('sha256').update(value, 'utf8').digest();

/**
 * A forwarded client address: an IPv4 or IPv6 literal (`net.isIP`), at most 45 characters, an
 * IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) as IPv4. Anything else (a list, a host name, a
 * port, a zone that `isIP` refuses) is `null`.
 */
export function normalizeForwardedIp(value: string | undefined): string | null {
  if (value === undefined) return null;
  const ip = value.trim();
  if (ip === '' || ip.length > MAX_IP_LENGTH || isIP(ip) === 0) return null;
  const mapped = /^::ffff:(.+)$/i.exec(ip)?.[1];
  if (mapped !== undefined && isIP(mapped) === 4) return mapped;
  return ip;
}

/** A single header value (Node joins repeated unknown headers with ", "). */
function header(req: Request, name: string): string | undefined {
  const value = req.headers[name];
  return Array.isArray(value) ? value.join(', ') : value;
}

/** Removes both headers from `headers` and `rawHeaders`: nothing after this middleware sees them. */
function stripHeaders(req: Request): void {
  delete req.headers[CLIENT_IP_HEADER];
  delete req.headers[FORWARDER_TOKEN_HEADER];
  const raw = req.rawHeaders;
  if (!Array.isArray(raw)) return;
  const kept: string[] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const name = raw[i]!.toLowerCase();
    if (name === CLIENT_IP_HEADER || name === FORWARDER_TOKEN_HEADER) continue;
    kept.push(raw[i]!, raw[i + 1]!);
  }
  if (kept.length !== raw.length) req.rawHeaders = kept;
}

export interface TrustedForwarderOptions {
  /** `API_TRUSTED_FORWARDER_TOKEN`; empty or undefined = the forwarder is off. */
  token: string | undefined;
  /** `api_trusted_forwarder_total{outcome}`. */
  outcomes: { inc(labels: { outcome: TrustedForwarderOutcome }): void };
  logger?: Pick<Logger, 'warn'>;
}

/**
 * The trusted client-IP forwarder (step 7.1 P5, §3.4, ADR-0060): the api's FIRST middleware.
 *
 * - Enabled and `X-EG-Forwarder-Token` equal to the configured token (SHA-256 digests compared
 *   with `timingSafeEqual`, so neither the length nor a prefix leaks) and `X-EG-Client-IP` a
 *   valid IP: that address becomes the request's `req.ip` (an own property of this request
 *   instance, shadowing Express's `trust proxy` getter), so `clientIp(req)`, every per-IP rate
 *   limit, the login throttle, `login_audit_logs`, `audit_logs.source_ip` and session IPs see the
 *   browser behind the portal (`accepted`).
 * - A missing or wrong token (`rejected`) or a missing or invalid address with the right token
 *   (`invalid_ip`): ignored, `req.ip` stays the socket / trust-proxy address; a warn log names
 *   the outcome only, never a header value.
 * - Disabled: the headers are ignored (`disabled`, counted only when one was sent).
 * - Both headers are ALWAYS removed from `req.headers` and `req.rawHeaders`, so no handler,
 *   interceptor or log line ever sees the token or an unverified address.
 */
export function trustedForwarderMiddleware(
  options: TrustedForwarderOptions,
): (req: Request, res: Response, next: NextFunction) => void {
  const expected = options.token ? digest(options.token) : null;
  const logger = options.logger ?? new Logger('TrustedForwarder');
  return (req, _res, next) => {
    const token = header(req, FORWARDER_TOKEN_HEADER);
    const forwarded = header(req, CLIENT_IP_HEADER);
    stripHeaders(req);
    if (token === undefined && forwarded === undefined) {
      next();
      return;
    }
    if (expected === null) {
      options.outcomes.inc({ outcome: 'disabled' });
      next();
      return;
    }
    if (token === undefined || !timingSafeEqual(digest(token), expected)) {
      options.outcomes.inc({ outcome: 'rejected' });
      logger.warn({ message: 'Trusted forwarder token rejected; client IP header ignored' });
      next();
      return;
    }
    const ip = normalizeForwardedIp(forwarded);
    if (ip === null) {
      options.outcomes.inc({ outcome: 'invalid_ip' });
      if (forwarded !== undefined) {
        logger.warn({ message: 'Trusted forwarder sent an invalid client IP; ignored' });
      }
      next();
      return;
    }
    Object.defineProperty(req, 'ip', {
      value: ip,
      configurable: true,
      enumerable: true,
      writable: false,
    });
    options.outcomes.inc({ outcome: 'accepted' });
    next();
  };
}

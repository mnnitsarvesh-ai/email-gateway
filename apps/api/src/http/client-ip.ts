import type { Request } from 'express';

/** `login_audit_logs.ip_address`, `audit_logs.source_ip` and friends are VARCHAR(45). */
const MAX_IP_LENGTH = 45;

/**
 * The client address as resolved by Express from the socket and `X-Forwarded-For`, honouring
 * `trust proxy` = HTTP_TRUST_PROXY hops (D6). IPv4-mapped IPv6 addresses are reported as IPv4.
 * Never read `X-Forwarded-For` directly: without the hop count it is client-controlled.
 */
export function clientIp(req: Pick<Request, 'ip'>): string | null {
  const ip = req.ip?.trim();
  if (!ip) return null;
  const normalized = ip.startsWith('::ffff:') && ip.includes('.') ? ip.slice(7) : ip;
  return normalized.slice(0, MAX_IP_LENGTH);
}

/**
 * Redis key layout of the smtp-adapter (step 2.2 D5, D6, D10, D11). Every key starts with `sa:`.
 * Names are normalized by the callers (lower-case ASCII domain names, canonical IP text,
 * lower-case hex fingerprints) so one entity has exactly one key.
 */
export const cacheKeys = {
  /** DomainPolicyView of a domain name (D5). */
  domain: (asciiName: string) => `sa:dom:${asciiName}`,
  /** Transport destination of a tenant domain (socketmap `transport`, derived from the name). */
  route: (asciiName: string) => `sa:route:${asciiName}`,
  /** Strictest TLS mode of a tenant destination `[host]:port` (socketmap `tls_policy`). */
  tlsPolicy: (host: string, port: number) => `sa:tls:${host}:${port}`,
  /** Allow-list membership of one lower-cased local part of a domain (D3). */
  recipient: (domainId: bigint, localPart: string) => `sa:rcpt:${domainId}:${localPart}`,
  /** Recipient/size limits of an organization (D6). */
  limits: (organizationId: bigint) => `sa:lim:${organizationId}`,
  /** Connector lookups (D11): by SASL username, client IP, certificate fingerprint. */
  connectorBySasl: (username: string) => `sa:conn:sasl:${username}`,
  connectorByIp: (ip: string) => `sa:conn:ip:${ip}`,
  connectorByFingerprint: (fingerprint: string) => `sa:conn:fp:${fingerprint}`,
  /** Smallest tenant size limit seen at RCPT for one Postfix `instance` (D4). */
  instance: (instance: string) => `sa:inst:${instance}`,
  /** AUTH failures per client IP (D10). */
  authFailures: (ip: string) => `sa:authfail:${ip}`,
} as const;

/** Keys to delete when a domain's status changes (D5 explicit invalidation). */
export function domainInvalidationKeys(asciiName: string): string[] {
  return [cacheKeys.domain(asciiName), cacheKeys.route(asciiName)];
}

/**
 * Redis key layout of the smtp-adapter (step 2.2 D5, D6, D10, D11). Every key starts with `sa:`.
 * Names are normalized by the callers (lower-case ASCII domain names, canonical IP text,
 * lower-case hex fingerprints) so one entity has exactly one key.
 */
export const cacheKeys = {
  /** DomainPolicyView of a domain name (D5). */
  domain: (asciiName: string) => `sa:dom:${asciiName}`,
  /**
   * Destination server list of a tenant domain (socketmap `transport`, derived from the name).
   * `v2` (step 2.3 R2): a list of servers; a 2.2 single-host entry is never read as one.
   */
  route: (asciiName: string) => `sa:route:v2:${asciiName}`,
  /**
   * TLS policies of every enabled destination row with this host, per port (socketmap
   * `tls_policy`). `v2` (step 2.3 R2): one key per host (not per `[host]:port`), so a
   * `domain.routing.changed.v1` event, which names hosts, can delete every port's answer.
   */
  tlsPolicy: (host: string) => `sa:tls:v2:${host}`,
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

/**
 * Keys to delete when a domain's destinations change (`domain.routing.changed.v1`, step 2.3
 * R2): the domain's route list and the TLS answers of every old and new host (normalized).
 */
export function routingInvalidationKeys(asciiName: string, hosts: readonly string[]): string[] {
  return [
    cacheKeys.route(asciiName),
    ...[...new Set(hosts)].map((host) => cacheKeys.tlsPolicy(host)),
  ];
}

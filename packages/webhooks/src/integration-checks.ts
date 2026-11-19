/**
 * Titles of the provider-connection health checks (step 8.2 D11, D12) for alert mails and
 * webhook consumers' documentation. The registry of record is `HEALTH_CHECKS` of
 * `@email-gateway/provider-integrations` (the api's unit test asserts this map equals it); the
 * notification-worker renders failing check codes with these titles without depending on the
 * provider library. Unknown codes (a check a later step registers) render as their code.
 */
export const INTEGRATION_CHECK_TITLES: Readonly<Record<string, string>> = Object.freeze({
  'credentials.token': 'Access token can be acquired',
  'permissions.granted': 'Exactly the requested read-only permissions are granted',
  'tenant.identity': 'Tenant is unchanged since binding',
  'domains.gateway_verified': 'Linked domains are verified at the gateway',
  'domains.provider_verified': 'Linked domains are verified in the provider tenant',
  'dns.mx_gateway': 'MX records point to the gateway',
  'inbound.destination': 'Gateway delivers inbound mail to the provider',
  'inbound.destination_matches_provider': 'Destination host matches the Microsoft 365 MX target',
  'inbound.smtp': 'Provider accepts SMTP connections from the gateway over TLS',
  'inbound.recent_deliveries': 'Recent inbound deliveries succeed',
  'dns.spf_gateway': 'SPF includes the gateway',
  'dns.dkim_provider': 'Provider DKIM signing is published',
  'outbound.probe':
    'A probe message arrived through the provider relay and passed the tenant proof',
  'outbound.relay_activity':
    'Outbound mail arrives through the provider relay and passes the tenant proof',
  'routing.no_loops': 'No mail loops for linked domains',
  'routing.loops': 'No mail loops for linked domains in the last 24 hours',
  'lockdown.attested': 'Direct delivery that bypasses the gateway is locked down (attested)',
  'credential.expiry': 'Uploaded credential is not about to expire',
  'egress.ranges_fresh': 'Provider sending ranges are current',
});

/** Display names of the providers (alert mails). */
export const INTEGRATION_PROVIDER_NAMES: Readonly<Record<string, string>> = Object.freeze({
  microsoft_365: 'Microsoft 365',
  google_workspace: 'Google Workspace',
});

/** The title of a check code, or the code itself when no title is known. */
export function integrationCheckTitle(code: string): string {
  return Object.prototype.hasOwnProperty.call(INTEGRATION_CHECK_TITLES, code)
    ? INTEGRATION_CHECK_TITLES[code]!
    : code;
}

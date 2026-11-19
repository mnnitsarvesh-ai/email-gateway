import { profileByKey } from '../profiles';
import type { IntegrationProvider } from '../types';

/**
 * A health or validation check (D10, D11, §4.3). `remediation` is an anchor of the
 * customer-specific setup guide (D14) or of a deployment document.
 */
export interface HealthCheckDefinition {
  code: string;
  provider: IntegrationProvider | 'any';
  severityOnFail: 'warning' | 'critical';
  /** Run by the integration-worker's `health` role. */
  periodic: boolean;
  title: string;
  remediation: string;
  /**
   * Per-grant checks: which grants the check iterates over (R2: the generic checks only over
   * `mail_flow` grants). Absent = a connection-level or per-domain check.
   */
  appliesToGrant?: (grant: { profile: string }) => boolean;
}

/** R2: the generic per-grant checks cover only grants whose profile purpose is `mail_flow`. */
export const isMailFlowGrant = (grant: { profile: string }): boolean =>
  profileByKey(grant.profile)?.purpose === 'mail_flow';

const CHECK_CODE = /^[a-z0-9_.]{1,64}$/;

/** The 8.2 checks (codes stable; D10 validation table and D11 periodic list). */
export const MAIL_FLOW_HEALTH_CHECKS: readonly HealthCheckDefinition[] = Object.freeze([
  {
    code: 'credentials.token',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: true,
    title: 'Access token can be acquired',
    remediation: '#grant-access',
    appliesToGrant: isMailFlowGrant,
  },
  {
    code: 'permissions.granted',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: true,
    title: 'Exactly the requested read-only permissions are granted',
    remediation: '#grant-access',
    appliesToGrant: isMailFlowGrant,
  },
  {
    code: 'tenant.identity',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: true,
    title: 'Tenant is unchanged since binding',
    remediation: '#grant-access',
  },
  {
    code: 'domains.gateway_verified',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: false,
    title: 'Linked domains are verified at the gateway',
    remediation: '#domains',
  },
  {
    code: 'domains.provider_verified',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: true,
    title: 'Linked domains are verified in the provider tenant',
    remediation: '#domains',
  },
  {
    code: 'dns.mx_gateway',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: true,
    title: 'MX records point to the gateway',
    remediation: '#inbound-mx',
  },
  {
    code: 'inbound.destination',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: false,
    title: 'Gateway delivers inbound mail to the provider',
    remediation: '#inbound-destination',
  },
  {
    code: 'inbound.destination_matches_provider',
    provider: 'microsoft_365',
    severityOnFail: 'warning',
    periodic: false,
    title: 'Destination host matches the Microsoft 365 MX target',
    remediation: '#inbound-destination',
  },
  {
    code: 'inbound.smtp',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: false,
    title: 'Provider accepts SMTP connections from the gateway over TLS',
    remediation: '#inbound-destination',
  },
  {
    code: 'inbound.recent_deliveries',
    provider: 'any',
    severityOnFail: 'warning',
    periodic: true,
    title: 'Recent inbound deliveries succeed',
    remediation: '#failover',
  },
  {
    code: 'dns.spf_gateway',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: false,
    title: 'SPF includes the gateway',
    remediation: '#outbound-spf',
  },
  {
    code: 'dns.dkim_provider',
    provider: 'any',
    severityOnFail: 'warning',
    periodic: false,
    title: 'Provider DKIM signing is published',
    remediation: '#outbound-dkim',
  },
  {
    code: 'outbound.probe',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: false,
    title: 'A probe message arrived through the provider relay and passed the tenant proof',
    remediation: '#outbound-validate',
  },
  {
    code: 'outbound.relay_activity',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: true,
    title: 'Outbound mail arrives through the provider relay and passes the tenant proof',
    remediation: '#outbound-connector',
  },
  {
    code: 'routing.no_loops',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: false,
    title: 'No mail loops for linked domains',
    remediation: '#internal-routing',
  },
  {
    code: 'routing.loops',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: true,
    title: 'No mail loops for linked domains in the last 24 hours',
    remediation: '#internal-routing',
  },
  {
    code: 'lockdown.attested',
    provider: 'any',
    severityOnFail: 'warning',
    periodic: false,
    title: 'Direct delivery that bypasses the gateway is locked down (attested)',
    remediation: '#inbound-lockdown',
  },
  {
    code: 'credential.expiry',
    provider: 'any',
    severityOnFail: 'critical',
    periodic: true,
    title: 'Uploaded credential is not about to expire',
    remediation: '#grant-access',
  },
  {
    code: 'egress.ranges_fresh',
    provider: 'any',
    severityOnFail: 'warning',
    periodic: true,
    title: 'Provider sending ranges are current',
    remediation: 'docs/deployment/provider-integrations.md#egress-ranges',
  },
] satisfies HealthCheckDefinition[]);

const registry: HealthCheckDefinition[] = [];

/** Every registered check (8.2's, then 8.5's `health/ato.ts`). */
export const HEALTH_CHECKS: readonly HealthCheckDefinition[] = registry;

export class HealthCheckRegistryError extends Error {
  override readonly name = 'HealthCheckRegistryError';
}

/** Registers checks at module load (D6); duplicate codes and invalid definitions are refused. */
export function registerHealthChecks(checks: readonly HealthCheckDefinition[]): void {
  const pending: HealthCheckDefinition[] = [];
  for (const check of checks) {
    const existing =
      registry.find((c) => c.code === check.code) ?? pending.find((c) => c.code === check.code);
    if (existing === check) continue;
    if (existing)
      throw new HealthCheckRegistryError(`health check ${check.code} is already registered`);
    if (!CHECK_CODE.test(check.code))
      throw new HealthCheckRegistryError(`invalid health check code ${check.code}`);
    if (!check.title.trim() || !check.remediation.trim()) {
      throw new HealthCheckRegistryError(
        `health check ${check.code} needs a title and a remediation anchor`,
      );
    }
    pending.push(check);
  }
  registry.push(...pending);
}

export const healthCheckByCode = (code: string): HealthCheckDefinition | undefined =>
  registry.find((c) => c.code === code);

/** Periodic checks for a provider (the `health` role's list). */
export function periodicHealthChecks(provider: IntegrationProvider): HealthCheckDefinition[] {
  return registry.filter((c) => c.periodic && (c.provider === 'any' || c.provider === provider));
}

/** The grants a per-grant check iterates over (R2). */
export function grantsForCheck<G extends { profile: string }>(
  check: HealthCheckDefinition,
  grants: readonly G[],
): G[] {
  return check.appliesToGrant ? grants.filter((g) => check.appliesToGrant!(g)) : [];
}

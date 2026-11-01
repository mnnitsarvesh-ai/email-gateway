/**
 * Domain primitives shared by every service and the admin portal.
 * Keep this package dependency-free: it is consumed by Node services and the browser.
 */

/** Branded string types prevent passing a tenant id where a message id is expected. */
export type Brand<T, B extends string> = T & { readonly __brand: B };

export type TenantId = Brand<string, 'TenantId'>;
export type MessageId = Brand<string, 'MessageId'>;
export type CorrelationId = Brand<string, 'CorrelationId'>;

/** Direction is derived from the listener/connector and verified domains, never from headers. */
export const MailDirection = {
  Inbound: 'inbound',
  Outbound: 'outbound',
  Internal: 'internal',
} as const;
export type MailDirection = (typeof MailDirection)[keyof typeof MailDirection];

/** Post-queue outcomes. The pipeline never bounces once the message was accepted with 250. */
export const PolicyAction = {
  Deliver: 'deliver',
  Tag: 'tag',
  Quarantine: 'quarantine',
  Discard: 'discard',
} as const;
export type PolicyAction = (typeof PolicyAction)[keyof typeof PolicyAction];

export const DeploymentMode = {
  SaaS: 'saas',
  Dedicated: 'dedicated',
} as const;
export type DeploymentMode = (typeof DeploymentMode)[keyof typeof DeploymentMode];

export const TenantStatus = {
  Active: 'active',
  Suspended: 'suspended',
  Deleted: 'deleted',
} as const;
export type TenantStatus = (typeof TenantStatus)[keyof typeof TenantStatus];

export type HealthStatus = 'ok' | 'error';

export interface DependencyHealth {
  name: string;
  status: HealthStatus;
  latencyMs: number;
  error?: string;
}

export interface HealthReport {
  service: string;
  status: HealthStatus;
  version: string;
  uptimeSeconds: number;
  checks: DependencyHealth[];
}

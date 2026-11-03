/** Constants of the SMTP connectors module (step 2.2 D10, §4.1). */

/** `audit_logs.resource_type` of every connector audit row. */
export const CONNECTOR_RESOURCE_TYPE = 'smtp_connector';

/** Audit actions (§4.1). Metadata never carries the password or its hash. */
export const ConnectorAuditAction = {
  Created: 'smtp_connector.created',
  Updated: 'smtp_connector.updated',
  SecretRotated: 'smtp_connector.secret_rotated',
  Deleted: 'smtp_connector.deleted',
} as const;
export type ConnectorAuditAction = (typeof ConnectorAuditAction)[keyof typeof ConnectorAuditAction];

/** Seconds to wait for the global network lock before answering `503` (D10). */
export const NETWORK_LOCK_TIMEOUT_SECONDS = 5;

/** Attempts to allocate a unique generated SASL username (100 random bits each). */
export const USERNAME_ATTEMPTS = 5;

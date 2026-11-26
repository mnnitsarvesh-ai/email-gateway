/**
 * The permission profiles whose grants the mailbox clients use (step API-1 D4, ADR-0099),
 * restated from `@email-gateway/provider-integrations` so callers need one import.
 */
import {
  GOOGLE_MAILBOX_REMEDIATION_PROFILE,
  M365_MAILBOX_REMEDIATION_PROFILE,
  MAILBOX_PROFILE_KEYS,
} from '@email-gateway/provider-integrations';

export {
  GOOGLE_MAILBOX_REMEDIATION_PROFILE,
  M365_MAILBOX_REMEDIATION_PROFILE,
  MAILBOX_PROFILE_KEYS,
};

/** Token resource of each client (8.2 `ProviderTokenService` `resource`). */
export const MAILBOX_TOKEN_RESOURCES = Object.freeze({
  graph: 'graph',
  gmail: 'google',
  google_directory: 'google',
} as const);

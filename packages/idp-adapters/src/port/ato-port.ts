/**
 * The step 8.4 provider adapter port (D15 of docs/plan/steps/24-account-takeover-core.md), taken
 * from the built `@email-gateway/ato-detection` (design note §0.2, merge note M1: the pre-rebase
 * verbatim copy and its shim schema were replaced by these re-exports; the built 8.4 names win).
 * PX1 (`ProviderEvent.deviceLabel`) is part of the 8.4 port since step 8.5 (ADR-0082).
 *
 * `looksSecretShaped` is 8.5's own, stricter value guard (bearer tokens, well-known key prefixes,
 * the simulators' token marker) applied by the mappers before a value enters an event; 8.4's
 * `providerEventSchema` (with its `SECRET_SHAPED` refinement) remains the contract.
 */
import { SECRET_SHAPED } from '@email-gateway/ato-detection';

export type {
  IdentityProviderAdapter,
  IdentityProviderKind,
  ProviderActionRequest,
  ProviderActionResult,
  ProviderActionType,
  ProviderCapabilities,
  ProviderEvent,
  ProviderIdentityRef,
  ProviderIngestPage,
  ProviderStream,
} from '@email-gateway/ato-detection';
export {
  IDENTITY_PROVIDER_KINDS,
  MAILBOX_CHANGES,
  PROVIDER_ACTION_TYPES,
  PROVIDER_STREAMS,
  ProviderAdapterError,
  providerEventSchema,
  providerIdentitySchema,
  SECRET_SHAPED,
} from '@email-gateway/ato-detection';

const EXTRA_SECRET_SHAPES: readonly RegExp[] = [
  /\bBearer\s+\S+/i,
  /\b(?:whsec|ghp|gho|ghs|xox[abp]|egk)_[A-Za-z0-9]/,
  /\bsk-[A-Za-z0-9]{8,}/,
  /\bAKIA[0-9A-Z]{12,}/,
  /\bAIza[0-9A-Za-z_-]{20,}/,
  /\bya29\.[0-9A-Za-z_-]+/,
  /EXAMPLE-sim-token-\d+/,
  /(?:access_token|refresh_token|client_secret|id_token)\s*[=:]/i,
];

/** 8.4's `SECRET_SHAPED` plus 8.5's extra credential shapes (design note §2.0 invariant 6). */
export function looksSecretShaped(value: string): boolean {
  return SECRET_SHAPED.test(value) || EXTRA_SECRET_SHAPES.some((pattern) => pattern.test(value));
}

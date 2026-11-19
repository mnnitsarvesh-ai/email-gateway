/**
 * `@email-gateway/provider-integrations` (step 8.2, docs/plan/steps/25-m365-google-connectors.md
 * D1–D6, §4.3; ADR-0076, ADR-0077): the provider-integration framework shared by the api, the
 * integration-worker and step 8.5. See README.md for the reuse surface.
 */

/** Version of the library's exported contracts (`provider-integrations/1`). */
export const PROVIDER_INTEGRATIONS_CONTRACT_VERSION = 1;

export * from './types';
export * from './errors';
export * from './endpoints';
export * from './directory';

// D1: permission profiles (registers the mail-flow profiles at load).
export * from './profiles';
// D5, ADR-0077: credential custody.
export * from './crypto/credential-cipher';
// D2, D6: the request primitive and retries.
export * from './http/provider-http';
export * from './http/retry';
// D2: token acquisition and provider clients.
export * from './microsoft/token';
export * from './microsoft/graph-client';
export * from './microsoft/directory';
export * from './google/token';
export * from './google/admin-client';
export * from './google/directory';
export * from './tokens/platform-credentials';
export * from './tokens/token-service';
// D6: writer-side grants and the connection view for 8.5.
export * from './grants/grant-store';
export * from './grants/connection-reader';
// D10, D11: health checks and validation results (registers the 8.2 checks at load).
export * from './health';
export * from './validation';
// D3, D13, D14, D11: consent URLs, impact tokens, setup guides, egress imports.
export * from './consent/admin-consent';
export * from './impact/impact-token';
export * from './guides';
export * from './egress/egress-import';

// D6 `testing`: FakeProviderServer, describeProviderClientContract and runtime test helpers.
export * as testing from './testing';

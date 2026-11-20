/**
 * `@email-gateway/idp-adapters` (step 8.5, design note §5.1, ADR-0082): ATO identity-provider
 * adapters over plain HTTPS, their port types, core (HTTP client, cursors, windows, traits,
 * snapshots, capabilities, settings, budgets), the permission catalogue and the adapter
 * configuration, the Microsoft and Google Workspace adapters and `createIdpAdapter`.
 */

// Port (re-exported from the built 8.4 @email-gateway/ato-detection, M1) and the 8.2 connection port.
export * from './port/ato-port';
export * from './port/connection-port';
export * from './port/state-ports';

// Kinds, requirements, configuration, adapter contracts and the factory.
export * from './kinds';
export * from './requirements';
export * from './config';
export * from './adapter-types';
export * from './factory';

// Bindings to step 8.2's library (post-rebase, WP3; the only code that knows 8.2's names).
export * from './bindings/provider-connections';
export * from './bindings/connection-directory';

// Core.
export * from './core/actions';
export * from './core/budget';
export * from './core/capabilities';
export * from './core/coverage';
export * from './core/cursor';
export * from './core/errors';
export * from './core/hash';
export * from './core/http';
export * from './core/normalize';
export * from './core/oauth-scopes';
export * from './core/page';
export * from './core/session';
export * from './core/settings';
export * from './core/snapshot';
export * from './core/traits';
export * from './core/windows';

// Microsoft adapter.
export { MicrosoftAdapter, createMicrosoftAdapter, throttledPage } from './microsoft/adapter';
export {
  CONSENT_ACTIVITIES,
  ENTRA_INTERRUPT_CODES,
  EXCHANGE_AUDIT_OPERATIONS,
  MICROSOFT_ADAPTER_VERSION,
  MICROSOFT_DECLARED_CAPABILITIES,
  TOKEN_RISK_TYPES,
  type ExchangeAuditOperation,
} from './microsoft/constants';

// Google Workspace adapter.
export { GoogleAdapter, UNSUPPORTED_CURSOR_PREFIX, createGoogleAdapter } from './google/adapter';
export {
  GOOGLE_ADAPTER_VERSION,
  GOOGLE_DECLARED_CAPABILITIES,
  GOOGLE_RISK_EVENTS,
  TOKEN_AUTHORIZE_EVENT,
} from './google/constants';

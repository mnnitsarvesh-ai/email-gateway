import { MAIL_FLOW_HEALTH_CHECKS, registerHealthChecks } from './checks';

// Step 8.2's checks are registered at module load (D10, D11).
registerHealthChecks(MAIL_FLOW_HEALTH_CHECKS);
// Step 8.5's check `ato.identity_provider` (D6; docs/plan/steps/26-ato-provider-adapters.md D11).
export * from './ato';

export * from './checks';
export * from './evaluate';
export * from './credential-expiry';

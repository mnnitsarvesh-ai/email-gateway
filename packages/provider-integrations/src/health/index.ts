import { MAIL_FLOW_HEALTH_CHECKS, registerHealthChecks } from './checks';

// Step 8.2's checks are registered at module load (D10, D11).
registerHealthChecks(MAIL_FLOW_HEALTH_CHECKS);
// Step 8.5 adds its check with one import line here: `import './ato';` (D6).

export * from './checks';
export * from './evaluate';
export * from './credential-expiry';

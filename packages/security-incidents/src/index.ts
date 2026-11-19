// @email-gateway/security-incidents (step 8.4 D24, ADR-0075): the security incident model shared
// by account takeover and (later) advanced threat protection: vocabulary, state machine, category
// handler registry, the transactional IncidentStore and report assembly. The test builders live
// under `@email-gateway/security-incidents/testing` and are never imported by runtime code.
export * from './vocabulary';
export * from './errors';
export * from './transitions';
export * from './registry';
export * from './rows';
export * from './audit';
export * from './outbox';
export * from './store';
export * from './report';

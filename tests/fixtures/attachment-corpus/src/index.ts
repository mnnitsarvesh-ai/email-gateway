// Attachment test corpus (step 4.2 §9, docs/plan/steps/10-attachment-scanning.md): every file
// is generated at test time, nothing binary is committed, and the EICAR string is assembled
// from fragments. Consumers: packages/clamav/integration, apps/email-worker (unit, integration,
// bench) and tests/integration (stack suites).
export * from './archives';
export * from './eicar';
export * from './files';
export * from './zip';

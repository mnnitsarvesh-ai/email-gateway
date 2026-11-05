// clamd transport (step 4.2 A7, docs/plan/steps/10-attachment-scanning.md): PING, VERSION and
// INSTREAM inside one IDSESSION over TCP, reply parsers and typed errors. No platform verdicts
// (the attachment engine of the email-worker maps results, A6).
export * from './client';
export * from './errors';
export * from './limiter';
export * from './reply';

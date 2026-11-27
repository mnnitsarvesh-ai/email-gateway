/**
 * `@email-gateway/mailbox-api` (step API-1, design D9, ADR-0100): provider mailbox clients of
 * API-mode protection (Microsoft Graph mail, Gmail, Google Directory) over 8.5's HTTPS client with
 * per-connection budgets and a shared throttle gate, the streaming Gmail raw extractor, and the
 * pure helpers of copies, dedupe, lag, coverage, health and Graph notifications. No database, no
 * Nest: the mailbox-worker and the api wire it.
 */
export * from './errors';
export * from './budget';
export * from './profiles';
export {
  guardedCall,
  normalizedStream,
  type MailboxClientContext,
  type MailboxContentStream,
} from './clients/context';
export * from './clients/graph-mail-client';
export * from './clients/gmail-client';
export * from './clients/google-directory-client';
export * from './gmail-raw-extractor';
export * from './headers';
export * from './identifiers';
export * from './classify';
export * from './notifications';
export * from './coverage';
export * from './health';
// Step API-2 (note 36 R2, R3, R5.6, R6; ADR-0101): remediation policy, keys and provider plans.
export * from './remediation/vocabulary';
export * from './remediation/policy';
export * from './remediation/keys';
export * from './remediation/provider-actions';
export * from './remediation/errors';

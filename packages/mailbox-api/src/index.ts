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
// Step API-3 (note 37 C2–C6, C8.5, C10, C11, C13, C17; ADR-0103/0104): clawback, search and
// purge, organization settings and user-reported phishing.
export * from './settings';
export * from './clawback/vocabulary';
export * from './clawback/criteria';
export * from './clawback/signal';
export * from './clawback/targets';
export * from './clawback/approval';
export * from './clawback/search-keys';
export * from './reports/vocabulary';
export * from './reports/extract';
export * from './reports/original';

/**
 * @email-gateway/archive — the pure library of step 8.1 (journaling and compliance archiving,
 * docs/plan/steps/23-journaling-archiving.md A1): crypto, documents, capture decision, journal
 * eligibility, retention and expiry, legal-hold matching, OpenSearch template and builders,
 * snapshot codec, object keys, download tokens and export manifests. No I/O, no clock (time is a
 * parameter), no logger.
 */
export * from './capture';
export * from './crypto';
export * from './documents';
export * from './export';
export * from './holds';
export * from './ids';
export * from './keys';
export * from './retention';
export * from './search';
export * from './snapshot';
export * from './tokens';
export * from './versions';
export * from './vocabulary';

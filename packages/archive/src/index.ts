/**
 * @email-gateway/archive — the pure library of step 8.1 (journaling and compliance archiving,
 * docs/plan/steps/23-journaling-archiving.md A1): crypto, documents, capture decision, journal
 * eligibility, retention and expiry, legal-hold matching, OpenSearch template and builders,
 * snapshot codec, object keys, download tokens and export manifests; and of step 8.6 (journal-only
 * intake and cross-source dedupe, docs/plan/steps/27-journal-intake-and-archive-split.md): the
 * journal report unwrapper, envelope parser, header-field stripper, intake addresses and tokens,
 * intake documents and networks, party classification, dedupe keys, fingerprint, body hash and
 * merge decision. No I/O, no clock (time is a parameter), no logger.
 */
export * from './capture';
export * from './crypto';
export * from './dedupe';
export * from './documents';
export * from './export';
export * from './holds';
export * from './ids';
export * from './intake';
export * from './keys';
export * from './retention';
export * from './search';
export * from './snapshot';
export * from './tokens';
export * from './versions';
export * from './vocabulary';

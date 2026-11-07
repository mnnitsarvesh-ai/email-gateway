/**
 * @email-gateway/dlp (docs/plan/steps/13-dlp.md, ADR-0036..0038): data loss prevention —
 * validators and the built-in detectors of the verdict map `dlp-map/1`, context-aware scoring
 * on the bec normalization, keyword dictionaries, tenant patterns on RE2 semantics (re2js),
 * classification, deterministic policy evaluation, masking, evidence building and its envelope
 * encryption, attachment text extraction (also as `@email-gateway/dlp/extract`), the `detect()`
 * text pipeline, versions and the synthetic fixture corpus. No Nest, no Prisma, no I/O except
 * the packaged data files: data access, budgets and storage are the caller's (email-worker,
 * api).
 */
export * from './classify';
export * from './context/scoring';
export * from './context/trie';
export * from './custom';
export * from './data';
export * from './detect';
export * from './detectors/numbers';
export * from './detectors/structure';
export * from './detectors/tokens';
export * from './detectors/types';
export * from './dictionaries';
export * from './evidence/build';
export * from './evidence/envelope';
export * from './extract';
export * from './mask';
export * from './policy';
export * from './validators';
export * from './versions';
export * from './corpus';

/**
 * `@email-gateway/dlp/extract` (step 4.5 D4): the attachment text extraction used by the DLP
 * extractor child. Format extractors, the bounded XML tokenizer, text decoding, the pdfjs
 * wrapper, `ExtractLimits` and the extraction result type. This entry point must not import
 * `@email-gateway/bec`, `@email-gateway/url-security`, an AI SDK or `child_process` (unit test
 * `extract-graph.test.ts` walks its import graph).
 */
export * from './office';
export * from './pdf';
export * from './session';
export * from './text';
export * from './types';
export * from './xml';
export { DLP_EXTRACTOR_VERSION, DLP_PDFJS_VERSION } from '../versions';

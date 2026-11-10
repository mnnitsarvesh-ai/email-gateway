/**
 * `@email-gateway/sandbox` (step 4.6, docs/plan/steps/14-sandbox.md §4, X11, X12, X13, X14;
 * ADR-0039/0040): the pieces of the sandbox engine that the email-worker and the
 * sandbox-controller share — the `sandbox-sample/1` and `sandbox-artifact/1` envelopes, key
 * parsing, the result MAC, the content-addressed analysis key, object keys and the verdict map
 * `sandbox-map/1` with the round aggregation. Pure (node:crypto only; no I/O except the
 * `artifact:open` ops script).
 */
export * from './keys';
export * from './object-keys';
export * from './envelope/errors';
export * from './envelope/sample';
export * from './envelope/artifact';
export * from './result-mac';
export * from './analysis-key';
export * from './verdict/map';

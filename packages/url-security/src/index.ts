/**
 * @email-gateway/url-security (docs/plan/steps/11-url-protection.md, ADR-0029..0032): URL
 * extraction, normalization, lookalike detection, the SSRF guard / restricted resolver / guarded
 * fetcher / egress proxy, reputation providers with the authenticated cache, landing features,
 * the verdict map url-map/1, click tokens and the streaming URL rewriter. No Nest, no Prisma:
 * database access is injected.
 */
export * from './extract';
export * from './landing';
export * from './lookalike';
export * from './net';
export * from './normalize';
export * from './reputation';
export * from './rewrite';
export * from './token';
export * from './verdict';

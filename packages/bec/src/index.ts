/**
 * @email-gateway/bec (docs/plan/steps/12-phishing-bec.md, ADR-0033..0035): phishing and BEC
 * detection: identity parsing and normalization, lookalikes through url-security, bounded
 * multilingual text analysis, the deterministic verdict map bec-map/1 with trust and feedback
 * suppression, communication-history key hashing, and the optional AI layer (local model
 * bec-lr/1, Anthropic LLM provider, fake provider) behind the aggregation invariant. No Nest,
 * no Prisma, no Redis: data access, budgets and breakers are the caller's (email-worker).
 */
export * from './ai';
export * from './data';
export * from './history';
export * from './identity';
export * from './rules';
export * from './static-data';
export * from './text';

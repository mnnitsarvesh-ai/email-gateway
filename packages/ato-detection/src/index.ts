// @email-gateway/ato-detection (step 8.4 §4.4, ADR-0070–0074): the account takeover detection
// library shared by the ato-worker and the api: versions, taxonomy, settings, the rule catalogue
// and evaluation, scoring, baselines, explanations, the incident category handler, responses,
// IP/geo/device helpers and keys, the Redis windows, the transactional ATO store, the GeoIP reader
// and the identity-provider port. The test kit lives under `@email-gateway/ato-detection/testing`.
export * from './versions';
export * from './taxonomy';
export * from './settings';
export * from './rules/catalogue';
export * from './rules/types';
export * from './rules/evaluate';
export * from './scoring';
export * from './baseline';
export * from './explain';
export * from './incident-handler';
export * from './responses';
export * from './net';
export * from './geo';
export * from './device';
export * from './keys';
export * from './windows';
export * from './store';
export * from './geoip';
export * from './provider';

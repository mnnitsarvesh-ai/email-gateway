/**
 * `@email-gateway/ato-detection/testing` (step 8.4 §4.4): the fake identity provider, the provider
 * contract kit, the minimal MMDB writer and the synthetic GeoIP spec, builders and `InMemoryRedis`.
 * Never imported by runtime code (asserted by a unit test here and in each consumer).
 */
export * from './fake-provider';
export * from './provider-contract';
export * from './mmdb-writer';
export * from './synthetic-geoip';
export * from './builders';
export * from './in-memory-redis';

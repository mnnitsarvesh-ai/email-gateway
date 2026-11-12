import { randomBytes } from 'node:crypto';

/**
 * Step 6.1 D8: global API limits high enough that no existing e2e suite reaches them. Suites that
 * test the limiter pass their own lower values after spreading these.
 */
export const TEST_GENEROUS_RATE_LIMITS: Readonly<Record<string, string>> = Object.freeze({
  API_RATE_PRINCIPAL_PER_MINUTE: '10000',
  API_RATE_TENANT_DEFAULT_PER_MINUTE: '100000',
  API_RATE_TENANT_MIN_PER_MINUTE: '100000',
  API_RATE_TENANT_MAX_PER_MINUTE: '1000000',
  API_RATE_SENSITIVE_PER_MINUTE: '600',
  API_RATE_EXPENSIVE_PER_MINUTE: '600',
});

/**
 * Keys without a default that every test building a full `ApiConfig` spreads into its env
 * object. Domain onboarding keys (design D16 of step 2.1) that every test building a full `ApiConfig`
 * spreads into its env object. `GATEWAY_MX_HOSTS` and `GATEWAY_SPF_INCLUDE` have no default, and
 * background domain jobs are off so no test checks DNS on a timer. `.test` names only: no test
 * resolves a public DNS name.
 */
export const TEST_DOMAIN_ENV: Record<string, string> = {
  GATEWAY_MX_HOSTS: '10:mx1.mail-gateway.test,20:mx2.mail-gateway.test',
  GATEWAY_SPF_INCLUDE: '_spf.mail-gateway.test',
  DOMAIN_BACKGROUND_JOBS_ENABLED: 'false',
  // Step 4.5 D16: the evidence key-encryption key is required (a fresh key per test process).
  DLP_EVIDENCE_KEY: randomBytes(32).toString('hex'),
  // Step 5.3 Q12: the download-token HMAC key is required (a fresh key per test process).
  QUARANTINE_DOWNLOAD_TOKEN_KEY: randomBytes(32).toString('hex'),
  // Step 6.1 D3: the v1 cursor HMAC key is required (a fresh key per test process).
  API_CURSOR_KEY: randomBytes(32).toString('hex'),
  ...TEST_GENEROUS_RATE_LIMITS,
};

import {
  ATTACHMENT_FILE_TYPE_VALUES,
  CLICK_DECISION_VALUES,
  ENGINE_OUTCOME_VALUES,
  SANDBOX_ATTACHMENT_VERDICT_VALUES,
  SCAN_VERDICT_VALUES,
  URL_VERDICT_VALUES,
} from '@email-gateway/event-contracts';
import {
  ATTACHMENT_REASON_CODES,
  CLICK_DECISIONS,
  ENGINE_OUTCOMES,
  FILE_TYPE_IDS,
  REASON_CODE_PATTERN,
  REWRITE_SKIP_REASONS as SECURITY_REWRITE_SKIP_REASONS,
  SCAN_VERDICTS,
  URL_BLOCKED_REASONS,
  URL_FETCH_ERRORS,
  URL_HOP_KINDS,
  URL_MAPPING_VERSION,
  URL_REASON_CODES,
  URL_SOURCES as SECURITY_URL_SOURCES,
  URL_VERDICTS,
} from '@email-gateway/security-contracts';
import {
  BLOCKED_REASONS,
  FETCH_ERRORS,
  REWRITE_SKIP_REASONS,
  URL_MAP_VERSION,
  URL_MAPPER_CODES,
  URL_SOURCES,
} from '@email-gateway/url-security';
import { describe, expect, it } from 'vitest';

/**
 * event-contracts has no dependency on security-contracts; the email-worker depends on both and
 * asserts the mirrored literal lists stay equal (step 4.1 §4).
 */
describe('scan verdict literals', () => {
  it('event-contracts mirrors security-contracts exactly', () => {
    expect([...SCAN_VERDICT_VALUES]).toEqual([...SCAN_VERDICTS]);
    expect([...ENGINE_OUTCOME_VALUES]).toEqual([...ENGINE_OUTCOMES]);
    expect(REASON_CODE_PATTERN.source).toBe('^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)+$');
  });
});

describe('attachment contract literals (step 4.2 §12 WP1)', () => {
  it('event-contracts mirrors FILE_TYPE_IDS exactly', () => {
    expect([...ATTACHMENT_FILE_TYPE_VALUES]).toEqual([...FILE_TYPE_IDS]);
    expect([...SANDBOX_ATTACHMENT_VERDICT_VALUES]).toEqual(['suspicious', 'unknown']);
    for (const code of ATTACHMENT_REASON_CODES) expect(code).toMatch(REASON_CODE_PATTERN);
  });
});

describe('url contract literals (step 4.3 U10, WP1/WP2 §12)', () => {
  it('url-security URL_MAPPER_CODES equals security-contracts URL_REASON_CODES (order included)', () => {
    expect([...URL_MAPPER_CODES]).toEqual([...URL_REASON_CODES]);
    for (const code of URL_REASON_CODES) expect(code).toMatch(REASON_CODE_PATTERN);
    expect(URL_MAP_VERSION).toBe(URL_MAPPING_VERSION);
  });

  it('the mirrored URL enums stay equal across url-security, security-contracts and event-contracts', () => {
    expect([...URL_VERDICT_VALUES].sort()).toEqual([...URL_VERDICTS].sort());
    expect([...CLICK_DECISION_VALUES]).toEqual([...CLICK_DECISIONS]);
    expect([...SECURITY_REWRITE_SKIP_REASONS]).toEqual([...REWRITE_SKIP_REASONS]);
    expect([...SECURITY_URL_SOURCES]).toEqual([...URL_SOURCES]);
    expect([...URL_BLOCKED_REASONS]).toEqual([...BLOCKED_REASONS]);
    expect([...URL_FETCH_ERRORS]).toEqual([...FETCH_ERRORS]);
    expect([...URL_HOP_KINDS]).toEqual(['initial', 'http', 'meta']);
  });
});

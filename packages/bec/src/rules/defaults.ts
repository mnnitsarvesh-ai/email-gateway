import { DEFAULT_LOOKALIKE_PARAMS } from '@email-gateway/url-security';
import type { BecRuleSettings } from './types';

/** Platform defaults of §5 (BEC_SUSPICIOUS_SCORE … BEC_TEXT_MAX_CHARS, URL_LOOKALIKE_*). */
export const BEC_DEFAULT_RULE_SETTINGS: Readonly<BecRuleSettings> = Object.freeze({
  suspiciousScore: 40,
  maliciousScore: 80,
  suppressionMaxWeight: 40,
  historyMinMessages: 3,
  textMaxChars: 40_000,
  lookalike: DEFAULT_LOOKALIKE_PARAMS,
});

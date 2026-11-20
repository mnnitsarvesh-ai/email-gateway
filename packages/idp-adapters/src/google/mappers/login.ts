/**
 * Google Reports `login` activities → normalized events (design note §3.2):
 *
 * - `login_success` → `sign_ins` success; `login_failure` → failure with
 *   `failureCode = 'gws_' + login_failure_type`; `login_challenge` with
 *   `login_challenge_status = 'Challenge Failed'` → failure (`gws_challenge_failed`), otherwise
 *   (passed) → interrupted;
 * - `suspicious_login` (medium), `suspicious_login_less_secure_app` (low),
 *   `suspicious_programmatic_login` (medium), `gov_attack_warning` (high),
 *   `account_disabled_password_leak` (high), `account_disabled_hijacked` (high),
 *   `account_disabled_spamming*` (medium) → `risk_events` with `riskDetail` = the event name;
 * - `logout` and every other event → dropped (`dropped_operation`).
 *
 * Google `login` events carry no user agent and no device data (§3.1).
 */
import { code64 } from '../../core/normalize';
import { activitySchema } from '../schemas';
import { CHALLENGE_FAILED, GOOGLE_RISK_EVENTS, GOOGLE_SPAMMING_PREFIX } from '../constants';
import { activityEvent, parameter, type ActivityEventResult } from './activity';

export function googleRiskLevel(name: string): 'low' | 'medium' | 'high' | null {
  if (Object.prototype.hasOwnProperty.call(GOOGLE_RISK_EVENTS, name)) {
    return GOOGLE_RISK_EVENTS[name] ?? null;
  }
  return name.startsWith(GOOGLE_SPAMMING_PREFIX) ? 'medium' : null;
}

/** Maps one `login` activity; malformed activities yield a single `invalid` result. */
export function mapLoginActivity(raw: unknown): ActivityEventResult[] {
  const parsed = activitySchema.safeParse(raw);
  if (!parsed.success) return [{ kind: 'invalid', stream: 'sign_ins' }];
  const activity = parsed.data;
  return activity.events.map((source, index): ActivityEventResult => {
    const level = googleRiskLevel(source.name);
    if (level !== null) {
      const event = activityEvent(activity, 'login', index, 'risk_events');
      if (!event) return { kind: 'invalid', stream: 'risk_events' };
      event.riskLevel = level;
      event.riskDetail = code64(source.name) || 'gws_risk';
      return { kind: 'event', event };
    }
    switch (source.name) {
      case 'login_success':
      case 'login_failure':
      case 'login_challenge': {
        const event = activityEvent(activity, 'login', index, 'sign_ins');
        if (!event) return { kind: 'invalid', stream: 'sign_ins' };
        if (source.name === 'login_success') {
          event.outcome = 'success';
        } else if (source.name === 'login_failure') {
          event.outcome = 'failure';
          const type = parameter(source, 'login_failure_type');
          event.failureCode = `gws_${code64(type ?? '') || 'unknown'}`.slice(0, 64);
        } else if (parameter(source, 'login_challenge_status') === CHALLENGE_FAILED) {
          event.outcome = 'failure';
          event.failureCode = 'gws_challenge_failed';
        } else {
          event.outcome = 'interrupted';
        }
        return { kind: 'event', event };
      }
      default:
        // `logout`, `login_verification`, password and 2SV changes, …: not ATO sign-in signals.
        return { kind: 'dropped', stream: 'sign_ins' };
    }
  });
}

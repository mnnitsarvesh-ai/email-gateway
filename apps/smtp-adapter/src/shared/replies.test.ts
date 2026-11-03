import { describe, expect, it } from 'vitest';
import * as replies from './replies';
import {
  DUNNO,
  FROM_MISMATCH,
  LMTP_ACCESS_DENIED,
  LMTP_OK,
  LMTP_TEMPFAIL,
  LMTP_UNKNOWN_RECIPIENT,
  LOOP,
  MUST_STARTTLS,
  NOT_READY_FOR_OUTBOUND,
  POLICY_TEMPFAIL,
  RATE_LIMITED,
  RELAY_DENIED,
  replyError,
  replyLine,
  SENDER_NOT_AUTHORIZED,
  SIGNING_UNAVAILABLE,
  SOCKETMAP_NOTFOUND,
  SOCKETMAP_OK,
  SOCKETMAP_RELAY_DOMAIN_OK,
  SOCKETMAP_TEMPFAIL,
  SOCKETMAP_UNKNOWN_MAP,
  type SmtpReply,
  SUPPRESSED,
  TOO_BIG,
  TOO_BIG_FOR_RECIPIENT,
  TRANSPORT_DESTINATION_NOT_CONFIGURED,
  UNKNOWN_USER,
} from './replies';

describe('SMTP/LMTP replies (D7, D13, D14)', () => {
  it('has the exact design texts', () => {
    expect(replyLine(LMTP_OK)).toBe('250 2.0.0 Ok');
    expect(replyLine(LMTP_TEMPFAIL)).toBe('451 4.3.0 Temporary failure, please retry');
    expect(replyLine(LOOP)).toBe('554 5.4.6 Routing loop detected');
    expect(replyLine(FROM_MISMATCH)).toBe(
      '550 5.7.1 From header does not match the authenticated sender domain',
    );
    expect(LMTP_ACCESS_DENIED.code).toBe(554);
    expect(LMTP_ACCESS_DENIED.text).toMatch(/^5\.7\.1 /);
    expect(replyLine(LMTP_UNKNOWN_RECIPIENT)).toBe(
      '550 5.1.1 Recipient address rejected: User unknown',
    );
  });

  it('pairs each code with a matching enhanced status class', () => {
    const all = Object.values(replies).filter(
      (v): v is SmtpReply => typeof v === 'object' && v !== null && 'code' in v,
    );
    expect(all.length).toBeGreaterThanOrEqual(6);
    for (const reply of all) {
      expect(reply.text[0], reply.text).toBe(String(reply.code)[0]);
      expect(reply.text).toMatch(/^[245]\.\d{1,3}\.\d{1,3} \S/);
      expect(Object.isFrozen(reply)).toBe(true);
    }
  });

  it('builds smtp-server errors carrying the response code', () => {
    const err = replyError(LMTP_TEMPFAIL);
    expect(err).toBeInstanceOf(Error);
    expect(err.responseCode).toBe(451);
    expect(err.message).toBe('4.3.0 Temporary failure, please retry');
    expect(Object.prototype.toString.call(err)).toBe('[object Error]');
  });
});

describe('policy actions (D4, D11)', () => {
  it('has the exact design texts', () => {
    expect(DUNNO).toBe('DUNNO');
    expect(POLICY_TEMPFAIL).toBe('DEFER_IF_PERMIT 4.3.5 Policy service temporarily unavailable');
    expect(RATE_LIMITED).toBe('DEFER_IF_PERMIT 4.7.1 Rate limit exceeded, try again later');
    expect(UNKNOWN_USER).toBe('REJECT 5.1.1 Recipient address rejected: User unknown');
    expect(RELAY_DENIED).toBe('REJECT 5.7.1 Relay access denied');
    expect(SENDER_NOT_AUTHORIZED).toBe('REJECT 5.7.1 Sender address not authorized');
    expect(NOT_READY_FOR_OUTBOUND).toBe(
      'REJECT 5.7.1 Sender domain is not ready for outbound mail',
    );
    expect(SUPPRESSED).toBe('REJECT 5.7.1 Recipient address suppressed');
    expect(SIGNING_UNAVAILABLE).toBe('DEFER_IF_PERMIT 4.7.0 Signing key not available');
    expect(TOO_BIG_FOR_RECIPIENT).toBe('REJECT 5.3.4 Message too big for recipient');
    expect(TOO_BIG).toBe('REJECT 5.3.4 Message too big');
    expect(MUST_STARTTLS).toBe('REJECT 5.7.1 Must issue a STARTTLS command first');
  });

  it('never answers OK, and every action is a single line Postfix accepts', () => {
    const actions = Object.entries(replies)
      .filter(([, v]) => typeof v === 'string')
      .filter(
        ([name]) =>
          !name.startsWith('SOCKETMAP_') && name !== 'TRANSPORT_DESTINATION_NOT_CONFIGURED',
      )
      .map(([, v]) => v as string);
    expect(actions.length).toBe(12);
    for (const action of actions) {
      expect(action).toMatch(/^(DUNNO|REJECT 5\.\d\.\d+ \S.*|DEFER_IF_PERMIT 4\.\d\.\d+ \S.*)$/);
      expect(action).not.toMatch(/[\r\n]/);
      expect(action.startsWith('OK')).toBe(false);
    }
  });
});

describe('socketmap answers (D2, D11)', () => {
  it('has the protocol texts of the design', () => {
    expect(SOCKETMAP_RELAY_DOMAIN_OK).toBe('OK active');
    expect(SOCKETMAP_OK).toBe('OK');
    expect(SOCKETMAP_NOTFOUND).toBe('NOTFOUND ');
    expect(SOCKETMAP_TEMPFAIL).toBe('TEMP Lookup failed');
    expect(SOCKETMAP_UNKNOWN_MAP).toBe('PERM Unknown map');
    expect(TRANSPORT_DESTINATION_NOT_CONFIGURED).toBe('retry:4.4.1 Destination not configured');
  });
});

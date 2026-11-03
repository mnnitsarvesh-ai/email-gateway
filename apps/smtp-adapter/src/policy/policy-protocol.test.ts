import { describe, expect, it } from 'vitest';
import {
  DUNNO,
  POLICY_TEMPFAIL,
  RATE_LIMITED,
  RELAY_DENIED,
  TOO_BIG,
  UNKNOWN_USER,
} from '../shared/replies';
import {
  formatResponse,
  MAX_REQUEST_BYTES,
  PolicyProtocolError,
  PolicyRequestParser,
  postfixAction,
} from './policy-protocol';

const request = 'request=smtpd_access_policy\nprotocol_state=RCPT\nrecipient=user@example.test\n\n';

describe('PolicyRequestParser', () => {
  it('parses a complete request', () => {
    const [parsed] = new PolicyRequestParser().push(request);
    expect(parsed).toEqual({
      request: 'smtpd_access_policy',
      protocol_state: 'RCPT',
      recipient: 'user@example.test',
    });
  });

  it('reassembles a request split across chunks', () => {
    const parser = new PolicyRequestParser();
    expect(parser.push(request.slice(0, 20))).toEqual([]);
    expect(parser.push(request.slice(20))).toHaveLength(1);
  });

  it('handles pipelined requests in one chunk', () => {
    expect(new PolicyRequestParser().push(request + request)).toHaveLength(2);
  });

  it('keeps "=" inside values', () => {
    const [parsed] = new PolicyRequestParser().push(
      'request=smtpd_access_policy\nsasl_username=a=b\n\n',
    );
    expect(parsed?.sasl_username).toBe('a=b');
  });

  it('rejects oversized and malformed input', () => {
    expect(() => new PolicyRequestParser().push('x'.repeat(MAX_REQUEST_BYTES + 1))).toThrow(
      PolicyProtocolError,
    );
    expect(() => new PolicyRequestParser().push('no-equals-sign\n\n')).toThrow(PolicyProtocolError);
  });
});

describe('formatResponse', () => {
  it('terminates the action with an empty line', () => {
    expect(formatResponse('DUNNO')).toBe('action=DUNNO\n\n');
  });

  it('refuses response splitting', () => {
    expect(() => formatResponse('DUNNO\n\naction=OK')).toThrow(PolicyProtocolError);
  });
});

describe('postfixAction', () => {
  it("sends permanent rejections as 550 without repeating Postfix's prefix", () => {
    expect(postfixAction(UNKNOWN_USER)).toBe('550 5.1.1 User unknown');
    expect(postfixAction(RELAY_DENIED)).toBe('550 5.7.1 Relay access denied');
    expect(postfixAction(TOO_BIG)).toBe('550 5.3.4 Message too big');
  });

  it('passes DUNNO and deferrals through unchanged', () => {
    for (const action of [DUNNO, POLICY_TEMPFAIL, RATE_LIMITED]) {
      expect(postfixAction(action)).toBe(action);
    }
  });
});

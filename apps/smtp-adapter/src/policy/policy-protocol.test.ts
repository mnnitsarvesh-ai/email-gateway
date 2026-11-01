import { describe, expect, it } from 'vitest';
import {
  formatResponse,
  MAX_REQUEST_BYTES,
  PolicyProtocolError,
  PolicyRequestParser,
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

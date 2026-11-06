import { describe, expect, it } from 'vitest';
import { untracedIncomingRequest } from './tracing';

describe('untracedIncomingRequest (click tokens never reach a span, step 4.3)', () => {
  const ignore = untracedIncomingRequest(['/c/']);

  it('matches click and continue paths in every spelling Express routes', () => {
    for (const url of [
      '/c/AbCdEf',
      '/c/AbCdEf/continue?n=nonce',
      '/C/AbCdEf',
      '//c//AbCdEf',
      'http://protect.example/c/AbCdEf?x=1',
    ]) {
      expect(ignore({ url })).toBe(true);
    }
  });

  it('keeps other paths traced', () => {
    for (const url of ['/health/ready', '/metrics', '/static/click.css', '/cx', undefined]) {
      expect(ignore({ url })).toBe(false);
    }
    expect(untracedIncomingRequest([])({ url: '/c/x' })).toBe(false);
    expect(ignore({ url: 'not a url' })).toBe(false);
  });
});

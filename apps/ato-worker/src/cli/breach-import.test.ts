import { describe, expect, it } from 'vitest';
import { parseAddresses, parseBreachImportArgs } from './breach-import';

describe('breach:import arguments', () => {
  it('parses the documented options with defaults', () => {
    expect(parseBreachImportArgs(['--', '--source', 'ops-list', '--file', '/tmp/x.txt'])).toEqual({
      source: 'ops-list',
      file: '/tmp/x.txt',
      severity: 'medium',
      expiresDays: 365,
    });
    expect(
      parseBreachImportArgs([
        '--source',
        'a',
        '--file',
        'f',
        '--severity',
        'high',
        '--expires-days',
        '30',
      ]),
    ).toMatchObject({ severity: 'high', expiresDays: 30 });
  });

  it('refuses bad input', () => {
    expect(() => parseBreachImportArgs(['--file', 'f'])).toThrow(/--source/);
    expect(() => parseBreachImportArgs(['--source', 'Bad Name', '--file', 'f'])).toThrow();
    expect(() => parseBreachImportArgs(['--source', 'a'])).toThrow(/--file/);
    expect(() =>
      parseBreachImportArgs(['--source', 'a', '--file', 'f', '--severity', 'extreme']),
    ).toThrow(/severity/);
    expect(() =>
      parseBreachImportArgs(['--source', 'a', '--file', 'f', '--expires-days', '0']),
    ).toThrow(/expires/);
    expect(() => parseBreachImportArgs(['--source', 'a', '--file', 'f', '--token', 'x'])).toThrow(
      /unknown option/,
    );
  });
});

describe('breach:import file parsing', () => {
  it('lower-cases, drops comments, blanks, invalid lines and duplicates (counts only)', () => {
    const text = [
      '# operator list',
      'Alice@Example.TEST',
      '',
      'alice@example.test',
      'not-an-address',
      'bob@example.test',
      'x'.repeat(330) + '@example.test',
    ].join('\n');
    expect(parseAddresses(text)).toEqual({
      addresses: ['alice@example.test', 'bob@example.test'],
      read: 5,
      invalid: 2,
      duplicates: 1,
    });
  });
});

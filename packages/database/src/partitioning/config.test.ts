import { describe, expect, it } from 'vitest';
import { loadConfig } from '@email-gateway/config';
import { maintenanceConfigSchema, parseArgs, parseDay, parseInstant } from './config';

describe('parseArgs', () => {
  it('parses positionals, value flags (spaced or inline) and boolean flags', () => {
    const args = parseArgs(
      ['--', 'apply', '--now', '2026-11-01T00:00:00Z', '--bootstrap-from=2026-07-01', '--no-purge'],
      ['now', 'bootstrap-from'],
      ['no-purge'],
    );
    expect(args.positionals).toEqual(['apply']);
    expect(args.values).toEqual({ now: '2026-11-01T00:00:00Z', 'bootstrap-from': '2026-07-01' });
    expect([...args.flags]).toEqual(['no-purge']);
  });

  it('rejects unknown options and missing values', () => {
    expect(() => parseArgs(['--drop-everything'], [], [])).toThrow(/Unknown option/);
    expect(() => parseArgs(['--now'], ['now'], [])).toThrow(/requires a value/);
  });
});

describe('date flags', () => {
  it('parses ISO instants and YYYY-MM-DD days in UTC', () => {
    expect(parseInstant('2026-12-31T23:00:00Z', '--now').toISOString()).toBe(
      '2026-12-31T23:00:00.000Z',
    );
    expect(parseDay('2028-02-29', '--bootstrap-from').toISOString()).toBe(
      '2028-02-29T00:00:00.000Z',
    );
    expect(() => parseDay('2027-02-29', '--bootstrap-from')).toThrow(/invalid date/);
    expect(() => parseDay('2026/01/01', '--bootstrap-from')).toThrow(/YYYY-MM-DD/);
    expect(() => parseInstant('yesterday', '--now')).toThrow(/invalid/);
  });
});

describe('maintenanceConfigSchema', () => {
  it('requires a mysql:// MIGRATION_DATABASE_URL', () => {
    expect(() => loadConfig(maintenanceConfigSchema, {})).toThrow(/MIGRATION_DATABASE_URL/);
    expect(() =>
      loadConfig(maintenanceConfigSchema, { MIGRATION_DATABASE_URL: 'postgres://x' }),
    ).toThrow(/mysql/);
    expect(
      loadConfig(maintenanceConfigSchema, { MIGRATION_DATABASE_URL: 'mysql://u:p@h:3306/db' })
        .MIGRATION_DATABASE_URL,
    ).toBe('mysql://u:p@h:3306/db');
  });
});

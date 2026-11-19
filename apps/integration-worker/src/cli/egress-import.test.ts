import { describe, expect, it } from 'vitest';
import { main, parseCliArgs } from './egress-import';

const valid = [
  '--provider',
  'microsoft_365',
  '--file',
  '/tmp/x.json',
  '--source',
  'https://learn.microsoft.com/microsoft-365/enterprise/urls-and-ip-address-ranges',
  '--published-at',
  '2026-11-01T00:00:00Z',
  '--operator',
  'ops.oncall',
];

describe('egress-import CLI arguments (D11)', () => {
  it('parses every option', () => {
    expect(parseCliArgs([...valid, '--force'])).toEqual({
      provider: 'microsoft_365',
      file: '/tmp/x.json',
      source: 'https://learn.microsoft.com/microsoft-365/enterprise/urls-and-ip-address-ranges',
      publishedAt: new Date('2026-11-01T00:00:00Z'),
      operator: 'ops.oncall',
      force: true,
      dryRun: false,
    });
  });

  it('refuses a missing or invalid option with the usage', () => {
    expect(() => parseCliArgs(valid.slice(2))).toThrow(/--provider/);
    expect(() => parseCliArgs(valid.slice(0, -2))).toThrow(/--operator is required/);
    expect(() =>
      parseCliArgs(valid.map((v) => (v === '2026-11-01T00:00:00Z' ? 'soon' : v))),
    ).toThrow(/--published-at/);
    expect(() => parseCliArgs([...valid, '--unknown'])).toThrow();
  });

  it('exits 1 without touching the database when the file is unreadable', async () => {
    const errors: string[] = [];
    const code = await main(
      valid.map((v) => (v === '/tmp/x.json' ? '/nonexistent/egress.json' : v)),
      {},
      () => undefined,
      (line) => errors.push(line),
    );
    expect(code).toBe(1);
    expect(errors.join('\n')).toContain('--file is not readable JSON');
  });
});

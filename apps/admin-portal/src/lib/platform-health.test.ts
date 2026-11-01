import { describe, expect, it } from 'vitest';
import { summarizeHealth } from './platform-health';

describe('summarizeHealth', () => {
  it('marks a missing report as unreachable', () => {
    expect(summarizeHealth(null)).toEqual({ reachable: false, status: 'unreachable', checks: [] });
  });

  it('marks a report with failing checks as degraded', () => {
    const summary = summarizeHealth({
      service: 'api',
      status: 'error',
      version: '1.0.0',
      uptimeSeconds: 5,
      checks: [{ name: 'mysql', status: 'error', latencyMs: 2000, error: 'timed out' }],
    });
    expect(summary).toMatchObject({ reachable: true, status: 'degraded', version: '1.0.0' });
  });
});

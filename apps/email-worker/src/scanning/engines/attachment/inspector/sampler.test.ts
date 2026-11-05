import { describe, expect, it } from 'vitest';
import { parseProcStat, parseProcStatusRss, parsePsTime, procSampler, psSampler } from './sampler';

describe('inspector resource sampler (step 4.2 A4)', () => {
  it('parses /proc/<pid>/stat utime + stime in clock ticks', () => {
    const stat =
      '4242 (node (worker)) S 1 4242 4242 0 -1 4194304 1000 0 0 0 250 50 0 0 20 0 7 0 100 1000 200 18446744073709551615';
    expect(parseProcStat(stat)).toBe(3);
    expect(parseProcStat('garbage')).toBeNull();
  });

  it('parses VmRSS of /proc/<pid>/status', () => {
    expect(parseProcStatusRss('Name:\tnode\nVmRSS:\t  204800 kB\nThreads: 7\n')).toBe(200);
    expect(parseProcStatusRss('Name:\tnode\n')).toBeNull();
  });

  it('parses ps time formats of macOS and Linux', () => {
    expect(parsePsTime('0:01.50')).toBe(1.5);
    expect(parsePsTime('12:03.25')).toBe(723.25);
    expect(parsePsTime('01:02:03')).toBe(3723);
    expect(parsePsTime('1-00:00:01')).toBe(86_401);
    expect(parsePsTime('soon')).toBeNull();
  });

  it('samples this process with the platform sampler and returns null for a gone pid', async () => {
    const sampler = process.platform === 'linux' ? procSampler : psSampler;
    const sample = await sampler(process.pid);
    expect(sample).not.toBeNull();
    expect(sample!.rssMb).toBeGreaterThan(10);
    expect(sample!.cpuSeconds).toBeGreaterThan(0);
    expect(await sampler(2 ** 22 + 12_345)).toBeNull();
  });
});

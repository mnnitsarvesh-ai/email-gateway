import { InternalServerErrorException, Logger } from '@nestjs/common';
import { MetricsService } from '@email-gateway/common';
import type * as Dlp from '@email-gateway/dlp';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DlpConfigRepository } from '../repositories/dlp-config.repository';
import { DlpPatternsService } from './dlp-patterns.service';
import type { DlpAuditor } from './dlp-views';
import { DlpMetrics, type DlpWriter } from './dlp-writer';

const MARKER = 'PATTERN-AND-SAMPLE-MARKER-91c2';
const explode = vi.hoisted(() => ({ on: false }));

vi.mock('@email-gateway/dlp', async (original) => {
  const actual = await original<typeof Dlp>();
  return {
    ...actual,
    testCustomPattern: (...args: Parameters<typeof actual.testCustomPattern>) => {
      // An unexpected library failure whose message carries the pattern (the worst case).
      if (explode.on) throw new RangeError(`internal failure on ${String(args[0].pattern)}`);
      return actual.testCustomPattern(...args);
    },
  };
});

const limits = {
  DLP_CUSTOM_PATTERNS_MAX_PER_TENANT: 50,
  DLP_CUSTOM_PATTERN_MAX_LENGTH: 256,
  DLP_CUSTOM_PATTERN_PROBE_MAX_MS: 50,
};

function service() {
  const metricsService = new MetricsService({ service: 't' });
  return {
    metricsService,
    patterns: new DlpPatternsService(
      limits,
      {} as DlpConfigRepository,
      {} as DlpWriter,
      {} as DlpAuditor,
      new DlpMetrics(metricsService),
    ),
  };
}

afterEach(() => {
  explode.on = false;
  vi.restoreAllMocks();
});

describe('DlpPatternsService.test (step 4.5 D9)', () => {
  it('returns masked matches and counts the result; never logs', async () => {
    const log = vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const { patterns, metricsService } = service();
    const result = patterns.test({
      pattern: 'ACCT-[0-9]{8}',
      caseInsensitive: false,
      sample: `${MARKER} ACCT-12345678`,
    });
    expect(result).toMatchObject({ valid: true, code: null });
    expect(result.matches).toEqual([
      expect.objectContaining({ masked: '********5678', validated: true }),
    ]);
    expect(JSON.stringify(result)).not.toContain(MARKER);
    expect(log).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
    const invalid = patterns.test({ pattern: '(a)\\1', caseInsensitive: false, sample: 'x' });
    expect(invalid).toMatchObject({ valid: false, code: 'pattern_unsupported', matches: [] });
    const text = await metricsService.metrics();
    expect(text).toContain('dlp_pattern_tests_total{result="valid",service="t"} 1');
    expect(text).toContain('dlp_pattern_tests_total{result="invalid",service="t"} 1');
  });

  it('turns an unexpected failure into a generic 500 whose log and body never carry the pattern', () => {
    explode.on = true;
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const { patterns } = service();
    let caught: unknown;
    try {
      patterns.test({ pattern: MARKER, caseInsensitive: false, sample: MARKER });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(InternalServerErrorException);
    const body = JSON.stringify((caught as InternalServerErrorException).getResponse());
    expect(body).not.toContain(MARKER);
    expect((caught as Error).message).not.toContain(MARKER);
    expect((caught as Error).cause).toBeUndefined();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(warn.mock.calls)).not.toContain(MARKER);
    expect(warn.mock.calls[0]![0]).toMatchObject({ errorName: 'RangeError' });
  });
});

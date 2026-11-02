import { BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { UsageQuerySchema } from '../dto/organizations.schemas';
import { resolveUsagePeriod, startOfUtcDay } from './usage-period';

const DAY = 24 * 60 * 60 * 1000;
const now = new Date('2026-11-02T10:30:00.000Z');

describe('resolveUsagePeriod', () => {
  it('defaults to the last 30 days', () => {
    const period = resolveUsagePeriod({}, now);
    expect(period.to).toEqual(now);
    expect(period.to.getTime() - period.from.getTime()).toBe(30 * DAY);
  });

  it('defaults from to 30 days before an explicit to', () => {
    const to = new Date('2026-10-15T00:00:00.000Z');
    expect(resolveUsagePeriod({ to }, now).from).toEqual(new Date(to.getTime() - 30 * DAY));
  });

  it('accepts exactly 31 days', () => {
    const from = new Date(now.getTime() - 31 * DAY);
    expect(resolveUsagePeriod({ from, to: now }, now)).toEqual({ from, to: now });
  });

  it('rejects windows over 31 days', () => {
    const from = new Date(now.getTime() - 31 * DAY - 1);
    expect(() => resolveUsagePeriod({ from, to: now }, now)).toThrow(BadRequestException);
  });

  it('rejects from >= to', () => {
    expect(() => resolveUsagePeriod({ from: now, to: now }, now)).toThrow(BadRequestException);
    expect(() => resolveUsagePeriod({ from: new Date(now.getTime() + 1), to: now }, now)).toThrow(
      BadRequestException,
    );
  });

  it('rejects an explicit from alone that is more than 31 days back', () => {
    const from = new Date(now.getTime() - 40 * DAY);
    let error: unknown;
    try {
      resolveUsagePeriod({ from }, now);
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(BadRequestException);
    expect((error as BadRequestException).getResponse()).toMatchObject({
      message: ['(root): the period must not exceed 31 days'],
    });
  });
});

describe('UsageQuerySchema', () => {
  const pipe = new ZodValidationPipe(UsageQuerySchema);

  it('parses ISO 8601 date-times with an offset', () => {
    expect(
      pipe.transform({ from: '2026-10-01T00:00:00Z', to: '2026-10-02T00:00:00+05:30' }),
    ).toEqual({
      from: new Date('2026-10-01T00:00:00Z'),
      to: new Date('2026-10-01T18:30:00Z'),
    });
  });

  it.each(['yesterday', '2026-13-01T00:00:00Z', '1730000000'])('rejects %j', (from) => {
    expect(() => pipe.transform({ from })).toThrow(BadRequestException);
  });
});

describe('startOfUtcDay', () => {
  it('truncates to midnight UTC', () => {
    expect(startOfUtcDay(now)).toEqual(new Date('2026-11-02T00:00:00.000Z'));
  });
});

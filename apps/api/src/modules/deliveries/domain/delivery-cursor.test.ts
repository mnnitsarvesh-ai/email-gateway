import { BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import {
  decodeDeliveryCursor,
  deliveryRange,
  encodeDeliveryCursor,
  MAX_RANGE_MS,
} from './delivery-cursor';

describe('delivery keyset cursor', () => {
  it('round-trips (received_at, id)', () => {
    const cursor = { receivedAt: new Date('2026-11-03T10:11:12.345Z'), id: 987654321n };
    expect(decodeDeliveryCursor(encodeDeliveryCursor(cursor))).toEqual(cursor);
  });

  it.each([
    '',
    'x',
    Buffer.from('1.0').toString('base64url'),
    Buffer.from('a.1').toString('base64url'),
    Buffer.from('01.1').toString('base64url') + '=',
  ])('refuses %j with 400', (value) => {
    expect(() => decodeDeliveryCursor(value)).toThrow(BadRequestException);
  });
});

describe('deliveryRange', () => {
  const now = new Date('2026-11-03T12:00:00.000Z');

  it('defaults to the last 24 hours', () => {
    expect(deliveryRange({}, now)).toEqual({ from: new Date('2026-11-02T12:00:00.000Z'), to: now });
    expect(deliveryRange({ to: '2026-11-01T00:00:00Z' }, now)).toEqual({
      from: new Date('2026-10-31T00:00:00.000Z'),
      to: new Date('2026-11-01T00:00:00.000Z'),
    });
  });

  it('allows at most 31 days and needs from < to', () => {
    const to = now.toISOString();
    expect(
      deliveryRange({ from: new Date(now.getTime() - MAX_RANGE_MS).toISOString(), to }, now).to,
    ).toEqual(now);
    expect(() =>
      deliveryRange({ from: new Date(now.getTime() - MAX_RANGE_MS - 1).toISOString(), to }, now),
    ).toThrow(BadRequestException);
    expect(() => deliveryRange({ from: to, to }, now)).toThrow(BadRequestException);
  });
});

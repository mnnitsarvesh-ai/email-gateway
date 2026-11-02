import { BadRequestException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import { decodeCursor, encodeCursor } from '../../http/pagination';
import type { UsersRepository } from '../users/users.repository';
import type { LoginEventRecord, LoginEventsRepository } from './login-events.repository';
import { LoginEventsService, loginEventsWindow } from './login-events.service';

const DAY = 86_400_000;
const now = new Date('2026-11-02T10:00:00Z');
const scope = systemScope(7n);
const USER_ID = '0190a0b0-0000-7000-8000-000000000033';

const row = (id: bigint, userId: bigint | null): LoginEventRecord => ({
  id,
  userId,
  emailAttempted: 'a@example.test',
  outcome: 'failure',
  failureReason: 'invalid_password',
  ipAddress: '203.0.113.1',
  userAgent: 'ua',
  createdAt: now,
});

describe('loginEventsWindow', () => {
  it('defaults to the last 7 days', () => {
    expect(loginEventsWindow({}, now)).toEqual({
      from: new Date(now.getTime() - 7 * DAY),
      to: now,
    });
  });

  it('allows up to 90 days and requires from < to', () => {
    const to = now.toISOString();
    const from90 = new Date(now.getTime() - 90 * DAY).toISOString();
    expect(loginEventsWindow({ from: from90, to }, now).from.toISOString()).toBe(from90);
    expect(() =>
      loginEventsWindow({ from: new Date(now.getTime() - 91 * DAY).toISOString(), to }, now),
    ).toThrow(BadRequestException);
    expect(() => loginEventsWindow({ from: to, to }, now)).toThrow(BadRequestException);
  });
});

describe('LoginEventsService', () => {
  function setup(rows: LoginEventRecord[], userId: bigint | null = 33n) {
    const events = { list: vi.fn(() => Promise.resolve(rows)) };
    const users = {
      findIdByPublicId: vi.fn(() => Promise.resolve(userId)),
      publicIds: vi.fn(() => Promise.resolve(new Map([[33n, USER_ID]]))),
    };
    const service = new LoginEventsService(
      events as unknown as LoginEventsRepository,
      users as unknown as UsersRepository,
    );
    return { service, events, users };
  }

  it('maps rows (decimal ids, public user ids) and returns a cursor for the next page', async () => {
    const { service, events } = setup([row(12n, 33n), row(11n, null), row(10n, 33n)]);
    const page = await service.list(scope, { limit: 2, outcome: 'failure' }, now);
    expect(page.data.map((e) => [e.id, e.userId])).toEqual([
      ['12', USER_ID],
      ['11', null],
    ]);
    expect(page.nextCursor).not.toBeNull();
    expect(decodeCursor(page.nextCursor!)).toBe(11n);
    expect(events.list).toHaveBeenCalledWith(
      scope,
      expect.objectContaining({ outcome: 'failure' }),
      { take: 3 },
    );
  });

  it('continues below the cursor', async () => {
    const { service, events } = setup([]);
    await service.list(scope, { limit: 25, cursor: encodeCursor(11n) }, now);
    expect(events.list).toHaveBeenCalledWith(scope, expect.anything(), { take: 26, beforeId: 11n });
  });

  it('filters by a user of the scope; an unknown or foreign user matches nothing', async () => {
    const found = setup([row(1n, 33n)]);
    await found.service.list(scope, { limit: 25, userId: USER_ID }, now);
    expect(found.events.list).toHaveBeenCalledWith(
      scope,
      expect.objectContaining({ userId: 33n }),
      expect.anything(),
    );

    const foreign = setup([row(1n, 33n)], null);
    expect(await foreign.service.list(scope, { limit: 25, userId: USER_ID }, now)).toEqual({
      data: [],
      nextCursor: null,
    });
    expect(foreign.events.list).not.toHaveBeenCalled();
  });
});

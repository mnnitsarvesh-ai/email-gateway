import { $Enums, type MessageStatus } from '@email-gateway/database';
import { MESSAGE_STATES as CONTRACT_STATES } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { MESSAGE_STATES, type MessageState } from './states';

/** §9 item 2: one list of states for the database, the events and the lifecycle. */

type Equals<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;

// Compile-time: the Prisma enum and the lifecycle states are the same union.
const prismaEqualsLifecycle: Equals<MessageStatus, MessageState> = true;

describe('MESSAGE_STATES', () => {
  it('equals the Prisma MessageStatus enum (type and values, in enum order)', () => {
    expect(prismaEqualsLifecycle).toBe(true);
    expect(Object.values($Enums.MessageStatus)).toEqual([...MESSAGE_STATES]);
  });

  it('is the event-contracts list (re-exported, defined once)', () => {
    expect(MESSAGE_STATES).toBe(CONTRACT_STATES);
    expect(MESSAGE_STATES).toHaveLength(15);
  });
});

import { $Enums, type MessageIngestSource, type MessageStatus } from '@email-gateway/database';
import {
  MESSAGE_STATES as CONTRACT_STATES,
  MESSAGE_INGEST_SOURCE_VALUES,
} from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { MESSAGE_STATES, type MessageState } from './states';
import { MESSAGE_INGEST_SOURCES, type MessageIngestSourceValue } from './transitions';

/** §9 item 2: one list of states for the database, the events and the lifecycle. */

type Equals<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;

// Compile-time: the Prisma enum and the lifecycle states are the same union.
const prismaEqualsLifecycle: Equals<MessageStatus, MessageState> = true;
// Compile-time (step API-1): the Prisma ingest sources and the lifecycle's are the same union.
const prismaEqualsIngestSources: Equals<MessageIngestSource, MessageIngestSourceValue> = true;

describe('MESSAGE_INGEST_SOURCES (step 8.6, API-1)', () => {
  it('equals the Prisma MessageIngestSource enum and the event-contracts list, in enum order', () => {
    expect(prismaEqualsIngestSources).toBe(true);
    expect(Object.values($Enums.MessageIngestSource)).toEqual([...MESSAGE_INGEST_SOURCES]);
    expect([...MESSAGE_INGEST_SOURCE_VALUES]).toEqual([...MESSAGE_INGEST_SOURCES]);
  });
});

describe('MESSAGE_STATES', () => {
  it('equals the Prisma MessageStatus enum (type and values, in enum order)', () => {
    expect(prismaEqualsLifecycle).toBe(true);
    expect(Object.values($Enums.MessageStatus)).toEqual([...MESSAGE_STATES]);
  });

  it('is the event-contracts list (re-exported, defined once)', () => {
    expect(MESSAGE_STATES).toBe(CONTRACT_STATES);
    // Step 8.6 appended `journaled` (ADR-0087).
    expect(MESSAGE_STATES).toHaveLength(16);
  });
});

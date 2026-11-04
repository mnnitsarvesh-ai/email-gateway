import { EXAMPLE_EVENT_PAYLOADS } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { outboxRow } from '../testing/fakes';
import { buildEnvelope, relayLockName } from './envelope';

const options = { appId: 'event-relay', maxMessageBytes: 131_072 };

describe('buildEnvelope', () => {
  it('accepts a payload stored as JSON text', () => {
    const payload = EXAMPLE_EVENT_PAYLOADS['mail.message.received.v1'];
    const built = buildEnvelope(outboxRow({ payload: JSON.stringify(payload) }), options);
    expect(built).toMatchObject({ ok: true, envelope: { payload } });
  });

  it('refuses unparseable JSON text and a malformed correlation id as contract_invalid', () => {
    expect(buildEnvelope(outboxRow({ payload: '{nope' }), options)).toEqual({
      ok: false,
      code: 'contract_invalid',
    });
    expect(buildEnvelope(outboxRow({ correlationId: 'short' }), options)).toEqual({
      ok: false,
      code: 'contract_invalid',
    });
  });

  it('validates every registered example payload', () => {
    for (const [eventType, payload] of Object.entries(EXAMPLE_EVENT_PAYLOADS)) {
      expect(buildEnvelope(outboxRow({ eventType, payload }), options).ok).toBe(true);
    }
  });
});

describe('relayLockName', () => {
  it('fits the 64-character GET_LOCK limit for every shard count', () => {
    expect(relayLockName('er', 0, 4)).toBe('er:relay#0/4');
    expect(relayLockName('er', 63, 64).length).toBeLessThanOrEqual(64);
  });
});

import { messageRescanRequestedV1 } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { jobStates, RESCAN_SELECTABLE_STATES, SYSTEM_REQUESTED_BY } from './rescan-runner';

describe('RescanJobRunner contracts (step 4.2 A13)', () => {
  it('restricts job states to the selectable ones (never scanning, delivery or terminal)', () => {
    expect(RESCAN_SELECTABLE_STATES).toEqual([
      'scanned',
      'scan_failed',
      'quarantined',
      'held_for_review',
    ]);
    expect(jobStates(['scanned', 'delivered', 'scanning'])).toEqual(['scanned']);
    expect(jobStates('["quarantined","quarantined"]')).toEqual(['quarantined']);
    expect(jobStates([])).toEqual(RESCAN_SELECTABLE_STATES);
    expect(jobStates(null)).toEqual(RESCAN_SELECTABLE_STATES);
  });

  it('builds a rescan_requested.v1 payload the event contract accepts', () => {
    expect(SYSTEM_REQUESTED_BY).toBe('system');
    for (const requestedBy of ['user', SYSTEM_REQUESTED_BY]) {
      const parsed = messageRescanRequestedV1.safeParse({
        messageId: '123',
        receivedAt: '2026-11-05T10:00:00.000Z',
        direction: 'inbound',
        emlS3Key: 'org/7/eml/2026/11/05/x.eml',
        lifecycleRound: 2,
        scanKind: 'rescan',
        requestedAt: '2026-11-05T11:00:00.000Z',
        requestedBy,
      });
      expect(parsed.success).toBe(true);
    }
  });
});

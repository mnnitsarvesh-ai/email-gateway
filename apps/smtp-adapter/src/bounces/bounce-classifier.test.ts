import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { bounceDedupeKey, classifyBounce, SUPPRESSING_STATUSES } from './bounce-classifier';
import type { DsnRecipient } from './dsn-parser';

const recipient = (action: string, status: string | null): DsnRecipient => ({
  finalRecipient: 'x@sink.test',
  originalRecipient: null,
  action,
  status,
  remoteMta: null,
  diagnosticCode: null,
  smtpCode: null,
});

describe('classifyBounce (D13)', () => {
  it('failed → hard; address failures suppress', () => {
    for (const status of ['5.1.1', '5.1.2', '5.1.3', '5.1.6', '5.1.10', '5.2.1']) {
      expect(classifyBounce(recipient('failed', status))).toEqual({
        bounceType: 'hard',
        reputationEvent: 'bounced_hard',
        suppress: true,
      });
    }
    expect(SUPPRESSING_STATUSES.size).toBe(6);
  });

  it('failed with other permanent statuses → hard without suppression', () => {
    for (const status of ['5.7.1', '5.4.4', '5.2.2', '5.1.0', null]) {
      expect(classifyBounce(recipient('failed', status))).toEqual({
        bounceType: 'hard',
        reputationEvent: 'bounced_hard',
        suppress: false,
      });
    }
  });

  it('failed after transient errors (queue lifetime expired) → bounced_soft, no suppression', () => {
    expect(classifyBounce(recipient('failed', '4.4.1'))).toEqual({
      bounceType: 'hard',
      reputationEvent: 'bounced_soft',
      suppress: false,
    });
  });

  it('delayed → soft / delayed', () => {
    expect(classifyBounce(recipient('delayed', '4.2.1'))).toEqual({
      bounceType: 'soft',
      reputationEvent: 'delayed',
      suppress: false,
    });
  });

  it('ignores delivered, relayed and expanded', () => {
    for (const action of ['delivered', 'relayed', 'expanded']) {
      expect(classifyBounce(recipient(action, '2.0.0'))).toBeNull();
    }
  });
});

describe('bounceDedupeKey', () => {
  it('is hex SHA-256 of queueId|finalRecipient|action|status', () => {
    expect(bounceDedupeKey('Q1', recipient('failed', '5.1.1'))).toBe(
      createHash('sha256').update('Q1|x@sink.test|failed|5.1.1').digest('hex'),
    );
    expect(bounceDedupeKey('Q1', recipient('delayed', '4.2.1'))).not.toBe(
      bounceDedupeKey('Q1', recipient('failed', '4.2.1')),
    );
    expect(bounceDedupeKey('Q1', recipient('failed', null))).toHaveLength(64);
  });
});

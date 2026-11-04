import { BadRequestException } from '@nestjs/common';
import { MESSAGE_STATES, type MessageState } from '@email-gateway/message-lifecycle';
import { describe, expect, it } from 'vitest';
import { CodedHttpException } from '../../../http/coded-exception';
import { IdempotencyRaceError } from '../../../http/idempotency/idempotency.service';
import {
  MESSAGE_NOT_FOUND,
  MESSAGE_STATE_CONFLICT,
  MESSAGE_VERSION_CONFLICT,
} from '../messages.errors';
import {
  allowedActions,
  apiTransitionKey,
  chunk,
  decisionConflict,
  decodeHistoryCursor,
  encodeHistoryCursor,
  nextDeliverySeq,
  operationTransition,
  outcomeError,
  RELEASE_SOURCES,
  releaseReasonFor,
  RESCAN_SOURCES,
} from './lifecycle-operations';

const snapshot = {
  state: 'delivered' as MessageState,
  version: 5,
  round: 0,
  statusChangedAt: new Date(),
  statusReason: null,
  direction: 'inbound' as const,
  emlObjectKey: 'org/1/eml/x.eml',
};

describe('lifecycle operation rules (L10, from the transition table)', () => {
  it('rescan sources are E19, release sources E14/E15', () => {
    expect([...RESCAN_SOURCES].sort()).toEqual(
      [
        'scanning',
        'scanned',
        'scan_failed',
        'policy_evaluated',
        'quarantined',
        'held_for_review',
        'expired',
      ].sort(),
    );
    expect(RELEASE_SOURCES).toEqual(['quarantined', 'held_for_review']);
  });

  it('chooses the release reason from the current state', () => {
    expect(releaseReasonFor('quarantined')).toBe('quarantine_release');
    expect(releaseReasonFor('held_for_review')).toBe('review_release');
    expect(operationTransition('release', 'held_for_review')).toEqual({
      to: 'approved',
      reason: 'review_release',
      expectedFrom: RELEASE_SOURCES,
    });
    expect(operationTransition('rescan', 'expired')).toEqual({
      to: 'scanning',
      reason: 'admin_rescan',
      expectedFrom: RESCAN_SOURCES,
    });
  });

  it('derives the allowed actions of every state from the edges only', () => {
    const actions = Object.fromEntries(MESSAGE_STATES.map((s) => [s, allowedActions(s)]));
    for (const state of MESSAGE_STATES) {
      expect(actions[state]!.rescan, state).toBe(RESCAN_SOURCES.includes(state));
      expect(actions[state]!.release, state).toBe(RELEASE_SOURCES.includes(state));
    }
    expect(actions.persisted).toEqual({ rescan: false, release: false });
    expect(actions.quarantined).toEqual({ rescan: true, release: true });
    expect(actions.delivered).toEqual({ rescan: false, release: false });
    expect(actions.scanning).toEqual({ rescan: true, release: false });
  });

  it('builds the L5.3 api transition key', () => {
    expect(apiTransitionKey(42n, 'rescan', 'k-1')).toBe('api:42:message.rescan:k-1');
    expect(apiTransitionKey(42n, 'release', 'k-1')).toBe('api:42:message.release:k-1');
  });
});

describe('outcome mapping (L10.1)', () => {
  const codeOf = (error: Error) => {
    expect(error).toBeInstanceOf(CodedHttpException);
    const coded = error as CodedHttpException;
    return { status: coded.getStatus(), code: coded.code, details: coded.details };
  };

  it('stale/version_mismatch is 409 message_version_conflict with the current state', () => {
    expect(
      codeOf(decisionConflict({ result: 'stale', why: 'version_mismatch' }, snapshot)),
    ).toEqual({
      status: 409,
      code: MESSAGE_VERSION_CONFLICT,
      details: { currentState: 'delivered', currentVersion: 5 },
    });
  });

  it.each([
    { result: 'stale', why: 'final_state' },
    { result: 'stale', why: 'overtaken' },
    { result: 'invalid', why: 'unexpected_from' },
    { result: 'invalid', why: 'edge_not_allowed' },
    { result: 'duplicate', why: 'same_state' },
  ] as const)('%o is 409 message_state_conflict', (decision) => {
    expect(codeOf(decisionConflict(decision, snapshot)).code).toBe(MESSAGE_STATE_CONFLICT);
    expect(codeOf(outcomeError({ ...decision, snapshot })).code).toBe(MESSAGE_STATE_CONFLICT);
  });

  it('not_found is 404, a transition-key duplicate is a race (replay)', () => {
    expect(codeOf(outcomeError({ result: 'not_found' }))).toMatchObject({
      status: 404,
      code: MESSAGE_NOT_FOUND,
    });
    expect(outcomeError({ result: 'duplicate', why: 'transition_key', snapshot })).toBeInstanceOf(
      IdempotencyRaceError,
    );
    expect(codeOf(outcomeError({ result: 'stale', why: 'version_mismatch', snapshot })).code).toBe(
      MESSAGE_VERSION_CONFLICT,
    );
  });
});

describe('release helpers', () => {
  it('deliverySeq is the highest + 1, or 1 without deliveries', () => {
    expect(nextDeliverySeq(null)).toBe(1);
    expect(nextDeliverySeq(0)).toBe(1);
    expect(nextDeliverySeq(3)).toBe(4);
  });

  it('chunks approvals by at most n recipients', () => {
    const items = Array.from({ length: 2501 }, (_, i) => i);
    expect(chunk(items, 1000).map((c) => c.length)).toEqual([1000, 1000, 501]);
    expect(chunk([], 1000)).toEqual([]);
    expect(chunk([1, 2, 3], 1000)).toEqual([[1, 2, 3]]);
    expect(() => chunk(items, 0)).toThrow();
  });
});

describe('history cursor', () => {
  it('round-trips a version and refuses anything else', () => {
    for (const version of [0, 1, 99, 4_294_967_295]) {
      expect(decodeHistoryCursor(encodeHistoryCursor(version))).toBe(version);
    }
    for (const bad of ['', 'x', Buffer.from('v-1').toString('base64url'), 'djAx', 'dg']) {
      expect(() => decodeHistoryCursor(bad)).toThrow(BadRequestException);
    }
  });
});

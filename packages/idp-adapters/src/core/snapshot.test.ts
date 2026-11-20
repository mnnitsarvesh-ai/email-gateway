import { describe, expect, it } from 'vitest';
import type { ProviderIdentityRef } from '../port/ato-port';
import { InMemoryMailboxStateStore } from '../testing/in-memory-stores';
import { identityHash } from './hash';
import { diffSnapshot, streamOfMailboxChange, type SnapshotItem } from './snapshot';

const NOW = new Date('2026-11-10T12:00:00.000Z');
const identity: ProviderIdentityRef = {
  provider: 'microsoft_entra',
  externalId: 'user-1',
  primaryEmail: 'alex@contoso-it.example',
};
const INTEGRATION = '501';
const hash = identityHash('microsoft_entra', 'user-1');

const forwardRule: SnapshotItem = {
  kind: 'inbox_rule',
  itemHash: 'a'.repeat(64),
  providerItemRef: 'rule-1',
  targetDomain: 'evil-mail.example',
  traits: ['forwards', 'forwards_external'],
  enabled: true,
  source: 'snapshot',
};
const archiveRule: SnapshotItem = {
  ...forwardRule,
  itemHash: 'b'.repeat(64),
  providerItemRef: 'rule-2',
  targetDomain: null,
  traits: ['moves_to_folder'],
};

async function step(store: InMemoryMailboxStateStore, current: SnapshotItem[], cursorSeq: bigint) {
  const known = await store.load(INTEGRATION, hash);
  const result = diffSnapshot({
    provider: 'microsoft_entra',
    identity,
    current,
    known,
    coveredKinds: ['inbox_rule'],
    cursorSeq,
    pageSeq: cursorSeq + 1n,
    now: NOW,
  });
  await store.write(INTEGRATION, identity, result.writes, cursorSeq + 1n);
  return result;
}

describe('snapshot diff with cursor-confirmed state (D8.3)', () => {
  it('emits added, changed and removed with deterministic ids and the right companion stream', async () => {
    const store = new InMemoryMailboxStateStore(() => NOW.getTime());
    const first = await step(store, [forwardRule, archiveRule], 0n);
    expect(first.events.map((e) => [e.stream, e.mailbox?.change])).toEqual([
      ['forwarding_changes', 'inbox_rule_added'],
      ['mailbox_audit', 'inbox_rule_added'],
    ]);
    expect(first.events[0]?.eventId).toMatch(/^snap:[0-9a-f]{32}$/);
    expect(first.events[0]?.mailbox).toEqual({
      change: 'inbox_rule_added',
      targetDomain: 'evil-mail.example',
      ruleHash: forwardRule.itemHash,
      ruleTraits: ['forwards', 'forwards_external'],
    });
    // Unchanged state: nothing.
    expect((await step(store, [forwardRule, archiveRule], 1n)).events).toEqual([]);
    // Changed traits.
    const changed = await step(
      store,
      [{ ...forwardRule, traits: ['forwards', 'forwards_external', 'deletes'] }, archiveRule],
      2n,
    );
    expect(changed.events.map((e) => e.mailbox?.change)).toEqual(['inbox_rule_changed']);
    // Removed: rules emit no removal event, but the row is removed.
    const removed = await step(store, [archiveRule], 3n);
    expect(removed.events).toEqual([]);
    expect(store.all(INTEGRATION).find((r) => r.itemHash === forwardRule.itemHash)?.state).toBe(
      'removed',
    );
  });

  it('records disabled rules as state only and emits when they are enabled', async () => {
    const store = new InMemoryMailboxStateStore(() => NOW.getTime());
    expect((await step(store, [{ ...forwardRule, enabled: false }], 0n)).events).toEqual([]);
    expect((await step(store, [forwardRule], 1n)).events.map((e) => e.mailbox?.change)).toEqual([
      'inbox_rule_changed',
    ]);
  });

  it('re-emits the identical event when the page that wrote the change was never committed', async () => {
    const store = new InMemoryMailboxStateStore(() => NOW.getTime());
    const first = await step(store, [forwardRule], 5n); // page seq 6, runner crashed: cursor stays 5
    const replay = await step(store, [forwardRule], 5n);
    expect(replay.events.map((e) => e.eventId)).toEqual(first.events.map((e) => e.eventId));
    // Once the cursor with seq 6 was committed, the change is known.
    expect((await step(store, [forwardRule], 6n)).events).toEqual([]);
  });

  it('distinguishes A→B→A→B changes and re-emits uncommitted removals', async () => {
    const store = new InMemoryMailboxStateStore(() => NOW.getTime());
    const forwarding: SnapshotItem = {
      ...forwardRule,
      kind: 'forwarding',
      itemHash: 'c'.repeat(64),
      traits: ['forwards'],
    };
    const load = () => store.load(INTEGRATION, hash);
    const run = async (current: SnapshotItem[], seq: bigint) => {
      const result = diffSnapshot({
        provider: 'microsoft_entra',
        identity,
        current,
        known: await load(),
        coveredKinds: ['forwarding'],
        cursorSeq: seq,
        pageSeq: seq + 1n,
        now: NOW,
      });
      await store.write(INTEGRATION, identity, result.writes, seq + 1n);
      return result.events;
    };
    const added1 = await run([forwarding], 0n);
    const removed1 = await run([], 1n);
    expect(removed1.map((e) => [e.stream, e.mailbox?.change])).toEqual([
      ['forwarding_changes', 'forwarding_removed'],
    ]);
    const replayRemoved = await run([], 1n);
    expect(replayRemoved.map((e) => e.eventId)).toEqual(removed1.map((e) => e.eventId));
    const added2 = await run([forwarding], 2n);
    expect(added2[0]?.eventId).not.toBe(added1[0]?.eventId);
  });

  it('maps item kinds to companion streams', () => {
    expect(streamOfMailboxChange('forwarding', [])).toBe('forwarding_changes');
    expect(streamOfMailboxChange('inbox_rule', ['redirects'])).toBe('forwarding_changes');
    expect(streamOfMailboxChange('inbox_rule', ['deletes'])).toBe('mailbox_audit');
    expect(streamOfMailboxChange('delegate', [])).toBe('delegation_changes');
    expect(streamOfMailboxChange('send_as', [])).toBe('delegation_changes');
  });
});

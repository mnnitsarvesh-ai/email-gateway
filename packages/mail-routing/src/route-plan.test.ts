import { describe, expect, it } from 'vitest';
import { recipientSetSha256 } from './reinjection-key';
import {
  MAX_RECIPIENTS_PER_GROUP,
  planRecipientRoutes,
  recipientDomain,
  type DomainView,
  type PlanRecipient,
  type PlanRecipientRoutesInput,
} from './route-plan';

const O = 7n;
const P = 9n;
const domains = new Map<string, DomainView>([
  ['acme.test', { domainId: 101n, ownerOrganizationId: O, ownerStatus: 'active' }],
  ['acme2.test', { domainId: 102n, ownerOrganizationId: O, ownerStatus: 'active' }],
  ['held.test', { domainId: 103n, ownerOrganizationId: O, ownerStatus: 'suspended' }],
  ['other.test', { domainId: 201n, ownerOrganizationId: P, ownerStatus: 'active' }],
  ['gone.test', { domainId: null, ownerOrganizationId: null, ownerStatus: 'none' }],
]);
let nextId = 1n;
const rcpt = (address: string, storedDirection: PlanRecipient['storedDirection'] = null) => {
  const recipientId = nextId++;
  return { recipientId, rcptSeq: Number(recipientId) - 1, address, storedDirection };
};
const plan = (overrides: Partial<PlanRecipientRoutesInput>) =>
  planRecipientRoutes({
    listenerDirection: 'outbound',
    messageOrganizationId: O,
    recipients: [],
    domains,
    suppressedAddresses: new Set(),
    maxRecipientsPerGroup: 100,
    ...overrides,
  });

describe('recipientDomain', () => {
  it('returns the lower-case domain part, or null', () => {
    expect(recipientDomain('User@Acme.TEST')).toBe('acme.test');
    expect(recipientDomain('"a@b"@acme.test')).toBe('acme.test');
    expect(recipientDomain('user@acme.test.')).toBe('acme.test');
    expect(recipientDomain('user@')).toBeNull();
    expect(recipientDomain('@acme.test')).toBeNull();
    expect(recipientDomain('user')).toBeNull();
  });
});

describe('planRecipientRoutes: outbound listener', () => {
  it('routes internal, cross-tenant, external and suppressed recipients', () => {
    const recipients = [
      rcpt('a@acme.test'),
      rcpt('b@Acme2.test'),
      rcpt('c@other.test'),
      rcpt('d@ext.example'),
      rcpt('Blocked@ext.example'),
      rcpt('e@gone.test'),
      rcpt('f@held.test'),
    ];
    const result = plan({ recipients, suppressedAddresses: new Set(['blocked@ext.example']) });
    expect(result.decisions.map((d) => [d.address, d.direction, d.kind])).toEqual([
      ['a@acme.test', 'internal', 'route'],
      ['b@acme2.test', 'internal', 'route'],
      ['c@other.test', 'outbound', 'route'],
      ['d@ext.example', 'outbound', 'route'],
      ['blocked@ext.example', 'outbound', 'refusal'],
      ['e@gone.test', 'outbound', 'route'],
      // A suspended own domain is not active: it goes out through the public MX (R1 table).
      ['f@held.test', 'outbound', 'route'],
    ]);
    const [internal, , crossTenant, external, suppressed] = result.decisions;
    expect(internal).toMatchObject({
      listener: 'reinject_inbound',
      destinationKey: 'tenant:101',
      notify: 'FAILURE,DELAY',
      traceDirection: 'in',
      hold: null,
    });
    // Another tenant of this gateway is never shortcut: its public MX.
    expect(crossTenant).toMatchObject({
      listener: 'reinject_outbound',
      destinationKey: 'mx:other.test',
      notify: 'FAILURE,DELAY',
      traceDirection: 'out',
    });
    expect(external).toMatchObject({ destinationKey: 'mx:ext.example' });
    expect(suppressed).toMatchObject({
      kind: 'refusal',
      status: 'suppressed',
      reason: 'suppressed',
    });

    // One group per tenant domain and per external recipient domain.
    expect(
      result.groups.map((g) => [g.listener, g.direction, g.destinationKey, g.recipientIds]),
    ).toEqual([
      ['reinject_inbound', 'internal', 'tenant:101', [recipients[0]!.recipientId]],
      ['reinject_inbound', 'internal', 'tenant:102', [recipients[1]!.recipientId]],
      ['reinject_outbound', 'outbound', 'mx:ext.example', [recipients[3]!.recipientId]],
      ['reinject_outbound', 'outbound', 'mx:gone.test', [recipients[5]!.recipientId]],
      ['reinject_outbound', 'outbound', 'mx:held.test', [recipients[6]!.recipientId]],
      ['reinject_outbound', 'outbound', 'mx:other.test', [recipients[2]!.recipientId]],
    ]);
    expect(result.groups[0]!.recipientSetSha256).toBe(recipientSetSha256(['a@acme.test']));
  });

  it('never suppresses internal recipients', () => {
    const result = plan({
      recipients: [rcpt('a@acme.test')],
      suppressedAddresses: new Set(['a@acme.test']),
    });
    expect(result.decisions[0]).toMatchObject({ kind: 'route', direction: 'internal' });
  });

  it('refuses a recipient whose stored direction differs from the current one', () => {
    const result = plan({
      recipients: [
        rcpt('a@acme.test', 'outbound'), // domain added since ingestion
        rcpt('b@ext.example', 'internal'), // domain removed since ingestion
        rcpt('c@acme.test', 'internal'),
        rcpt('d@ext.example', 'outbound'),
      ],
    });
    expect(result.decisions.map((d) => (d.kind === 'refusal' ? d.reason : d.kind))).toEqual([
      'direction_changed',
      'direction_changed',
      'route',
      'route',
    ]);
    expect(result.decisions[0]).toMatchObject({ status: 'failed', direction: 'internal' });
    expect(result.groups).toHaveLength(2);
  });

  it('uses the punycode form of IDN recipient domains in mx keys', () => {
    const result = plan({ recipients: [rcpt('x@Bücher.example')] });
    expect(result.decisions[0]).toMatchObject({ destinationKey: 'mx:xn--bcher-kva.example' });
  });

  it('refuses addresses without a domain', () => {
    const result = plan({ recipients: [rcpt('nobody')] });
    expect(result.decisions[0]).toMatchObject({
      kind: 'refusal',
      status: 'failed',
      reason: 'recipient_domain_inactive',
    });
  });
});

describe('planRecipientRoutes: inbound listener', () => {
  it('routes the organization’s domains with NOTIFY=NEVER, holds suspended ones, refuses others', () => {
    const recipients = [
      rcpt('a@acme.test'),
      rcpt('b@acme2.test'),
      rcpt('c@held.test'),
      rcpt('d@other.test'),
      rcpt('e@gone.test'),
      rcpt('f@unknown.test'),
    ];
    const result = plan({ listenerDirection: 'inbound', recipients });
    expect(result.decisions.map((d) => d.direction)).toEqual(Array(6).fill('inbound'));
    expect(result.decisions[0]).toMatchObject({
      kind: 'route',
      listener: 'reinject_inbound',
      destinationKey: 'tenant:101',
      notify: 'NEVER',
      traceDirection: 'in',
      hold: null,
    });
    expect(result.decisions[2]).toMatchObject({
      kind: 'route',
      destinationKey: 'tenant:103',
      hold: 'gateway_hold',
    });
    for (const decision of result.decisions.slice(3)) {
      expect(decision).toMatchObject({
        kind: 'refusal',
        status: 'failed',
        reason: 'recipient_domain_inactive',
      });
    }
    expect(result.groups.map((g) => [g.destinationKey, g.hold])).toEqual([
      ['tenant:101', null],
      ['tenant:102', null],
      ['tenant:103', 'gateway_hold'],
    ]);
  });

  it('ignores suppressions for inbound mail and refuses a stored non-inbound direction', () => {
    const result = plan({
      listenerDirection: 'inbound',
      recipients: [rcpt('a@acme.test', 'inbound'), rcpt('b@acme.test', 'internal')],
      suppressedAddresses: new Set(['a@acme.test']),
    });
    expect(result.decisions[0]).toMatchObject({ kind: 'route' });
    expect(result.decisions[1]).toMatchObject({ kind: 'refusal', reason: 'direction_changed' });
  });
});

describe('planRecipientRoutes: grouping', () => {
  it('chunks a destination into groups of maxRecipientsPerGroup in recipient id order', () => {
    const recipients = Array.from({ length: 250 }, (_, i) => rcpt(`u${i}@ext.example`)).reverse();
    const result = plan({ recipients });
    expect(result.groups.map((g) => g.recipientIds.length)).toEqual([100, 100, 50]);
    const ids = result.groups.flatMap((g) => g.recipientIds);
    expect(ids).toEqual([...ids].sort((a, b) => (a < b ? -1 : 1)));
    for (const group of result.groups) {
      expect(group.addresses).toEqual([...group.addresses].sort());
      expect(group.recipientSetSha256).toBe(recipientSetSha256(group.addresses));
    }
    expect(new Set(result.groups.map((g) => g.recipientSetSha256)).size).toBe(3);
    expect(plan({ recipients, maxRecipientsPerGroup: 1 }).groups).toHaveLength(250);
  });

  it('is deterministic regardless of input order', () => {
    const recipients = [rcpt('a@acme.test'), rcpt('b@ext.example'), rcpt('c@acme.test')];
    const forward = plan({ recipients });
    const backward = plan({ recipients: [...recipients].reverse() });
    expect(backward.groups).toEqual(forward.groups);
  });

  it('refuses invalid group sizes and duplicate recipient ids', () => {
    expect(MAX_RECIPIENTS_PER_GROUP).toBe(100);
    for (const max of [0, 101, 1.5]) {
      expect(() => plan({ maxRecipientsPerGroup: max })).toThrow();
    }
    const r = rcpt('a@acme.test');
    expect(() => plan({ recipients: [r, { ...r, rcptSeq: 9 }] })).toThrow();
  });

  it('returns no groups when every recipient is refused', () => {
    const result = plan({
      recipients: [rcpt('x@ext.example')],
      suppressedAddresses: new Set(['x@ext.example']),
    });
    expect(result.groups).toEqual([]);
    expect(result.decisions).toHaveLength(1);
  });
});

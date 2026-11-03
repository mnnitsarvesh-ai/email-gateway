import { describe, expect, it } from 'vitest';
import { classifyRecipient, deliveryPathFor, messageDirection } from './direction';

const O = 7n;
const P = 9n;

describe('classifyRecipient', () => {
  it('keeps inbound mail inbound, whoever owns the domain (incl. a same-organization sender)', () => {
    for (const owner of [{ organizationId: O }, { organizationId: P }, null]) {
      expect(
        classifyRecipient({
          listenerDirection: 'inbound',
          messageOrganizationId: O,
          recipientDomainOwner: owner,
        }),
      ).toBe('inbound');
    }
  });

  it('classifies outbound mail to an active domain of the same organization as internal', () => {
    expect(
      classifyRecipient({
        listenerDirection: 'outbound',
        messageOrganizationId: O,
        recipientDomainOwner: { organizationId: O },
      }),
    ).toBe('internal');
  });

  it('sends mail to another tenant of this gateway, or to unowned/inactive domains, outbound', () => {
    expect(
      classifyRecipient({
        listenerDirection: 'outbound',
        messageOrganizationId: O,
        recipientDomainOwner: { organizationId: P },
      }),
    ).toBe('outbound');
    expect(
      classifyRecipient({
        listenerDirection: 'outbound',
        messageOrganizationId: O,
        recipientDomainOwner: null,
      }),
    ).toBe('outbound');
  });
});

describe('messageDirection', () => {
  it('is internal only for outbound listeners with every recipient internal', () => {
    expect(messageDirection('outbound', ['internal'])).toBe('internal');
    expect(messageDirection('outbound', ['internal', 'internal'])).toBe('internal');
    expect(messageDirection('outbound', ['internal', 'outbound'])).toBe('outbound');
    expect(messageDirection('outbound', ['outbound'])).toBe('outbound');
    expect(messageDirection('outbound', [])).toBe('outbound');
    expect(messageDirection('inbound', ['internal'])).toBe('inbound');
    expect(messageDirection('inbound', ['inbound'])).toBe('inbound');
    expect(messageDirection('inbound', [])).toBe('inbound');
  });
});

describe('deliveryPathFor', () => {
  it('maps directions to the R4 listeners, NOTIFY and trace directions', () => {
    expect(deliveryPathFor('inbound')).toEqual({
      listener: 'reinject_inbound',
      notify: 'NEVER',
      traceDirection: 'in',
    });
    expect(deliveryPathFor('internal')).toEqual({
      listener: 'reinject_inbound',
      notify: 'FAILURE,DELAY',
      traceDirection: 'in',
    });
    expect(deliveryPathFor('outbound')).toEqual({
      listener: 'reinject_outbound',
      notify: 'FAILURE,DELAY',
      traceDirection: 'out',
    });
  });
});

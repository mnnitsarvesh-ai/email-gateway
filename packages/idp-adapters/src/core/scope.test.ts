import { describe, expect, it } from 'vitest';
import type { ProviderSession } from './session';
import { inScope, scopeDomains } from './scope';

const session = {
  view: {
    linkedDomains: [
      { name: 'Contoso-IT.example', providerVerified: true },
      { name: 'contoso-labs.example', providerVerified: false },
    ],
  },
} as unknown as ProviderSession;

describe('identity scope (inv. 4)', () => {
  it('uses the integration domains, else only the provider-verified linked domains', () => {
    expect([...scopeDomains(['A.example'], session)]).toEqual(['a.example']);
    expect([...scopeDomains(undefined, session)]).toEqual(['contoso-it.example']);
    expect([...scopeDomains([], session)]).toEqual(['contoso-it.example']);
  });

  it('admits members of a scope domain and rejects other domains and guests', () => {
    const domains = new Set(['contoso-it.example']);
    const ref = (primaryEmail?: string, userPrincipalName?: string) => ({
      provider: 'microsoft_entra' as const,
      externalId: 'x',
      ...(primaryEmail ? { primaryEmail } : {}),
      ...(userPrincipalName ? { userPrincipalName } : {}),
    });
    expect(inScope(ref('alex@contoso-it.example'), domains)).toBe(true);
    expect(inScope(ref(undefined, 'Alex@Contoso-IT.example'), domains)).toBe(true);
    expect(inScope(ref('blake@contoso-labs.example'), domains)).toBe(false);
    expect(
      inScope(
        ref('frank@contoso-it.example', 'frank_partner.example#EXT#@contoso-it.example'),
        domains,
      ),
    ).toBe(false);
    expect(inScope(ref(), domains)).toBe(false);
  });
});

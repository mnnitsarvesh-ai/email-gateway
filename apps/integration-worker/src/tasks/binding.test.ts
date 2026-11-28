import { describe, expect, it } from 'vitest';
import { BINDING_PROOF_DOMAIN_STATUSES, bindingProofDomainWhere } from './binding';

/**
 * The binding proof rule (step API-4 B3.5, B4, ADR-0107, P-I6): linked domains of the
 * organization in gateway status `verified` or `active` with DNS-TXT ownership (NULL treated as
 * `dns_txt`); provider-proven domains never count. The MySQL behaviour is pinned by the
 * integration suite `provider-ownership.test.ts`.
 */
describe('bindingProofDomainWhere', () => {
  it('accepts verified and active domains (was active only)', () => {
    expect(BINDING_PROOF_DOMAIN_STATUSES).toEqual(['verified', 'active']);
    expect(bindingProofDomainWhere(7n)).toEqual({
      organizationId: 7n,
      status: { in: ['verified', 'active'] },
      OR: [{ ownershipMethod: 'dns_txt' }, { ownershipMethod: null }],
    });
  });

  it('never admits provider_tenant ownership', () => {
    const where = bindingProofDomainWhere(1n);
    expect(JSON.stringify(where.OR)).not.toContain('provider_tenant');
  });
});

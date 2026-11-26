import { describe, expect, it } from 'vitest';
import {
  apiModeActive,
  domainForAddress,
  featureEnabled,
  isApiSide,
  type OrgDomain,
} from './api-mode-state';

const domains: OrgDomain[] = [
  { id: 1n, name: 'api.example', configuredMode: 'api', effectiveMode: 'api' },
  { id: 2n, name: 'inline.example', configuredMode: null, effectiveMode: 'inline' },
];

describe('API-mode state (D1)', () => {
  it('reads the feature from the organization row, else the plan default', () => {
    expect(
      featureEnabled({ enabled: false }, { api_mode_protection: true }, 'api_mode_protection'),
    ).toBe(false);
    expect(featureEnabled(null, { api_mode_protection: true }, 'api_mode_protection')).toBe(true);
    expect(featureEnabled(null, {}, 'api_mode_protection')).toBe(false);
    expect(featureEnabled(null, null, 'api_mode_protection')).toBe(false);
  });

  it('is active only when entitled with an api or hybrid domain', () => {
    expect(apiModeActive(true, domains)).toBe(true);
    expect(apiModeActive(false, domains)).toBe(false);
    expect(apiModeActive(true, [domains[1]!])).toBe(false);
    expect(isApiSide('hybrid')).toBe(true);
    expect(isApiSide('inline')).toBe(false);
  });

  it('matches recipient domains exactly', () => {
    expect(domainForAddress(domains, 'Alex@API.example')?.id).toBe(1n);
    expect(domainForAddress(domains, 'alex@sub.api.example')).toBeNull();
    expect(domainForAddress(domains, 'nobody')).toBeNull();
  });
});

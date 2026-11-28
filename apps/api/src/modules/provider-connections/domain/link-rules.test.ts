import { describe, expect, it } from 'vitest';
import { isLinkableDomainStatus } from './link-rules';

describe('provider domain link rule (step API-4 B4)', () => {
  it.each([
    ['verified', true],
    ['active', true],
    ['pending_verification', false],
    ['failed', false],
    ['suspended', false],
    ['deleted', false],
  ] as const)('%s → %s', (status, linkable) => {
    expect(isLinkableDomainStatus(status)).toBe(linkable);
  });
});

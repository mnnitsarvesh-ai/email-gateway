import { POLICY_LIMITS } from '@email-gateway/policy-dsl';
import type { INestApplication } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import {
  POLICY_BODY_ROUTES,
  POLICY_JSON_BODY_LIMIT_BYTES,
  usePolicyBodyLimit,
} from './policy-body-limit';

describe('policy routes JSON body limit (step 7.3 §14.8, B16)', () => {
  it('admits every definition the DSL accepts plus the request wrapper', () => {
    expect(POLICY_JSON_BODY_LIMIT_BYTES).toBe(POLICY_LIMITS.documentBytes + 64 * 1024);
    expect(POLICY_JSON_BODY_LIMIT_BYTES).toBeGreaterThan(100 * 1024);
  });

  it('mounts one parser on the definition routes, not named like Nest’s global jsonParser', () => {
    const use = vi.fn();
    usePolicyBodyLimit({ use } as unknown as INestApplication);
    expect(use).toHaveBeenCalledTimes(1);
    const [paths, handler] = use.mock.calls[0] as [string[], (...args: unknown[]) => void];
    expect(paths).toEqual([...POLICY_BODY_ROUTES]);
    expect(paths).toContain('/api/v1/policies');
    // Nest skips its own global parser when a layer named `jsonParser` is already applied.
    expect(handler.name).not.toBe('jsonParser');
    expect(handler.name).toBe('policyJsonBody');
  });
});

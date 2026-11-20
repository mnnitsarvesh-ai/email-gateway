import { describe, expect, it } from 'vitest';
import { createAssistantHarness } from '../../../../test/support/assistant-harness';
import { assistantKeys, utcDayKey } from '../assistant.constants';

const ORG = 7001n;
const NOW = new Date('2026-11-20T10:00:00.000Z');

describe('AssistantAvailabilityService: status reasons in order (D11, §4.1)', () => {
  it('platform_disabled → feature_disabled → tenant_disabled → provider_unavailable → budget_exhausted', async () => {
    const off = createAssistantHarness({ ASSISTANT_ENABLED: 'false' });
    await expect(off.availability.status(off.scope, NOW)).resolves.toMatchObject({
      available: false,
      reason: 'platform_disabled',
      provider: 'fake',
      model: 'fake',
      limits: { messageMaxChars: 4000, turnsPerMinute: 6 },
      budget: { dailyTokens: 1_000_000, usedToday: 0 },
    });

    const h = createAssistantHarness({ ASSISTANT_BREAKER_THRESHOLD: '2' });
    await expect(h.availability.status(h.scope, NOW)).resolves.toMatchObject({
      reason: 'feature_disabled',
    });
    h.world.features.set(ORG, true);
    await expect(h.availability.status(h.scope, NOW)).resolves.toMatchObject({
      reason: 'tenant_disabled',
    });
    h.world.enable(ORG, { externalProcessingAckAt: null });
    await expect(h.availability.status(h.scope, NOW)).resolves.toMatchObject({
      reason: 'tenant_disabled',
    });
    h.world.enable(ORG, { dailyTokenBudget: 1000 });
    const ok = await h.availability.status(h.scope, NOW);
    expect(ok).toMatchObject({ available: true, budget: { dailyTokens: 1000, usedToday: 0 } });
    expect(ok).not.toHaveProperty('reason');

    await h.kv.set('as:brk:fake', '2', 60);
    await expect(h.availability.status(h.scope, NOW)).resolves.toMatchObject({
      reason: 'provider_unavailable',
    });
    await h.kv.del('as:brk:fake');

    await h.kv.set(assistantKeys.tenantTokens(ORG, utcDayKey(NOW)), '1000', 60);
    await expect(h.availability.status(h.scope, NOW)).resolves.toMatchObject({
      available: false,
      reason: 'budget_exhausted',
      budget: { dailyTokens: 1000, usedToday: 1000 },
    });
  });

  it('seeds the daily counter from ai_chat_usage_daily on a Redis miss', async () => {
    const h = createAssistantHarness();
    h.world.enable(ORG);
    h.world.usage.push({
      organizationId: ORG,
      day: new Date('2026-11-20T00:00:00.000Z'),
      provider: 'fake',
      model: 'fake',
      turns: 3,
      inputTokens: 300n,
      outputTokens: 30n,
      cacheReadTokens: 0n,
      cacheWriteTokens: 0n,
      costMicros: 0n,
    });
    await expect(h.availability.status(h.scope, NOW)).resolves.toMatchObject({
      budget: { usedToday: 330 },
    });
    expect(await h.kv.get(assistantKeys.tenantTokens(ORG, '20261120'))).toBe('330');
  });

  it('caps a tenant budget at ASSISTANT_TENANT_DAILY_TOKENS_MAX', () => {
    const h = createAssistantHarness({ ASSISTANT_TENANT_DAILY_TOKENS_MAX: '2000000' });
    expect(h.limits.tenantBudget(9_000_000)).toBe(2_000_000);
    expect(h.limits.tenantBudget(null)).toBe(1_000_000);
  });
});

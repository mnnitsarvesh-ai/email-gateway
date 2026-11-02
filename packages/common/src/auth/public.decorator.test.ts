import { Reflector } from '@nestjs/core';
import { describe, expect, it } from 'vitest';
import { HealthController } from '../health/health.controller';
import { IS_PUBLIC_KEY, Public } from './public.decorator';

describe('Public()', () => {
  it('sets the public metadata on classes and methods', () => {
    @Public()
    class OpenController {}
    class MixedController {
      @Public()
      open(): void {}
      closed(): void {}
    }
    const reflector = new Reflector();
    expect(reflector.get(IS_PUBLIC_KEY, OpenController)).toBe(true);
    expect(reflector.get(IS_PUBLIC_KEY, MixedController.prototype.open)).toBe(true);
    expect(reflector.get(IS_PUBLIC_KEY, MixedController.prototype.closed)).toBeUndefined();
  });

  it('marks the health probes as public', () => {
    expect(new Reflector().get(IS_PUBLIC_KEY, HealthController)).toBe(true);
  });
});

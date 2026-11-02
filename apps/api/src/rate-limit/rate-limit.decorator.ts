import { UseGuards } from '@nestjs/common';
import { RateLimitGuard } from './rate-limit.guard';
import {
  assertRateLimitOptions,
  RATE_LIMIT_KEY,
  type RateLimitOptions,
} from './rate-limit.options';

export { RATE_LIMIT_KEY, type RateLimitOptions } from './rate-limit.options';

/**
 * Limits a route (or every route of a controller) per caller. Stackable: each `@RateLimit()`
 * adds one counter, e.g. 5 per 15 min per IP **and** 3 per hour per email; the guard is attached
 * once and checks all of them.
 */
export function RateLimit(options: RateLimitOptions): MethodDecorator & ClassDecorator {
  assertRateLimitOptions(options);
  const limit = Object.freeze({ ...options });
  return <T>(
    target: object,
    propertyKey?: string | symbol,
    descriptor?: TypedPropertyDescriptor<T>,
  ): void => {
    const holder = (descriptor ? descriptor.value : target) as object;
    const existing = (Reflect.getMetadata(RATE_LIMIT_KEY, holder) as RateLimitOptions[]) ?? [];
    Reflect.defineMetadata(RATE_LIMIT_KEY, [...existing, limit], holder);
    if (existing.length === 0) {
      if (descriptor) UseGuards(RateLimitGuard)(target, propertyKey!, descriptor);
      else UseGuards(RateLimitGuard)(target as abstract new (...args: never[]) => unknown);
    }
  };
}

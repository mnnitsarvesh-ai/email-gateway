import { applyDecorators, SetMetadata } from '@nestjs/common';
import { ApiExtension } from '@nestjs/swagger';

/** Metadata key of a route's rate class (step 6.1 D8). */
export const RATE_CLASS_KEY = 'rateLimit:class';
/** Marker of a route whose response carries a secret (step 6.1 D9); never idempotency-stored. */
export const RETURNS_SECRET_KEY = 'http:returnsSecret';
/** Set by `@Idempotent()` (http/idempotency); read here to refuse the combination with secrets. */
export const IDEMPOTENT_KEY = 'http:idempotent';

export type RateClass = 'sensitive' | 'expensive';
export const RATE_CLASSES: readonly RateClass[] = ['sensitive', 'expensive'];

/**
 * Puts a route into a per-principal class bucket of the global API limiter (D8, §3.5):
 * `sensitive` (`API_RATE_SENSITIVE_PER_MINUTE`) for the sensitive mutations and secret-bearing
 * routes, `expensive` (`API_RATE_EXPENSIVE_PER_MINUTE`) for reports, usage, lookups and dry-runs.
 * Documented as `x-eg-rate-class`. A route has at most one class; two different ones throw.
 */
export function RateClass(rateClass: RateClass): MethodDecorator & ClassDecorator {
  if (!RATE_CLASSES.includes(rateClass))
    throw new Error(`Unknown rate class: ${String(rateClass)}`);
  const apply = applyDecorators(
    SetMetadata(RATE_CLASS_KEY, rateClass),
    ApiExtension('x-eg-rate-class', rateClass),
  );
  return (target: object, propertyKey?: string | symbol, descriptor?: PropertyDescriptor) => {
    const holder = (descriptor ? descriptor.value : target) as object;
    const existing = Reflect.getMetadata(RATE_CLASS_KEY, holder) as RateClass | undefined;
    if (existing !== undefined && existing !== rateClass) {
      throw new Error(`A route has one rate class; got ${existing} and ${rateClass}`);
    }
    if (descriptor) {
      (apply as MethodDecorator)(target, propertyKey!, descriptor);
    } else {
      (apply as ClassDecorator)(target as abstract new (...args: never[]) => unknown);
    }
  };
}

/**
 * Marks a route whose response contains a secret (API key, connector secret, TOTP seed,
 * recovery codes, override token; D9). It is in the `sensitive` rate class and can never be
 * combined with `@Idempotent()` (its response would be stored as plain JSON in MySQL): the
 * combination throws when the class is decorated. Documented as `x-eg-returns-secret: true`.
 */
export function ReturnsSecret(): MethodDecorator {
  const apply = applyDecorators(
    SetMetadata(RETURNS_SECRET_KEY, true),
    ApiExtension('x-eg-returns-secret', true),
    RateClass('sensitive'),
  );
  return (target: object, propertyKey: string | symbol, descriptor: PropertyDescriptor) => {
    if (Reflect.getMetadata(IDEMPOTENT_KEY, descriptor.value as object) !== undefined) {
      throw new Error(
        `${String(propertyKey)}: @ReturnsSecret() routes must not be @Idempotent() (D9)`,
      );
    }
    apply(target, propertyKey, descriptor);
  };
}

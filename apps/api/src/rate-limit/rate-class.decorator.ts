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
 * Set by `@ReturnsSecret({ redactedReplay: true })` (ADR-0057): the route takes a transactional
 * Idempotency-Key whose STORED response is the redacted representation (`secret: null`).
 */
export const RETURNS_SECRET_REDACTED_REPLAY_KEY = 'http:returnsSecretRedactedReplay';

export interface ReturnsSecretOptions {
  /**
   * ADR-0057 (step 6.2): the route keeps the Idempotency-Key of the transactional mechanism
   * (`IdempotencyService.execute`), stores only the redacted representation (`secret: null`)
   * and returns the secret in the live response only; a replay returns the redacted body. Only
   * the routes of the inventory's `SECRET_BEARING_REDACTED_REPLAY` list may set it.
   */
  redactedReplay?: true;
}

/**
 * Marks a route whose response contains a secret (API key, connector secret, TOTP seed,
 * recovery codes, override token, webhook signing secret; D9). It is in the `sensitive` rate
 * class and can never be combined with `@Idempotent()` (the reservation interceptor would store
 * the response as plain JSON in MySQL): the combination throws when the class is decorated, and
 * the interceptor refuses such a route at runtime. Documented as `x-eg-returns-secret: true`.
 *
 * `{ redactedReplay: true }` (ADR-0057) marks the two webhook secret routes, which use the
 * transactional Idempotency-Key with a redacted stored response (`x-eg-secret-replay:
 * redacted`); it does not lift the `@Idempotent()` ban.
 */
export function ReturnsSecret(options: ReturnsSecretOptions = {}): MethodDecorator {
  const redacted = options.redactedReplay === true;
  const apply = applyDecorators(
    SetMetadata(RETURNS_SECRET_KEY, true),
    ...(redacted
      ? [
          SetMetadata(RETURNS_SECRET_REDACTED_REPLAY_KEY, true),
          ApiExtension('x-eg-secret-replay', 'redacted'),
        ]
      : []),
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

import type { PublishedSigningState, SigningPlan } from '../domain/dkim-signing-plan';

/**
 * The DKIM signing key store the publisher writes (step 2.2 D12): redis-dkim in every
 * environment (`RedisDkimStore`); tests may substitute an in-memory double.
 */
export abstract class DkimKeyStore {
  /** False when no store is configured (`REDIS_DKIM_URL` empty): the publisher is disabled. */
  abstract readonly configured: boolean;
  /** Current selectors and key field names (never the PEMs). */
  abstract readState(): Promise<PublishedSigningState>;
  /** Applies the plan atomically (`MULTI`/`EXEC`). */
  abstract apply(plan: SigningPlan): Promise<void>;
}

/** Thrown by the publisher when no key store is configured. */
export class DkimSigningDisabledError extends Error {
  constructor() {
    super('DKIM signing publisher is disabled: REDIS_DKIM_URL is not set');
    this.name = 'DkimSigningDisabledError';
  }
}

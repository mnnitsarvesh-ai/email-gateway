/**
 * Step 6.1 WP4: e2e helpers for the legacy sensitive mutations of §3.5, which now take an
 * `Idempotency-Key` (`@Idempotent({ legacy: true })`, `API_IDEMPOTENCY_LEGACY_MODE=enforce` by
 * default). The suites that build their own testing module install the in-memory
 * `api_idempotency_keys` store (`InMemoryIdempotencyStore` of test/support/api-test-app.ts) as
 * provider overrides; suites built by a shared helper they cannot change install it on the
 * running app's repository instances. Test code only.
 */
import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import type { TestingModuleBuilder } from '@nestjs/testing';
import { TransactionRunner } from '../src/database/transaction-runner';
import { IdempotencyReservationRepository } from '../src/http/idempotency/idempotency-reservation.repository';
import { IdempotencyReservationService } from '../src/http/idempotency/idempotency-reservation.service';
import { IdempotencyRepository } from '../src/http/idempotency/idempotency.repository';
import { immediateRunner, InMemoryIdempotencyStore } from './support/api-test-app';

/** A fresh `Idempotency-Key` header for one request. */
export const idem = (key: string = `wp4-${randomUUID()}`): { 'Idempotency-Key': string } => ({
  'Idempotency-Key': key,
});

/**
 * Overrides the two idempotency repositories with `store`; also `TransactionRunner` with the
 * immediate runner unless the suite overrides the runner itself (`runner: false`).
 */
export function withIdempotencyStore(
  builder: TestingModuleBuilder,
  store: InMemoryIdempotencyStore,
  options: { runner?: boolean } = {},
): TestingModuleBuilder {
  const next = builder
    .overrideProvider(IdempotencyRepository)
    .useValue(store.records)
    .overrideProvider(IdempotencyReservationRepository)
    .useValue(store.reservations);
  return options.runner === false
    ? next
    : next.overrideProvider(TransactionRunner).useValue(immediateRunner);
}

/**
 * For an app compiled by a shared helper (test/support/policy-app.ts): replaces the methods of
 * the repositories the app's `IdempotencyReservationService` (the interceptor's) holds with the
 * in-memory store's (`IdempotencyRepository` has several instances: ApiCommonModule's and
 * IdempotencyModule's). The helper's own TransactionRunner (an in-memory one) stays.
 */
export function installIdempotencyStore(app: INestApplication): InMemoryIdempotencyStore {
  const store = new InMemoryIdempotencyStore();
  const service = app.get<
    IdempotencyReservationService,
    { records: IdempotencyRepository; reservations: IdempotencyReservationRepository }
  >(IdempotencyReservationService);
  Object.assign(service.records, store.records);
  Object.assign(service.reservations, store.reservations);
  return store;
}

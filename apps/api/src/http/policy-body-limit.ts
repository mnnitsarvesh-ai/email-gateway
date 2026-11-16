import { POLICY_LIMITS } from '@email-gateway/policy-dsl';
import type { INestApplication } from '@nestjs/common';
import express, { type NextFunction, type Request, type Response } from 'express';

/**
 * Bytes a request may add around a policy definition: the keys, a change note, a row version,
 * synthetic test facts or a dry-run sample (step 7.3 §14.8).
 */
export const POLICY_REQUEST_WRAPPER_BYTES = 64 * 1024;

/**
 * The JSON body limit of the routes that carry a policy definition: the DSL's document limit
 * (`POLICY_LIMITS.documentBytes`, 256 KiB) plus the wrapper, so every definition the DSL accepts
 * can be saved, validated, tested and dry-run (B16). Every other route keeps Express's default
 * 100 KiB. A larger body is answered `413 payload_too_large` (`bodyParserHttpException`).
 */
export const POLICY_JSON_BODY_LIMIT_BYTES =
  POLICY_LIMITS.documentBytes + POLICY_REQUEST_WRAPPER_BYTES;

/**
 * The routes that accept a definition: `POST /policies`, `POST /policies/{id}/versions`,
 * `PUT /policies/{id}/versions/{n}`, `POST /policies/validate | test | dry-run` (every route
 * under `/policies`) and the per-message dry-run with an inline `{ definition }` target.
 */
export const POLICY_BODY_ROUTES: readonly string[] = Object.freeze([
  '/api/v1/policies',
  '/api/v1/messages/:messageId/scans/:scanId/policy/dry-run',
]);

/**
 * Registers the larger JSON parser for `POLICY_BODY_ROUTES` on the Express instance. Must run
 * before `app.init()`: Nest registers its global parsers (100 KiB) at init, after this one, and
 * they skip a body that was already read. The wrapper function is named so that Nest's
 * "already applied" check (`layer.handle.name === 'jsonParser'`) does not mistake it for the
 * global parser and skip registering that for every other route.
 */
export function usePolicyBodyLimit(app: INestApplication): void {
  const parser = express.json({ limit: POLICY_JSON_BODY_LIMIT_BYTES });
  const policyJsonBody = (req: Request, res: Response, next: NextFunction): void =>
    parser(req, res, next);
  app.use([...POLICY_BODY_ROUTES], policyJsonBody);
}

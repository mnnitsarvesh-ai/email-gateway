import { BadRequestException } from '@nestjs/common';
import type { z } from 'zod';
import type { Principal } from '../../../auth-contracts/principal';
import { CodedForbiddenException } from '../../../http/coded-exception';
import { formatZodIssues } from '../../../validation/zod-validation.pipe';
import { PublicIdSchema } from '../dto/provider-connections.schemas';

/** A path id: a UUID, `400` before any read (lower-cased). */
export function parsePublicId(raw: unknown, name: string): string {
  const parsed = PublicIdSchema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException([`${name}: must be a UUID`]);
  return parsed.data.toLowerCase();
}

/** A permission profile key of a path (`m365.mail_flow`); `400` otherwise. */
export function parseProfileKey(raw: unknown): string {
  if (typeof raw !== 'string' || !/^[a-z0-9]+(\.[a-z0-9_]+)+$/.test(raw) || raw.length > 48) {
    throw new BadRequestException(['profile: must be a permission profile key']);
  }
  return raw;
}

/** A body parsed in the service (after the Idempotency-Key checks); `400 validation_failed`. */
export function parseBody<S extends z.ZodType>(schema: S, raw: unknown): z.output<S> {
  const parsed = schema.safeParse(raw ?? {});
  if (!parsed.success) throw new BadRequestException(formatZodIssues(parsed.error));
  return parsed.data;
}

/** The public id of the principal (impact tokens, attestations, requesters). */
export function principalPublicId(principal: Principal): string {
  return principal.kind === 'api_key' ? principal.apiKeyPublicId : principal.userPublicId;
}

/** The internal user id of a user principal (FK columns), null for API keys. */
export function principalUserId(principal: Principal): bigint | null {
  return principal.kind === 'user' ? principal.userId : null;
}

/** `user` / `api_key` (validation run requester, `ProviderActorType`). */
export function principalType(principal: Principal): 'user' | 'api_key' {
  return principal.kind;
}

/**
 * The second permission of a gateway-side mail-flow change (D13, I4): `403 forbidden` without
 * it. The route requires `integration:manage` itself.
 */
export function requirePermission(principal: Principal, permission: string): void {
  if (!principal.permissions.has(permission)) {
    throw new CodedForbiddenException('forbidden', `Missing permission ${permission}`);
  }
}

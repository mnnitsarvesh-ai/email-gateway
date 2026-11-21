import { createHmac, timingSafeEqual } from 'node:crypto';
import { Inject, Injectable, type NestMiddleware } from '@nestjs/common';
import { runReadsOnWriter } from '@email-gateway/common';
import type { NextFunction, Request, Response } from 'express';
import { API_CONFIG } from '../../../api-config.token';
import type { AssistantConfig } from '../assistant.constants';

/**
 * Header of the assistant's precondition reads (step AI-2 review, ADR-0093 amendment (b)): the
 * GET routes that guard a confirmation read the MySQL writer instead of the replica, so a change
 * committed inside the replica-lag window is never invisible to the proposal read or to the
 * confirm-time re-read. Its value is `readPrimaryToken(AUTH_TOKEN_PEPPER)`: a server secret the
 * client never sees, identical on every api replica (ASSISTANT_LOOPBACK_URL may name any of them).
 */
export const READ_PRIMARY_HEADER = 'x-eg-assistant-read-primary';

const READ_PRIMARY_LABEL = 'eg-assistant-read-primary/1';

/** The header value: HMAC-SHA256(AUTH_TOKEN_PEPPER, label), base64url. */
export function readPrimaryToken(pepper: string): string {
  return createHmac('sha256', pepper).update(READ_PRIMARY_LABEL).digest('base64url');
}

/**
 * Honours `x-eg-assistant-read-primary` only when it carries the server token (constant-time
 * compare): the rest of the request then runs inside `runReadsOnWriter`, so every
 * `PrismaReadService.client` read of the route uses the writer. The header is removed from the
 * request either way; a missing or wrong value changes nothing (the request reads as usual). It
 * grants no permission: authentication, RBAC and tenant scope are unchanged, and the only effect
 * is a stronger read consistency.
 */
@Injectable()
export class AssistantReadPrimaryMiddleware implements NestMiddleware {
  private readonly expected: Buffer | null;

  constructor(@Inject(API_CONFIG) config: Pick<AssistantConfig, 'AUTH_TOKEN_PEPPER'>) {
    this.expected = config.AUTH_TOKEN_PEPPER
      ? Buffer.from(readPrimaryToken(config.AUTH_TOKEN_PEPPER), 'utf8')
      : null;
  }

  use(req: Request, _res: Response, next: NextFunction): void {
    const raw = req.headers[READ_PRIMARY_HEADER];
    if (raw === undefined) {
      next();
      return;
    }
    delete req.headers[READ_PRIMARY_HEADER];
    if (this.matches(raw)) {
      runReadsOnWriter(next);
      return;
    }
    next();
  }

  private matches(raw: string | string[]): boolean {
    if (this.expected === null || typeof raw !== 'string') return false;
    const got = Buffer.from(raw, 'utf8');
    return got.length === this.expected.length && timingSafeEqual(got, this.expected);
  }
}

import { Injectable } from '@nestjs/common';
import type { PolicyRequest } from './policy-protocol';

/**
 * In-session (pre-queue) decisions. This path is latency critical: Postfix holds the SMTP
 * session open while we answer. Only fast checks belong here (recipient validation, tenant
 * resolution, rate limits); content scanning runs post-queue.
 *
 * Failure mode: on any internal error the server answers a 4xx tempfail, never accept-all.
 */
@Injectable()
export class PolicyDecisionService {
  decide(request: PolicyRequest): Promise<string> {
    if (request.request !== 'smtpd_access_policy') {
      return Promise.resolve('DEFER_IF_PERMIT Unsupported policy request');
    }
    // Phase 0: no tenant policy yet. DUNNO hands the decision back to Postfix's own restrictions.
    return Promise.resolve('DUNNO');
  }
}

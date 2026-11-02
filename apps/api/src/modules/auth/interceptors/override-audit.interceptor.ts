import {
  type CallHandler,
  type ExecutionContext,
  Injectable,
  type NestInterceptor,
} from '@nestjs/common';
import type { Response } from 'express';
import type { Observable } from 'rxjs';
import type { AuthenticatedRequest } from '../../../auth-contracts/request';
import { OverrideRequestAuditor } from '../services/override-request-auditor.service';

/**
 * Global interceptor (D9): every request made with a platform-override token is audited as
 * `platform.override_request` once the response completes, success or error. `AuthGuard`
 * already attaches the auditor (so requests rejected by later guards are audited too); this
 * interceptor guarantees it for every handler that runs. Attaching twice is a no-op.
 */
@Injectable()
export class OverrideAuditInterceptor implements NestInterceptor {
  constructor(private readonly auditor: OverrideRequestAuditor) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    if (context.getType() === 'http') {
      const http = context.switchToHttp();
      this.auditor.attach(http.getRequest<AuthenticatedRequest>(), http.getResponse<Response>());
    }
    return next.handle();
  }
}

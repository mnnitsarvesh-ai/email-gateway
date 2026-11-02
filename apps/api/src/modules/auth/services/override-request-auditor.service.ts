import { Injectable, Logger } from '@nestjs/common';
import { getContext, runWithContext } from '@email-gateway/logger';
import type { Response } from 'express';
import { AuditService } from '../../../audit/audit.service';
import type { AuthenticatedRequest } from '../../../auth-contracts/request';
import { clientIp } from '../../../http/client-ip';

const ATTACHED = Symbol('overrideAuditAttached');
type Tracked = AuthenticatedRequest & { [ATTACHED]?: true };

/** The matched route template (e.g. `/api/v1/users/:id`), never the raw URL or query. */
export function routeTemplate(req: AuthenticatedRequest): string {
  const route = (req as { route?: { path?: unknown } }).route;
  const path = typeof route?.path === 'string' ? route.path : 'unmatched';
  return `${req.baseUrl ?? ''}${path}`.slice(0, 200);
}

/**
 * Writes `platform.override_request` (D9) once per request made with an override token, after
 * the response is complete (success or error, including guard rejections), with the route
 * template and the final status code.
 */
@Injectable()
export class OverrideRequestAuditor {
  private readonly logger = new Logger(OverrideRequestAuditor.name);

  constructor(private readonly audit: AuditService) {}

  attach(req: AuthenticatedRequest, res: Response): void {
    const tracked = req as Tracked;
    if (tracked[ATTACHED]) return;
    const principal = req.principal;
    if (principal?.kind !== 'user' || !principal.override) return;
    tracked[ATTACHED] = true;

    const override = principal.override;
    const requestContext = getContext();
    let done = false;
    const write = (): void => {
      if (done) return;
      done = true;
      const record = () =>
        this.audit.record({
          organizationId: override.targetOrganizationId,
          actor: this.audit.actorFrom(principal),
          action: 'platform.override_request',
          resourceType: 'organization',
          resourceId: override.targetOrganizationPublicId,
          sourceIp: clientIp(req),
          metadata: {
            overrideId: override.id,
            reason: override.reason,
            method: req.method,
            route: routeTemplate(req),
            statusCode: res.statusCode,
          },
        });
      const run = requestContext ? () => runWithContext(requestContext, record) : record;
      run().catch((err: unknown) =>
        this.logger.error({ message: 'Failed to audit an override request', err }),
      );
    };
    res.once('finish', write);
    res.once('close', write);
  }
}

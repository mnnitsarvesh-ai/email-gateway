import { Controller, Get, HttpStatus, Res, VERSION_NEUTRAL } from '@nestjs/common';
import type { HealthReport } from '@email-gateway/shared-types';
import type { Response } from 'express';
import { HealthService } from './health.service';

/** Unversioned probe endpoints used by Docker, Kubernetes and load balancers. */
@Controller({ path: 'health', version: VERSION_NEUTRAL })
export class HealthController {
  constructor(private readonly health: HealthService) {}

  @Get('live')
  live(): HealthReport {
    return this.health.liveness();
  }

  @Get('ready')
  async ready(@Res({ passthrough: true }) res: Response): Promise<HealthReport> {
    const report = await this.health.readiness();
    if (report.status !== 'ok') res.status(HttpStatus.SERVICE_UNAVAILABLE);
    return report;
  }
}

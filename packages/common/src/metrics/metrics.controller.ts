import { Controller, Get, Res, VERSION_NEUTRAL } from '@nestjs/common';
import type { Response } from 'express';
import { Public } from '../auth/public.decorator';
import { MetricsService } from './metrics.service';

/**
 * Unversioned Prometheus scrape endpoint (`GET /metrics`, step 2.2 D16). Public like the health
 * probes: it is reachable only on the service's internal HTTP port, and series never carry
 * secrets or personal data (labels are bounded: ids, contexts, outcomes).
 */
@Public()
@Controller({ path: 'metrics', version: VERSION_NEUTRAL })
export class MetricsController {
  constructor(private readonly metrics: MetricsService) {}

  @Get()
  async scrape(@Res({ passthrough: true }) res: Response): Promise<string> {
    const body = await this.metrics.metrics();
    res.setHeader('Content-Type', this.metrics.contentType);
    res.setHeader('Cache-Control', 'no-store');
    return body;
  }
}

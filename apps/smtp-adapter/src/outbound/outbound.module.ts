import { Module } from '@nestjs/common';
import {
  createDkimProbeClient,
  DKIM_PROBE_CLIENT_FACTORY,
  DkimReadinessService,
} from './dkim-readiness.service';
import { SuppressionService } from './suppression.service';

/** Outbound checks of the policy (step 2.2 D11): suppressions and DKIM signing readiness. */
@Module({
  providers: [
    SuppressionService,
    DkimReadinessService,
    { provide: DKIM_PROBE_CLIENT_FACTORY, useValue: createDkimProbeClient },
  ],
  exports: [SuppressionService, DkimReadinessService],
})
export class OutboundModule {}

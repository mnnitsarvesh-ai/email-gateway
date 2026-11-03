import { Module } from '@nestjs/common';
import { DeliveriesController } from './controllers/deliveries.controller';
import { DeliveriesRepository } from './repositories/deliveries.repository';
import { DeliveriesService } from './services/deliveries.service';

/**
 * Per-recipient delivery status and the delivery audit trail (step 2.3 R9, R13): read-only
 * views of `email_deliveries` and `delivery_status_events`, written by the delivery-worker and
 * the smtp-adapter. Reads use the replica (PrismaReadService).
 */
@Module({
  controllers: [DeliveriesController],
  providers: [DeliveriesRepository, DeliveriesService],
})
export class DeliveriesModule {}

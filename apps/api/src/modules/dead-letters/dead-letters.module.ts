import { Module } from '@nestjs/common';
import { AmqpDeadLetterBroker, DeadLetterBroker } from './broker/dead-letter-broker';
import { DeadLettersController } from './controllers/dead-letters.controller';
import { DeadLettersRepository } from './dead-letters.repository';
import { DeadLetterReplayService } from './services/dead-letter-replay.service';

/**
 * Dead letters of the pipeline (step 3.2 Q9, docs/plan/steps/07-rabbitmq.md): the platform view
 * of `email.dead-letter` and the audited replay. The broker connection (`RABBITMQ_OPS_URL`, the
 * `eg-ops` role user) is opened per request and closed after it; the shared building blocks
 * (audit, key-value store, API_CONFIG, MetricsService) are global.
 */
@Module({
  controllers: [DeadLettersController],
  providers: [
    { provide: DeadLetterBroker, useClass: AmqpDeadLetterBroker },
    DeadLettersRepository,
    DeadLetterReplayService,
  ],
})
export class DeadLettersModule {}

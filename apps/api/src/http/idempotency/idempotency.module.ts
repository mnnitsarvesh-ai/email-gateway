import { Module } from '@nestjs/common';
import { IdempotencyRepository } from './idempotency.repository';
import { IdempotencyService } from './idempotency.service';

/** The Idempotency-Key store (step 3.3 L11); feature modules import it for their write routes. */
@Module({
  providers: [IdempotencyRepository, IdempotencyService],
  exports: [IdempotencyService],
})
export class IdempotencyModule {}

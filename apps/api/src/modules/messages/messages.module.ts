import { Module } from '@nestjs/common';
import { IdempotencyModule } from '../../http/idempotency/idempotency.module';
import { MessageLifecycleController } from './controllers/message-lifecycle.controller';
import { MessageScansController } from './controllers/message-scans.controller';
import { ApiLifecycleMetrics } from './lifecycle-metrics';
import { MessageLifecycleReadRepository } from './repositories/message-lifecycle-read.repository';
import { MessageLifecycleRepository } from './repositories/message-lifecycle.repository';
import { MessageScansReadRepository } from './repositories/message-scans-read.repository';
import { LifecycleGateway } from './services/lifecycle-gateway';
import { MessageLifecycleReadService } from './services/message-lifecycle-read.service';
import { MessageLifecycleService } from './services/message-lifecycle.service';
import { MessageScansReadService } from './services/message-scans-read.service';

/**
 * Message lifecycle (step 3.3 L10, L12, docs/plan/steps/08-message-lifecycle.md): the lifecycle
 * and history reads (replica, PrismaReadService) and the administrative rescan and quarantine
 * release (writer, Idempotency-Key, audited), and the security scan results of step 4.1 S16
 * (replica). Every lifecycle write goes through
 * `@email-gateway/message-lifecycle` (LifecycleGateway). The shared building blocks (audit,
 * transactions, MetricsService) are global.
 */
@Module({
  imports: [IdempotencyModule],
  controllers: [MessageLifecycleController, MessageScansController],
  providers: [
    ApiLifecycleMetrics,
    LifecycleGateway,
    MessageLifecycleRepository,
    MessageLifecycleReadRepository,
    MessageLifecycleService,
    MessageLifecycleReadService,
    MessageScansReadRepository,
    MessageScansReadService,
  ],
  // Step 5.3: the quarantine module applies its lifecycle edges through the same door.
  exports: [ApiLifecycleMetrics, LifecycleGateway, MessageLifecycleRepository],
})
export class MessagesModule {}

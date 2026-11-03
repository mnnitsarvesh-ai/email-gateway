import { Module } from '@nestjs/common';
import { FixedWindowLimiter } from './fixed-window-limiter';

/** Redis fixed-window counters (step 2.2 D6). Needs the global RedisModule and MetricsModule. */
@Module({
  providers: [FixedWindowLimiter],
  exports: [FixedWindowLimiter],
})
export class RateLimitModule {}

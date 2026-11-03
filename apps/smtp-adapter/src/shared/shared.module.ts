import { Global, Module } from '@nestjs/common';
import { ReputationRecorder } from './reputation';

/**
 * Services shared by the smtp-adapter's policy, socketmap, SASL, LMTP and bounce components
 * (step 2.2). Global; expects `RedisModule` and `MetricsModule` (from `@email-gateway/common`)
 * to be registered globally by the app module.
 */
@Global()
@Module({
  providers: [ReputationRecorder],
  exports: [ReputationRecorder],
})
export class SmtpSharedModule {}

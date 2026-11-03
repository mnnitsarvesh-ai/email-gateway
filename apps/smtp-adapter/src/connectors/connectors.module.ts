import { Module } from '@nestjs/common';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { TenancyModule } from '../tenancy/tenancy.module';
import {
  argon2PasswordVerifier,
  ConnectorAuthService,
  PASSWORD_VERIFIER,
} from './connector-auth.service';
import { ConnectorResolver } from './connector-resolver.service';

/** Outbound connector resolution and SASL credential checks (step 2.2 D10, D11). */
@Module({
  imports: [TenancyModule, RateLimitModule],
  providers: [
    ConnectorResolver,
    ConnectorAuthService,
    { provide: PASSWORD_VERIFIER, useValue: argon2PasswordVerifier },
  ],
  exports: [ConnectorResolver, ConnectorAuthService],
})
export class ConnectorsModule {}

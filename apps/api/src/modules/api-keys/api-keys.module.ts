import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { ApiKeysController } from './api-keys.controller';
import { ApiKeysRepository } from './api-keys.repository';
import { ApiKeysService } from './api-keys.service';

/** API key management (D11, §4.2). Authentication with keys lives in the auth module. */
@Module({
  imports: [AuthModule],
  controllers: [ApiKeysController],
  providers: [ApiKeysRepository, ApiKeysService],
})
export class ApiKeysModule {}

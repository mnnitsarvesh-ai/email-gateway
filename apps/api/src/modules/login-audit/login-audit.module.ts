import { Module } from '@nestjs/common';
import { UsersModule } from '../users/users.module';
import { LoginEventsController } from './login-events.controller';
import { LoginEventsRepository } from './login-events.repository';
import { LoginEventsService } from './login-events.service';

/** `GET /audit/login-events` (§4.2): the organization's login attempts. */
@Module({
  imports: [UsersModule],
  controllers: [LoginEventsController],
  providers: [LoginEventsRepository, LoginEventsService],
})
export class LoginAuditModule {}

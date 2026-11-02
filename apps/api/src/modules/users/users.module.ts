import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { RolesModule } from '../roles/roles.module';
import { UsersController } from './users.controller';
import { UsersRepository } from './users.repository';
import { UsersService } from './users.service';

/**
 * Identity administration (D11, §4.2): users, invitations, status, roles, MFA reset and the
 * sessions of other users. Exports `UsersRepository` for scoped user lookups (login events).
 */
@Module({
  imports: [AuthModule, RolesModule],
  controllers: [UsersController],
  providers: [UsersRepository, UsersService],
  exports: [UsersRepository],
})
export class UsersModule {}

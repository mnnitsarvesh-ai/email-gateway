import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { PermissionsController, RolesController } from './roles.controller';
import { RolesRepository } from './roles.repository';
import { RolesService } from './roles.service';

/**
 * Roles and the permission catalog (D8, §4.2). Exports `RolesService` so identity
 * administration can resolve role assignments and count administrators.
 */
@Module({
  imports: [AuthModule],
  controllers: [PermissionsController, RolesController],
  providers: [RolesRepository, RolesService],
  exports: [RolesService],
})
export class RolesModule {}

import { Module } from '@nestjs/common';
import { PoliciesModule } from '../policies/policies.module';
import { DepartmentsController } from './controllers/departments.controller';
import { DepartmentsRepository } from './repositories/departments.repository';
import { DepartmentsService } from './services/departments.service';

/**
 * The tenant directory of step 5.2 (P5, P22): departments and their members, referenced by
 * policies. Managed under `user:read` / `user:manage`. Uses the policy writer, auditor, metrics
 * and the `policy_settings` lock of PoliciesModule (one serialization point with activation).
 */
@Module({
  imports: [PoliciesModule],
  controllers: [DepartmentsController],
  providers: [DepartmentsRepository, DepartmentsService],
})
export class DirectoryModule {}

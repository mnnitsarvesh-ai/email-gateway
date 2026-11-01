import { type DynamicModule, Module } from '@nestjs/common';
import { PolicyDecisionService } from './policy-decision.service';
import {
  POLICY_SERVER_OPTIONS,
  type PolicyServerOptions,
  PolicyServerService,
} from './policy-server.service';

@Module({})
export class PolicyModule {
  static forRoot(options: PolicyServerOptions): DynamicModule {
    return {
      module: PolicyModule,
      global: true,
      providers: [
        { provide: POLICY_SERVER_OPTIONS, useValue: options },
        PolicyDecisionService,
        PolicyServerService,
      ],
      exports: [PolicyServerService],
    };
  }
}

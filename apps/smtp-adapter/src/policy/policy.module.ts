import { Global, Module } from '@nestjs/common';
import type { BlockList } from 'node:net';
import { ADAPTER_CONFIG, INTERNAL_NETWORKS, type SmtpAdapterConfig } from '../config';
import { ConnectorsModule } from '../connectors/connectors.module';
import { OutboundModule } from '../outbound/outbound.module';
import { RateLimitModule } from '../rate-limit/rate-limit.module';
import { TenancyModule } from '../tenancy/tenancy.module';
import { InstanceSizeStore } from './instance-size.store';
import { PolicyDecisionService } from './policy-decision.service';
import {
  POLICY_SERVER_OPTIONS,
  type PolicyServerOptions,
  PolicyServerService,
} from './policy-server.service';

/**
 * Postfix policy delegation server (step 2.2 D4, D11) on POLICY_HOST:POLICY_PORT. Needs the
 * global infrastructure modules and the adapter's ADAPTER_CONFIG / ADAPTER_LOGGER /
 * INTERNAL_NETWORKS providers, and SmtpSharedModule (ReputationRecorder). Global so the
 * HealthModule can inject the listener as a readiness indicator.
 */
@Global()
@Module({
  imports: [TenancyModule, RateLimitModule, ConnectorsModule, OutboundModule],
  providers: [
    {
      provide: POLICY_SERVER_OPTIONS,
      useFactory: (
        config: Pick<SmtpAdapterConfig, 'POLICY_HOST' | 'POLICY_PORT'>,
        internalNetworks: BlockList,
      ): PolicyServerOptions => ({
        host: config.POLICY_HOST,
        port: config.POLICY_PORT,
        internalNetworks,
      }),
      inject: [ADAPTER_CONFIG, INTERNAL_NETWORKS],
    },
    InstanceSizeStore,
    PolicyDecisionService,
    PolicyServerService,
  ],
  exports: [PolicyServerService],
})
export class PolicyModule {}

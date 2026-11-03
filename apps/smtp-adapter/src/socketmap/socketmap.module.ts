import { Global, Module } from '@nestjs/common';
import type { BlockList } from 'node:net';
import { ADAPTER_CONFIG, INTERNAL_NETWORKS, type SmtpAdapterConfig } from '../config';
import { ConnectorsModule } from '../connectors/connectors.module';
import { TenancyModule } from '../tenancy/tenancy.module';
import { SocketmapLookupService } from './socketmap-lookup.service';
import {
  SOCKETMAP_SERVER_OPTIONS,
  type SocketmapServerOptions,
  SocketmapServerService,
} from './socketmap-server.service';

/**
 * Postfix socketmap tables (step 2.2 D2, D11) on MAIL_LISTEN_HOST:SOCKETMAP_PORT. Global so
 * the HealthModule can inject the listener as a readiness indicator.
 */
@Global()
@Module({
  imports: [TenancyModule, ConnectorsModule],
  providers: [
    {
      provide: SOCKETMAP_SERVER_OPTIONS,
      useFactory: (
        config: Pick<SmtpAdapterConfig, 'MAIL_LISTEN_HOST' | 'SOCKETMAP_PORT'>,
        internalNetworks: BlockList,
      ): SocketmapServerOptions => ({
        host: config.MAIL_LISTEN_HOST,
        port: config.SOCKETMAP_PORT,
        internalNetworks,
      }),
      inject: [ADAPTER_CONFIG, INTERNAL_NETWORKS],
    },
    SocketmapLookupService,
    SocketmapServerService,
  ],
  exports: [SocketmapServerService],
})
export class SocketmapModule {}

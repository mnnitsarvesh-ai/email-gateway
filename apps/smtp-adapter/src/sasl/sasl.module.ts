import { Global, Module } from '@nestjs/common';
import type { BlockList } from 'node:net';
import { ADAPTER_CONFIG, INTERNAL_NETWORKS, type SmtpAdapterConfig } from '../config';
import { ConnectorsModule } from '../connectors/connectors.module';
import {
  SASL_SERVER_OPTIONS,
  type SaslServerOptions,
  SaslServerService,
} from './sasl-server.service';

/**
 * Dovecot-auth-protocol server for Postfix submission SASL (step 2.2 D10) on
 * MAIL_LISTEN_HOST:SASL_AUTH_PORT. Global so the HealthModule can inject the listener as a
 * readiness indicator.
 */
@Global()
@Module({
  imports: [ConnectorsModule],
  providers: [
    {
      provide: SASL_SERVER_OPTIONS,
      useFactory: (
        config: Pick<SmtpAdapterConfig, 'MAIL_LISTEN_HOST' | 'SASL_AUTH_PORT'>,
        internalNetworks: BlockList,
      ): SaslServerOptions => ({
        host: config.MAIL_LISTEN_HOST,
        port: config.SASL_AUTH_PORT,
        internalNetworks,
      }),
      inject: [ADAPTER_CONFIG, INTERNAL_NETWORKS],
    },
    SaslServerService,
  ],
  exports: [SaslServerService],
})
export class SaslModule {}

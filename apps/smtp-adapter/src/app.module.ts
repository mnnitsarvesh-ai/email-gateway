import { type DynamicModule, Global, Module } from '@nestjs/common';
import {
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  MetricsModule,
  PrismaService,
  RedisModule,
  RedisService,
  S3Module,
  S3Service,
} from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import { BOUNCES_HEALTH_INDICATORS, BouncesModule } from './bounces/bounces.module';
import {
  ADAPTER_CONFIG,
  ADAPTER_LOGGER,
  INTERNAL_NETWORKS,
  type SmtpAdapterConfig,
} from './config';
import { INGESTION_HEALTH_INDICATORS, IngestionModule } from './ingestion/ingestion.module';
import { PolicyModule } from './policy/policy.module';
import { PolicyServerService } from './policy/policy-server.service';
import { SaslModule } from './sasl/sasl.module';
import { SaslServerService } from './sasl/sasl-server.service';
import { parseNetworkList } from './shared/internal-networks';
import { REPUTATION_LOGGER } from './shared/reputation';
import { SmtpSharedModule } from './shared/shared.module';
import { SocketmapModule } from './socketmap/socketmap.module';
import { SocketmapServerService } from './socketmap/socketmap-server.service';

export const SERVICE_NAME = 'smtp-adapter';

/** Validated config, root logger and the internal-peer allow-list, for every component. */
@Global()
@Module({})
export class AdapterCoreModule {
  static forRoot(config: Readonly<SmtpAdapterConfig>): DynamicModule {
    const logger = createLogger({
      service: SERVICE_NAME,
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    });
    const providers = [
      { provide: ADAPTER_CONFIG, useValue: config },
      { provide: ADAPTER_LOGGER, useValue: logger },
      { provide: REPUTATION_LOGGER, useValue: logger },
      {
        provide: INTERNAL_NETWORKS,
        useValue: parseNetworkList(config.SMTP_INTERNAL_CLIENT_NETWORKS),
      },
    ];
    return {
      module: AdapterCoreModule,
      providers,
      exports: providers.map((provider) => provider.provide),
    };
  }
}

/**
 * SMTP gateway adapter (step 2.2, ADR-0019): the Node side of the two Postfix instances. It
 * implements only Postfix extension protocols and LMTP; Postfix speaks SMTP.
 *
 * - policy delegation (:10040, D4/D11), socketmap tables (:10041, D2/D11), Dovecot SASL
 *   (:10042, D10) — in-session, fail closed;
 * - LMTP ingestion (:10050 inbound, :10051 outbound, D7) and bounce notices (:10052, D13).
 *
 * Data plane: the MySQL **writer** only (no PrismaReadService, ADR-0014). Every listener closes
 * its connections on shutdown (Nest shutdown hooks, `bootstrapService`).
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<SmtpAdapterConfig>): DynamicModule {
    const lmtp = {
      config,
      listenHost: config.MAIL_LISTEN_HOST,
      internalNetworks: config.SMTP_INTERNAL_CLIENT_NETWORKS,
      logLevel: config.LOG_LEVEL,
    };
    return {
      module: AppModule,
      imports: [
        CorrelationModule,
        AdapterCoreModule.forRoot(config),
        DatabaseModule.forRoot({ url: config.DATABASE_URL }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        SmtpSharedModule,
        PolicyModule,
        SocketmapModule,
        SaslModule,
        IngestionModule.forRoot(lmtp),
        BouncesModule.forRoot(lmtp),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [
            PrismaService,
            RedisService,
            S3Service,
            PolicyServerService,
            SocketmapServerService,
            SaslServerService,
            ...INGESTION_HEALTH_INDICATORS,
            ...BOUNCES_HEALTH_INDICATORS,
          ],
        }),
      ],
    };
  }
}

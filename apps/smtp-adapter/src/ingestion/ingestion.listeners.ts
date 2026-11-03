import { Inject, Injectable } from '@nestjs/common';
import { createLogger } from '@email-gateway/logger';
import { LmtpListener } from '../lmtp/lmtp-listener';
import { LmtpListenerService, type ManagedLmtpListener } from '../lmtp/lmtp-listener.service';
import { parseNetworkList } from '../shared/internal-networks';
import type { IngestDirection } from './ingestion-keys';
import { INGESTION_OPTIONS, type IngestionModuleOptions } from './ingestion.options';
import { IngestionService } from './ingestion.service';

function createIngestionListener(
  name: string,
  direction: IngestDirection,
  options: IngestionModuleOptions,
  ingestion: IngestionService,
): ManagedLmtpListener {
  const config = options.config;
  return new LmtpListener(
    {
      name,
      host: options.listenHost,
      port: direction === 'inbound' ? config.LMTP_INBOUND_PORT : config.LMTP_OUTBOUND_PORT,
      maxClients: config.LMTP_MAX_CLIENTS,
      maxMessageBytes: config.INGEST_MAX_MESSAGE_BYTES,
      internalNetworks: parseNetworkList(options.internalNetworks),
    },
    ingestion.handler(direction),
    createLogger({ service: 'smtp-adapter', level: options.logLevel }).child({
      component: name,
    }),
  );
}

/** `:10050` (LMTP_INBOUND_PORT): Postfix inbound `relay_transport`, direction `inbound`. */
@Injectable()
export class LmtpInboundListener extends LmtpListenerService {
  readonly healthName = 'lmtp-inbound';
  protected readonly listener: ManagedLmtpListener;

  constructor(
    @Inject(INGESTION_OPTIONS) options: IngestionModuleOptions,
    ingestion: IngestionService,
  ) {
    super();
    this.listener = createIngestionListener(this.healthName, 'inbound', options, ingestion);
  }
}

/** `:10051` (LMTP_OUTBOUND_PORT): postfix-outbound `content_filter`, direction `outbound`. */
@Injectable()
export class LmtpOutboundListener extends LmtpListenerService {
  readonly healthName = 'lmtp-outbound';
  protected readonly listener: ManagedLmtpListener;

  constructor(
    @Inject(INGESTION_OPTIONS) options: IngestionModuleOptions,
    ingestion: IngestionService,
  ) {
    super();
    this.listener = createIngestionListener(this.healthName, 'outbound', options, ingestion);
  }
}

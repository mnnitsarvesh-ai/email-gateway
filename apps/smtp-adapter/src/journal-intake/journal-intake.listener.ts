import { Inject, Injectable } from '@nestjs/common';
import { createLogger } from '@email-gateway/logger';
import { LmtpListener } from '../lmtp/lmtp-listener';
import { LmtpListenerService, type ManagedLmtpListener } from '../lmtp/lmtp-listener.service';
import { parseNetworkList } from '../shared/internal-networks';
import { JOURNAL_INTAKE_OPTIONS, type JournalIntakeModuleOptions } from './journal-intake.options';
import { JournalIntakeService } from './journal-intake.service';

/**
 * `:10053` (LMTP_JOURNAL_PORT, step 8.6 D2.4): the inbound Postfix's `transport_maps` route of
 * the journal intake domain. Same `LmtpListener` (internal peers only, XFORWARD, per-recipient
 * replies) and the same INGEST_MAX_MESSAGE_BYTES ceiling as the gateway listeners; readiness
 * check `lmtp-journal`.
 */
@Injectable()
export class JournalIntakeListener extends LmtpListenerService {
  readonly healthName = 'lmtp-journal';
  protected readonly listener: ManagedLmtpListener;

  constructor(
    @Inject(JOURNAL_INTAKE_OPTIONS) options: JournalIntakeModuleOptions,
    intake: JournalIntakeService,
  ) {
    super();
    const config = options.config;
    this.listener = new LmtpListener(
      {
        name: this.healthName,
        host: options.listenHost,
        port: config.LMTP_JOURNAL_PORT,
        maxClients: config.LMTP_MAX_CLIENTS,
        maxMessageBytes: config.INGEST_MAX_MESSAGE_BYTES,
        internalNetworks: parseNetworkList(options.internalNetworks),
      },
      intake.handler(),
      createLogger({ service: 'smtp-adapter', level: options.logLevel }).child({
        component: this.healthName,
      }),
    );
  }
}

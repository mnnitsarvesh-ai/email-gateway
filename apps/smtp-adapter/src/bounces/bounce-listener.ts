import { Inject, Injectable } from '@nestjs/common';
import { createLogger } from '@email-gateway/logger';
import { LmtpListener } from '../lmtp/lmtp-listener';
import { LmtpListenerService, type ManagedLmtpListener } from '../lmtp/lmtp-listener.service';
import { parseNetworkList } from '../shared/internal-networks';
import { BounceNoticeService } from './bounce-notice.service';
import { BOUNCES_OPTIONS, type BouncesModuleOptions } from './bounces.options';

/** `:10052` (LMTP_BOUNCE_PORT): postmaster DSN copies from postfix-outbound (D13). */
@Injectable()
export class LmtpBounceListener extends LmtpListenerService {
  readonly healthName = 'lmtp-bounces';
  protected readonly listener: ManagedLmtpListener;

  constructor(
    @Inject(BOUNCES_OPTIONS) options: BouncesModuleOptions,
    notices: BounceNoticeService,
  ) {
    super();
    this.listener = new LmtpListener(
      {
        name: this.healthName,
        host: options.listenHost,
        port: options.config.LMTP_BOUNCE_PORT,
        maxClients: 10,
        maxMessageBytes: options.config.BOUNCE_MAX_MESSAGE_BYTES,
        internalNetworks: parseNetworkList(options.internalNetworks),
      },
      notices.handler(),
      createLogger({ service: 'smtp-adapter', level: options.logLevel }).child({
        component: this.healthName,
      }),
    );
  }
}

import type { IngestionConfig } from '../ingestion/ingestion.config';
import type { BouncesConfig } from './bounces.config';

export const BOUNCES_OPTIONS = Symbol('BOUNCES_OPTIONS');

export interface BouncesModuleOptions {
  /**
   * The bounce handler's own settings, the X-Gateway-Trace key (a notice counts only for mail
   * the gateway reinjected for delivery) and postfix-outbound's `myhostname` (the domain of its
   * `double-bounce` sender).
   */
  config: BouncesConfig &
    Pick<IngestionConfig, 'GATEWAY_TRACE_SECRET' | 'GATEWAY_TRACE_ID'> & {
      POSTFIX_OUTBOUND_MYHOSTNAME: string;
    };
  /** MAIL_LISTEN_HOST. */
  listenHost: string;
  /** SMTP_INTERNAL_CLIENT_NETWORKS (comma-separated CIDRs). */
  internalNetworks: string;
  logLevel: string;
}

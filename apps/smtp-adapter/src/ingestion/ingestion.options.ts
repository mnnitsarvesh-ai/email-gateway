import type { IngestionConfig } from './ingestion.config';

export const INGESTION_OPTIONS = Symbol('INGESTION_OPTIONS');

export interface IngestionModuleOptions {
  config: IngestionConfig;
  /** MAIL_LISTEN_HOST. */
  listenHost: string;
  /** SMTP_INTERNAL_CLIENT_NETWORKS (comma-separated CIDRs). */
  internalNetworks: string;
  logLevel: string;
}

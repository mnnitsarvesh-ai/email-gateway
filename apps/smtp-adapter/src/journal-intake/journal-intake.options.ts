import type { IngestionConfig } from '../ingestion/ingestion.config';
import type { JournalIntakeConfig } from './journal-intake.config';

export const JOURNAL_INTAKE_OPTIONS = Symbol('JOURNAL_INTAKE_OPTIONS');

/** The journal LMTP's view of the configuration (ingestion limits + intake keys). */
export type JournalIntakeModuleConfig = Pick<
  IngestionConfig,
  | 'LMTP_MAX_CLIENTS'
  | 'INGEST_MAX_MESSAGE_BYTES'
  | 'INGEST_S3_PART_SIZE_BYTES'
  | 'INGEST_S3_QUEUE_SIZE'
  | 'INGEST_S3_TIMEOUT_MS'
  | 'INGEST_DB_TIMEOUT_MS'
  | 'INGEST_HEADER_MAX_BYTES'
> &
  JournalIntakeConfig;

export interface JournalIntakeModuleOptions {
  config: JournalIntakeModuleConfig;
  /** MAIL_LISTEN_HOST. */
  listenHost: string;
  /** SMTP_INTERNAL_CLIENT_NETWORKS (comma-separated CIDRs). */
  internalNetworks: string;
  logLevel: string;
}

import type { DlpExtraction, ExtractHint } from '@email-gateway/dlp/extract';
import type { Logger } from '@email-gateway/logger';
import {
  type ChildDescriptor,
  childEntryNextTo,
  ChildPool,
  type ChildPoolOptions,
  type PoolOutcome,
} from '../../attachment/inspector/pool';
import { isExtractorReady } from '../../attachment/inspector/protocol';
import { type DlpExtractJobLimits, parseExtraction } from './extraction';

/** `extractor_version` the worker expects of its children (D4, D23). */
export const EXPECTED_EXTRACTOR_VERSION = 'dlp-extract/1';

export type ExtractOutcome = PoolOutcome<DlpExtraction>;

/** What the dlp engine needs of the extractor pool (a fake or an in-process one in tests). */
export interface DlpExtractor {
  extract(
    bytes: Buffer,
    limits: DlpExtractJobLimits,
    hint: ExtractHint,
    signal: AbortSignal,
  ): Promise<ExtractOutcome>;
  start(): Promise<void>;
  stop(): Promise<void>;
  readonly readyCount: number;
  readonly rlimitMode: 'prlimit' | 'none';
  readonly permissionModel: boolean;
}

/**
 * The DLP extractor child descriptor (step 4.5 D4): entry `extractor/child.js` (`.ts` in source
 * runs), no arguments, no extra read roots (pdfjs, its CMaps and the dlp package live under the
 * workspace root the pool already allows), the `dlp-extractor` handshake with the expected
 * extractor version, and the bounded `extraction` reply (anything else is a crash).
 */
export function extractorDescriptor(options: {
  logger: Logger;
  maxTextChars: number;
}): ChildDescriptor<DlpExtraction> {
  const logger = options.logger.child({ component: 'dlp-extractor' });
  return {
    component: 'dlp-extractor',
    rlimitsKey: 'DLP_EXTRACTOR_RLIMITS',
    entry: childEntryNextTo(__dirname, __filename),
    args: [],
    readRoots: [],
    startDetails: { extractorVersion: EXPECTED_EXTRACTOR_VERSION },
    checkReady: (message) => {
      if (!isExtractorReady(message) || message.extractorVersion !== EXPECTED_EXTRACTOR_VERSION) {
        logger.error(
          { expected: EXPECTED_EXTRACTOR_VERSION },
          'extractor child reported another kind or version; refused',
        );
        return 'extractor_mismatch';
      }
      return null;
    },
    resultOf: (message) => parseExtraction(message.extraction, options.maxTextChars),
  };
}

/** The DLP extractor pool: a second instance of the generalized 4.2 child pool. */
export class DlpExtractorPool extends ChildPool<DlpExtraction> implements DlpExtractor {
  constructor(options: ChildPoolOptions & { maxTextChars: number }) {
    super(
      options,
      extractorDescriptor({ logger: options.logger, maxTextChars: options.maxTextChars }),
    );
  }

  extract(
    bytes: Buffer,
    limits: DlpExtractJobLimits,
    hint: ExtractHint,
    signal: AbortSignal,
  ): Promise<ExtractOutcome> {
    return this.job(
      {
        op: 'extract',
        bytes,
        limits: limits,
        hint: { ...hint },
      },
      signal,
    );
  }
}

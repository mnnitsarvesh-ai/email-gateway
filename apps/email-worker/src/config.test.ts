import { DEFAULT_MIME_LIMITS } from '@email-gateway/mime-parser';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig, parseMemoryBytes, worstCasePartPathChars } from './config';
import { mimeLimitsFromConfig } from './mime-ingestion/limits';

const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_URL: 'amqp://test:test@localhost:5672',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
};

const load = (env: Record<string, string> = {}) => loadWorkerConfig({ ...base, ...env });

/** The startup refusal of one invalid combination (asserts the key is named). */
const refusal = (env: Record<string, string>, key: string) =>
  expect(() => load(env)).toThrow(new RegExp(key));

describe('email-worker MIME config (design §5, M5)', () => {
  it('applies the design defaults and maps them onto the parser limits', () => {
    const config = load();
    expect(config.MIME_INGESTION_ENABLED).toBe(true);
    expect(config.MIME_CONCURRENCY).toBe(4);
    expect(config.MIME_OUTBOX_POLL_INTERVAL_MS).toBe(1000);
    expect(config.MIME_OUTBOX_SAFETY_LAG_MS).toBe(120_000);
    expect(config.MIME_OUTBOX_BATCH_SIZE).toBe(100);
    expect(config.MIME_OUTBOX_SHARDS).toBe(1);
    expect(config.MIME_OUTBOX_MAX_HELD_SHARDS).toBe(1);
    expect(config.MIME_RETRY_BASE_MS).toBe(1000);
    expect(config.MIME_RETRY_MAX_MS).toBe(60_000);
    expect(config.MIME_MAX_ATTEMPTS).toBe(5);
    expect(config.MIME_DB_TIMEOUT_MS).toBe(15_000);
    expect(config.MIME_S3_TIMEOUT_MS).toBe(30_000);
    expect(config.MIME_S3_PART_SIZE_BYTES).toBe(5_242_880);
    expect(config.MIME_S3_QUEUE_SIZE).toBe(2);
    expect(config.MIME_MEMORY_BUDGET_BYTES).toBe(268_435_456);
    // The parser's own defaults are the design defaults too.
    expect(mimeLimitsFromConfig(config)).toEqual(DEFAULT_MIME_LIMITS);
  });

  it('coerces values from the environment', () => {
    const config = load({
      MIME_INGESTION_ENABLED: 'false',
      MIME_MAX_DECODED_RATIO: '1.5',
      MIME_OUTBOX_SHARDS: '4',
      MIME_OUTBOX_MAX_HELD_SHARDS: '2',
    });
    expect(config.MIME_INGESTION_ENABLED).toBe(false);
    expect(config.MIME_MAX_DECODED_RATIO).toBe(1.5);
    expect(mimeLimitsFromConfig(config).maxDecodedRatio).toBe(1.5);
    expect(config.MIME_OUTBOX_SHARDS).toBe(4);
  });

  it('refuses per-part limits above the message limit', () => {
    refusal({ MIME_MAX_ATTACHMENT_BYTES: '53477377' }, 'MIME_MAX_ATTACHMENT_BYTES');
    refusal({ MIME_MAX_BODY_BYTES: '53477377' }, 'MIME_MAX_BODY_BYTES');
    expect(load({ MIME_MAX_ATTACHMENT_BYTES: '53477376' }).MIME_MAX_ATTACHMENT_BYTES).toBe(
      53_477_376,
    );
  });

  it('refuses a header line limit above the header block limit', () => {
    refusal({ MIME_MAX_HEADER_LINE_BYTES: '262145' }, 'MIME_MAX_HEADER_LINE_BYTES');
  });

  it('refuses a decoded ratio below 1', () => {
    refusal({ MIME_MAX_DECODED_RATIO: '0.99' }, 'MIME_MAX_DECODED_RATIO');
    expect(load({ MIME_MAX_DECODED_RATIO: '1' }).MIME_MAX_DECODED_RATIO).toBe(1);
  });

  it('refuses depth, part and attachment counts outside their ranges', () => {
    refusal({ MIME_MAX_DEPTH: '0' }, 'MIME_MAX_DEPTH');
    refusal({ MIME_MAX_DEPTH: '51' }, 'MIME_MAX_DEPTH');
    refusal({ MIME_MAX_PARTS: '1' }, 'MIME_MAX_PARTS');
    refusal({ MIME_MAX_PARTS: '1001' }, 'MIME_MAX_PARTS');
    refusal({ MIME_MAX_PARTS: '50', MIME_MAX_ATTACHMENTS: '51' }, 'MIME_MAX_ATTACHMENTS');
    expect(load({ MIME_MAX_DEPTH: '31', MIME_MAX_PARTS: '1000' }).MIME_MAX_PARTS).toBe(1000);
  });

  it('refuses depth and part limits whose part_path could overflow VARCHAR(128)', () => {
    // '0' + one '.<n>' per level, n < MIME_MAX_PARTS.
    expect(worstCasePartPathChars(10, 250)).toBe(41);
    expect(worstCasePartPathChars(31, 1000)).toBe(125);
    expect(worstCasePartPathChars(32, 1000)).toBe(129);
    expect(worstCasePartPathChars(42, 100)).toBe(127);
    expect(worstCasePartPathChars(50, 2)).toBe(101);
    refusal({ MIME_MAX_DEPTH: '32', MIME_MAX_PARTS: '1000' }, 'MIME_MAX_DEPTH');
    refusal({ MIME_MAX_DEPTH: '50', MIME_MAX_PARTS: '1000' }, 'part_path');
    refusal({ MIME_MAX_DEPTH: '43', MIME_MAX_PARTS: '100' }, 'MIME_MAX_DEPTH');
    expect(load({ MIME_MAX_DEPTH: '42', MIME_MAX_PARTS: '100' }).MIME_MAX_DEPTH).toBe(42);
    expect(
      load({ MIME_MAX_DEPTH: '50', MIME_MAX_PARTS: '10', MIME_MAX_ATTACHMENTS: '10' })
        .MIME_MAX_DEPTH,
    ).toBe(50);
  });

  it('refuses an S3 wait budget that is not below the parse budget', () => {
    refusal({ MIME_S3_TIMEOUT_MS: '120000' }, 'MIME_S3_TIMEOUT_MS');
    refusal({ MIME_S3_TIMEOUT_MS: '5000', MIME_PARSE_TIMEOUT_MS: '4000' }, 'MIME_S3_TIMEOUT_MS');
    expect(load({ MIME_S3_TIMEOUT_MS: '119999' }).MIME_S3_TIMEOUT_MS).toBe(119_999);
  });

  it('refuses stored-header and filename caps outside their ranges', () => {
    refusal({ MIME_MAX_STORED_HEADERS: '0' }, 'MIME_MAX_STORED_HEADERS');
    refusal({ MIME_MAX_STORED_HEADERS: '501' }, 'MIME_MAX_STORED_HEADERS');
    refusal({ MIME_FILENAME_MAX_CHARS: '15' }, 'MIME_FILENAME_MAX_CHARS');
    refusal({ MIME_FILENAME_MAX_CHARS: '241' }, 'MIME_FILENAME_MAX_CHARS');
  });

  it('refuses a safety lag below the ingestion transaction budget', () => {
    refusal({ MIME_OUTBOX_SAFETY_LAG_MS: '29999' }, 'MIME_OUTBOX_SAFETY_LAG_MS');
    expect(load({ MIME_OUTBOX_SAFETY_LAG_MS: '30000' }).MIME_OUTBOX_SAFETY_LAG_MS).toBe(30_000);
  });

  it('refuses holding more shards than exist and a retry cap below its base', () => {
    refusal(
      { MIME_OUTBOX_SHARDS: '2', MIME_OUTBOX_MAX_HELD_SHARDS: '3' },
      'MIME_OUTBOX_MAX_HELD_SHARDS',
    );
    refusal({ MIME_RETRY_BASE_MS: '5000', MIME_RETRY_MAX_MS: '4000' }, 'MIME_RETRY_MAX_MS');
  });

  it('refuses a parse memory footprint above MIME_MEMORY_BUDGET_BYTES', () => {
    // Per parse 5 MiB x 3 + 8 MiB = 23 MiB: 11 x 23 = 253 MiB fits 256 MiB, 12 x 23 does not.
    expect(parseMemoryBytes(load())).toBe(4 * 23 * 1024 * 1024);
    expect(load({ MIME_CONCURRENCY: '11' }).MIME_CONCURRENCY).toBe(11);
    refusal({ MIME_CONCURRENCY: '12' }, 'MIME_MEMORY_BUDGET_BYTES');
    refusal({ MIME_S3_QUEUE_SIZE: '4', MIME_CONCURRENCY: '8' }, 'MIME_MEMORY_BUDGET_BYTES');
    refusal(
      { MIME_ARCHIVE_MAX_CENTRAL_DIRECTORY_BYTES: '67108864', MIME_CONCURRENCY: '4' },
      'MIME_MEMORY_BUDGET_BYTES',
    );
  });

  it('counts every shard one replica may hold in the memory footprint', () => {
    // Each held shard runs its own MIME_CONCURRENCY parses: 4 x 8 x 23 MiB = 736 MiB.
    refusal(
      { MIME_CONCURRENCY: '4', MIME_OUTBOX_SHARDS: '8', MIME_OUTBOX_MAX_HELD_SHARDS: '8' },
      'MIME_MEMORY_BUDGET_BYTES',
    );
    expect(
      load({ MIME_CONCURRENCY: '4', MIME_OUTBOX_SHARDS: '8', MIME_OUTBOX_MAX_HELD_SHARDS: '2' })
        .MIME_OUTBOX_MAX_HELD_SHARDS,
    ).toBe(2);
    expect(
      load({
        MIME_CONCURRENCY: '4',
        MIME_OUTBOX_SHARDS: '8',
        MIME_OUTBOX_MAX_HELD_SHARDS: '8',
        MIME_MEMORY_BUDGET_BYTES: String(4 * 8 * 23 * 1024 * 1024),
      }).MIME_OUTBOX_MAX_HELD_SHARDS,
    ).toBe(8);
  });

  it('refuses S3 parts below the 5 MiB multipart minimum', () => {
    refusal({ MIME_S3_PART_SIZE_BYTES: '5242879' }, 'MIME_S3_PART_SIZE_BYTES');
  });
});

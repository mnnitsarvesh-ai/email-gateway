import { ARCHIVE_INDEX_MAPPING_REVISION } from '../versions';
import { indexPattern } from './names';

/**
 * The composable index template of the archive metadata index (§4.3). `dynamic: strict`: a
 * document with any other field is rejected by OpenSearch, so no body, header value, attachment
 * content or URL can ever be indexed by accident.
 */

export const KEYWORD_NORMALIZER = 'eg_lowercase';

const keyword = { type: 'keyword' } as const;
const normalized = { type: 'keyword', normalizer: KEYWORD_NORMALIZER } as const;

export const ARCHIVE_INDEX_MAPPING = Object.freeze({
  dynamic: 'strict',
  properties: {
    org_id: keyword,
    message_id: keyword,
    received_at: { type: 'date' },
    captured_at: { type: 'date' },
    direction: keyword,
    category: keyword,
    sources: keyword,
    status: keyword,
    envelope_from: normalized,
    header_from: normalized,
    sender_domain: normalized,
    recipients: normalized,
    recipient_domains: normalized,
    subject: {
      type: 'text',
      analyzer: 'standard',
      fields: { raw: { type: 'keyword', normalizer: KEYWORD_NORMALIZER, ignore_above: 256 } },
    },
    message_id_key: keyword,
    size_bytes: { type: 'long' },
    attachment_count: { type: 'integer' },
    attachment_names: {
      type: 'text',
      fields: { raw: { type: 'keyword', normalizer: KEYWORD_NORMALIZER, ignore_above: 256 } },
    },
    attachment_sha256: normalized,
    verdict: keyword,
    final_action: keyword,
    risk_score: { type: 'short' },
    malicious: { type: 'boolean' },
    dlp_matched: { type: 'boolean' },
    spf: keyword,
    dkim: keyword,
    dmarc: keyword,
    retain_until: { type: 'date' },
    legal_hold: { type: 'boolean' },
    lock_mode: keyword,
    indexed_at: { type: 'date' },
    /** Step 8.6 (mapping revision 2): `gateway`, `journal_intake` (the record's source flags). */
    ingest_sources: keyword,
  },
} as const);

/** Every document field (§4.3); the document builder emits exactly these. */
export const ARCHIVE_INDEX_FIELDS = Object.freeze(
  Object.keys(ARCHIVE_INDEX_MAPPING.properties),
) as readonly (keyof typeof ARCHIVE_INDEX_MAPPING.properties)[];

export interface IndexTemplateOptions {
  prefix: string;
  version?: number;
  /** `ARCHIVE_INDEX_SHARDS` (1 locally). */
  shards: number;
  /** `ARCHIVE_INDEX_REPLICAS` (0 locally). */
  replicas: number;
}

/** Body of `PUT _index_template/<prefix>-v<version>`. */
export function buildIndexTemplate(options: IndexTemplateOptions): Record<string, unknown> {
  const version = options.version ?? 1;
  if (!Number.isInteger(options.shards) || options.shards < 1 || options.shards > 64) {
    throw new RangeError('shards must be 1 … 64');
  }
  if (!Number.isInteger(options.replicas) || options.replicas < 0 || options.replicas > 16) {
    throw new RangeError('replicas must be 0 … 16');
  }
  return {
    index_patterns: [indexPattern(options.prefix, version)],
    priority: 200,
    template: {
      settings: {
        number_of_shards: options.shards,
        number_of_replicas: options.replicas,
        refresh_interval: '1s',
        analysis: {
          normalizer: {
            [KEYWORD_NORMALIZER]: { type: 'custom', filter: ['lowercase'] },
          },
        },
      },
      mappings: ARCHIVE_INDEX_MAPPING,
    },
    _meta: {
      owner: 'archive-worker',
      version,
      mappingRevision: ARCHIVE_INDEX_MAPPING_REVISION,
      design: 'step 8.1 §4.3, step 8.6 D7',
    },
  };
}

/**
 * Body of `PUT <index>/_mapping` that upgrades an existing index of the same version to the
 * current mapping revision (step 8.6 adds `ingest_sources`). Adding a field is an additive mapping
 * change OpenSearch accepts on a live index, so no reindex is needed; documents indexed before it
 * simply lack the field (the `source` filter treats a missing field as `gateway`). Re-run it for
 * every `<prefix>-v<version>-*` index before indexing documents with the field (the template
 * covers indices created afterwards). The 8.1 rebuild tooling (`cli/reindex`) remains the
 * fallback.
 */
export function buildIndexMappingUpdate(): Record<string, unknown> {
  return {
    properties: { ingest_sources: ARCHIVE_INDEX_MAPPING.properties.ingest_sources },
    _meta: { mappingRevision: ARCHIVE_INDEX_MAPPING_REVISION },
  };
}

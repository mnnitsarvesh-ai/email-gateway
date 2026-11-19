import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { PolicyRoundRows } from './input';
import type { SyntheticFacts } from './synthetic';

/**
 * The input corpus of the step 8.4 golden test (D23, §10.2): stored-row inputs of every trigger
 * and direction plus the synthetic facts of every worked example of
 * docs/architecture/policy-dsl.md (the 7.3 corpus). `ato-input.test.ts` proves that their
 * `inputSha256` values are exactly the ones the 7.3 build produced (recorded in
 * `golden-input-sha256.json` from the pre-8.4 build): inputs without ATO facts never change.
 */

const COMPLETED = new Date('2026-11-10T10:00:00.000Z');

function rows(extra: Partial<PolicyRoundRows> = {}): PolicyRoundRows {
  return {
    trigger: 'scanned',
    message: {
      direction: 'inbound',
      envelopeFrom: 'Alice@Partner.Example',
      headerFrom: 'alice@partner.example',
      clientIp: '::ffff:198.51.100.7',
      clientName: 'MX1.Partner.Example',
      sizeBytes: 12345,
      recipientCount: 2,
      attachmentCount: 1,
      lifecycleRound: 0,
    },
    recipients: [
      { rcptSeq: 1, address: 'Bob@Corp.Example' },
      { rcptSeq: 0, address: 'carol@corp.example' },
    ],
    scan: {
      scanId: 4242n,
      lifecycleRound: 0,
      scanKind: 'initial',
      status: 'completed',
      scanVerdict: 'clean',
      reasonCodes: [],
      requiredEngines: ['rspamd', 'attachment', 'url', 'bec', 'dlp'],
      completedAt: COMPLETED,
    },
    parseFailedAt: null,
    finals: [
      { engine: 'rspamd', outcome: 'clean', reasonCodes: ['clean.below_threshold'] },
      { engine: 'attachment', outcome: 'suspicious', reasonCodes: ['archive.encrypted'] },
      { engine: 'url', outcome: 'clean', reasonCodes: ['clean.no_findings'] },
      { engine: 'bec', outcome: 'clean', reasonCodes: ['clean.below_threshold'] },
      { engine: 'dlp', outcome: 'clean', reasonCodes: ['dlp.no_findings'] },
    ],
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', arc: 'none' },
    bec: { deterministicVerdict: 'clean', verdict: 'clean', rules: [] },
    dlp: { action: 'allow', verdict: 'clean', coverage: 'complete', categories: [] },
    risk: [],
    attachments: [
      {
        partIndex: 2,
        filename: 'Report.ZIP',
        declaredContentType: 'Application/Zip; name="x"',
        detectedContentType: 'application/zip',
        sizeBytes: 2048,
        sha256: 'A'.repeat(64),
        archiveInfo: { type: 'zip', encryptedEntries: 1 },
      },
    ],
    attachmentResults: [
      {
        partIndex: 2,
        detectedType: 'zip',
        typeFamily: 'archive',
        typeMismatch: false,
        verdict: 'suspicious',
        reasonCodes: ['archive.encrypted', 'archive.depth'],
        archive: { encrypted: true },
      },
    ],
    urls: [
      {
        urlSeq: 0,
        host: 'Login.Example.COM',
        registrableDomain: 'example.com',
        scheme: 'https',
        hostKind: 'domain',
        truncated: false,
      },
    ],
    urlResults: [{ urlSeq: 0, verdict: 'clean', reasonCodes: [], rewritten: true }],
    urlRewrite: { status: 'rewritten', skipReason: null },
    directory: { departmentsByAddress: {}, usersByAddress: {} },
    ...extra,
  };
}

const outboundMessage = (direction: 'outbound' | 'internal') => ({
  ...rows().message,
  direction,
  envelopeFrom: 'Finance@Corp.Example',
  headerFrom: 'finance@corp.example',
});

/** Stored-row inputs: every trigger and direction. */
export function rowCorpus(): Array<[string, PolicyRoundRows]> {
  return [
    ['inbound-scanned', rows()],
    ['outbound-scanned', rows({ message: outboundMessage('outbound') })],
    ['internal-scanned', rows({ message: outboundMessage('internal') })],
    [
      'inbound-scan-failed',
      rows({
        trigger: 'scan_failed',
        scan: { ...rows().scan!, status: 'timed_out', scanVerdict: 'error' },
        finals: [{ engine: 'rspamd', outcome: 'timeout', reasonCodes: [] }],
      }),
    ],
    [
      'outbound-parse-failed',
      rows({
        trigger: 'parse_failed',
        message: outboundMessage('outbound'),
        scan: null,
        parseFailedAt: COMPLETED,
        finals: [],
        auth: null,
        bec: null,
        dlp: null,
        attachments: [],
        attachmentResults: [],
        urls: [],
        urlResults: [],
        urlRewrite: null,
      }),
    ],
  ];
}

/** Synthetic facts of every worked example of docs/architecture/policy-dsl.md. */
export function docsFactsCorpus(): Array<[string, SyntheticFacts]> {
  const doc = readFileSync(resolve(__dirname, '../../../docs/architecture/policy-dsl.md'), 'utf8');
  return doc
    .split(/^### Example /m)
    .slice(1)
    .map((full): [string, SyntheticFacts] => {
      const section = full.split(/^## /m)[0]!;
      const title = section.split('\n', 1)[0]!;
      const blocks = [...section.matchAll(/```json\n([\s\S]*?)```/g)].map(
        (m) => JSON.parse(m[1]!) as unknown,
      );
      return [title, (blocks[1] as SyntheticFacts | undefined) ?? {}];
    });
}

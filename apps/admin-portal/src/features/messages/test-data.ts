import type { ListItem, SuccessBody } from '@/lib/api/types';

/** Test builders for the mail pages (typed against schema.gen.ts; synthetic values only). */
export const MESSAGE_ID = '01933c3a-1b2c-7d4e-8f00-00000000a001';
export const HOSTILE_SUBJECT =
  '<script>window.__pwned = 1</script><img src=x onerror=alert(1)>Invoice';

export function messageRow(
  overrides: Partial<ListItem<'MessagesController_list_v1'>> = {},
): ListItem<'MessagesController_list_v1'> {
  return {
    id: MESSAGE_ID,
    receivedAt: '2026-11-12T09:14:03.120Z',
    direction: 'inbound',
    status: 'quarantined',
    statusChangedAt: '2026-11-12T09:14:08.000Z',
    subject: 'Quarterly report',
    envelopeFrom: 'alex.lee12@example.com',
    headerFrom: 'alex.lee12@example.com',
    recipientCount: 2,
    attachmentCount: 1,
    sizeBytes: 48_213,
    finalVerdict: 'phishing',
    finalAction: 'quarantine',
    riskScore: 870,
    domainId: '01933c3a-1b2c-7d4e-8f00-00000000d001',
    ...overrides,
  };
}

export function messageDetail(
  overrides: Partial<SuccessBody<'MessagesController_detail_v1'>> = {},
): SuccessBody<'MessagesController_detail_v1'> {
  return {
    ...messageRow(),
    internetMessageId: '<abc.1@mail.example.test>',
    lifecycleRound: 0,
    version: 6,
    statusReason: 'policy_quarantine',
    clientIp: '198.51.100.7',
    clientHelo: 'mx1.example.test',
    mtaQueueId: '4XABCDEF12',
    ...overrides,
  };
}

/**
 * Proof that attacker-controlled strings stayed text: no element was created from them (the
 * next-themes inline script of the test providers is the only script allowed), no event-handler
 * attribute exists, no image, no iframe and no element with a `javascript:` or data URL.
 */
export function expectNoInjectedMarkup(container: HTMLElement): void {
  const scripts = Array.from(container.querySelectorAll('script')).filter(
    (script) => !script.textContent?.includes('prefers-color-scheme'),
  );
  if (scripts.length > 0) throw new Error('An injected <script> element was rendered');
  for (const selector of ['img', 'iframe', 'svg[onload]', 'object', 'embed']) {
    if (container.querySelector(selector))
      throw new Error(`An injected <${selector}> was rendered`);
  }
  for (const element of Array.from(container.querySelectorAll('*'))) {
    for (const attribute of Array.from(element.attributes)) {
      if (/^on/i.test(attribute.name)) throw new Error(`Event handler attribute ${attribute.name}`);
      if (/^(javascript|data):/i.test(attribute.value.trim()) && /href|src/i.test(attribute.name)) {
        throw new Error(`Dangerous URL in ${attribute.name}`);
      }
    }
  }
}

type ScanRound = ListItem<'MessageScansController_scansOf_v1'>;
type Evaluation = SuccessBody<'PolicyMessagesController_evaluations_v1'>['data'][number];

export function evaluation(overrides: Partial<Evaluation> = {}): Evaluation {
  return {
    status: 'evaluated',
    round: { trigger: 'scanned', direction: 'inbound', lifecycleRound: 0, scanId: '900001' },
    disposition: 'quarantine',
    finalVerdict: 'phishing',
    riskScore: 870,
    decisive: {
      source: 'tenant_rule',
      policyPublicId: 'pol-inbound-threats',
      versionNo: 3,
      ruleId: 'block-high-risk',
      reason: 'policy.rule.matched',
    },
    actions: [
      {
        type: 'QUARANTINE',
        params: {},
        origin: 'tenant_rule',
        ruleRefs: ['pol-inbound-threats/3#block-high-risk'],
        applicability: 'applies',
      },
    ],
    delivery: null,
    notices: { senderNonDelivery: false },
    matchedRules: [
      {
        ref: 'pol-inbound-threats/3#block-high-risk',
        policyPublicId: 'pol-inbound-threats',
        versionNo: 3,
        ruleId: 'block-high-risk',
        disposition: 'quarantine',
        actionTypes: ['QUARANTINE'],
        override: false,
      },
    ],
    trace: [],
    traceTruncated: false,
    floor: { disposition: null, tag: false, reasons: [] },
    recommendation: {
      disposition: 'quarantine',
      tag: false,
      levelOnly: false,
      riskAction: 'quarantine',
      revisions: [0],
    },
    override: null,
    clamps: [],
    reasonCodes: ['policy.rule.matched'],
    explanation: { lines: [], text: 'Decided by rule block-high-risk: quarantine.' },
    versions: {
      dsl: 'policy-dsl/1',
      evaluator: 'policy-eval/2',
      input: 'policy-input/1',
      platformDefault: 'platform-default/1',
      snapshotSha256: 'a'.repeat(64),
      generation: '42',
      tzdata: '2026a',
      policies: [],
    },
    inputSha256: 'b'.repeat(64),
    lifecycleRound: 0,
    trigger: 'scanned',
    direction: 'inbound',
    finalAction: 'quarantine',
    actionStatuses: ['enforced'],
    deliveredObject: 'none',
    evaluatedAt: '2026-11-12T09:14:07.000Z',
    durationUs: 1850,
    recipientSplit: false,
    recipientDecisions: null,
    ...overrides,
  };
}

export function scanRound(overrides: Partial<ScanRound> = {}): ScanRound {
  return {
    scanId: '900001',
    round: 0,
    scanKind: 'initial',
    status: 'completed',
    verdict: 'malicious',
    reasonCodes: ['phishing.lookalike'],
    requiredEngines: ['rspamd', 'url'],
    startedAt: '2026-11-12T09:14:03.400Z',
    completedAt: '2026-11-12T09:14:05.800Z',
    deadlineAt: '2026-11-12T09:16:03.400Z',
    auth: {
      spf: 'softfail',
      spfDomain: 'example.com',
      dkim: 'fail',
      dkimSignatures: [{ domain: 'example.com', result: 'fail', selector: 's2026' }],
      dmarc: 'fail',
      dmarcPolicy: 'quarantine',
      dmarcDomain: 'example.com',
      arc: 'none',
    },
    engines: [
      {
        engine: 'rspamd',
        final: true,
        engineVersion: '3.10.2',
        outcome: 'clean',
        score: 1.2,
        requiredScore: 6,
        action: 'no action',
        reasonCodes: ['clean.no_findings'],
        symbols: [
          {
            name: 'FROM_NEQ_ENVFROM',
            score: 0.4,
            options: ['<b onmouseover=alert(1)>spoof@example.test</b>'],
          },
        ],
        attempts: [
          {
            attempt: 1,
            outcome: 'clean',
            errorCode: null,
            durationMs: 120,
            at: '2026-11-12T09:14:03.600Z',
          },
        ],
        durationMs: 130,
        settingsVersion: 'rspamd/4',
        completedAt: '2026-11-12T09:14:04.000Z',
      },
      {
        engine: 'url',
        final: true,
        engineVersion: 'url/1.6.0',
        outcome: 'malicious',
        score: null,
        requiredScore: null,
        action: null,
        reasonCodes: ['phishing.lookalike'],
        symbols: [],
        attempts: [
          {
            attempt: 1,
            outcome: 'timeout',
            errorCode: 'engine.timeout',
            durationMs: null,
            at: '2026-11-12T09:14:04.000Z',
          },
        ],
        durationMs: null,
        settingsVersion: 'url/2',
        completedAt: '2026-11-12T09:14:05.000Z',
      },
      {
        engine: 'dlp',
        final: true,
        engineVersion: 'dlp/1.1.0',
        outcome: 'clean',
        score: null,
        requiredScore: null,
        action: null,
        reasonCodes: ['clean.no_findings'],
        symbols: [],
        attempts: [],
        durationMs: null,
        settingsVersion: 'dlp/2',
        completedAt: '2026-11-12T09:14:05.000Z',
        dlp: null,
      },
    ],
    risk: [
      {
        status: 'scored',
        score: 870,
        level: 'critical',
        verdict: 'phishing',
        recommendedAction: 'quarantine',
        hardBlocks: [],
        reasonCodes: ['risk.phishing'],
        contributions: [],
        groups: [],
        engines: [],
        failures: [],
        floors: [],
        trust: { status: 'off', factorPermille: 1000, reducedGroups: [], pointsRemoved: 0 },
        evidence: {
          auth: null,
          dlp: null,
          bec: null,
          sandbox: null,
          unmappedCodes: [],
          aiRaiseOnly: false,
        },
        explanation: { lines: [], text: 'Risk 870 (critical); top signal url_threat.' },
        versions: {
          scorer: 'risk-score/1',
          signalMap: 'risk-signals/1',
          input: 'risk-input/1',
          profile: {
            source: 'platform',
            id: 'rsk-default/1',
            versionNo: null,
            sha256: 'c'.repeat(64),
          },
        },
        inputSha256: 'd'.repeat(64),
        revision: 0,
        createdAt: '2026-11-12T09:14:06.000Z',
      },
    ],
    policy: evaluation(),
    ...overrides,
  };
}

export function attachmentRow(
  overrides: Partial<ListItem<'AttachmentsController_ofMessage_v1'>> = {},
): ListItem<'AttachmentsController_ofMessage_v1'> {
  return {
    partIndex: 2,
    filename: 'invoice.pdf',
    declaredContentType: 'application/pdf',
    detectedContentType: 'application/pdf',
    sizeBytes: 81_920,
    sha256: 'e'.repeat(64),
    disposition: 'attachment',
    depth: 0,
    verdict: 'clean',
    latestScan: {
      verdict: 'clean',
      reasonCodes: ['clean.no_findings'],
      detectedType: 'pdf',
      typeFamily: 'document',
      typeMismatch: false,
      clamav: { signature: null, engineVersion: '1.4.1', dbVersion: 27450 },
      yara: null,
      archive: null,
      knownHash: null,
      round: 0,
    },
    ...overrides,
  };
}

export function urlRow(
  overrides: Partial<ListItem<'UrlProtectionController_ofMessage_v1'>> = {},
): ListItem<'UrlProtectionController_ofMessage_v1'> {
  return {
    urlSeq: 0,
    url: 'https://cdn.example.test/newsletter',
    host: 'cdn.example.test',
    unicodeHost: null,
    registrableDomain: 'example.test',
    hostKind: 'domain',
    sources: { html_href: 1 },
    flags: [],
    latest: { round: 0, verdict: 'clean', reasonCodes: ['clean.no_findings'], rewritten: true },
    rewrite: { status: 'rewritten', skipReason: null, round: 0 },
    clicks: { total: 2, byDecision: { allowed: 2 } },
    ...overrides,
  };
}

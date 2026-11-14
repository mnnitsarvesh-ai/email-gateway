import type { ListItem, OperationId, SuccessBody } from '@/lib/api/types';
import { mockApi, okJson, type MockHandler } from '@/test';
import { CATALOG, entryDetail, entrySummary } from '@/features/quarantine/test-data';
import {
  MESSAGE_ID,
  attachmentRow,
  evaluation,
  messageDetail,
  scanRound,
  urlRow,
} from '../test-data';

/** Test builders and MSW wiring of the Email Details tests (synthetic values only). */
type ScanRound = ListItem<'MessageScansController_scansOf_v1'>;
type Engine = ScanRound['engines'][number];

export { MESSAGE_ID };
export const RECEIVED_AT = messageDetail().receivedAt;
export const ENTRY_ID = entrySummary().id;
export const SECOND_ENTRY_ID = '01933c3a-1b2c-7d4e-8f00-0000000e0002';

export function lifecycleBody(
  overrides: Partial<SuccessBody<'MessageLifecycleController_lifecycle_v1'>> = {},
): SuccessBody<'MessageLifecycleController_lifecycle_v1'> {
  return {
    messageId: MESSAGE_ID,
    receivedAt: RECEIVED_AT,
    direction: 'inbound',
    state: 'quarantined',
    statusReason: 'policy_quarantine',
    version: 6,
    lifecycleRound: 0,
    statusChangedAt: '2026-11-12T09:14:08.000Z',
    parse: { status: 'parsed', completedAt: '2026-11-12T09:14:03.900Z' },
    recipients: { total: 2, byStatus: { quarantined: 2 } },
    deliverySeq: null,
    actions: { rescan: true, release: true },
    ...overrides,
  };
}

export function historyItem(
  version: number,
  toState: ListItem<'MessageLifecycleController_history_v1'>['toState'],
  fromState: ListItem<'MessageLifecycleController_history_v1'>['fromState'] = null,
): ListItem<'MessageLifecycleController_history_v1'> {
  return {
    version,
    fromState,
    toState,
    reasonCode: toState === 'quarantined' ? 'policy_quarantine' : null,
    lifecycleRound: 0,
    actor: { role: 'policy', type: 'system', service: 'email-worker', id: null },
    causationEventId: null,
    correlationId: null,
    occurredAt: '2026-11-12T09:14:05.000Z',
    changedAt: '2026-11-12T09:14:05.000Z',
  };
}

export function recipientRow(
  rcptSeq: number,
  overrides: Partial<ListItem<'MessagesController_recipients_v1'>> = {},
): ListItem<'MessagesController_recipients_v1'> {
  return {
    rcptSeq,
    address: rcptSeq === 0 ? 'p***@alpha.example.test' : 'm***@alpha.example.test',
    addressMasked: true,
    status: 'quarantined',
    finalAction: 'quarantine',
    direction: 'inbound',
    userId: null,
    latestDelivery: null,
    ...overrides,
  };
}

/** Clear values of the reveal (synthetic). */
export const REVEALED = {
  subject: 'Revealed subject: invoice 4471',
  to: 'priya.rao4@alpha.example.test, maria.silva7@alpha.example.test',
  addresses: ['priya.rao4@alpha.example.test', 'maria.silva7@alpha.example.test'],
};

export function revealBody(
  options: { recipients?: [number, string][]; nextCursor?: string | null; subject?: boolean } = {},
): SuccessBody<'MessageRevealController_reveal_v1'> {
  const recipients = options.recipients ?? [[0, REVEALED.addresses[0] ?? '']];
  return {
    messageId: MESSAGE_ID,
    revealedAt: '2026-11-14T09:02:11.418Z',
    ...(options.subject === false
      ? {}
      : {
          subject: REVEALED.subject,
          headers: [
            { seq: 3, name: 'To', value: REVEALED.to },
            { seq: 5, name: 'Subject', value: REVEALED.subject },
          ],
        }),
    recipients: {
      data: recipients.map(([rcptSeq, address]) => ({
        rcptSeq,
        address,
        userId: rcptSeq === 0 ? '01933c3a-1b2c-7d4e-8f00-0000000c0a11' : null,
      })),
      nextCursor: options.nextCursor ?? null,
    },
  };
}

export function headersBody(
  availability: SuccessBody<'MessageHeadersController_headers_v1'>['availability'] = 'available',
): SuccessBody<'MessageHeadersController_headers_v1'> {
  return {
    messageId: MESSAGE_ID,
    availability,
    storedHeaderNames: [
      'From',
      'Sender',
      'Reply-To',
      'To',
      'Cc',
      'Subject',
      'Message-ID',
      'Date',
      'In-Reply-To',
      'References',
      'Return-Path',
      'Authentication-Results',
    ],
    safeHeaderNames: [
      'From',
      'Sender',
      'Reply-To',
      'Return-Path',
      'Date',
      'Message-ID',
      'In-Reply-To',
      'References',
      'Authentication-Results',
    ],
    headers:
      availability === 'available'
        ? [
            { seq: 0, name: 'Return-Path', value: '<alex.lee12@example.com>', masked: false },
            {
              seq: 1,
              name: 'Authentication-Results',
              value: 'mx.alpha.example.test; spf=softfail smtp.mailfrom=example.com; dmarc=fail',
              masked: false,
            },
            {
              seq: 2,
              name: 'From',
              value: '"<img src=x onerror=alert(1)>" <alex.lee12@example.com>',
              masked: false,
            },
            { seq: 3, name: 'To', value: null, masked: true },
            { seq: 4, name: 'Message-ID', value: '<abc.1@mail.example.test>', masked: false },
            { seq: 5, name: 'Subject', value: null, masked: true },
          ]
        : [],
  };
}

/** A round with every engine's details (attachment, sandbox, url + rewrite, bec, dlp). */
export function fullRound(overrides: Partial<ScanRound> = {}): ScanRound {
  const base = scanRound();
  const engines: Engine[] = base.engines.map((engine): Engine => {
    if (engine.engine === 'url') {
      return {
        ...engine,
        urls: [
          {
            urlSeq: 0,
            url: 'https://login.micr0soft-example.example.test/verify',
            host: 'login.micr0soft-example.example.test',
            unicodeHost: null,
            registrableDomain: 'micr0soft-example.example.test',
            hostKind: 'domain',
            sources: { html_href: 1 },
            flags: ['url.lookalike_homoglyph'],
            verdict: 'malicious',
            reasonCodes: ['url.lookalike_homoglyph'],
            landing: null,
            dynamic: null,
            rewritten: true,
            reputation: [
              { provider: 'local_feed', kind: 'domain', status: 'listed', category: 'phishing' },
            ],
            lookalike: [
              {
                rule: 'L1',
                targetKind: 'brand',
                targetDomain: 'microsoft-example.example.test',
                score: 0.92,
              },
            ],
            fetch: null,
            clicks: { total: 2, lastDecision: 'blocked', lastAt: '2026-11-12T10:00:00.000Z' },
          },
        ],
        rewrite: {
          status: 'rewritten',
          skipReason: null,
          linksRewritten: 1,
          partsRewritten: 1,
          dkimSigned: false,
          expiresAt: '2026-12-12T09:14:05.000Z',
        },
      };
    }
    if (engine.engine === 'dlp') {
      return {
        ...engine,
        outcome: 'suspicious',
        dlp: {
          engineVersion: 'dlp/1.1.0',
          rulesVersion: 'dlp-rules/4',
          settingsVersion: 'dlp-settings/2',
          policyVersion: 'dlp-policy/9',
          extractorVersion: 'extractor/3',
          verdict: 'suspicious',
          action: 'quarantine',
          actionSource: 'tenant_policy',
          coverage: 'complete',
          coverageDetail: [
            {
              source: 'body_text',
              format: 'text',
              status: 'scanned',
              reasons: [],
              chars: 2310,
              truncated: false,
            },
          ],
          aadhaar: 'disabled',
          categories: [
            { category: 'payment_card', count: 2, maxSeverity: 'high', maxConfidence: 0.97 },
          ],
          findings: [
            {
              detector: 'PC1',
              code: 'dlp.payment_card',
              category: 'payment_card',
              severity: 'high',
              confidence: 0.97,
              count: 2,
              capped: false,
              sources: [{ kind: 'body_text' }],
              masked: ['4111 11•• •••• 1111'],
            },
          ],
          policy: {
            winner: { policyId: 'dlp-pol-1', ruleId: 'dlp-rule-1' },
            matched: [],
            exceptionsApplied: [],
          },
          evidence: { status: 'stored', expiresAt: '2026-12-12T09:14:05.000Z', purged: false },
        },
      };
    }
    return engine;
  });
  engines.push(
    {
      engine: 'attachment',
      final: true,
      engineVersion: 'attachment/2.1.0',
      outcome: 'clean',
      score: null,
      requiredScore: null,
      action: null,
      reasonCodes: ['clean.no_findings'],
      symbols: [],
      attempts: [],
      durationMs: null,
      settingsVersion: 'attachment/3',
      completedAt: '2026-11-12T09:14:05.000Z',
      attachments: [
        {
          partIndex: 2,
          sha256: 'e'.repeat(64),
          sizeBytes: 81_920,
          detectedType: 'pdf',
          typeFamily: 'document',
          typeMismatch: false,
          verdict: 'clean',
          reasonCodes: ['clean.no_findings'],
          clamav: null,
          yara: null,
          archive: null,
          knownHash: null,
          filename: '<img src=x onerror=alert(1)>.pdf',
          declaredContentType: 'application/pdf',
          sandbox: null,
        },
      ],
    },
    {
      engine: 'sandbox',
      final: true,
      engineVersion: 'sandbox/1.0.0',
      outcome: 'unknown',
      score: null,
      requiredScore: null,
      action: null,
      reasonCodes: ['sandbox.not_executed.backend_disabled'],
      symbols: [],
      attempts: [],
      durationMs: null,
      settingsVersion: 'sandbox/1',
      completedAt: '2026-11-12T09:15:00.000Z',
      submissions: [
        {
          submissionId: '01933c3a-1b2c-7d4e-8f00-0000000d5001',
          status: 'completed',
          skipReason: null,
          verdict: 'unknown',
          reasonCodes: ['sandbox.not_executed.backend_disabled'],
          executed: false,
          isolation: 'process',
          completedAt: '2026-11-12T09:15:00.000Z',
          partIndex: 2,
          sha256: 'e'.repeat(64),
          backend: 'static',
          versions: { controller: null, backend: null, analyzer: null, map: null },
          findings: [{ code: 'static.pe_packed', severity: 'high', count: 1 }],
          indicators: { dns: ['update.example.test'], httpHosts: [], tlsSni: [], ips: [] },
          processes: { count: 0, images: [] },
          droppedFiles: [],
          limitsHit: [],
          artifacts: [],
        },
      ],
    },
    {
      engine: 'bec',
      final: true,
      engineVersion: 'bec/1.2.0',
      outcome: 'suspicious',
      score: 520,
      requiredScore: null,
      action: null,
      reasonCodes: ['bec.impersonation.executive_name'],
      symbols: [],
      attempts: [],
      durationMs: null,
      settingsVersion: 'bec/1',
      completedAt: '2026-11-12T09:14:05.000Z',
      bec: {
        rulesVersion: 'bec-rules/7',
        engineVersion: 'bec/1.2.0',
        settingsVersion: 'bec-settings/3',
        lexiconVersion: 'lexicon/12',
        verdict: 'suspicious',
        deterministicVerdict: 'suspicious',
        score: 520,
        deterministicScore: 520,
        thresholds: { suspicious: 400, malicious: 800 },
        inputs: { auth: 'available', url: 'available', text: 'complete', history: 'enabled' },
        rules: [
          {
            id: 'I1',
            code: 'bec.impersonation.executive_name',
            category: 'impersonation',
            severity: 'high',
            weight: 220,
            suppressed: null,
            evidence: [
              {
                header: 'From',
                displayName: '<b onmouseover=alert(1)>Chief Executive</b>',
                profile: { kind: 'executive', id: 'prof-ceo', match: 'token_set' },
              },
            ],
          },
        ],
        ai: [
          {
            layer: 'local',
            mode: 'active',
            provider: 'local',
            modelId: 'bec-local',
            modelVersion: '2026.10',
            promptTemplateVersion: null,
            status: 'ok',
            labels: [{ label: 'bec', confidence: 0.81 }],
            confidence: 0.81,
            indicators: ['executive_impersonation'],
            citedFeatures: [],
            spans: [],
            effect: 'none',
          },
        ],
        aiShadow: [],
        feedback: [
          { id: 'fb-0001', kind: 'false_positive', createdAt: '2026-11-12T12:00:00.000Z' },
        ],
      },
    },
  );
  const risk = base.risk.map((revision) => ({
    ...revision,
    contributions: [
      {
        signal: 'url_known_phishing' as const,
        group: 'url_threat' as const,
        weight: 450,
        codes: ['url.feed_malicious'],
        applied: 450,
      },
    ],
    groups: [
      {
        group: 'url_threat' as const,
        rule: 'max' as const,
        raw: 450,
        multiplierPermille: 1000,
        trustFactorPermille: null,
        cap: null,
        total: 450,
      },
    ],
  }));
  return { ...base, reasonCodes: ['phishing.lookalike'], engines, risk, ...overrides };
}

export function deliveriesBody(): SuccessBody<'DeliveriesController_forMessage_v1'> {
  return {
    message: {
      id: MESSAGE_ID,
      direction: 'inbound',
      status: 'delivered',
      statusReason: null,
      receivedAt: RECEIVED_AT,
    },
    deliveries: [
      {
        rcptSeq: 0,
        deliverySeq: 0,
        recipient: 'p***@alpha.example.test',
        recipientMasked: true,
        direction: 'inbound',
        status: 'delivered',
        attemptCount: 1,
        lastAttemptAt: '2026-11-12T09:14:11.000Z',
        deliveredAt: '2026-11-12T09:14:11.000Z',
        remoteHost: 'mx1.alpha.example.test',
        finalSmtpCode: 250,
        enhancedStatus: '2.0.0',
        finalSmtpResponse: '250 2.0.0 Ok: queued as 4XABC for <p***@alpha.example.test>',
        lastErrorClass: null,
        failureReason: null,
        dsnGenerated: false,
        statusChangedAt: '2026-11-12T09:14:11.000Z',
      },
    ],
  };
}

export function deliveryEvent(
  overrides: Partial<ListItem<'DeliveriesController_events_v1'>> = {},
): ListItem<'DeliveriesController_events_v1'> {
  return {
    rcptSeq: 0,
    deliverySeq: 0,
    source: 'postfix_log',
    fromStatus: 'queued',
    toStatus: 'delivered',
    applied: true,
    occurredAt: '2026-11-12T09:14:11.000Z',
    queueId: '4XABC',
    smtpCode: 250,
    enhancedStatus: '2.0.0',
    remoteHost: 'mx1.alpha.example.test',
    errorClass: null,
    detail: 'delivered to <p***@alpha.example.test>',
    ...overrides,
  };
}

export function auditRow(
  overrides: Partial<ListItem<'AuditLogsController_search_v1'>> = {},
): ListItem<'AuditLogsController_search_v1'> {
  return {
    id: '9500001',
    createdAt: '2026-11-13T10:00:00.000Z',
    actor: { type: 'user', id: '01930000-0000-7000-8000-000000000101' },
    action: 'message.revealed',
    resourceType: 'message',
    resourceId: MESSAGE_ID,
    correlationId: null,
    sourceIp: '198.51.100.10',
    metadata: { fields: ['subject'], bulk: true, requestId: 'req-1' },
    ...overrides,
  };
}

export interface RecordedRequest {
  readonly operationId: OperationId;
  readonly url: URL;
  readonly body: unknown;
  readonly headers: Headers;
}

/** Default answers of every operation the details page may call (override per test). */
export function detailHandlers(): Partial<Record<OperationId, MockHandler>> {
  return {
    MessagesController_detail_v1: () => okJson(messageDetail()),
    MessageLifecycleController_lifecycle_v1: () => okJson(lifecycleBody()),
    MessageLifecycleController_history_v1: () =>
      okJson({
        data: [historyItem(1, 'received'), historyItem(2, 'quarantined', 'received')],
        nextCursor: null,
      }),
    MessagesController_recipients_v1: () =>
      okJson({ data: [recipientRow(0), recipientRow(1)], nextCursor: null }),
    MessageRevealController_reveal_v1: () =>
      okJson(revealBody(), 200, { 'cache-control': 'no-store' }),
    MessageHeadersController_headers_v1: () => okJson(headersBody()),
    MessageScansController_scansOf_v1: () =>
      okJson({ messageId: MESSAGE_ID, data: [fullRound()], nextCursor: null }),
    UrlProtectionController_ofMessage_v1: () =>
      okJson({ data: [urlRow({ url: 'javascript:alert(document.domain)' })], nextCursor: null }),
    AttachmentsController_ofMessage_v1: () => okJson({ data: [attachmentRow()], nextCursor: null }),
    PolicyMessagesController_evaluations_v1: () =>
      okJson({ messageId: MESSAGE_ID, data: [evaluation()] }),
    DeliveriesController_forMessage_v1: () => okJson(deliveriesBody()),
    DeliveriesController_events_v1: () => okJson({ data: [deliveryEvent()], nextCursor: null }),
    QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
    QuarantineEntriesController_search_v1: () =>
      okJson({
        items: [entrySummary({ recipient: 'priya.rao4@alpha.example.test' })],
        nextCursor: null,
      }),
    QuarantineEntriesController_detail_v1: () => okJson(entryDetail()),
    QuarantineEntriesController_history_v1: () =>
      okJson({
        actions: [
          {
            action: 'quarantine',
            actor: { type: 'system', id: null },
            result: 'held',
            reason: null,
            at: '2026-11-12T09:14:08.000Z',
          },
        ],
        releases: [],
      }),
    AuditLogsController_search_v1: ({ url }) =>
      okJson({
        data:
          url.searchParams.get('resourceType') === 'dlp_evidence'
            ? [
                auditRow({
                  id: '9500002',
                  action: 'dlp_evidence.read',
                  resourceType: 'dlp_evidence',
                }),
              ]
            : [auditRow()],
        nextCursor: null,
      }),
  };
}

/** Mocks every details operation (defaults + overrides) and records each request in order. */
export function mockDetails(overrides: Partial<Record<OperationId, MockHandler>> = {}): {
  readonly requests: RecordedRequest[];
  readonly calls: (operationId: OperationId) => RecordedRequest[];
} {
  const requests: RecordedRequest[] = [];
  const handlers = { ...detailHandlers(), ...overrides };
  mockApi(
    Object.fromEntries(
      Object.entries(handlers).map(([operationId, handler]) => [
        operationId,
        ((context) => {
          requests.push({
            operationId: operationId as OperationId,
            url: context.url,
            body: context.body,
            headers: context.request.headers,
          });
          return handler(context);
        }) satisfies MockHandler,
      ]),
    ),
  );
  return {
    requests,
    calls: (operationId) => requests.filter((request) => request.operationId === operationId),
  };
}

export const detailsRoute = (query = '') => `/messages/${MESSAGE_ID}${query ? `?${query}` : ''}`;

/** `window.matchMedia` that answers min/max-width queries for a viewport width. */
export function setViewportWidth(width: number): () => void {
  const descriptor = Object.getOwnPropertyDescriptor(window, 'matchMedia');
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string) => {
      const min = /min-width:\s*(\d+)px/.exec(query);
      const max = /max-width:\s*(\d+)px/.exec(query);
      const matches = (!min || width >= Number(min[1])) && (!max || width <= Number(max[1]));
      return {
        matches,
        media: query,
        onchange: null,
        addListener: () => undefined,
        removeListener: () => undefined,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        dispatchEvent: () => false,
      };
    },
  });
  return () => {
    if (descriptor) Object.defineProperty(window, 'matchMedia', descriptor);
  };
}

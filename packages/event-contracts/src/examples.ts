import type { RegisteredEventType } from './registry';

/**
 * One valid, metadata-only example payload per registered event type (organization `42`).
 * Used by contract tests (registry, content guard) and documentation; never by production code.
 * Each example passes its registry schema (asserted by `registry.test.ts`).
 */
const receivedAt = '2026-11-01T10:15:30.123Z';
const messageId = '9007199254740993';
const emlS3Key = 'org/42/eml/2026/11/01/9007199254740993.eml';
const partPrefix = 'org/42/part/2026/11/01/9007199254740993';
const sandboxTaskId = '01890a5d-ac96-774b-bcce-b302099a8070';
const policyPublicId = '01890a5d-ac96-774b-bcce-b302099a8090';
const atoUserPublicId = '01890a5d-ac96-774b-bcce-b302099a80a1';
const atoAccountPublicId = '01890a5d-ac96-774b-bcce-b302099a80a2';
const atoIncidentPublicId = '01890a5d-ac96-774b-bcce-b302099a80a3';
const atoActionPublicId = '01890a5d-ac96-774b-bcce-b302099a80a4';

export const EXAMPLE_EVENT_PAYLOADS: Readonly<Record<RegisteredEventType, unknown>> = {
  'mail.message.received.v1': {
    messageId,
    receivedAt,
    direction: 'inbound',
    emlS3Key,
    sizeBytes: 1024,
    envelopeFrom: 'sender@example.com',
    recipientCount: 1,
    // Step 8.6 (optional; absent = gateway): `journal_intake` for journal intake copies; step
    // API-1: `mailbox_api` for provider mailbox feed copies.
    ingestSource: 'gateway',
  },
  'mail.message.parsed.v1': {
    messageId,
    receivedAt,
    direction: 'inbound',
    emlS3Key,
    parseStatus: 'parsed',
    parserVersion: '1.0.0',
    limitsExceeded: [],
    defects: [],
    textBody: { s3Key: `${partPrefix}/1.text`, sha256: 'a'.repeat(64), sizeBytes: 120 },
    htmlBody: { s3Key: `${partPrefix}/2.html`, sha256: 'b'.repeat(64), sizeBytes: 480 },
    attachmentCount: 2,
    flaggedAttachmentCount: 1,
    attachmentFlags: ['filename_double_extension', 'executable'],
    partCount: 5,
    maxDepth: 2,
    headerCount: 14,
  },
  'mail.message.parse_failed.v1': {
    messageId,
    receivedAt,
    direction: 'outbound',
    emlS3Key,
    reason: 'integrity_mismatch',
    attempts: 1,
    parserVersion: '1.0.0',
  },
  'mail.message.scanned.v1': {
    messageId,
    receivedAt,
    direction: 'inbound',
    emlS3Key,
    lifecycleRound: 0,
    scanId: '11',
    scanKind: 'initial',
    outcome: 'scanned',
    verdict: 'spam',
    engines: [{ engine: 'rspamd', required: true, outcome: 'spam', attempts: 1 }],
    reasonCodes: ['spam.score', 'reputation.ip_listed', 'auth.spf_fail'],
    completedAt: '2026-11-01T10:15:31.456Z',
  },
  'mail.policy.decided.v1': {
    messageId,
    receivedAt,
    direction: 'inbound',
    lifecycleRound: 0,
    scanId: '11',
    trigger: 'scanned',
    disposition: 'quarantine',
    finalAction: 'quarantine',
    finalVerdict: 'phishing',
    riskScore: 720,
    nonTerminalActions: ['ARCHIVE', 'ALERT'],
    decisive: {
      source: 'tenant_rule',
      policyId: policyPublicId,
      versionNo: 3,
      ruleId: 'quarantine-malware-phishing',
    },
    overrideApplied: false,
    policyGeneration: '7',
    snapshotSha256: 'd'.repeat(64),
    inputSha256: 'e'.repeat(64),
    evaluatedAt: '2026-11-01T10:15:31.789Z',
  },
  'mail.message.archive_requested.v1': {
    messageId,
    receivedAt,
    direction: 'inbound',
    lifecycleRound: 0,
    emlS3Key,
    source: 'policy',
    ruleRef: `${policyPublicId}#3/archive-legal`,
    policyGeneration: '7',
    requestedAt: '2026-11-01T10:15:31.789Z',
  },
  'mail.policy.notification_requested.v1': {
    messageId,
    receivedAt,
    direction: 'outbound',
    lifecycleRound: 0,
    kind: 'sender_non_delivery',
    severity: 'warning',
    disposition: 'reject',
    decisive: {
      source: 'tenant_rule',
      policyId: policyPublicId,
      versionNo: 3,
      ruleId: 'block-card-numbers',
    },
    ruleRefs: [`${policyPublicId}#3/block-card-numbers`],
    requestedAt: '2026-11-01T10:15:31.789Z',
  },
  'mail.quarantine.release_requested.v1': {
    releaseId: '01890a5d-ac96-774b-bcce-b302099a80a0',
    messageId,
    receivedAt,
    entryIds: ['01890a5d-ac96-774b-bcce-b302099a80a1', '01890a5d-ac96-774b-bcce-b302099a80a2'],
    mode: 'approved',
    approvalRequestId: '01890a5d-ac96-774b-bcce-b302099a80a3',
    requestedBy: { type: 'user', id: '01890a5d-ac96-774b-bcce-b302099a80a4' },
    requestedAt: '2026-11-02T09:00:00.000Z',
  },
  'mail.quarantine.notification_requested.v1': {
    kind: 'user_digest',
    refs: {
      userId: '01890a5d-ac96-774b-bcce-b302099a80a4',
      digestId: '01890a5d-ac96-774b-bcce-b302099a80a5',
    },
    window: { from: '2026-11-01T08:00:00.000Z', to: '2026-11-02T08:00:00.000Z' },
    requestedAt: '2026-11-02T08:00:01.000Z',
  },
  'mail.delivery.approved.v1': {
    messageId,
    receivedAt,
    deliverySeq: 0,
    source: 'policy',
    emlS3Key,
    recipients: [
      { recipientId: '11', rcptSeq: 0 },
      { recipientId: '12', rcptSeq: 1 },
    ],
    approvedAt: '2026-11-01T10:16:00.000Z',
    lifecycleRound: 0,
  },
  'mail.message.state_changed.v1': {
    messageId,
    receivedAt,
    direction: 'inbound',
    previousState: 'delivery_pending',
    state: 'delivered',
    version: 4,
    lifecycleRound: 0,
    reasonCode: 'delivery_complete',
    actorRole: 'delivery',
    actorType: 'system',
    actorService: 'delivery-worker',
    causationEventId: '01890a5d-ac96-774b-bcce-b302099a8057',
    changedAt: '2026-11-01T10:20:01.000Z',
  },
  'mail.message.rescan_requested.v1': {
    messageId,
    receivedAt,
    direction: 'inbound',
    emlS3Key,
    lifecycleRound: 1,
    scanKind: 'rescan',
    requestedAt: '2026-11-02T08:00:00.000Z',
    requestedBy: 'user',
  },
  'mail.delivery.status_changed.v1': {
    messageId,
    receivedAt,
    deliveryId: '501',
    recipientId: '11',
    rcptSeq: 0,
    deliverySeq: 0,
    direction: 'outbound',
    previousStatus: 'queued',
    status: 'delivered',
    occurredAt: '2026-11-01T10:20:00.000Z',
    attemptCount: 1,
    smtpCode: 250,
    enhancedStatus: '2.0.0',
    queueId: '4ZkQ2s1Hb7z9',
  },
  'domain.status.changed.v1': {
    domainId: '77',
    domainPublicId: '01890a5d-ac96-774b-bcce-b302099a8057',
    name: 'acme.example',
    previousStatus: 'verified',
    status: 'active',
    reason: null,
    changedAt: '2026-11-02T09:00:00.000Z',
  },
  'mail.attachment.sandbox_requested.v1': {
    submissionId: '301',
    messageId,
    receivedAt,
    direction: 'inbound',
    scanId: '11',
    lifecycleRound: 0,
    attachment: {
      partIndex: 3,
      sha256: 'c'.repeat(64),
      sizeBytes: 48_213,
      detectedType: '7z',
      objectKey: `${partPrefix}/3.att`,
    },
    attachmentVerdict: 'unknown',
    reasonCodes: ['archive.unsupported_format'],
    requestedAt: '2026-11-01T10:15:31.200Z',
  },
  'mail.url.inspection_requested.v1': {
    inspectionId: '701',
    messageId,
    receivedAt,
    scanId: '11',
    lifecycleRound: 0,
    urlSeq: 2,
    url: 'https://short-link.test/s/evil#top',
    urlSha256: 'd'.repeat(64),
    requestedAt: '2026-11-01T10:15:31.200Z',
    deadlineAt: '2026-11-01T11:15:31.200Z',
  },
  'mail.url.inspection_completed.v1': {
    inspectionId: '701',
    messageId,
    receivedAt,
    urlSeq: 2,
    urlSha256: 'd'.repeat(64),
    status: 'completed',
    errorCode: null,
    workerVersion: 'url-browser/1',
    browserVersion: 'chromium-headless-shell 131.0.6778.33',
    finalUrlSha256: 'e'.repeat(64),
    finalHost: 'phish-login.test',
    navigations: [
      { host: 'short-link.test', status: 302, kind: 'initial' },
      { host: 'phish-login.test', status: 200, kind: 'http' },
    ],
    signals: {
      passwordFields: 1,
      forms: 1,
      crossOriginFormAction: true,
      formActionHosts: ['collector-site.test'],
      downloadAttempted: false,
      blockedRequests: 0,
      requests: 7,
      bytes: 18_342,
      titleBrandMatches: ['examplebank'],
      jsRedirect: false,
      dialogs: 0,
    },
    durationMs: 3_412,
    completedAt: '2026-11-01T10:15:36.000Z',
  },
  'mail.url.clicked.v1': {
    clickId: '01890a5d-ac96-774b-bcce-b302099a8058',
    messageId,
    receivedAt,
    urlSeq: 2,
    decision: 'blocked',
    verdict: 'malicious',
    reasonCodes: ['url.feed_malicious', 'url.shortened'],
    clickedAt: '2026-11-02T08:30:00.000Z',
  },
  'mail.message.scan_stage_ready.v1': {
    messageId,
    receivedAt,
    direction: 'inbound',
    emlS3Key,
    lifecycleRound: 0,
    scanId: '11',
    scanKind: 'initial',
    engine: 'bec',
    dependencies: [
      { engine: 'rspamd', outcome: 'clean' },
      { engine: 'url', outcome: 'suspicious' },
    ],
    readyAt: '2026-11-01T10:15:31.300Z',
  },
  'mail.message.dlp_incident.v1': {
    messageId,
    receivedAt,
    direction: 'outbound',
    lifecycleRound: 0,
    scanId: '11',
    action: 'quarantine',
    actionSource: 'tenant_policy',
    policyId: '01890a5d-ac96-774b-bcce-b302099a8061',
    ruleId: '01890a5d-ac96-774b-bcce-b302099a8062',
    categories: [
      { category: 'payment_card', count: 3, maxSeverity: 'high' },
      { category: 'personal_info', count: 1, maxSeverity: 'low' },
    ],
    detectorCodes: [
      'dlp.payment_card.number',
      'dlp.personal_info.email_address',
      'dlp.not_extracted.image',
    ],
    exceptionApplied: false,
    coverage: 'partial',
    evidenceAvailable: true,
    detectedAt: '2026-11-01T10:15:31.900Z',
  },
  'mail.sandbox.task_requested.v1': {
    taskId: sandboxTaskId,
    analysisId: '501',
    sample: {
      key: `samples/2026/11/${sandboxTaskId}.bin`,
      sha256: 'c'.repeat(64),
      sizeBytes: 48_213,
      detectedType: 'script_js',
    },
    profile: 'execute',
    limits: {
      wallTimeoutMs: 60_000,
      memoryMb: 512,
      cpuMillis: 1000,
      pids: 128,
      scratchMb: 64,
      maxArtifacts: 16,
      maxArtifactBytes: 2_097_152,
      maxTotalArtifactBytes: 8_388_608,
    },
    requestedAt: '2026-11-01T10:15:32.000Z',
    deadlineAt: '2026-11-01T10:30:32.000Z',
    resultToken:
      't1.AAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBB.CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
  },
  'mail.sandbox.task_completed.v1': {
    taskId: sandboxTaskId,
    analysisId: '501',
    sampleSha256: 'c'.repeat(64),
    resultMac: 'f'.repeat(64),
    status: 'completed',
    notExecutedReason: null,
    errorCode: null,
    backend: 'static',
    backendVersion: 'sandbox-static/1',
    isolation: 'process',
    executed: false,
    profile: 'execute',
    controllerVersion: 'sandbox-controller/0.1.0',
    analyzerVersion: 'sandbox-static/1',
    startedAt: '2026-11-01T10:15:33.000Z',
    completedAt: '2026-11-01T10:15:34.250Z',
    durationMs: 1250,
    observations: {
      processes: [],
      processCount: 0,
      network: {
        dns: [{ name: 'payload-host.test', type: 'A', source: 'static' }],
        http: [],
        tls: [],
        connections: [],
        totals: { dns: 1, http: 0, tls: 0, connections: 0 },
      },
      files: { dropped: [], deniedWrites: 0 },
      findings: [
        { code: 'static.script_download_cradle', severity: 'high', count: 1 },
        { code: 'static.embedded_urls', severity: 'info', count: 2 },
      ],
      limitsHit: [],
      browser: null,
    },
    artifacts: [
      {
        seq: 0,
        kind: 'static_report',
        contentType: 'application/json',
        key: `artifacts/2026/11/${sandboxTaskId}/0f1e2d3c4b5a6978/0-static_report.bin`,
        objectSha256: 'a'.repeat(64),
        plainSha256: 'b'.repeat(64),
        sizeBytes: 1024,
        wrappedKey:
          'x1.k1.MCowBQYDK2VuAyEA.AAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBB.CCCCCCCCCCCCCCCC',
        keyId: 'k1',
        algorithm: 'sandbox-artifact/1',
      },
    ],
    cleanup: { runnerRemoved: null, scratchRemoved: true },
  },
  'mail.attachment.sandbox_completed.v1': {
    submissionId: '301',
    messageId,
    receivedAt,
    scanId: '11',
    lifecycleRound: 0,
    partIndex: 3,
    sha256: 'c'.repeat(64),
    status: 'completed',
    verdict: 'malicious',
    reasonCodes: ['sandbox.static.script_download_cradle', 'sandbox.static.embedded_urls'],
    executed: false,
    isolation: 'process',
    completedAt: '2026-11-01T10:15:35.000Z',
  },
  'domain.routing.changed.v1': {
    domainId: '77',
    domainPublicId: '01890a5d-ac96-774b-bcce-b302099a8057',
    name: 'acme.example',
    hosts: ['mx1.acme.example', 'acme-example.mail.protection.outlook.com'],
    changedAt: '2026-11-03T09:00:00.000Z',
  },
  'domain.dns.records_changed.v1': {
    domainId: '77',
    domainPublicId: '01890a5d-ac96-774b-bcce-b302099a8057',
    name: 'acme.example',
    domainStatus: 'active',
    changes: [
      { recordKey: 'spf', purpose: 'spf', previousStatus: 'valid', status: 'invalid' },
      { recordKey: 'dmarc', purpose: 'dmarc', previousStatus: 'valid', status: 'missing' },
    ],
    checkedAt: '2026-11-13T09:00:00.000Z',
  },
  'notification.alert_requested.v1': {
    kind: 'threat_detected',
    severity: 'high',
    refs: {
      webhookEventId: '0193a1b2-7c3d-8e4f-9a0b-1c2d3e4f5a6b',
      messageId,
      receivedAt,
    },
    window: { from: '2026-11-01T10:00:00.000Z', to: '2026-11-01T11:00:00.000Z' },
    counts: { suppressedBefore: 3 },
    requestedAt: '2026-11-01T10:15:31.000Z',
  },
  // Step 8.4 (D2): account takeover and security incident events. Documentation ranges only
  // (192.0.2.0/24, 2001:db8::/32) and example.com addresses.
  'auth.login.recorded.v1': {
    loginAuditId: '5001',
    occurredAt: '2026-11-18T08:00:00.000Z',
    outcome: 'failure',
    failureReason: 'invalid_password',
    accountKnown: true,
    userId: '12',
    channel: 'portal',
  },
  'auth.account.changed.v1': {
    auditLogId: '7001',
    auditCreatedAt: '2026-11-18T08:05:00.000Z',
    action: 'auth.mfa_disabled',
    actorType: 'user',
    actorPublicId: atoUserPublicId,
    resourceType: 'user',
    resourcePublicId: atoUserPublicId,
  },
  'smtp.auth.recorded.v1': {
    producer: { instance: 'smtp-adapter-0' },
    entries: [
      {
        seq: 0,
        occurredAt: '2026-11-18T08:00:01.000Z',
        result: 'ok',
        mechanism: 'plain',
        connectorId: '3',
        clientIp: '192.0.2.10',
        usernameClass: 'connector',
        usernameHash: null,
        failureReason: null,
      },
      {
        seq: 1,
        occurredAt: '2026-11-18T08:00:02.000Z',
        result: 'fail',
        mechanism: 'login',
        connectorId: '3',
        clientIp: '2001:db8::7',
        usernameClass: 'connector',
        usernameHash: null,
        failureReason: 'bad_credentials',
      },
    ],
  },
  'smtp.submission.recorded.v1': {
    producer: { instance: 'smtp-adapter-0' },
    entries: [
      {
        seq: 0,
        occurredAt: '2026-11-18T08:00:03.000Z',
        context: 'submission',
        connectorId: '3',
        connectorAuthType: 'sasl',
        queueId: '4XkQ2b1Zz3',
        clientIp: '192.0.2.10',
        heloName: 'mail.acme.example',
        tlsProtocol: 'TLSv1.3',
        senderAddress: 'finance@acme.example',
        recipientCount: 2,
        sizeBytes: 20480,
      },
    ],
  },
  'ato.account.risk.updated.v1': {
    accountId: '901',
    accountPublicId: atoAccountPublicId,
    kind: 'mailbox',
    score: 65,
    level: 'high',
    previousScore: 24,
    previousLevel: 'low',
    trigger: 'signal',
    computedAt: '2026-11-18T08:01:00.000Z',
  },
  'security.incident.created.v1': {
    incidentId: '301',
    incidentPublicId: atoIncidentPublicId,
    category: 'account_takeover',
    subject: { type: 'ato_account', publicId: atoAccountPublicId },
    origin: 'detection',
    severity: 'high',
    status: 'open',
    detectedAt: '2026-11-18T08:01:00.000Z',
    reasonCodes: ['ato.intel.spraying_success', 'ato.access.new_ip_prefix'],
  },
  'security.incident.updated.v1': {
    incidentId: '301',
    incidentPublicId: atoIncidentPublicId,
    category: 'account_takeover',
    subject: { type: 'ato_account', publicId: atoAccountPublicId },
    status: 'investigating',
    previousStatus: 'open',
    severity: 'high',
    previousSeverity: 'high',
    assigned: true,
    changedFields: ['status', 'assignee'],
    actorType: 'user',
    updatedAt: '2026-11-18T08:20:00.000Z',
  },
  'ato.response.requested.v1': {
    actionId: '401',
    actionPublicId: atoActionPublicId,
    phase: 'execute',
    actionType: 'revoke_sessions',
    provider: 'fake',
    incidentId: '301',
    accountId: '901',
    requestedAt: '2026-11-18T08:25:00.000Z',
  },
  'ato.response.completed.v1': {
    actionId: '402',
    actionPublicId: atoActionPublicId,
    phase: 'execute',
    actionType: 'restrict_smtp_sending',
    provider: 'gateway',
    status: 'succeeded',
    providerStatus: 'applied',
    resultCode: null,
    incidentPublicId: atoIncidentPublicId,
    accountPublicId: atoAccountPublicId,
    completedAt: '2026-11-18T08:26:00.000Z',
  },
  'ato.restriction.changed.v1': {
    restrictionId: '51',
    kind: 'send_block',
    scope: 'mailbox',
    connectorId: null,
    mailboxSha256: 'c'.repeat(64),
    status: 'active',
    expiresAt: '2026-11-18T12:26:00.000Z',
    changedAt: '2026-11-18T08:26:00.000Z',
  },
  'ato.notification.requested.v1': {
    kind: 'incident_alert',
    audience: 'tenant',
    severity: 'high',
    refs: { incidentPublicId: atoIncidentPublicId, accountPublicId: atoAccountPublicId },
    window: { from: '2026-11-18T08:00:00.000Z', to: '2026-11-18T08:15:00.000Z' },
    counts: { suppressedBefore: 0 },
    digestPeriod: null,
    requestedAt: '2026-11-18T08:01:01.000Z',
  },
  'integration.connection.health_changed.v1': {
    connectionId: '01890a5d-ac96-774b-bcce-b302099a80a0',
    provider: 'microsoft_365',
    previousStatus: 'healthy',
    status: 'critical',
    changedAt: '2026-11-17T09:00:00.000Z',
    failingChecks: ['token.acquire', 'domain.provider_verified'],
  },
  // Step AI-R D8: ids and the request time only (no address, HTML or figures).
  'assistant.report.email_requested.v1': {
    deliveryId: '01890a5d-ac96-774b-bcce-b302099a80b1',
    reportId: '01890a5d-ac96-774b-bcce-b302099a80b0',
    requestedAt: '2026-11-23T08:00:00.000Z',
  },
  // Step AI-6 D5: the job and report public ids and the request time only (no window, session or
  // credential).
  'assistant.report.generate_requested.v1': {
    jobId: '01890a5d-ac96-774b-bcce-b302099a80c1',
    reportId: '01890a5d-ac96-774b-bcce-b302099a80c0',
    requestedAt: '2026-11-26T08:00:00.000Z',
  },
  // Step API-1 D8: ids, the outcome, verdict, risk score and times only (no address or subject).
  'mail.message.copy_scanned.v1': {
    messageId,
    messagePublicId: '01890a5d-ac96-774b-bcce-b302099a80d0',
    receivedAt,
    ingestSource: 'mailbox_api',
    lifecycleRound: 0,
    scanId: '11',
    outcome: 'scanned',
    verdict: 'phishing',
    riskScore: 870,
    completedAt: '2026-11-01T10:15:31.456Z',
  },
  // Step API-3 C2.1: ids, verdict, level, hard-block ids, hashes and times only (no address,
  // subject, file name or URL).
  'mail.threat.late_signal.v1': {
    kind: 'sandbox_revision',
    messageId,
    receivedAt,
    scanId: '11',
    revision: 1,
    verdict: 'malware',
    level: 'critical',
    hardBlocks: ['hb.sandbox.malicious'],
    attachmentSha256: ['3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b'],
    urlSha256: [],
    signalAt: '2026-11-01T10:25:00.000Z',
  },
  // Step API-3 C12: the report public id, kind and time only (no address or text).
  'mail.report.feedback_requested.v1': {
    reportId: '01890a5d-ac96-774b-bcce-b302099a80e0',
    kind: 'received',
    requestedAt: '2026-11-27T08:00:00.000Z',
  },
  // Step API-4 A8.2: ids, codes, enums, counts and times only (no address, subject, URL or
  // matched value). A phishing journal copy for two mailboxes with a tenant quarantine rule.
  'mail.message.copy_detected.v1': {
    messageId,
    messagePublicId: '01890a5d-ac96-774b-bcce-b302099a80d0',
    receivedAt,
    ingestSource: 'journal_intake',
    copySource: 'journal',
    direction: 'inbound',
    protectionMode: 'api',
    verdict: 'phishing',
    riskScore: 870,
    policy: {
      state: 'evaluated',
      disposition: 'quarantine',
      decisionSource: 'tenant_rule',
      overrideApplied: false,
      actionTypes: ['QUARANTINE', 'ALERT'],
    },
    dlp: null,
    copies: { counted: 2, remediation: { pending: 2, simulated: 0, skipped: 0, none: 0 } },
    detectionIds: ['01890a5d-ac96-774b-bcce-b302099a80f0', '01890a5d-ac96-774b-bcce-b302099a80f1'],
    decidedAt: '2026-11-01T10:15:32.000Z',
  },
};

/**
 * Step API-1 (D11.3): the `api_mode_unhealthy` variant of `notification.alert_requested.v1` (an
 * API-mode connection became degraded or failing; refs name the API-mode connection only).
 */
export const EXAMPLE_API_MODE_UNHEALTHY_ALERT_PAYLOAD = Object.freeze({
  kind: 'api_mode_unhealthy',
  severity: 'high',
  refs: { apiModeConnectionId: '01890a5d-ac96-774b-bcce-b302099a80d1' },
  window: { from: '2026-11-26T08:00:00.000Z', to: '2026-11-27T08:00:00.000Z' },
  counts: { suppressedBefore: 0 },
  requestedAt: '2026-11-26T08:00:01.000Z',
});

/**
 * Step API-3 (C6): the `api_mode_purge_approval` variant of `notification.alert_requested.v1` (a
 * clawback needs a second approver; refs name the clawback only).
 */
export const EXAMPLE_API_MODE_PURGE_APPROVAL_ALERT_PAYLOAD = Object.freeze({
  kind: 'api_mode_purge_approval',
  severity: 'medium',
  refs: { clawbackId: '01890a5d-ac96-774b-bcce-b302099a80e1' },
  window: { from: '2026-11-27T08:00:00.000Z', to: '2026-11-28T08:00:00.000Z' },
  counts: { suppressedBefore: 0 },
  requestedAt: '2026-11-27T08:00:01.000Z',
});

/**
 * Step API-3 (C13): the `api_mode_report_received` variant of `notification.alert_requested.v1`
 * (new user reports await triage; no refs: the notification-worker counts them at send time).
 */
export const EXAMPLE_API_MODE_REPORT_RECEIVED_ALERT_PAYLOAD = Object.freeze({
  kind: 'api_mode_report_received',
  severity: 'low',
  refs: {},
  window: { from: '2026-11-27T08:00:00.000Z', to: '2026-11-27T09:00:00.000Z' },
  counts: { suppressedBefore: 2 },
  requestedAt: '2026-11-27T08:00:01.000Z',
});

/**
 * Step API-4 (A8.2): an outbound DLP detection of `mail.message.copy_detected.v1` (recorded on
 * the sender's mailbox, never remediated: one counted copy, skipped).
 */
export const EXAMPLE_COPY_DETECTED_OUTBOUND_DLP_PAYLOAD = Object.freeze({
  messageId: '42',
  messagePublicId: '01890a5d-ac96-774b-bcce-b302099a80d2',
  receivedAt: '2026-11-27T09:00:00.000Z',
  ingestSource: 'journal_intake',
  copySource: 'journal',
  direction: 'outbound',
  protectionMode: 'api',
  verdict: 'clean',
  riskScore: 40,
  policy: {
    state: 'evaluated',
    disposition: 'reject',
    decisionSource: 'floor',
    overrideApplied: false,
    actionTypes: ['REJECT'],
  },
  dlp: { action: 'block', verdict: 'suspicious', categories: ['payment_card'] },
  copies: { counted: 1, remediation: { pending: 0, simulated: 0, skipped: 1, none: 0 } },
  detectionIds: ['01890a5d-ac96-774b-bcce-b302099a80f2'],
  decidedAt: '2026-11-27T09:00:02.000Z',
});

/**
 * Step API-4 (A7): a policy ALERT of a detect evaluation of an API-mode copy
 * (`mail.policy.notification_requested.v1` with `evaluationMode = 'detect'`; never a sender
 * notice).
 */
export const EXAMPLE_POLICY_ALERT_DETECT_PAYLOAD = Object.freeze({
  messageId: '42',
  receivedAt: '2026-11-27T09:00:00.000Z',
  direction: 'inbound',
  lifecycleRound: 0,
  kind: 'policy_alert',
  severity: 'warning',
  disposition: 'quarantine',
  decisive: {
    source: 'tenant_rule',
    policyId: '01890a5d-ac96-774b-bcce-b302099a80f5',
    versionNo: 2,
    ruleId: 'alert-finance-fraud',
  },
  ruleRefs: ['01890a5d-ac96-774b-bcce-b302099a80f5#2/alert-finance-fraud'],
  requestedAt: '2026-11-27T09:00:02.000Z',
  evaluationMode: 'detect',
});

/**
 * Step API-4 (A9.2): the `dlp_detected` variant of `notification.alert_requested.v1` (a DLP
 * detection of an API-mode copy; refs as `threat_detected`).
 */
export const EXAMPLE_DLP_DETECTED_ALERT_PAYLOAD = Object.freeze({
  kind: 'dlp_detected',
  severity: 'high',
  refs: {
    webhookEventId: '01890a5d-ac96-774b-bcce-b302099a80f3',
    messageId: '42',
    receivedAt: '2026-11-27T09:00:00.000Z',
  },
  window: { from: '2026-11-27T09:00:00.000Z', to: '2026-11-27T10:00:00.000Z' },
  counts: { suppressedBefore: 0 },
  requestedAt: '2026-11-27T09:00:03.000Z',
});

/**
 * Step API-4 (B7): the `api_mode_detect_only_ended` variant of `notification.alert_requested.v1`
 * (a remediation policy's detect-only period ended; refs name the policy only).
 */
export const EXAMPLE_API_MODE_DETECT_ONLY_ENDED_ALERT_PAYLOAD = Object.freeze({
  kind: 'api_mode_detect_only_ended',
  severity: 'low',
  refs: { remediationPolicyId: '01890a5d-ac96-774b-bcce-b302099a80f4' },
  window: { from: '2026-12-04T09:00:00.000Z', to: '2026-12-05T09:00:00.000Z' },
  counts: { suppressedBefore: 0 },
  requestedAt: '2026-12-04T09:00:01.000Z',
});

/**
 * Step 8.5 (D11): the `provider_unhealthy` variant of `ato.notification.requested.v1` (an ATO
 * identity-provider integration turned unhealthy; refs name the integration only).
 */
export const EXAMPLE_ATO_PROVIDER_UNHEALTHY_PAYLOAD = Object.freeze({
  kind: 'provider_unhealthy',
  audience: 'tenant',
  severity: null,
  refs: { integrationPublicId: '01890a5d-ac96-774b-bcce-b302099a80a5' },
  window: { from: '2026-11-18T08:00:00.000Z', to: '2026-11-18T14:00:00.000Z' },
  counts: { suppressedBefore: 0 },
  digestPeriod: null,
  requestedAt: '2026-11-18T08:00:01.000Z',
});

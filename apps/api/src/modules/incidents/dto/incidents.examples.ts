import type {
  IncidentDetailView,
  IncidentMessagePage,
  IncidentPage,
  IncidentReportView,
  IncidentSummaryView,
  TimelineEntryView,
  TimelinePage,
} from './incidents.schemas';

/** OpenAPI examples of the incident routes (step 8.4 §5.2); placeholders are well-formed. */
const ID = {
  incident: '0193b0a0-2222-7a00-8000-000000000001',
  account: '0193b0a0-1111-7a00-8000-000000000001',
  user: '0193b0a0-7777-7a00-8000-000000000001',
  message: '0193b0a0-aaaa-7a00-8000-000000000001',
} as const;
export const INCIDENT_EXAMPLE_IDS = ID;

const summary: IncidentSummaryView = {
  id: ID.incident,
  category: 'account_takeover',
  subject: { type: 'ato_account', id: ID.account, display: 'jane.doe@corp.example' },
  origin: 'detection',
  status: 'investigating',
  severity: 'critical',
  titleCode: 'ato.geo.impossible_travel',
  reasonCodes: ['ato.geo.impossible_travel', 'ato.access.new_asn', 'ato.outbound.volume_spike'],
  detectedAt: '2026-11-18T10:42:00.000Z',
  lastEvidenceAt: '2026-11-18T10:50:00.000Z',
  evidenceCount: 14,
  assigneeId: ID.user,
  escalatedAt: null,
  resolvedAt: null,
  resolutionCode: null,
  createdAt: '2026-11-18T10:42:00.000Z',
  updatedAt: '2026-11-18T10:55:00.000Z',
};

const detail: IncidentDetailView = {
  ...summary,
  rowVersion: 4,
  detectorVersion: 'ato-rules/1',
  firstEvidenceAt: '2026-11-18T10:41:55.000Z',
  assignedAt: '2026-11-18T10:55:00.000Z',
  confirmedAt: null,
  mitigatedAt: null,
  resolution: null,
  createdBy: { type: 'system', id: null },
  canManage: true,
  allowedTransitions: [
    { to: 'confirmed', resolutionCodes: [], noteRequired: true },
    {
      to: 'false_positive',
      resolutionCodes: ['false_positive', 'benign_activity', 'duplicate'],
      noteRequired: true,
    },
    {
      to: 'resolved',
      resolutionCodes: ['remediated', 'benign_activity', 'duplicate', 'other'],
      noteRequired: true,
    },
  ],
  evidence: { ato_signal: 6, ato_auth_event: 4, message: 4 },
  detail: {
    account: {
      id: ID.account,
      kind: 'mailbox',
      address: 'jane.doe@corp.example',
      riskScore: 78,
      riskLevel: 'critical',
      protected: false,
    },
    riskScoreAtOpen: 62,
    peakRiskScore: 78,
    detectionReason: { codes: ['ato.geo.impossible_travel'], versions: { rules: 'ato-rules/1' } },
    detectionReasonText: ['Impossible travel +35', 'Sign-in from a new ASN +18'],
    recommendedActions: [{ actionType: 'restrict_smtp_sending', availability: 'available' }],
    relatedIps: [{ ip: '203.0.113.45', countryCode: 'DE', asn: 64501, count: 3 }],
    geoSummary: { countries: ['IN', 'DE'] },
    deviceSummary: null,
    counts: { signals: 6, authEvents: 4, messages: 4, findings: 0 },
    responses: { total: 1, pendingApproval: 1, byStatus: { pending_approval: 1 } },
  },
};

const note: TimelineEntryView = {
  id: '5e4d3c2b1a0f9e8d7c6b',
  at: '2026-11-18T10:56:00.000Z',
  type: 'note_added',
  actor: { type: 'user', id: ID.user },
  fromStatus: null,
  toStatus: null,
  fromSeverity: null,
  toSeverity: null,
  note: 'Called the user; they are not travelling.',
  details: null,
};

const page: IncidentPage = { data: [summary], nextCursor: 'EXAMPLE-CURSOR' };
const timeline: TimelinePage = {
  data: [
    {
      id: '1a2b3c4d5e6f7a8b9c0d',
      at: '2026-11-18T10:42:00.000Z',
      type: 'created',
      actor: { type: 'system', id: null },
      fromStatus: null,
      toStatus: 'open',
      fromSeverity: null,
      toSeverity: 'high',
      note: null,
      details: { origin: 'detection', reasonCodes: ['ato.geo.impossible_travel'] },
    },
    note,
  ],
  nextCursor: null,
};
const messages: IncidentMessagePage = {
  data: [
    {
      id: ID.message,
      receivedAt: '2026-11-18T10:48:00.000Z',
      direction: 'outbound',
      finalVerdict: 'phishing',
      finalAction: 'quarantine',
      riskScore: 870,
      riskLevel: 'high',
      recipientCount: 40,
      externalDomainCount: 31,
      findingCodes: ['url.phishing.known_bad'],
    },
  ],
  nextCursor: null,
};
const report: IncidentReportView = {
  version: 'security-incident-report/1',
  generatedAt: '2026-11-18T12:00:00.000Z',
  incident: {
    id: ID.incident,
    category: 'account_takeover',
    status: 'investigating',
    severity: 'critical',
  },
  resolution: null,
  timeline: [{ at: '2026-11-18T10:42:00.000Z', type: 'created', actorType: 'system' }],
  notes: [{ at: note.at, actorType: 'user', actorId: ID.user, note: note.note! }],
  evidence: { ato_signal: 6, ato_auth_event: 4, message: 4 },
  messages: [
    {
      messageId: ID.message,
      receivedAt: '2026-11-18T10:48:00.000Z',
      direction: 'outbound',
      senderMasked: 'j***@corp.example',
    },
  ],
  truncated: false,
  sections: [{ id: 'ato.detection', title: 'Detection reason', data: { peakRiskScore: 78 } }],
};

export const INCIDENT_EXAMPLES = {
  page,
  detail,
  note,
  timeline,
  messages,
  report,
  create: {
    category: 'account_takeover',
    subject: { type: 'ato_account', id: ID.account },
    severity: 'high' as const,
    reason: 'User reported sign-in prompts they did not start',
  },
  update: {
    expectedRowVersion: 4,
    status: 'false_positive' as const,
    resolution: { code: 'benign_activity' as const, note: 'Confirmed business trip to Frankfurt' },
    categoryFeedback: {
      trustedContexts: [
        { kind: 'country', value: 'DE', expiresInDays: 30, reason: 'Business trip' },
      ],
      dismissSignals: true,
    },
  },
  addNote: { note: 'Called the user; they are not travelling.' },
} as const;

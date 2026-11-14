/**
 * Explicit OpenAPI examples of the step 6.1 message data routes (D14). Illustrative values only
 * (documentation, never served). Since step 7.2 the subject is withheld (`subjectMasked`) and
 * recipient addresses are masked on every read (ADR-0062).
 */
const item = {
  id: '0193a1b2-7c3d-7e4f-8a5b-6c7d8e9f0a1b',
  receivedAt: '2026-11-12T08:15:30.125Z',
  direction: 'inbound',
  status: 'delivered',
  statusChangedAt: '2026-11-12T08:15:33.004Z',
  subject: null,
  subjectMasked: true,
  envelopeFrom: 'billing@vendor.example',
  headerFrom: 'Vendor Billing <billing@vendor.example>',
  recipientCount: 2,
  attachmentCount: 1,
  sizeBytes: 48213,
  finalVerdict: 'clean',
  finalAction: 'deliver',
  riskScore: 120,
  domainId: '0192f0aa-1b2c-7d3e-8f40-5a6b7c8d9e0f',
};

export const MESSAGE_EXAMPLES = {
  listPage: {
    data: [item],
    nextCursor:
      'eyJ2IjoxLCJyIjoibWVzc2FnZXMiLCJrIjpbIjIwMjYtMTEtMTJUMDg6MTU6MzAuMTI1WiIsIjQyIl0sImYiOiIxYTJiM2M0ZDVlNmY3YTgiLCJkIjoiZGVzYyIsInciOlsxNzYyOTMzNzMwMDAwLDE3NjMwMjAxMzAwMDBdLCJ0IjoxNzYzMDIwMTMwfQ.Hk3pZ0x9bQ2mV7nR4sT1uA',
  },
  detail: {
    ...item,
    internetMessageId: '<20261112081530.1234@vendor.example>',
    lifecycleRound: 0,
    version: 7,
    statusReason: 'delivered',
    clientIp: '198.51.100.23',
    clientHelo: 'mail.vendor.example',
    mtaQueueId: '4XbT2c1LkPz9',
  },
  recipientsPage: {
    data: [
      {
        rcptSeq: 0,
        address: 'a***@acme.example',
        addressMasked: true,
        status: 'delivered',
        finalAction: 'deliver',
        direction: 'inbound',
        userId: null,
        latestDelivery: {
          deliverySeq: 0,
          status: 'delivered',
          finalSmtpCode: 250,
          deliveredAt: '2026-11-12T08:15:33.004Z',
        },
      },
    ],
    nextCursor: null,
  },
  /** `GET /messages/{messageId}/headers` (step 7.2 §2 E7). */
  headers: {
    messageId: item.id,
    availability: 'available',
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
    headers: [
      { seq: 0, name: 'From', value: 'Vendor Billing <billing@vendor.example>', masked: false },
      { seq: 1, name: 'To', value: null, masked: true },
      { seq: 2, name: 'Subject', value: null, masked: true },
      { seq: 3, name: 'Date', value: 'Thu, 12 Nov 2026 08:15:29 +0000', masked: false },
      {
        seq: 4,
        name: 'Message-ID',
        value: '<20261112081530.1234@vendor.example>',
        masked: false,
      },
      {
        seq: 5,
        name: 'Authentication-Results',
        value: 'mx.acme.example; spf=pass smtp.mailfrom=vendor.example; dkim=pass',
        masked: false,
      },
    ],
  },
  /** `POST /messages/reveal` (step 7.2 §2 E6): placeholder ids and an illustrative subject. */
  revealManyBody: {
    messageIds: [item.id, '0193a1b2-7c3d-7e4f-8a5b-6c7d8e9f0a1c'],
  },
  revealMany: {
    revealedAt: '2026-11-12T09:02:11.418Z',
    data: [{ id: item.id, subject: 'EXAMPLE quarterly invoice' }],
  },
  /** `POST /messages/{messageId}/reveal` (step 7.2 §2 E6). */
  revealBody: { fields: ['subject', 'headers', 'recipients'], recipientsLimit: 100 },
  revealMoreRecipientsBody: {
    fields: ['recipients'],
    recipientsCursor: 'EXAMPLE-recipients-nextCursor-of-the-previous-reveal',
  },
  reveal: {
    messageId: item.id,
    revealedAt: '2026-11-12T09:02:11.418Z',
    subject: 'EXAMPLE quarterly invoice',
    headers: [
      { seq: 1, name: 'To', value: 'Alice <alice@acme.example>, bob@acme.example' },
      { seq: 2, name: 'Subject', value: 'EXAMPLE quarterly invoice' },
    ],
    recipients: {
      data: [
        {
          rcptSeq: 0,
          address: 'alice@acme.example',
          userId: '0192e111-2a3b-7c4d-8e5f-6a7b8c9d0e1f',
        },
        { rcptSeq: 1, address: 'bob@acme.example', userId: null },
      ],
      nextCursor: null,
    },
  },
} as const;

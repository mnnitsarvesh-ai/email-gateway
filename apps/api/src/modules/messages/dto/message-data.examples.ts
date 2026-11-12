/**
 * Explicit OpenAPI examples of the step 6.1 message data routes (D14). Illustrative values only
 * (documentation, never served).
 */
const item = {
  id: '0193a1b2-7c3d-7e4f-8a5b-6c7d8e9f0a1b',
  receivedAt: '2026-11-12T08:15:30.125Z',
  direction: 'inbound',
  status: 'delivered',
  statusChangedAt: '2026-11-12T08:15:33.004Z',
  subject: 'Quarterly invoice',
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
        address: 'alice@acme.example',
        status: 'delivered',
        finalAction: 'deliver',
        direction: 'inbound',
        userId: '0192e111-2a3b-7c4d-8e5f-6a7b8c9d0e1f',
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
} as const;

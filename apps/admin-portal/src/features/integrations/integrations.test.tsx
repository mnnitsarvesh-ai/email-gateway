import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { ApiKeysPage, apiKeyBody, apiKeySchema, grantableScopes } from './api-keys-page';
import { IntegrationsPage } from './integrations-page';
import { replayBody, replaySchema } from './webhook-deliveries';
import { WebhookDetailPage, rotateSchema } from './webhook-detail-page';
import {
  webhookCreateBody,
  webhookDefaults,
  webhookSchema,
  webhookUpdateBody,
} from './webhook-form';

const T = '2026-11-12T09:00:00.000Z';
// Synthetic secrets, assembled at runtime so no secret-shaped literal sits in the source.
const fixtureSecret = (label: string) => ['whsec', 'dev', 'fixture', label].join('_');
const CREATED_SECRET = fixtureSecret('once');
const ROTATED_SECRET = fixtureSecret('rotated');
const CREATED_API_KEY = ['egk', 'dev', 'fixture', 'shown', 'once'].join('_');
const WEBHOOK_ID = '0193f100-0000-7000-8000-000000000001';
const hook = (overrides: Record<string, unknown> = {}) => ({
  id: WEBHOOK_ID,
  name: 'SIEM feed',
  description: null,
  url: 'https://hooks.example.com/eg?token=receiver-secret',
  eventTypes: ['email.threat.detected'],
  filters: null,
  status: 'active',
  disabledReason: null,
  disabledAt: null,
  maxConcurrency: null,
  secretVersion: 1,
  secretRotatedAt: null,
  previousSecretExpiresAt: null,
  consecutiveFailures: 0,
  failingSince: null,
  lastSuccessAt: T,
  lastFailureAt: null,
  createdBy: null,
  createdAt: T,
  updatedAt: T,
  rowVersion: 7,
  ...overrides,
});
const CATALOG = {
  data: ['email.threat.detected', 'email.quarantined', 'domain.dns.failed'].map((type) => ({
    type,
    version: 1,
    description: `${type} happened`,
    severity: 'medium',
    appliesFilters: ['directions'],
    subscribable: true,
    example: {},
  })),
  severities: ['info', 'low', 'medium', 'high'],
};
const delivery = (i: number, overrides: Record<string, unknown> = {}) => ({
  id: `0193f200-0000-7000-8000-${String(i).padStart(12, '0')}`,
  eventId: `0193f300-0000-7000-8000-${String(i).padStart(12, '0')}`,
  eventType: 'email.threat.detected',
  occurredAt: T,
  status: 'failed',
  trigger: 'event',
  deliverySeq: 0,
  attemptCount: 2,
  nextAttemptAt: null,
  firstAttemptAt: T,
  lastAttemptAt: T,
  lastResponseCode: 503,
  lastLatencyMs: 120,
  lastError: 'http_503',
  completedAt: null,
  createdAt: T,
  ...overrides,
});

describe('IntegrationsPage', () => {
  it('shows webhooks, link cards and the unavailable connectors to an organization admin (axe clean)', async () => {
    mockApi({ WebhooksController_list_v1: () => okJson({ data: [hook()], nextCursor: null }) });
    const { container } = renderWithProviders(<IntegrationsPage />, { route: '/integrations' });
    expect(await screen.findByRole('link', { name: 'SIEM feed' })).toHaveAttribute(
      'href',
      `/webhooks/${WEBHOOK_ID}`,
    );
    // The endpoint URL is text with a copy button, never a link.
    expect(screen.getByText(/hooks\.example\.com/)).not.toHaveAttribute('href');
    expect(screen.queryByRole('link', { name: /hooks\.example\.com/ })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Manage API keys' })).toHaveAttribute(
      'href',
      '/integrations/api-keys',
    );
    expect(screen.getByRole('link', { name: 'Manage SMTP connectors' })).toHaveAttribute(
      'href',
      '/mail-servers?tab=connectors',
    );
    expect(screen.getByText('Arrives in step 8.2')).toBeInTheDocument();
    expect(screen.getByText('Arrives in step 8.1')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('gates sections by role: read-only users see no webhooks; mailbox users get 403', () => {
    const { unmount } = renderWithProviders(<IntegrationsPage />, {
      role: 'read_only_user',
      route: '/integrations',
    });
    expect(screen.queryByText('Webhooks')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Manage API keys' })).toBeInTheDocument();
    unmount();
    renderWithProviders(<IntegrationsPage />, { role: 'mailbox_user', route: '/integrations' });
    expect(screen.getByText('You do not have access to this page')).toBeInTheDocument();
  });

  it('webhooks: loading, error with request id, empty, status filter and sort in the URL', async () => {
    const requests: URL[] = [];
    let fail = true;
    mockApi({
      WebhooksController_list_v1: ({ url }) => {
        requests.push(url);
        return fail
          ? apiErrorJson(500, 'internal_error', 'Boom', { requestId: 'req-w-1' })
          : okJson({ data: [], nextCursor: null });
      },
    });
    const { user } = renderWithProviders(<IntegrationsPage />, {
      role: 'security_analyst',
      route: '/integrations',
    });
    expect(screen.getByText(/Loading Webhooks/)).toBeInTheDocument();
    expect(await screen.findByText('req-w-1')).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('No webhooks yet')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'New webhook' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('combobox', { name: 'Status' }));
    await user.click(await screen.findByRole('option', { name: 'Disabled' }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('status')).toBe('disabled'));
    expect(currentTestUrl()).toBe('/integrations?wstatus=disabled');
  });

  it('creates a webhook (contract, Idempotency-Key) and shows the secret once', async () => {
    const calls: { body: unknown; key: string | null }[] = [];
    mockApi({
      WebhooksController_list_v1: () => okJson({ data: [], nextCursor: null }),
      WebhooksController_eventTypes_v1: () => okJson(CATALOG),
      DomainsController_list_v1: () => okJson({ data: [], nextCursor: null }),
      WebhooksController_create_v1: ({ body, request }) => {
        calls.push({ body, key: request.headers.get('idempotency-key') });
        return calls.length === 1
          ? apiErrorJson(422, 'webhook_url_not_allowed', 'The host is not allowed', {
              extra: { reason: 'name' },
            })
          : okJson({ ...hook({ name: 'Ops' }), secret: CREATED_SECRET }, 201);
      },
    });
    const { user, router, container } = renderWithProviders(<IntegrationsPage />, {
      route: '/integrations',
    });
    await user.click(await screen.findByRole('button', { name: 'New webhook' }));
    const dialog = await screen.findByRole('dialog', { name: 'New webhook' });
    await within(dialog).findByRole('checkbox', { name: /email\.quarantined/ });
    await expectNoAxeViolations(container);
    await user.type(within(dialog).getByLabelText('Name (required)'), 'Ops');
    await user.type(
      within(dialog).getByLabelText('Endpoint URL (required)'),
      'https://hooks.internal/eg',
    );
    await user.click(within(dialog).getByRole('checkbox', { name: /email\.quarantined/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Create webhook' }));
    expect(await within(dialog).findByText(/host is not allowed \(name\)/)).toBeInTheDocument();
    expect(calls[0]?.body).toEqual({
      name: 'Ops',
      url: 'https://hooks.internal/eg',
      eventTypes: ['email.quarantined'],
      status: 'active',
    });
    expectRequestMatchesContract('WebhooksController_create_v1', calls[0]?.body);
    expect(calls[0]?.key).toMatch(/^[0-9a-f-]{36}$/);
    const url = within(dialog).getByLabelText('Endpoint URL (required)');
    await user.clear(url);
    await user.type(url, 'https://hooks.example.com/eg');
    await user.click(within(dialog).getByRole('button', { name: 'Create webhook' }));
    const reveal = await screen.findByRole('dialog', { name: 'Webhook signing secret' });
    expect(within(reveal).getByText(CREATED_SECRET)).toBeInTheDocument();
    await user.click(within(reveal).getByRole('checkbox'));
    await user.click(within(reveal).getByRole('button', { name: 'Done' }));
    await waitFor(() => expect(screen.queryByText(CREATED_SECRET)).not.toBeInTheDocument());
    expect(router.push).toHaveBeenCalledWith(`/webhooks/${WEBHOOK_ID}`);
  });

  it('explains a redacted replay (secret null) after retrying a lost create with the same key', async () => {
    const keys: (string | null)[] = [];
    mockApi({
      WebhooksController_list_v1: () => okJson({ data: [], nextCursor: null }),
      WebhooksController_eventTypes_v1: () => okJson(CATALOG),
      DomainsController_list_v1: () => okJson({ data: [], nextCursor: null }),
      WebhooksController_create_v1: ({ request }) => {
        keys.push(request.headers.get('idempotency-key'));
        return keys.length === 1
          ? HttpResponse.error()
          : okJson({ ...hook(), secret: null }, 201, { 'idempotency-replayed': 'true' });
      },
    });
    const { user } = renderWithProviders(<IntegrationsPage />, { route: '/integrations' });
    await user.click(await screen.findByRole('button', { name: 'New webhook' }));
    const dialog = await screen.findByRole('dialog', { name: 'New webhook' });
    await user.type(within(dialog).getByLabelText('Name (required)'), 'SIEM feed');
    await user.type(
      within(dialog).getByLabelText('Endpoint URL (required)'),
      'https://hooks.example.com/eg',
    );
    await user.click(
      await within(dialog).findByRole('checkbox', { name: /email\.threat\.detected/ }),
    );
    await user.click(within(dialog).getByRole('button', { name: 'Create webhook' }));
    await user.click(await within(dialog).findByRole('button', { name: 'Retry the same request' }));
    const explanation = await screen.findByRole('dialog', { name: 'The webhook already existed' });
    expect(explanation).toHaveTextContent('shown only in the original response');
    expect(within(explanation).getByRole('link', { name: /rotate the secret/ })).toHaveAttribute(
      'href',
      `/webhooks/${WEBHOOK_ID}`,
    );
    expect(keys[1]).toBe(keys[0]);
  });
});

function mockWebhook(overrides: Parameters<typeof mockApi>[0] = {}, detail = hook()) {
  mockApi({
    WebhooksController_get_v1: () => okJson(detail),
    WebhooksController_eventTypes_v1: () => okJson(CATALOG),
    WebhookDeliveriesController_list_v1: () =>
      okJson({
        data: [
          delivery(1),
          delivery(2, { status: 'succeeded', lastResponseCode: 200, lastError: null }),
        ],
        nextCursor: null,
      }),
    ...overrides,
  });
}

describe('WebhookDetailPage', () => {
  it('shows settings (URL as text), health and deliveries (axe clean)', async () => {
    mockWebhook();
    const { container } = renderWithProviders(<WebhookDetailPage webhookId={WEBHOOK_ID} />, {
      route: `/webhooks/${WEBHOOK_ID}`,
    });
    expect(await screen.findByRole('heading', { level: 1, name: 'SIEM feed' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy the endpoint URL' })).toBeInTheDocument();
    expect(container.querySelector('a[href^="https://hooks"]')).toBeNull();
    expect(await screen.findAllByText('HTTP 503')).not.toHaveLength(0);
    await expectNoAxeViolations(container);
  });

  it('renders the 404 page for a foreign or unknown webhook and a malformed id', async () => {
    mockApi({
      WebhooksController_get_v1: () => apiErrorJson(404, 'webhook_not_found', 'Webhook not found'),
    });
    const { unmount } = renderWithProviders(<WebhookDetailPage webhookId={WEBHOOK_ID} />);
    expect(await screen.findByText('Page not found')).toBeInTheDocument();
    unmount();
    renderWithProviders(<WebhookDetailPage webhookId="nope" />);
    expect(screen.getByText('Page not found')).toBeInTheDocument();
  });

  it('hides every action from read-only roles; refuses roles without webhook:read', async () => {
    mockWebhook();
    const { unmount } = renderWithProviders(<WebhookDetailPage webhookId={WEBHOOK_ID} />, {
      role: 'compliance_auditor',
    });
    await screen.findByRole('heading', { level: 1, name: 'SIEM feed' });
    for (const name of [
      'Edit settings',
      'Pause',
      'Send test event',
      'Rotate secret',
      'Delete',
      'Replay a range',
    ])
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
    unmount();
    renderWithProviders(<WebhookDetailPage webhookId={WEBHOOK_ID} />, { role: 'read_only_user' });
    expect(screen.getByText('You do not have access to this page')).toBeInTheDocument();
  });

  it('edits (contract with row version) and pauses; explains version conflicts', async () => {
    const calls: unknown[] = [];
    mockWebhook({
      DomainsController_list_v1: () => okJson({ data: [], nextCursor: null }),
      WebhooksController_update_v1: ({ body }) => {
        calls.push(body);
        return calls.length === 2
          ? apiErrorJson(409, 'webhook_version_conflict', 'Changed meanwhile', {
              extra: { currentRowVersion: 8 },
            })
          : okJson(hook({ rowVersion: 8 }));
      },
    });
    const { user } = renderWithProviders(<WebhookDetailPage webhookId={WEBHOOK_ID} />);
    await user.click(await screen.findByRole('button', { name: 'Edit settings' }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit webhook' });
    const name = within(dialog).getByLabelText('Name (required)');
    await user.clear(name);
    await user.type(name, 'SIEM feed v2');
    await user.click(within(dialog).getByRole('button', { name: 'Save webhook' }));
    await waitFor(() =>
      expect(calls[0]).toEqual({
        expectedRowVersion: 7,
        name: 'SIEM feed v2',
        description: null,
        url: 'https://hooks.example.com/eg?token=receiver-secret',
        eventTypes: ['email.threat.detected'],
        filters: null,
        maxConcurrency: null,
      }),
    );
    expectRequestMatchesContract('WebhooksController_update_v1', calls[0]);
    await user.click(await screen.findByRole('button', { name: 'Pause' }));
    const confirm = await screen.findByRole('alertdialog');
    await user.click(within(confirm).getByRole('button', { name: 'Pause' }));
    expect(
      await within(confirm).findByText(/Someone else changed the webhook/),
    ).toBeInTheDocument();
    expect(calls[1]).toEqual({ expectedRowVersion: 7, status: 'paused' });
    expectRequestMatchesContract('WebhooksController_update_v1', calls[1]);
  });

  it('rotates the secret (Idempotency-Key, secret once) and explains a redacted replay', async () => {
    const calls: { body: unknown; key: string | null }[] = [];
    mockWebhook({
      WebhooksController_rotate_v1: ({ body, request }) => {
        calls.push({ body, key: request.headers.get('idempotency-key') });
        return okJson(
          {
            id: WEBHOOK_ID,
            secret: calls.length === 1 ? ROTATED_SECRET : null,
            secretVersion: 2,
            secretRotatedAt: T,
            previousSecretExpiresAt: T,
          },
          200,
          calls.length === 1 ? {} : { 'idempotency-replayed': 'true' },
        );
      },
    });
    const { user } = renderWithProviders(<WebhookDetailPage webhookId={WEBHOOK_ID} />);
    await user.click(await screen.findByRole('button', { name: 'Rotate secret' }));
    let confirm = await screen.findByRole('alertdialog');
    const overlap = within(confirm).getByLabelText('Overlap in hours (0–168)');
    await user.clear(overlap);
    await user.type(overlap, '12');
    await user.click(within(confirm).getByRole('button', { name: 'Rotate secret' }));
    const reveal = await screen.findByRole('dialog', { name: 'New signing secret' });
    expect(within(reveal).getByText(ROTATED_SECRET)).toBeInTheDocument();
    expect(calls[0]?.body).toEqual({ overlapHours: 12 });
    expectRequestMatchesContract('WebhooksController_rotate_v1', calls[0]?.body);
    expect(calls[0]?.key).toMatch(/^[0-9a-f-]{36}$/);
    await user.click(within(reveal).getByRole('checkbox'));
    await user.click(within(reveal).getByRole('button', { name: 'Done' }));
    await waitFor(() => expect(screen.queryByText(ROTATED_SECRET)).not.toBeInTheDocument());

    await user.click(screen.getByRole('button', { name: 'Rotate secret' }));
    confirm = await screen.findByRole('alertdialog');
    await user.click(within(confirm).getByRole('button', { name: 'Rotate secret' }));
    const explanation = await screen.findByRole('dialog', {
      name: 'The rotation was already applied',
    });
    expect(explanation).toHaveTextContent('rotate the secret');
    expect(within(explanation).getByRole('button', { name: 'Rotate again' })).toBeInTheDocument();
  });

  it('sends a test event and shows its delivery with response snippets as text only', async () => {
    mockWebhook({
      WebhooksController_test_v1: () =>
        okJson({ deliveryId: delivery(9).id, eventId: delivery(9).eventId }, 202),
      WebhookDeliveriesController_get_v1: () =>
        okJson({
          ...delivery(9, { eventType: 'webhook.ping', trigger: 'test' }),
          attempts: [
            {
              attemptNo: 1,
              attemptedAt: T,
              outcome: 'http_error',
              httpStatus: 503,
              latencyMs: 90,
              responseSnippet: '<script>alert(1)</script><a href="https://evil.example">x</a>',
              retryAfterSeconds: 30,
              errorCode: 'http_503',
              signatureCount: 1,
            },
          ],
          event: { type: 'webhook.ping' },
        }),
    });
    const { user, container } = renderWithProviders(<WebhookDetailPage webhookId={WEBHOOK_ID} />);
    await user.click(await screen.findByRole('button', { name: 'Send test event' }));
    await user.click(await screen.findByRole('button', { name: 'View the test delivery' }));
    const dialog = await screen.findByRole('dialog', { name: 'Test delivery' });
    expect(await within(dialog).findByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument();
    expect(document.querySelector('a[href="https://evil.example"]')).toBeNull();
    const scripts = [...container.ownerDocument.querySelectorAll('script')];
    expect(scripts.some((script) => script.textContent?.includes('alert'))).toBe(false);
  });

  it('filters deliveries in the URL, replays one and a range (polled), deletes with typed confirmation', async () => {
    const requests: URL[] = [];
    const keys: Record<string, string | null> = {};
    let replayPolls = 0;
    let deleted = false;
    mockWebhook({
      WebhookDeliveriesController_list_v1: ({ url }) => (
        requests.push(url),
        okJson({ data: [delivery(1)], nextCursor: null })
      ),
      WebhookDeliveriesController_replay_v1: ({ request }) => (
        (keys.replay = request.headers.get('idempotency-key')),
        okJson({ deliveryId: delivery(5).id }, 202)
      ),
      WebhookDeliveriesController_createReplay_v1: ({ body, request }) => {
        keys.range = request.headers.get('idempotency-key');
        expectRequestMatchesContract('WebhookDeliveriesController_createReplay_v1', body);
        return okJson({ replayId: '0193f400-0000-7000-8000-000000000001', status: 'queued' }, 202);
      },
      WebhookDeliveriesController_getReplay_v1: () => {
        replayPolls += 1;
        return okJson({
          id: '0193f400-0000-7000-8000-000000000001',
          status: 'completed',
          from: T,
          to: T,
          statuses: ['failed', 'dead'],
          eventTypes: null,
          matchedCount: 4,
          createdCount: 3,
          truncated: false,
          errorCode: null,
          createdAt: T,
          startedAt: T,
          completedAt: T,
        });
      },
      WebhooksController_delete_v1: ({ request }) => (
        (keys.delete = request.headers.get('idempotency-key')),
        (deleted = true),
        noContentResponse()
      ),
    });
    const { user, router } = renderWithProviders(<WebhookDetailPage webhookId={WEBHOOK_ID} />, {
      route: `/webhooks/${WEBHOOK_ID}`,
    });
    await screen.findAllByText('HTTP 503');
    await user.click(screen.getByRole('combobox', { name: 'Delivery status' }));
    await user.click(await screen.findByRole('option', { name: 'Dead' }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('status')).toBe('dead'));
    expect(currentTestUrl()).toContain('dstatus=dead');
    expect(requests.at(-1)?.searchParams.get('from')).toBeTruthy();

    await user.click(screen.getByRole('button', { name: /Actions for email\.threat\.detected/ }));
    await user.click(await screen.findByRole('menuitem', { name: 'Replay' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Replay' }),
    );
    await waitFor(() => expect(keys.replay).toMatch(/^[0-9a-f-]{36}$/));

    await user.click(screen.getByRole('button', { name: 'Replay a range' }));
    const dialog = await screen.findByRole('dialog', { name: 'Replay a range of deliveries' });
    await user.click(within(dialog).getByRole('button', { name: 'Replay deliveries' }));
    expect(await screen.findByText(/4 matching deliveries, 3 replayed/)).toBeInTheDocument();
    expect(replayPolls).toBeGreaterThan(0);
    expect(keys.range).toMatch(/^[0-9a-f-]{36}$/);

    await user.click(screen.getByRole('button', { name: 'Delete' }));
    const confirm = await screen.findByRole('alertdialog');
    expect(within(confirm).getByRole('button', { name: 'Delete webhook' })).toBeDisabled();
    await user.type(within(confirm).getByRole('textbox'), 'SIEM feed');
    await user.click(within(confirm).getByRole('button', { name: 'Delete webhook' }));
    await waitFor(() => expect(deleted).toBe(true));
    expect(keys.delete).toMatch(/^[0-9a-f-]{36}$/);
    expect(router.push).toHaveBeenCalledWith('/integrations');
  });
});

const KEY = (i: number, overrides: Record<string, unknown> = {}) => ({
  id: `0193f500-0000-7000-8000-${String(i).padStart(12, '0')}`,
  name: `Key ${i}`,
  prefix: `egk_${i}`,
  scopes: ['report:read'],
  createdBy: { id: '0193f600-0000-7000-8000-000000000001', displayName: 'Admin' },
  lastUsedAt: T,
  expiresAt: null,
  revokedAt: null,
  createdAt: T,
  ...overrides,
});

describe('ApiKeysPage', () => {
  it('lists keys (axe clean), creates one with held scopes only (contract) and shows the key once', async () => {
    let body: unknown = null;
    mockApi({
      ApiKeysController_list_v1: () =>
        okJson({ data: [KEY(1), KEY(2, { revokedAt: T })], nextCursor: null }),
      PermissionsController_list_v1: () =>
        okJson({
          data: [
            { key: 'report:read', description: 'View reports', category: 'report' },
            { key: 'platform:operations', description: 'Platform', category: 'platform' },
            { key: 'user:read', description: 'View users', category: 'user' },
          ],
        }),
      ApiKeysController_create_v1: ({ body: b }) => (
        (body = b),
        okJson({ apiKey: KEY(3, { name: 'SIEM' }), key: CREATED_API_KEY }, 201)
      ),
    });
    const { user, container } = renderWithProviders(<ApiKeysPage />, {
      route: '/integrations/api-keys',
    });
    expect(await screen.findByText('Key 1')).toBeInTheDocument();
    expect(screen.getByText('Revoked')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'New API key' }));
    const dialog = await screen.findByRole('dialog', { name: 'New API key' });
    await user.type(within(dialog).getByLabelText('Name (required)'), 'SIEM');
    expect(
      within(dialog).queryByRole('checkbox', { name: /platform:operations/ }),
    ).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Create API key' }));
    expect(await within(dialog).findByText('Choose at least one scope')).toBeInTheDocument();
    await user.click(await within(dialog).findByRole('checkbox', { name: /report:read/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Create API key' }));
    await waitFor(() => expect(body).toEqual({ name: 'SIEM', scopes: ['report:read'] }));
    expectRequestMatchesContract('ApiKeysController_create_v1', body);
    const reveal = await screen.findByRole('dialog', { name: 'API key SIEM' });
    expect(within(reveal).getByText(CREATED_API_KEY)).toBeInTheDocument();
    await user.click(within(reveal).getByRole('checkbox'));
    await user.click(within(reveal).getByRole('button', { name: 'Done' }));
    await waitFor(() => expect(screen.queryByText(CREATED_API_KEY)).not.toBeInTheDocument());
  });

  it('revokes only after typing the key name; revoked keys offer no action', async () => {
    let revoked = '';
    mockApi({
      ApiKeysController_list_v1: () =>
        okJson({ data: [KEY(1), KEY(2, { revokedAt: T })], nextCursor: null }),
      ApiKeysController_revoke_v1: ({ params }) => (
        (revoked = params.id ?? ''),
        noContentResponse()
      ),
    });
    const { user } = renderWithProviders(<ApiKeysPage />, { route: '/integrations/api-keys' });
    await screen.findByText('Key 1');
    expect(screen.queryByRole('button', { name: 'Actions for Key 2' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Actions for Key 1' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Revoke' }));
    const confirm = await screen.findByRole('alertdialog');
    expect(within(confirm).getByRole('button', { name: 'Revoke key' })).toBeDisabled();
    await user.type(within(confirm).getByRole('textbox'), 'Key 1');
    await user.click(within(confirm).getByRole('button', { name: 'Revoke key' }));
    await waitFor(() => expect(revoked).toBe(KEY(1).id));
  });

  it('shows empty and error states, hides actions from read-only users, refuses domain admins', async () => {
    mockApi({
      ApiKeysController_list_v1: () =>
        apiErrorJson(500, 'internal_error', 'Boom', { requestId: 'req-k-1' }),
    });
    const first = renderWithProviders(<ApiKeysPage />);
    expect(await screen.findByText('req-k-1')).toBeInTheDocument();
    first.unmount();
    mockApi({ ApiKeysController_list_v1: () => okJson({ data: [], nextCursor: null }) });
    const second = renderWithProviders(<ApiKeysPage />, { role: 'read_only_user' });
    expect(await screen.findByText('No API keys')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'New API key' })).not.toBeInTheDocument();
    second.unmount();
    renderWithProviders(<ApiKeysPage />, { role: 'domain_admin' });
    expect(screen.getByText('You do not have access to this page')).toBeInTheDocument();
  });
});

describe('integration forms', () => {
  it('mirror the request contracts', () => {
    const values = webhookSchema.parse({
      ...webhookDefaults(),
      name: 'Feed',
      url: 'https://hooks.example.com/x',
      eventTypes: ['email.quarantined', 'domain.dns.failed'],
      directions: ['inbound'],
      domainIds: ['0193a000-0000-7000-8000-000000000001'],
      minSeverity: 'high',
      verdicts: ['malicious'],
      maxConcurrency: '4',
      description: 'd',
    });
    expectRequestMatchesContract('WebhooksController_create_v1', webhookCreateBody(values));
    expectRequestMatchesContract(
      'WebhooksController_update_v1',
      webhookUpdateBody({ rowVersion: 3 }, values),
    );
    expect(
      webhookSchema.safeParse({
        ...webhookDefaults(),
        name: 'x',
        url: 'https://u:p@h.example.com',
        eventTypes: ['email.received'],
      }).success,
    ).toBe(false);
    expectRequestMatchesContract(
      'WebhooksController_rotate_v1',
      rotateSchema.parse({ overlapHours: '0' }),
    );
    expectRequestMatchesContract(
      'WebhookDeliveriesController_createReplay_v1',
      replayBody(
        replaySchema.parse({
          from: '2026-11-12T08:00',
          to: '2026-11-12T20:00',
          statuses: ['dead'],
          eventTypes: ['email.quarantined'],
        }),
      ),
    );
    expect(
      replaySchema.safeParse({
        from: '2026-11-08T08:00',
        to: '2026-11-12T20:00',
        statuses: ['dead'],
        eventTypes: [],
      }).success,
    ).toBe(false);
    expectRequestMatchesContract(
      'ApiKeysController_create_v1',
      apiKeyBody(
        apiKeySchema.parse({
          name: 'K',
          scopes: ['report:read'],
          expiresOn: new Date(Date.now() + 5 * 86_400_000).toISOString().slice(0, 10),
        }),
      ),
    );
    expect(
      grantableScopes(new Set(['report:read', 'platform:operations']), undefined).map((p) => p.key),
    ).toEqual(['report:read']);
  });
});

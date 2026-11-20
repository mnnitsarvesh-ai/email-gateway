import 'server-only';
import type { ListItem, RequestBody, SuccessBody } from '@/lib/api/types';
import { SeededRandom, fixtureAnchor, paginate, stableUuid } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandler,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { archiveSettingsRow } from './archive';
import { fixtureGuard } from './messages';
import { resolveFixturePrincipal } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of Journaling (step 8.6 WP6): the 12 operations of `/journaling/**` (D11) over
 * an in-memory set of intake sources per organization (on globalThis, shared by the separately
 * bundled BFF route handlers of `next dev`) and the archive settings row of the archive fixtures
 * (Journaling and the Archive edit the same row). The api rules the pages depend on are kept:
 * MFA routes, Idempotency-Key with replays (secrets redacted), CAS conflicts, masking unless
 * `journal:manage` + `?reveal=true`, one-time address display, network validation, disabled is
 * terminal. Addresses are synthetic (`journal-<26 chars>@journal.gateway.example.test`).
 */

export const JOURNALING_OPERATIONS = [
  'JournalingController_get_v1',
  'JournalingController_update_v1',
  'JournalingController_status_v1',
  'IntakeSourcesController_list_v1',
  'IntakeSourcesController_create_v1',
  'IntakeSourcesController_get_v1',
  'IntakeSourcesController_update_v1',
  'IntakeSourcesController_disable_v1',
  'IntakeSourcesController_rotate_v1',
  'IntakeSourcesController_wizard_v1',
  'IntakeSourcesController_guide_v1',
  'IntakeSourcesController_attest_v1',
] as const;

type Source = SuccessBody<'IntakeSourcesController_get_v1'>;
type SourceRow = ListItem<'IntakeSourcesController_list_v1'>;
type Kind = Source['kind'];
type Guide = SuccessBody<'IntakeSourcesController_guide_v1'>;

const INTAKE_DOMAIN = 'journal.gateway.example.test';
const DAY = 86_400_000;
const iso = (ms: number) => new Date(ms).toISOString();

interface OrgJournal {
  sources: Map<string, Source>;
  idempotency: Map<string, { fingerprint: string; response: FixtureResponse }>;
}

const globalState = globalThis as typeof globalThis & {
  __egDevFixtureJournaling?: Map<string, OrgJournal>;
};

/** Resets the in-memory journaling state (tests). */
export function resetJournalingFixtures(): void {
  globalState.__egDevFixtureJournaling = new Map();
}

const ATTESTATIONS: Record<Kind, readonly { code: string; statement: string }[]> = {
  microsoft_365_journal: [
    {
      code: 'journal.m365.rule_created',
      statement: 'A journal rule sends reports to the intake address.',
    },
    {
      code: 'journal.m365.ndr_mailbox_set',
      statement: 'An alternate mailbox for undeliverable journal reports is set.',
    },
  ],
  google_workspace_copy: [
    {
      code: 'journal.google.route_created',
      statement: 'A routing rule adds the intake address as an additional recipient.',
    },
    {
      code: 'journal.google.headers_added',
      statement: 'The routing rule adds the X-EG-Journal-Token header.',
    },
  ],
  exchange_onprem_journal: [
    {
      code: 'journal.onprem.journal_recipient_created',
      statement: 'A journal recipient (mail contact) with the intake address exists.',
    },
    {
      code: 'journal.onprem.send_connector_tls',
      statement: 'A Send connector delivers to the gateway with TLS.',
    },
  ],
  smtp_bcc: [
    {
      code: 'journal.smtp.bcc_configured',
      statement: 'The SMTP server sends a BCC copy of every message to the intake address.',
    },
  ],
};

function token(seed: string): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  const r = new SeededRandom(seed);
  return Array.from({ length: 26 }, () => alphabet[r.int(0, 31)]).join('');
}

function addressOf(id: string, version: number): string {
  return `journal-${token(`${id}:address:${version}`)}@${INTAKE_DOMAIN}`;
}

function headerTokenOf(id: string, version: number): string {
  return token(`${id}:header:${version}`);
}

function mask(address: string): string {
  const [local, domain] = address.split('@');
  return `journal-••••${(local ?? '').slice(-4)}@${domain ?? ''}`;
}

function maskToken(value: string): string {
  return `••••${value.slice(-4)}`;
}

function counters(id: string, accepted: boolean): Source['counters'] {
  if (!accepted) return [];
  const r = new SeededRandom(`${id}:counters`);
  const anchor = fixtureAnchor();
  return Array.from({ length: 7 }, (_, i) => {
    const n = r.int(80, 900);
    return {
      day: iso(anchor - (6 - i) * DAY).slice(0, 10),
      accepted: n,
      duplicates: r.int(0, 4),
      bytes: n * r.int(18_000, 60_000),
      refusedAddress: 0,
      refusedNetwork: i === 3 ? 2 : 0,
      refusedTls: 0,
      refusedSize: i === 5 ? 1 : 0,
      refusedRate: 0,
      refusedUnavailable: 0,
      droppedProof: i === 2 ? 1 : 0,
      unwrapFailed: 0,
    };
  });
}

function seedSource(
  organizationId: string,
  key: string,
  kind: Kind,
  displayName: string,
  status: Source['status'],
  health: Source['health']['status'],
): Source {
  const id = stableUuid(`${organizationId}:intake:${key}`);
  const anchor = fixtureAnchor();
  const accepted = status === 'active' || status === 'paused';
  const network = kind === 'exchange_onprem_journal' || kind === 'smtp_bcc';
  return {
    id,
    kind,
    displayName,
    status,
    providerConnectionId: network ? null : stableUuid(`${organizationId}:connection:${kind}`),
    networks: network ? ['203.0.113.0/28'] : null,
    requireTls: true,
    clientCertFingerprints: [],
    maxMessageBytes: null,
    silenceAlertMinutes: 240,
    addressVersion: 1,
    address: mask(addressOf(id, 1)),
    headerToken: kind === 'google_workspace_copy' ? maskToken(headerTokenOf(id, 1)) : null,
    revealed: false,
    previousAddressValidUntil: null,
    verifiedAt: accepted ? iso(anchor - 20 * DAY) : null,
    lastAcceptedAt: accepted ? iso(anchor - (health === 'silent' ? 400 : 3) * 60_000) : null,
    lastRefusedAt: accepted ? iso(anchor - 2 * DAY) : null,
    lastRefusalCode: accepted ? 'refused_network' : null,
    health: { status: health, changedAt: iso(anchor - 2 * DAY) },
    attestations: accepted
      ? ATTESTATIONS[kind].map((a) => ({
          code: a.code,
          at: iso(anchor - 21 * DAY),
          userId: stableUuid(`${organizationId}:user:admin`),
        }))
      : [],
    counters: counters(id, accepted),
    disabledAt: null,
    rowVersion: 1,
    createdAt: iso(anchor - 25 * DAY),
    updatedAt: iso(anchor - 2 * DAY),
  };
}

function orgOf(request: FixtureRequest): OrgJournal {
  globalState.__egDevFixtureJournaling ??= new Map();
  const id = principalOf(request).organizationId;
  let org = globalState.__egDevFixtureJournaling.get(id);
  if (!org) {
    const sources = [
      seedSource(
        id,
        'm365',
        'microsoft_365_journal',
        'EXAMPLE Microsoft 365 journal',
        'active',
        'healthy',
      ),
      seedSource(
        id,
        'onprem',
        'exchange_onprem_journal',
        'EXAMPLE Head office Exchange',
        'active',
        'silent',
      ),
      seedSource(
        id,
        'bcc',
        'smtp_bcc',
        'EXAMPLE Branch Postfix BCC',
        'pending_verification',
        'unknown',
      ),
    ];
    org = { sources: new Map(sources.map((s) => [s.id, s])), idempotency: new Map() };
    globalState.__egDevFixtureJournaling.set(id, org);
  }
  return org;
}

type Principal = NonNullable<ReturnType<typeof resolveFixturePrincipal>>;

function principalOf(request: FixtureRequest): Principal {
  const principal = resolveFixturePrincipal(request.token);
  if (!principal) throw new Error('fixture principal missing after the guard');
  return principal;
}

function has(request: FixtureRequest, permission: string): boolean {
  return principalOf(request).permissions.includes(permission);
}

function bodyOf(request: FixtureRequest): Record<string, unknown> {
  return request.body && typeof request.body === 'object'
    ? (request.body as Record<string, unknown>)
    : {};
}

function route(
  handler: (request: FixtureRequest, org: OrgJournal) => FixtureResponse,
): FixtureHandler {
  return (request) => fixtureGuard(request) ?? handler(request, orgOf(request));
}

function mfa(request: FixtureRequest): FixtureResponse | null {
  return principalOf(request).mfaAuthenticated
    ? null
    : apiError(403, 'mfa_required', 'This action requires a session signed in with MFA');
}

function idempotent(
  request: FixtureRequest,
  org: OrgJournal,
  handler: () => FixtureResponse,
  redact?: (response: FixtureResponse) => FixtureResponse,
): FixtureResponse {
  const key = request.headers.get('idempotency-key');
  if (!key)
    return apiError(400, 'idempotency_key_required', 'The Idempotency-Key header is required');
  const scoped = `${principalOf(request).userId}:${key}`;
  const fingerprint = JSON.stringify([request.operationId, request.params, request.body]);
  const stored = org.idempotency.get(scoped);
  if (stored) {
    if (stored.fingerprint !== fingerprint) {
      return apiError(
        422,
        'idempotency_key_reused',
        'The Idempotency-Key was used for another request',
      );
    }
    return {
      ...stored.response,
      headers: { ...(stored.response.headers ?? {}), 'idempotency-replayed': 'true' },
    };
  }
  const response = handler();
  if (response.status >= 200 && response.status < 300) {
    org.idempotency.set(scoped, { fingerprint, response: redact ? redact(response) : response });
  }
  return response;
}

function rowOf(source: Source): SourceRow {
  const { counters: _counters, ...row } = source;
  return row;
}

function withSource(
  request: FixtureRequest,
  org: OrgJournal,
  handler: (source: Source) => FixtureResponse,
): FixtureResponse {
  const source = org.sources.get(request.params.sourceId ?? '');
  if (!source)
    return apiError(404, 'journal_intake_source_not_found', 'Journal intake source not found');
  return handler(source);
}

const CIDR = /^(\d{1,3})(\.\d{1,3}){3}\/(\d{1,2})$|^[0-9a-f:]+\/(\d{1,3})$/i;
const PROVIDER_LIKE = /^(40\.|52\.|104\.47\.|209\.85\.|172\.217\.)/;

function networksInvalid(networks: unknown): FixtureResponse | null {
  if (!Array.isArray(networks) || networks.length === 0 || networks.length > 32) {
    return apiError(422, 'journal_intake_networks_invalid', 'Networks are required (1-32 CIDRs)', {
      issues: [{ code: 'count', index: 0 }],
    });
  }
  const index = networks.findIndex((n) => typeof n !== 'string' || !CIDR.test(n));
  if (index >= 0)
    return apiError(422, 'journal_intake_networks_invalid', 'Invalid network', {
      issues: [{ code: 'invalid', index }],
    });
  const overlap = (networks as string[]).findIndex((n) => PROVIDER_LIKE.test(n));
  if (overlap >= 0)
    return apiError(422, 'journal_intake_networks_invalid', 'A network overlaps a provider range', {
      issues: [{ code: 'provider_overlap', index: overlap }],
    });
  return null;
}

function revealed(source: Source): Source {
  const address = addressOf(source.id, source.addressVersion);
  return {
    ...source,
    address,
    headerToken:
      source.kind === 'google_workspace_copy'
        ? headerTokenOf(source.id, source.addressVersion)
        : null,
    revealed: true,
  };
}

function journalingView(request: FixtureRequest): SuccessBody<'JournalingController_get_v1'> {
  const s = archiveSettingsRow(request).get();
  return {
    enabled: s.enabled,
    entitled: s.entitled,
    intakeAvailable: true,
    intakeEntitled: true,
    journalEnabledAt: s.journalEnabledAt,
    settings: {
      directions: s.settings.directions,
      include: s.settings.include,
      scope: s.settings.scope,
      policyArchive: s.settings.policyArchive,
      intake: s.settings.intake,
    },
    generation: s.generation,
    rowVersion: s.rowVersion,
    updatedAt: s.updatedAt,
  };
}

function guideOf(request: FixtureRequest, source: Source): Guide {
  const reveal = has(request, 'journal:manage');
  const shown = reveal ? revealed(source) : source;
  const kindLabel: Record<Kind, string> = {
    microsoft_365_journal: 'Microsoft 365',
    google_workspace_copy: 'Google Workspace',
    exchange_onprem_journal: 'Exchange Server',
    smtp_bcc: 'your SMTP server',
  };
  const attested = new Map(source.attestations.map((a) => [a.code, a.at]));
  const attestations = ATTESTATIONS[source.kind].map((a) => ({
    code: a.code,
    statement: a.statement,
    attested: attested.has(a.code),
    attestedAt: attested.get(a.code) ?? null,
  }));
  return {
    schema: 'journal-intake-guide/1',
    kind: source.kind,
    source: { id: source.id, displayName: source.displayName, kind: source.kind },
    address: shown.address ?? '',
    ...(shown.headerToken ? { headerToken: shown.headerToken } : {}),
    revealed: reveal,
    notice: `EXAMPLE guide for ${kindLabel[source.kind]}: you make these changes in your own mail system; the gateway never changes it.`,
    sections: [
      {
        id: 'before',
        number: 1,
        title: 'Before you start',
        paragraphs: ['Archiving must be enabled and one of your domains verified.'],
        steps: [],
      },
      {
        id: 'configure',
        number: 2,
        title: `Configure ${kindLabel[source.kind]}`,
        paragraphs: ['Send a copy of every message to the intake address.'],
        steps: [
          {
            id: 'configure-address',
            title: 'Use the intake address',
            paragraphs: ['Enter this address as the journal recipient.'],
            values: [{ label: 'Intake address', value: shown.address ?? '' }],
            ...(source.kind === 'microsoft_365_journal'
              ? {
                  commands: [
                    {
                      language: 'powershell' as const,
                      code: `New-JournalRule -Name "Email security gateway journal" -JournalEmailAddress ${shown.address ?? ''} -Scope Global -Enabled $true`,
                    },
                  ],
                }
              : {}),
            ...(attestations[0] ? { attestation: attestations[0] } : {}),
          },
        ],
      },
      {
        id: 'verify',
        number: 3,
        title: 'Verify',
        paragraphs: [
          'Send a test message; the source becomes active with the first accepted copy.',
        ],
        steps: [],
      },
    ],
    attestations,
    generatedAt: iso(Date.now()),
  };
}

function markdownOf(guide: Guide): string {
  return [
    `# Journal intake setup: ${guide.source.displayName}`,
    '',
    guide.notice,
    '',
    ...guide.sections.flatMap((s) => [`## ${s.number}. ${s.title}`, '', ...s.paragraphs, '']),
  ].join('\n');
}

function wizardOf(
  request: FixtureRequest,
  source: Source,
): SuccessBody<'IntakeSourcesController_wizard_v1'> {
  const enabled = archiveSettingsRow(request).get().enabled;
  const network = source.providerConnectionId === null;
  const missing = ATTESTATIONS[source.kind]
    .filter((a) => !source.attestations.some((x) => x.code === a.code))
    .map((a) => a.code);
  const verified = source.verifiedAt !== null;
  const steps: SuccessBody<'IntakeSourcesController_wizard_v1'>['steps'] = [
    {
      step: 'archiving',
      status: enabled ? 'done' : 'blocked',
      blockers: enabled ? [] : ['archiving_disabled'],
    },
    { step: 'domains', status: 'done', blockers: [] },
    { step: 'connection', status: network ? 'skipped' : 'done', blockers: [] },
    { step: 'configure', status: missing.length === 0 ? 'done' : 'in_progress', blockers: [] },
    { step: 'verify', status: verified ? 'done' : 'in_progress', blockers: [] },
    {
      step: 'monitor',
      status: !verified ? 'not_started' : source.health.status === 'failing' ? 'blocked' : 'done',
      blockers: source.health.status === 'failing' ? ['health_failing'] : [],
    },
  ];
  const next = steps.find((s) => s.status !== 'done' && s.status !== 'skipped');
  return {
    sourceId: source.id,
    kind: source.kind,
    steps,
    missingAttestations: missing,
    nextAction: next
      ? {
          step: next.step,
          action:
            next.step === 'verify'
              ? 'Send a test message through your journal rule.'
              : next.step === 'configure'
                ? 'Follow the setup guide and confirm your statements.'
                : 'Resolve the blockers.',
        }
      : null,
  };
}

export const fixtures: FixtureHandlers = {
  JournalingController_get_v1: route((request) =>
    ok('JournalingController_get_v1', journalingView(request)),
  ),
  JournalingController_update_v1: route(
    (request, org) =>
      mfa(request) ??
      idempotent(request, org, () => {
        const body = bodyOf(request) as Partial<RequestBody<'JournalingController_update_v1'>>;
        const row = archiveSettingsRow(request);
        const s = row.get();
        if (typeof body.expectedRowVersion !== 'number')
          return apiError(400, 'validation_failed', ['expectedRowVersion: Required']);
        if (body.expectedRowVersion !== s.rowVersion) {
          return apiError(409, 'archive_settings_conflict', 'The settings changed', {
            currentRowVersion: s.rowVersion,
          });
        }
        const enabled = body.enabled ?? s.enabled;
        if (enabled && !s.entitled)
          return apiError(
            403,
            'archiving_not_enabled',
            'Archiving is not enabled for this organization',
          );
        if (enabled && !row.defaultPolicyLive()) {
          return apiError(
            422,
            'archive_default_retention_required',
            'A live default retention policy is required',
          );
        }
        const next = body.settings ?? {};
        row.set({
          ...s,
          enabled,
          settings: {
            ...s.settings,
            directions: { ...s.settings.directions, ...next.directions },
            include: { ...s.settings.include, ...next.include },
            scope: { ...s.settings.scope, ...next.scope },
            policyArchive: { ...s.settings.policyArchive, ...next.policyArchive },
            intake: { ...s.settings.intake, ...next.intake },
          },
          generation: s.generation + 1,
          journalEnabledAt: enabled && !s.enabled ? iso(Date.now()) : s.journalEnabledAt,
          rowVersion: s.rowVersion + 1,
          updatedAt: iso(Date.now()),
        });
        return ok('JournalingController_update_v1', journalingView(request));
      }),
  ),
  JournalingController_status_v1: route((request, org) => {
    const s = archiveSettingsRow(request).get();
    const sources = [...org.sources.values()];
    const count = (key: (x: Source) => string, keys: readonly string[]) =>
      sources.reduce<Record<string, number>>(
        (acc, x) => {
          acc[key(x)] = (acc[key(x)] ?? 0) + 1;
          return acc;
        },
        Object.fromEntries(keys.map((k) => [k, 0])),
      );
    const today = sources.flatMap((x) => x.counters.slice(-1));
    const sum = (k: keyof Source['counters'][number]) =>
      today.reduce((n, c) => n + (c[k] as number), 0);
    return ok('JournalingController_status_v1', {
      generatedAt: iso(Date.now()),
      settings: {
        enabled: s.enabled,
        entitled: s.entitled,
        intakeAvailable: true,
        intakeEntitled: true,
        generation: s.generation,
      },
      capture: {
        pending: 3,
        capturedOpen: 12,
        closed: 1840,
        failed: 0,
        lost: 0,
        skipped: 41,
        oldestPendingAt: null,
      },
      sources: {
        total: sources.length,
        byStatus: count((x) => x.status, ['pending_verification', 'active', 'paused', 'disabled']),
        byHealth: count(
          (x) => x.health.status,
          ['unknown', 'healthy', 'silent', 'failing', 'paused'],
        ),
      },
      intakeToday: {
        day: iso(Date.now()).slice(0, 10),
        accepted: sum('accepted'),
        duplicates: sum('duplicates'),
        refused:
          sum('refusedAddress') +
          sum('refusedNetwork') +
          sum('refusedTls') +
          sum('refusedSize') +
          sum('refusedRate') +
          sum('refusedUnavailable'),
        droppedProof: sum('droppedProof'),
        unwrapFailed: sum('unwrapFailed'),
        bytes: sum('bytes'),
      },
    });
  }),
  IntakeSourcesController_list_v1: route((request, org) => {
    const q = request.query;
    const rows = [...org.sources.values()]
      .filter((x) => !q.get('status') || x.status === q.get('status'))
      .filter((x) => !q.get('kind') || x.kind === q.get('kind'))
      .filter((x) => !q.get('health') || x.health.status === q.get('health'))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(rowOf);
    return { status: 200, body: paginate(rows, q), headers: { 'cache-control': 'no-store' } };
  }),
  IntakeSourcesController_create_v1: route(
    (request, org) =>
      mfa(request) ??
      idempotent(
        request,
        org,
        () => {
          const body = bodyOf(request) as Partial<RequestBody<'IntakeSourcesController_create_v1'>>;
          const kind = body.kind;
          const name = typeof body.displayName === 'string' ? body.displayName.trim() : '';
          if (!kind || !name)
            return apiError(400, 'validation_failed', ['kind and displayName are required']);
          if ([...org.sources.values()].some((x) => x.displayName === name))
            return apiError(
              409,
              'journal_intake_source_name_taken',
              'An intake source with this name exists',
            );
          if (org.sources.size >= 20)
            return apiError(409, 'journal_intake_source_limit', 'Too many intake sources');
          const network = kind === 'exchange_onprem_journal' || kind === 'smtp_bcc';
          if (network) {
            const invalid = networksInvalid(body.networks);
            if (invalid) return invalid;
          } else if (!body.providerConnectionId) {
            return apiError(
              422,
              'journal_intake_connection_invalid',
              'providerConnectionId is required',
            );
          }
          const now = Date.now();
          const id = crypto.randomUUID();
          const source: Source = {
            id,
            kind,
            displayName: name,
            status: 'pending_verification',
            providerConnectionId: network ? null : (body.providerConnectionId ?? null),
            networks: network ? (body.networks ?? []) : null,
            requireTls: body.requireTls ?? true,
            clientCertFingerprints: body.clientCertFingerprints ?? [],
            maxMessageBytes: body.maxMessageBytes ?? null,
            silenceAlertMinutes:
              body.silenceAlertMinutes === undefined ? 240 : body.silenceAlertMinutes,
            addressVersion: 1,
            address: mask(addressOf(id, 1)),
            headerToken: kind === 'google_workspace_copy' ? maskToken(headerTokenOf(id, 1)) : null,
            revealed: false,
            previousAddressValidUntil: null,
            verifiedAt: null,
            lastAcceptedAt: null,
            lastRefusedAt: null,
            lastRefusalCode: null,
            health: { status: 'unknown', changedAt: null },
            attestations: [],
            counters: [],
            disabledAt: null,
            rowVersion: 1,
            createdAt: iso(now),
            updatedAt: iso(now),
          };
          org.sources.set(id, source);
          const full = revealed(source);
          return {
            ...ok(
              'IntakeSourcesController_create_v1',
              { source: rowOf(source), address: full.address, headerToken: full.headerToken },
              201,
            ),
            headers: { 'cache-control': 'no-store' },
          };
        },
        (response) => ({
          ...response,
          body: { ...(response.body as object), address: null, headerToken: null },
        }),
      ),
  ),
  IntakeSourcesController_get_v1: route((request, org) =>
    withSource(request, org, (source) => {
      const reveal = request.query.get('reveal') === 'true';
      if (reveal && !has(request, 'journal:manage'))
        return apiError(403, 'forbidden', 'Revealing the intake address needs journal:manage');
      return {
        ...ok('IntakeSourcesController_get_v1', reveal ? revealed(source) : source),
        headers: { 'cache-control': 'no-store' },
      };
    }),
  ),
  IntakeSourcesController_update_v1: route(
    (request, org) =>
      mfa(request) ??
      idempotent(request, org, () =>
        withSource(request, org, (source) => {
          const body = bodyOf(request) as Partial<RequestBody<'IntakeSourcesController_update_v1'>>;
          if (source.status === 'disabled')
            return apiError(409, 'journal_intake_source_disabled', 'The intake source is disabled');
          if (body.expectedRowVersion !== source.rowVersion) {
            return apiError(409, 'journal_intake_source_conflict', 'The intake source changed', {
              currentRowVersion: source.rowVersion,
            });
          }
          if (body.networks !== undefined) {
            const invalid = networksInvalid(body.networks);
            if (invalid) return invalid;
          }
          const status =
            body.status === 'paused'
              ? 'paused'
              : body.status === 'active'
                ? source.verifiedAt
                  ? 'active'
                  : 'pending_verification'
                : source.status;
          const next: Source = {
            ...source,
            displayName: body.displayName?.trim() || source.displayName,
            networks: body.networks ?? source.networks,
            requireTls: body.requireTls ?? source.requireTls,
            silenceAlertMinutes:
              body.silenceAlertMinutes === undefined
                ? source.silenceAlertMinutes
                : body.silenceAlertMinutes,
            status,
            health:
              status === 'paused'
                ? { status: 'paused', changedAt: iso(Date.now()) }
                : source.status === 'paused'
                  ? {
                      status: source.verifiedAt ? 'healthy' : 'unknown',
                      changedAt: iso(Date.now()),
                    }
                  : source.health,
            rowVersion: source.rowVersion + 1,
            updatedAt: iso(Date.now()),
          };
          org.sources.set(source.id, next);
          return ok('IntakeSourcesController_update_v1', rowOf(next));
        }),
      ),
  ),
  IntakeSourcesController_disable_v1: route(
    (request, org) =>
      mfa(request) ??
      withSource(request, org, (source) => {
        if (source.status === 'disabled')
          return apiError(409, 'journal_intake_source_disabled', 'The intake source is disabled');
        const next: Source = {
          ...source,
          status: 'disabled',
          disabledAt: iso(Date.now()),
          rowVersion: source.rowVersion + 1,
          updatedAt: iso(Date.now()),
        };
        org.sources.set(source.id, next);
        return ok('IntakeSourcesController_disable_v1', rowOf(next));
      }),
  ),
  IntakeSourcesController_rotate_v1: route(
    (request, org) =>
      mfa(request) ??
      idempotent(
        request,
        org,
        () =>
          withSource(request, org, (source) => {
            if (source.status === 'disabled')
              return apiError(
                409,
                'journal_intake_source_disabled',
                'The intake source is disabled',
              );
            const version = source.addressVersion + 1;
            const next: Source = {
              ...source,
              addressVersion: version,
              address: mask(addressOf(source.id, version)),
              headerToken:
                source.kind === 'google_workspace_copy'
                  ? maskToken(headerTokenOf(source.id, version))
                  : null,
              previousAddressValidUntil: iso(Date.now() + 7 * DAY),
              rowVersion: source.rowVersion + 1,
              updatedAt: iso(Date.now()),
            };
            org.sources.set(source.id, next);
            const full = revealed(next);
            return {
              ...ok('IntakeSourcesController_rotate_v1', {
                source: rowOf(next),
                address: full.address,
                headerToken: full.headerToken,
              }),
              headers: { 'cache-control': 'no-store' },
            };
          }),
        (response) => ({
          ...response,
          body: { ...(response.body as object), address: null, headerToken: null },
        }),
      ),
  ),
  IntakeSourcesController_wizard_v1: route((request, org) =>
    withSource(request, org, (source) =>
      ok('IntakeSourcesController_wizard_v1', wizardOf(request, source)),
    ),
  ),
  IntakeSourcesController_guide_v1: route((request, org) =>
    withSource(request, org, (source) => {
      const guide = guideOf(request, source);
      const markdown =
        request.query.get('format') === 'markdown' ||
        (request.headers.get('accept') ?? '').includes('text/markdown');
      if (markdown) {
        return {
          status: 200,
          body: markdownOf(guide),
          headers: {
            'content-type': 'text/markdown; charset=utf-8',
            'content-disposition': `attachment; filename="journal-intake-${source.kind.replace(/_/g, '-')}.md"`,
          },
        };
      }
      return ok('IntakeSourcesController_guide_v1', guide);
    }),
  ),
  IntakeSourcesController_attest_v1: route(
    (request, org) =>
      mfa(request) ??
      withSource(request, org, (source) => {
        const body = bodyOf(request);
        const code = typeof body.code === 'string' ? body.code : '';
        if (!ATTESTATIONS[source.kind].some((a) => a.code === code))
          return apiError(422, 'journal_intake_attestation_unknown', 'Unknown attestation code');
        const others = source.attestations.filter((a) => a.code !== code);
        const attestations =
          body.attested === true
            ? [...others, { code, at: iso(Date.now()), userId: principalOf(request).userId }]
            : others;
        const rowVersion = source.rowVersion + 1;
        org.sources.set(source.id, {
          ...source,
          attestations,
          rowVersion,
          updatedAt: iso(Date.now()),
        });
        return ok('IntakeSourcesController_attest_v1', {
          sourceId: source.id,
          attestations,
          rowVersion,
        });
      }),
  ),
};

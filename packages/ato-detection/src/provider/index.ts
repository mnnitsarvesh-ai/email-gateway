/**
 * Identity-provider adapter port (step 8.4 D15, ADR-0070, ADR-0072): the provider-neutral types,
 * the strict normalized event schema (never a raw provider payload, no token- or secret-shaped
 * values), the registry (empty in 8.4 production; the fake adapter only in local/ci with the flag)
 * and the normalization of provider events into rule observations. Step 8.5 adds the Microsoft
 * Entra ID / Microsoft 365 and Google Workspace adapters behind this port.
 */
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { deviceFromUserAgent } from '../device';
import { canonicalIp, ipPrefix } from '../net';
import type { AuthObservation, Observation, ProviderObservation } from '../rules/types';

export const IDENTITY_PROVIDER_KINDS = ['microsoft_entra', 'google_workspace', 'fake'] as const;
export type IdentityProviderKind = (typeof IDENTITY_PROVIDER_KINDS)[number];

export const PROVIDER_STREAMS = [
  'sign_ins',
  'risk_events',
  'oauth_consents',
  'mailbox_audit',
  'forwarding_changes',
  'delegation_changes',
  'session_events',
] as const;
export type ProviderStream = (typeof PROVIDER_STREAMS)[number];

export { PROVIDER_ACTION_TYPES, type ProviderActionType } from '../responses';
import { PROVIDER_ACTION_TYPES, type ProviderActionType } from '../responses';

export interface ProviderCapabilities {
  streams: Partial<Record<ProviderStream, { supported: boolean; latencySeconds?: number }>>;
  actions: Partial<
    Record<
      ProviderActionType,
      { supported: boolean; rollback: boolean; confirmation: 'synchronous' | 'polling' }
    >
  >;
}

export interface ProviderIdentityRef {
  provider: IdentityProviderKind;
  externalId: string;
  userPrincipalName?: string;
  primaryEmail?: string;
}

export const MAILBOX_CHANGES = [
  'forwarding_added',
  'forwarding_removed',
  'inbox_rule_added',
  'inbox_rule_changed',
  'delegate_added',
  'permission_added',
  'access',
] as const;

export interface ProviderEvent {
  provider: IdentityProviderKind;
  eventId: string;
  stream: ProviderStream;
  occurredAt: string;
  identity: ProviderIdentityRef;
  outcome?: 'success' | 'failure' | 'interrupted';
  failureCode?: string;
  ip?: string;
  userAgent?: string;
  deviceIdHash?: string;
  /**
   * PX1 (step 8.5, ADR-0082): `<browser> · <os>` built by the adapter from structured provider
   * device data (Entra sign-ins carry no raw user agent in Graph v1.0), ≤ 96 characters.
   */
  deviceLabel?: string;
  providerLocation?: { countryCode?: string; city?: string; lat?: number; lon?: number };
  riskLevel?: 'low' | 'medium' | 'high';
  riskDetail?: string;
  mailbox?: {
    change: (typeof MAILBOX_CHANGES)[number];
    targetDomain?: string;
    ruleHash?: string;
    ruleTraits?: string[];
    clientType?: string;
  };
  oauth?: {
    appIdHash: string;
    appDisplayName?: string;
    scopes: string[];
    consentType: 'user' | 'admin';
    publisherVerified?: boolean;
  };
}

export interface ProviderIngestPage {
  events: ProviderEvent[];
  cursor: string;
  hasMore: boolean;
  retryAfterMs?: number;
}

export type ProviderActionResult =
  | { status: 'confirmed'; providerReference: string; confirmedAt: string }
  | { status: 'pending'; providerReference: string; pollAfterMs: number }
  | { status: 'unsupported' }
  | { status: 'failed'; code: string; retryable: boolean };

export interface ProviderActionRequest {
  actionPublicId: string;
  idempotencyKey: string;
  type: ProviderActionType;
  identity: ProviderIdentityRef;
  params: Record<string, string | number | boolean>;
}

export interface IdentityProviderAdapter {
  readonly kind: IdentityProviderKind;
  readonly version: string;
  capabilities(): ProviderCapabilities;
  health(signal: AbortSignal): Promise<{ ok: boolean; code?: string }>;
  ingest(
    stream: ProviderStream,
    cursor: string | null,
    signal: AbortSignal,
  ): Promise<ProviderIngestPage>;
  resolveIdentity(address: string, signal: AbortSignal): Promise<ProviderIdentityRef | null>;
  execute(request: ProviderActionRequest, signal: AbortSignal): Promise<ProviderActionResult>;
  confirm(
    ref: { type: ProviderActionType; providerReference: string },
    signal: AbortSignal,
  ): Promise<ProviderActionResult>;
  rollback?(
    request: Omit<ProviderActionRequest, 'params'> & { providerReference: string },
    signal: AbortSignal,
  ): Promise<ProviderActionResult>;
}

/** Classified adapter error (the runner retries only `retryable` ones). */
export class ProviderAdapterError extends Error {
  constructor(
    readonly code: string,
    readonly retryable: boolean,
    readonly retryAfterMs?: number,
  ) {
    super(`provider error ${code}`);
    this.name = 'ProviderAdapterError';
  }
}

// ------------------------------------------------------------------ strict event schema

/** Token- or secret-shaped: JWT-like, long base64/hex runs or common key prefixes. */
export const SECRET_SHAPED =
  /(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})|([A-Za-z0-9+/_=-]{40,})|(-----BEGIN)|(\b(?:sk|ghp|xox[abp])[-_][A-Za-z0-9]{8,})/;

const safe = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    // eslint-disable-next-line no-control-regex
    .refine((v) => !/[\u0000-\u001f\u007f]/.test(v), 'control characters')
    .refine((v) => !SECRET_SHAPED.test(v), 'token- or secret-shaped value');
const hash = z.string().regex(/^[0-9a-f]{16,64}$/, 'lower-case hex hash');
const code = z.string().regex(/^[a-z0-9][a-z0-9_.-]{0,63}$/, 'lower-case code');

export const providerIdentitySchema = z.strictObject({
  provider: z.enum(IDENTITY_PROVIDER_KINDS),
  externalId: safe(128),
  userPrincipalName: z.string().max(320).optional(),
  primaryEmail: z.email().max(320).optional(),
});

/** The strict normalized provider event (D15). */
export const providerEventSchema = z
  .strictObject({
    provider: z.enum(IDENTITY_PROVIDER_KINDS),
    eventId: safe(128),
    stream: z.enum(PROVIDER_STREAMS),
    occurredAt: z.iso.datetime(),
    identity: providerIdentitySchema,
    outcome: z.enum(['success', 'failure', 'interrupted']).optional(),
    failureCode: code.optional(),
    ip: z
      .string()
      .max(45)
      .refine((v) => canonicalIp(v) !== null, 'IP literal')
      .optional(),
    userAgent: z.string().max(512).optional(),
    deviceIdHash: hash.optional(),
    deviceLabel: safe(96).optional(),
    providerLocation: z
      .strictObject({
        countryCode: z
          .string()
          .regex(/^[A-Z]{2}$/)
          .optional(),
        city: safe(64).optional(),
        lat: z.number().min(-90).max(90).optional(),
        lon: z.number().min(-180).max(180).optional(),
      })
      .optional(),
    riskLevel: z.enum(['low', 'medium', 'high']).optional(),
    riskDetail: code.optional(),
    mailbox: z
      .strictObject({
        change: z.enum(MAILBOX_CHANGES),
        targetDomain: z
          .string()
          .max(253)
          .regex(/^[a-z0-9.-]+$/, 'lower-case domain')
          .optional(),
        ruleHash: hash.optional(),
        ruleTraits: z.array(code).max(16).optional(),
        clientType: code.optional(),
      })
      .optional(),
    oauth: z
      .strictObject({
        appIdHash: hash,
        appDisplayName: safe(128).optional(),
        scopes: z.array(code).max(64),
        consentType: z.enum(['user', 'admin']),
        publisherVerified: z.boolean().optional(),
      })
      .optional(),
  })
  .superRefine((e, ctx) => {
    if (e.identity.provider !== e.provider) {
      ctx.addIssue({
        code: 'custom',
        path: ['identity', 'provider'],
        message: 'provider mismatch',
      });
    }
    if (e.stream === 'sign_ins' && e.outcome === undefined) {
      ctx.addIssue({ code: 'custom', path: ['outcome'], message: 'a sign-in has an outcome' });
    }
    if (e.stream === 'oauth_consents' && e.oauth === undefined) {
      ctx.addIssue({ code: 'custom', path: ['oauth'], message: 'a consent event has oauth' });
    }
    if (
      (e.stream === 'mailbox_audit' ||
        e.stream === 'forwarding_changes' ||
        e.stream === 'delegation_changes') &&
      e.mailbox === undefined
    ) {
      ctx.addIssue({ code: 'custom', path: ['mailbox'], message: 'a mailbox event has mailbox' });
    }
  });

// ------------------------------------------------------------------ registry

/**
 * The integration an adapter is bound to (PX2, step 8.5): the `ato_provider_integrations` row as
 * the worker read it. Factories read the fields they need from their own row type.
 */
export interface ProviderIntegrationRef {
  id: bigint;
  organizationId: bigint;
  provider: string;
}

/** PX2: builds the adapter bound to one integration (one instance per binding). */
export type ProviderAdapterFactory<TIntegration extends ProviderIntegrationRef> = (
  integration: TIntegration,
) => IdentityProviderAdapter;

/**
 * Provider kind → singleton adapter (8.4 D15) or, since step 8.5 (PX2, merge note M2), kind →
 * factory with `adapterFor(integration)`. 8.4 callers of `get` keep working unchanged.
 */
export class ProviderRegistry<
  TIntegration extends ProviderIntegrationRef = ProviderIntegrationRef,
> {
  private readonly adapters = new Map<IdentityProviderKind, IdentityProviderAdapter>();
  private readonly factories = new Map<
    IdentityProviderKind,
    ProviderAdapterFactory<TIntegration>
  >();

  register(adapter: IdentityProviderAdapter): this {
    if (this.adapters.has(adapter.kind) || this.factories.has(adapter.kind))
      throw new Error(`Provider ${adapter.kind} already registered`);
    if (adapter.kind === 'fake') {
      throw new Error('The fake adapter is registered only through registerFake');
    }
    this.adapters.set(adapter.kind, adapter);
    return this;
  }

  /**
   * Registers the fake adapter: only with `ATO_PROVIDER_FAKE_ENABLED=true` and `APP_ENV` in
   * {local, ci}; refused otherwise (D15).
   */
  registerFake(
    adapter: IdentityProviderAdapter,
    options: { enabled: boolean; appEnv: string },
  ): this {
    if (!options.enabled) return this;
    if (options.appEnv !== 'local' && options.appEnv !== 'ci') {
      throw new Error('The fake identity provider adapter is allowed only in local and ci');
    }
    if (adapter.kind !== 'fake') throw new Error('registerFake takes the fake adapter');
    this.adapters.set('fake', adapter);
    return this;
  }

  /**
   * PX2 (step 8.5, merge note M2): registers the factory of a provider kind whose adapters are
   * bound per integration (Microsoft Entra ID, Google Workspace). Never the fake adapter.
   */
  registerFactory(kind: IdentityProviderKind, factory: ProviderAdapterFactory<TIntegration>): this {
    if (kind === 'fake') {
      throw new Error('The fake adapter is registered only through registerFake');
    }
    if (this.adapters.has(kind) || this.factories.has(kind)) {
      throw new Error(`Provider ${kind} already registered`);
    }
    this.factories.set(kind, factory);
    return this;
  }

  /**
   * PX2: the adapter bound to `integration`: its kind's factory, else the kind's singleton adapter
   * (the fake adapter's "factory" returns its single instance); `undefined` when neither exists.
   */
  adapterFor(integration: TIntegration): IdentityProviderAdapter | undefined {
    const factory = this.factories.get(integration.provider as IdentityProviderKind);
    if (factory) return factory(integration);
    return this.adapters.get(integration.provider as IdentityProviderKind);
  }

  /** Whether the kind's adapters are bound per integration (PX2). */
  hasFactory(kind: string): boolean {
    return this.factories.has(kind as IdentityProviderKind);
  }

  /** Kinds served by a singleton adapter (8.4's fake adapter). */
  singletonKinds(): IdentityProviderKind[] {
    return [...this.adapters.keys()].sort();
  }

  /** The singleton adapter of a kind (8.4); per-integration kinds answer through `adapterFor`. */
  get(kind: string): IdentityProviderAdapter | undefined {
    return this.adapters.get(kind as IdentityProviderKind);
  }

  kinds(): IdentityProviderKind[] {
    return [...new Set([...this.adapters.keys(), ...this.factories.keys()])].sort();
  }

  get size(): number {
    return this.adapters.size + this.factories.size;
  }
}

/** Whether an adapter declares support for an action. */
export function adapterSupports(
  adapter: IdentityProviderAdapter,
  type: ProviderActionType,
): boolean {
  return adapter.capabilities().actions[type]?.supported === true;
}

export const isProviderActionType = (value: string): value is ProviderActionType =>
  (PROVIDER_ACTION_TYPES as readonly string[]).includes(value);

// ------------------------------------------------------------------ normalization

export interface NormalizeContext {
  /** Domains the account has contacted (M1 "never contacted"). */
  knownDomains?: ReadonlySet<string>;
  /** Client types in the account's baseline (M4). */
  knownClientTypes?: ReadonlySet<string>;
}

/** Stable source key of a provider event (≤ 64 characters). */
export function providerEventKey(
  event: Pick<ProviderEvent, 'provider' | 'stream' | 'eventId'>,
): string {
  const digest = createHash('sha256')
    .update(`${event.provider}|${event.stream}|${event.eventId}`, 'utf8')
    .digest('hex');
  return `prov:${digest.slice(0, 40)}`;
}

/**
 * `normalizeProviderEvent(event)`: a sign-in becomes an `auth` observation (source `idp_sign_in`,
 * enriched later by the worker with GeoIP and reputation); every other stream becomes a `provider`
 * observation for the M, Q and R rules. The event is validated with `providerEventSchema` first.
 */
export function normalizeProviderEvent(
  event: ProviderEvent,
  context: NormalizeContext = {},
): Observation {
  const e = providerEventSchema.parse(event);
  const key = providerEventKey(e);
  const occurredAt = new Date(e.occurredAt);
  if (e.stream === 'sign_ins') {
    const ip = e.ip ? canonicalIp(e.ip) : null;
    const device = deviceFromUserAgent(e.userAgent);
    const observation: AuthObservation = {
      type: 'auth',
      key,
      source: 'idp_sign_in',
      channel: 'idp',
      outcome:
        e.outcome === 'success'
          ? 'success'
          : e.outcome === 'interrupted'
            ? 'mfa_required'
            : 'failure',
      failureCode: e.failureCode ?? null,
      occurredAt,
      ip,
      ipPrefix: ip ? ipPrefix(ip) : null,
      geo: null,
      // PX1: without a user agent, the provider device id hash is the device, labelled with the
      // adapter's structured `deviceLabel` when present.
      device: device
        ? { hash: device.hash, label: device.label }
        : e.deviceIdHash
          ? { hash: e.deviceIdHash.slice(0, 16), label: e.deviceLabel ?? 'Provider device' }
          : null,
      reputation: null,
      dnsblListed: null,
      ipFlag: null,
      blockedNetwork: false,
      trustedNetwork: false,
      authEventRef: null,
    };
    return observation;
  }
  const observation: ProviderObservation = {
    type: 'provider',
    key,
    occurredAt,
    stream: e.stream,
    provider: e.provider,
    eventId: e.eventId,
    riskLevel: e.riskLevel ?? null,
    mailbox: e.mailbox
      ? {
          change: e.mailbox.change,
          targetDomain: e.mailbox.targetDomain ?? null,
          targetDomainKnown: e.mailbox.targetDomain
            ? (context.knownDomains?.has(e.mailbox.targetDomain) ?? false)
            : false,
          ruleHash: e.mailbox.ruleHash ?? null,
          ruleTraits: e.mailbox.ruleTraits ?? [],
          clientType: e.mailbox.clientType ?? null,
          clientTypeKnown: e.mailbox.clientType
            ? (context.knownClientTypes?.has(e.mailbox.clientType) ?? false)
            : true,
        }
      : null,
    oauth: e.oauth
      ? {
          appIdHash: e.oauth.appIdHash,
          scopes: e.oauth.scopes,
          consentType: e.oauth.consentType,
          publisherVerified: e.oauth.publisherVerified ?? null,
        }
      : null,
    tokenAnomaly: e.stream === 'session_events' && e.riskDetail === 'token_anomaly',
  };
  return observation;
}

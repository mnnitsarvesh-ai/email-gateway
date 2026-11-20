import { isIP } from 'node:net';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import {
  isMetadataAddress,
  isPublicIpAddress,
  mailDestinationPresetSchema,
  type MailDestinationPresetView,
  validateDestinationHost,
  type ValidateDestinationHostOptions,
} from '@email-gateway/mail-routing';
import {
  boundEvidence,
  type CheckSeverity,
  type CheckStatus,
  comparePermissions,
  degradedSinceOf,
  evaluateAtoIdentityProvider,
  evaluateCredentialExpiry,
  type GrantRef,
  grantsForCheck,
  healthCheckByCode,
  isCustomerCredentialMethod,
  lockdownAttestations,
  profileByKey,
  type ProviderDomainStatus,
  readAtoIntegrationHealth,
  type ValidationResult,
} from '@email-gateway/provider-integrations';
import type { IntegrationMetrics } from '../metrics/integration-metrics';
import type { ProviderRuntime } from '../providers/provider-runtime';
import { num } from '../shared/db';
import { errorCode, isTransientProviderError } from '../shared/errors';
import type { ConnectionGrantView, ConnectionView, LinkedDomainView } from './context';
import type { ProbeResolver } from './dns';
import type { SmtpProbeOptions, SmtpProbeResult } from './smtp-probe';

/** One check result (`provider-validation/1` entry; also a `provider_health_checks` row). */
export type CheckResult = ValidationResult;

/** Grant statuses a token may be requested for (verification, use, re-checks of failures). */
const TOKEN_GRANT_STATUSES = new Set(['verifying', 'active', 'error']);

/** Stored DNS observations older than this are stale (`warn`, D10 `dns.mx_gateway`). */
export const DNS_OBSERVATION_MAX_AGE_MS = 24 * 3_600_000;
/** Microsoft 365 DKIM selectors (CNAMEs published per domain). */
const MICROSOFT_DKIM_SELECTORS = ['selector1', 'selector2'];
/** Google Workspace's default DKIM selector. */
const GOOGLE_DKIM_SELECTOR = 'google';
/** `outbound.relay_activity`: proof failures above 20 % of at least 20 messages fail (D11). */
const PROOF_FAILURE_RATIO = 0.2;
const PROOF_FAILURE_MIN = 20;
/** `inbound.recent_deliveries`: problems above 20 % of at least 10 deliveries warn. */
const DELIVERY_PROBLEM_RATIO = 0.2;
const DELIVERY_PROBLEM_MIN = 10;

/** Builds one result with the registry's severity and remediation anchor. */
export function checkResult(
  code: string,
  subject: string,
  status: CheckStatus,
  evidence: Record<string, unknown> = {},
): CheckResult {
  const definition = healthCheckByCode(code);
  const severity: CheckSeverity =
    status === 'pass' || status === 'skipped'
      ? 'info'
      : status === 'warn'
        ? 'warning'
        : (definition?.severityOnFail ?? 'critical');
  return {
    code,
    subject: subject.slice(0, 253),
    status,
    severity,
    evidence: boundEvidence(evidence),
    remediation: (definition?.remediation ?? '').slice(0, 256),
  };
}

export interface CheckRunnerDeps {
  writer: PrismaClient;
  /** Delivery statistics (the replica when configured; else the writer). */
  reader: () => PrismaClient;
  runtime: ProviderRuntime;
  resolver: ProbeResolver;
  probeSmtp: (options: SmtpProbeOptions) => Promise<SmtpProbeResult>;
  metrics: IntegrationMetrics;
  now: () => Date;
  settings: {
    gatewayMxHosts: readonly string[];
    spfInclude: string | null;
    egressMaxAgeDays: number;
    relayIdleWarnHours: number;
    probeHelo: string;
    probeTimeoutMs: number;
    probeCa: string[] | undefined;
    /** Resolved probe addresses may be non-public (local/ci stand-ins, or the routing switch). */
    allowNonPublicProbeAddresses: boolean;
    destinationHosts: ValidateDestinationHostOptions;
  };
}

/** Per-run cache: one token, tenant and domain answer per grant (validation and health). */
interface RunState {
  tokens: Map<string, { observed: string[] } | { error: unknown }>;
  tenant: { tenantId: string } | { error: unknown } | null;
  probes: Map<string, CheckResult>;
}

export type CheckCode =
  | 'credentials.token'
  | 'permissions.granted'
  | 'tenant.identity'
  | 'domains.gateway_verified'
  | 'domains.provider_verified'
  | 'dns.mx_gateway'
  | 'inbound.destination'
  | 'inbound.destination_matches_provider'
  | 'inbound.smtp'
  | 'inbound.recent_deliveries'
  | 'dns.spf_gateway'
  | 'dns.dkim_provider'
  | 'outbound.relay_activity'
  | 'routing.no_loops'
  | 'routing.loops'
  | 'lockdown.attested'
  | 'credential.expiry'
  | 'egress.ranges_fresh'
  // Step 8.5 (health/ato.ts of the library): ATO integration health, read from stored rows.
  | 'ato.identity_provider';

/** Codes that talk to the provider (back-off and grace apply, D11, D15). */
export const PROVIDER_CHECK_CODES: ReadonlySet<string> = new Set([
  'credentials.token',
  'permissions.granted',
  'tenant.identity',
  'domains.provider_verified',
]);

/**
 * The D10/D11 check implementations (ADR-0079). Provider checks read through the token service
 * and the directories; gateway checks read stored rows (domains, DNS observations, destinations,
 * deliveries, relay counters, egress sets); `inbound.smtp` probes the destination hosts (never
 * DATA); `dns.dkim_provider` resolves the provider's DKIM selectors (evidence only). Results are
 * bounded and non-secret.
 */
export class CheckRunner {
  constructor(private readonly deps: CheckRunnerDeps) {}

  /** Runs `codes` (in the order given) for a connection; one result list per call. */
  async run(
    connection: ConnectionView,
    codes: readonly CheckCode[],
    signal: AbortSignal,
  ): Promise<CheckResult[]> {
    const state: RunState = { tokens: new Map(), tenant: null, probes: new Map() };
    const out: CheckResult[] = [];
    for (const code of codes) {
      if (signal.aborted) break;
      out.push(...(await this.one(code, connection, state, signal)));
    }
    return out;
  }

  private async one(
    code: CheckCode,
    c: ConnectionView,
    state: RunState,
    signal: AbortSignal,
  ): Promise<CheckResult[]> {
    switch (code) {
      case 'credentials.token':
        return this.credentialsToken(c, state, signal);
      case 'permissions.granted':
        return this.permissionsGranted(c, state, signal);
      case 'tenant.identity':
        return [await this.tenantIdentity(c, state, signal)];
      case 'domains.gateway_verified':
        return this.gatewayVerified(c);
      case 'domains.provider_verified':
        return this.providerVerified(c, state, signal);
      case 'dns.mx_gateway':
        return this.dnsRecord(c, 'dns.mx_gateway', 'mx');
      case 'dns.spf_gateway':
        return this.dnsRecord(c, 'dns.spf_gateway', 'spf');
      case 'dns.dkim_provider':
        return this.dkimProvider(c);
      case 'inbound.destination':
        return this.inboundDestination(c);
      case 'inbound.destination_matches_provider':
        return this.destinationMatchesProvider(c);
      case 'inbound.smtp':
        return this.inboundSmtp(c, state);
      case 'inbound.recent_deliveries':
        return this.recentDeliveries(c);
      case 'outbound.relay_activity':
        return [await this.relayActivity(c)];
      case 'routing.no_loops':
      case 'routing.loops':
        return [await this.loops(c, code)];
      case 'lockdown.attested':
        return [this.lockdown(c)];
      case 'credential.expiry':
        return this.credentialExpiry(c);
      case 'egress.ranges_fresh':
        return [await this.egressFresh(c)];
      case 'ato.identity_provider':
        return [await this.atoIdentityProvider(c)];
    }
  }

  // ---- provider checks --------------------------------------------------------------------

  /** The mail-flow grants a token may be requested for (R2). */
  private tokenGrants(c: ConnectionView): ConnectionGrantView[] {
    const definition = healthCheckByCode('credentials.token');
    const grants = definition ? grantsForCheck(definition, c.grants) : c.grants;
    return grants.filter((g) => TOKEN_GRANT_STATUSES.has(g.status));
  }

  private ref(c: ConnectionView, grant: ConnectionGrantView): GrantRef {
    return {
      organizationId: c.organizationId,
      connectionPublicId: c.publicId,
      profile: grant.profile,
    };
  }

  private async token(
    c: ConnectionView,
    grant: ConnectionGrantView,
    state: RunState,
    signal: AbortSignal,
  ): Promise<{ observed: string[] } | { error: unknown }> {
    const cached = state.tokens.get(grant.publicId);
    if (cached) return cached;
    let outcome: { observed: string[] } | { error: unknown };
    try {
      const token = await this.deps.runtime.tokens.getAccessToken(this.ref(c, grant), signal);
      outcome = { observed: token.observedPermissions };
      await this.deps.writer.providerConnectionGrant.updateMany({
        where: { id: grant.id, organizationId: c.organizationId },
        data: { lastTokenAt: this.deps.now() },
      });
    } catch (error) {
      outcome = { error };
    }
    state.tokens.set(grant.publicId, outcome);
    return outcome;
  }

  private failureOf(error: unknown): { status: CheckStatus; evidence: Record<string, unknown> } {
    return {
      status: isTransientProviderError(error) ? 'error' : 'fail',
      evidence: { code: errorCode(error) },
    };
  }

  private async credentialsToken(
    c: ConnectionView,
    state: RunState,
    signal: AbortSignal,
  ): Promise<CheckResult[]> {
    const grants = this.tokenGrants(c);
    if (grants.length === 0) {
      return [checkResult('credentials.token', '', 'fail', { reason: 'no_active_grant' })];
    }
    const out: CheckResult[] = [];
    for (const grant of grants) {
      const token = await this.token(c, grant, state, signal);
      if ('error' in token) {
        const failure = this.failureOf(token.error);
        out.push(
          checkResult('credentials.token', grant.profile, failure.status, {
            ...failure.evidence,
            authMethod: grant.authMethod,
          }),
        );
      } else {
        out.push(
          checkResult('credentials.token', grant.profile, 'pass', { authMethod: grant.authMethod }),
        );
      }
    }
    return out;
  }

  private async permissionsGranted(
    c: ConnectionView,
    state: RunState,
    signal: AbortSignal,
  ): Promise<CheckResult[]> {
    const grants = this.tokenGrants(c);
    if (grants.length === 0) {
      return [checkResult('permissions.granted', '', 'skipped', { reason: 'no_active_grant' })];
    }
    const out: CheckResult[] = [];
    for (const grant of grants) {
      const profile = profileByKey(grant.profile);
      const token = await this.token(c, grant, state, signal);
      if (!profile || 'error' in token) {
        out.push(
          checkResult('permissions.granted', grant.profile, 'skipped', { reason: 'no_token' }),
        );
        continue;
      }
      const { missing, excess } = comparePermissions(profile, token.observed);
      await this.deps.writer.providerConnectionGrant.updateMany({
        where: { id: grant.id, organizationId: c.organizationId },
        data: {
          observedPermissions: [...token.observed].sort(),
          missingPermissions: missing.length > 0 ? missing : Prisma.DbNull,
          excessPermissions: excess.length > 0 ? excess : Prisma.DbNull,
        },
      });
      const status: CheckStatus = missing.length > 0 ? 'fail' : excess.length > 0 ? 'warn' : 'pass';
      out.push(
        checkResult('permissions.granted', grant.profile, status, {
          ...(missing.length > 0 ? { missing } : {}),
          ...(excess.length > 0
            ? { excess, note: 'over-privileged: remove the excess permissions' }
            : {}),
        }),
      );
    }
    return out;
  }

  /** The first token-capable mail-flow grant (directory reads). */
  private directoryGrant(c: ConnectionView): ConnectionGrantView | null {
    return this.tokenGrants(c).find((g) => g.status === 'active') ?? this.tokenGrants(c)[0] ?? null;
  }

  private async tenantIdentity(
    c: ConnectionView,
    state: RunState,
    signal: AbortSignal,
  ): Promise<CheckResult> {
    if (!c.externalTenantId) {
      return checkResult('tenant.identity', '', 'skipped', { reason: 'tenant_not_bound' });
    }
    const grant = this.directoryGrant(c);
    if (!grant) return checkResult('tenant.identity', '', 'skipped', { reason: 'no_active_grant' });
    if (!state.tenant) {
      try {
        const tenant = await this.deps.runtime.directories[c.provider].tenant(
          this.ref(c, grant),
          signal,
        );
        state.tenant = { tenantId: tenant.tenantId };
      } catch (error) {
        state.tenant = { error };
      }
    }
    if ('error' in state.tenant) {
      const failure = this.failureOf(state.tenant.error);
      return checkResult('tenant.identity', '', failure.status, failure.evidence);
    }
    const matches = state.tenant.tenantId.toLowerCase() === c.externalTenantId.toLowerCase();
    return checkResult(
      'tenant.identity',
      '',
      matches ? 'pass' : 'fail',
      matches ? { matches } : { matches, reason: 'tenant_changed' },
    );
  }

  /**
   * Provider-side verification of every linked domain (D4); updates `provider_verification`,
   * `provider_checked_at` and `provider_mx_host`. Exposed for the domain-check task.
   */
  async checkProviderDomains(
    c: ConnectionView,
    signal: AbortSignal,
  ): Promise<{ domain: LinkedDomainView; status: ProviderDomainStatus | null; error: unknown }[]> {
    const grant = this.directoryGrant(c);
    const out: { domain: LinkedDomainView; status: ProviderDomainStatus | null; error: unknown }[] =
      [];
    if (!grant) return c.domains.map((domain) => ({ domain, status: null, error: null }));
    for (const domain of c.domains) {
      if (signal.aborted) break;
      try {
        const status = await this.deps.runtime.directories[c.provider].domain(
          this.ref(c, grant),
          domain.name,
          signal,
        );
        await this.deps.writer.providerConnectionDomain.updateMany({
          where: { id: domain.linkId, organizationId: c.organizationId, connectionId: c.id },
          data: {
            providerVerification: status.status,
            providerCheckedAt: this.deps.now(),
            providerMxHost: status.mxHost,
          },
        });
        domain.providerVerification = status.status;
        domain.providerMxHost = status.mxHost;
        domain.providerCheckedAt = this.deps.now();
        out.push({ domain, status, error: null });
      } catch (error) {
        out.push({ domain, status: null, error });
      }
    }
    return out;
  }

  private async providerVerified(
    c: ConnectionView,
    _state: RunState,
    signal: AbortSignal,
  ): Promise<CheckResult[]> {
    if (c.domains.length === 0) {
      return [
        checkResult('domains.provider_verified', '', 'fail', { reason: 'no_linked_domains' }),
      ];
    }
    if (!this.directoryGrant(c)) {
      return [
        checkResult('domains.provider_verified', '', 'skipped', { reason: 'no_active_grant' }),
      ];
    }
    const checked = await this.checkProviderDomains(c, signal);
    const anyVerified = checked.some((r) => r.status?.status === 'verified');
    // A domain that is not (or no longer) verified fails when mail flow depends on it, or when no
    // linked domain is verified at all (≥ 1 is required, D10); otherwise it warns (D4).
    const mailFlowActive = c.outboundMode !== 'off' || c.internalRouting;
    return checked.map(({ domain, status, error }) => {
      if (!status) {
        const failure = this.failureOf(error);
        return checkResult(
          'domains.provider_verified',
          domain.name,
          failure.status,
          failure.evidence,
        );
      }
      if (status.status === 'verified') {
        return checkResult('domains.provider_verified', domain.name, 'pass', {
          verification: status.status,
          ...(status.mxHost ? { mxHost: status.mxHost } : {}),
        });
      }
      const strict = mailFlowActive || !anyVerified;
      return checkResult('domains.provider_verified', domain.name, strict ? 'fail' : 'warn', {
        verification: status.status,
      });
    });
  }

  // ---- gateway checks ---------------------------------------------------------------------

  private gatewayVerified(c: ConnectionView): CheckResult[] {
    if (c.domains.length === 0) {
      return [checkResult('domains.gateway_verified', '', 'fail', { reason: 'no_linked_domains' })];
    }
    return c.domains.map((d) =>
      checkResult(
        'domains.gateway_verified',
        d.name,
        d.gatewayStatus === 'active' ? 'pass' : 'fail',
        {
          gatewayStatus: d.gatewayStatus,
        },
      ),
    );
  }

  /** Stored step 2.1 DNS observations: `mx` (every gateway MX record) or `spf`. */
  private async dnsRecord(
    c: ConnectionView,
    code: 'dns.mx_gateway' | 'dns.spf_gateway',
    purpose: 'mx' | 'spf',
  ): Promise<CheckResult[]> {
    if (code === 'dns.spf_gateway' && c.outboundMode === 'off') {
      return c.domains.map((d) => checkResult(code, d.name, 'skipped', { reason: 'outbound_off' }));
    }
    if (c.domains.length === 0)
      return [checkResult(code, '', 'fail', { reason: 'no_linked_domains' })];
    const rows = await this.deps.writer.domainDnsRecord.findMany({
      where: {
        organizationId: c.organizationId,
        domainId: { in: c.domains.map((d) => d.domainId) },
        purpose,
      },
      select: { domainId: true, recordKey: true, status: true, lastCheckedAt: true },
    });
    const now = this.deps.now().getTime();
    return c.domains.map((d) => {
      const own = rows.filter((r) => r.domainId === d.domainId);
      if (own.length === 0) return checkResult(code, d.name, 'fail', { reason: 'not_observed' });
      const statuses = Object.fromEntries(own.map((r) => [r.recordKey, r.status]));
      const invalid = own.some((r) => r.status !== 'valid');
      if (invalid) return checkResult(code, d.name, 'fail', { records: statuses });
      const oldest = Math.min(...own.map((r) => r.lastCheckedAt?.getTime() ?? 0));
      if (now - oldest > DNS_OBSERVATION_MAX_AGE_MS) {
        return checkResult(code, d.name, 'warn', {
          records: statuses,
          reason: 'observation_stale',
          checkedAt: oldest > 0 ? new Date(oldest).toISOString() : null,
        });
      }
      return checkResult(code, d.name, 'pass', {
        records: statuses,
        ...(purpose === 'spf' && this.deps.settings.spfInclude
          ? { include: this.deps.settings.spfInclude }
          : {}),
      });
    });
  }

  /** The provider's DKIM selectors are published for the domain (evidence only, D10). */
  private async dkimProvider(c: ConnectionView): Promise<CheckResult[]> {
    if (c.outboundMode === 'off') {
      return c.domains.map((d) =>
        checkResult('dns.dkim_provider', d.name, 'skipped', { reason: 'outbound_off' }),
      );
    }
    const out: CheckResult[] = [];
    for (const d of c.domains) {
      const selectors =
        c.provider === 'microsoft_365' ? MICROSOFT_DKIM_SELECTORS : [GOOGLE_DKIM_SELECTOR];
      const found: string[] = [];
      let lookupFailed = false;
      for (const selector of selectors) {
        const name = `${selector}._domainkey.${d.name}`;
        try {
          const [cname, txt] = await Promise.all([
            this.deps.resolver.cname(name),
            this.deps.resolver.txt(name),
          ]);
          if (cname.length > 0 || txt.some((t) => /(^|;)\s*p=/i.test(t))) found.push(selector);
        } catch {
          lookupFailed = true;
        }
      }
      out.push(
        checkResult('dns.dkim_provider', d.name, found.length > 0 ? 'pass' : 'warn', {
          selectors: found,
          ...(found.length === 0
            ? { reason: lookupFailed ? 'lookup_failed' : 'not_published' }
            : {}),
        }),
      );
    }
    return out;
  }

  private async destinations(c: ConnectionView) {
    if (c.domains.length === 0) return [];
    return this.deps.writer.domainMailServer.findMany({
      where: {
        organizationId: c.organizationId,
        domainId: { in: c.domains.map((d) => d.domainId) },
        role: 'inbound_destination',
        enabled: true,
      },
      select: { domainId: true, host: true, port: true, provider: true, priority: true },
      orderBy: [{ priority: 'asc' }, { id: 'asc' }],
    });
  }

  private async inboundDestination(c: ConnectionView): Promise<CheckResult[]> {
    if (c.domains.length === 0) {
      return [checkResult('inbound.destination', '', 'fail', { reason: 'no_linked_domains' })];
    }
    const servers = await this.destinations(c);
    return c.domains.map((d) => {
      const own = servers.filter((s) => s.domainId === d.domainId);
      const matching = own.filter((s) => s.provider === c.provider);
      if (own.length > 0 && matching.length === own.length) {
        return checkResult('inbound.destination', d.name, 'pass', { servers: matching.length });
      }
      return checkResult('inbound.destination', d.name, 'fail', {
        servers: own.length,
        providers: [...new Set(own.map((s) => s.provider))],
        reason: own.length === 0 ? 'no_destinations' : 'other_provider',
      });
    });
  }

  private async destinationMatchesProvider(c: ConnectionView): Promise<CheckResult[]> {
    if (c.provider !== 'microsoft_365') return [];
    const servers = await this.destinations(c);
    return c.domains.map((d) => {
      const hosts = servers
        .filter((s) => s.domainId === d.domainId && s.provider === 'microsoft_365' && s.host)
        .map((s) => s.host!.toLowerCase());
      if (!d.providerMxHost) {
        return checkResult('inbound.destination_matches_provider', d.name, 'skipped', {
          reason: 'provider_mx_unknown',
        });
      }
      if (hosts.length === 0) {
        return checkResult('inbound.destination_matches_provider', d.name, 'skipped', {
          reason: 'no_destinations',
        });
      }
      const matches = hosts.includes(d.providerMxHost.toLowerCase());
      return checkResult(
        'inbound.destination_matches_provider',
        d.name,
        matches ? 'pass' : 'warn',
        {
          providerMxHost: d.providerMxHost,
          hosts,
        },
      );
    });
  }

  private async preset(provider: string): Promise<MailDestinationPresetView | null> {
    const row = await this.deps.writer.mailDestinationPreset.findUnique({
      where: { provider: provider as 'microsoft_365' | 'google_workspace' },
    });
    if (!row || !row.enabled) return null;
    const parsed = mailDestinationPresetSchema.safeParse(row);
    return parsed.success ? parsed.data : null;
  }

  /** SMTP probe per destination host of the provider preset (D10; never DATA). */
  private async inboundSmtp(c: ConnectionView, state: RunState): Promise<CheckResult[]> {
    const servers = (await this.destinations(c)).filter((s) => s.provider === c.provider && s.host);
    if (servers.length === 0) {
      return [checkResult('inbound.smtp', '', 'fail', { reason: 'no_destinations' })];
    }
    const preset = await this.preset(c.provider);
    if (!preset)
      return [checkResult('inbound.smtp', '', 'error', { reason: 'preset_unavailable' })];
    const out: CheckResult[] = [];
    for (const server of servers) {
      const host = server.host!.toLowerCase();
      const domain = c.domains.find((d) => d.domainId === server.domainId);
      if (!domain) continue;
      const key = `${host}:${server.port}:${domain.name}`;
      let result = state.probes.get(key);
      if (!result) {
        result = await this.probeHost(host, server.port, domain.name, preset);
        state.probes.set(key, result);
        this.deps.metrics.smtpProbes.inc({ result: result.status });
      }
      out.push(result);
    }
    return out;
  }

  private async probeHost(
    host: string,
    port: number,
    domain: string,
    preset: MailDestinationPresetView,
  ): Promise<CheckResult> {
    const settings = this.deps.settings;
    // Re-validate the stored host against today's rules and the preset (R3).
    const valid = validateDestinationHost(host, port, {
      ...settings.destinationHosts,
      provider: preset,
    });
    if (!valid.ok) return checkResult('inbound.smtp', host, 'fail', { reason: valid.reason });
    let addresses: string[];
    try {
      addresses = isIP(valid.host) ? [valid.host] : await this.deps.resolver.addresses(valid.host);
    } catch {
      return checkResult('inbound.smtp', host, 'fail', { reason: 'dns_failed' });
    }
    const usable = addresses.filter(
      (a) =>
        !isMetadataAddress(a) && (settings.allowNonPublicProbeAddresses || isPublicIpAddress(a)),
    );
    if (usable.length === 0) {
      return checkResult('inbound.smtp', host, 'fail', {
        reason: addresses.length === 0 ? 'no_address' : 'address_not_allowed',
      });
    }
    const probe = await this.deps.probeSmtp({
      host: valid.host,
      address: usable[0]!,
      port: valid.port,
      helo: settings.probeHelo,
      domain,
      verifyNames: preset.tlsVerifyNames,
      timeoutMs: settings.probeTimeoutMs,
      ...(settings.probeCa ? { ca: settings.probeCa } : {}),
    });
    return checkResult('inbound.smtp', host, probe.status, {
      result: probe.code,
      domain,
      ...probe.evidence,
    });
  }

  /** Last 24 h deliveries to the linked domains (reader): delivered / deferred / TLS errors. */
  private async recentDeliveries(c: ConnectionView): Promise<CheckResult[]> {
    if (c.domains.length === 0) return [];
    const since = new Date(this.deps.now().getTime() - 24 * 3_600_000);
    const keys = c.domains.map((d) => `tenant:${d.domainId.toString()}`);
    const rows = await this.deps.reader().$queryRaw<
      Array<{ destination_key: string; status: string; tls: bigint | number; n: bigint | number }>
    >`SELECT destination_key, status,
             (last_error_class IS NOT NULL AND last_error_class LIKE '%tls%') AS tls,
             COUNT(*) AS n
        FROM email_deliveries
       WHERE organization_id = ${c.organizationId}
         AND received_at >= ${since}
         AND direction IN ('inbound', 'internal')
         AND destination_key IN (${Prisma.join(keys)})
       GROUP BY destination_key, status, tls`;
    return c.domains.map((d) => {
      const own = rows.filter((r) => r.destination_key === `tenant:${d.domainId.toString()}`);
      const count = (pred: (r: (typeof own)[number]) => boolean) =>
        own.filter(pred).reduce((sum, r) => sum + num(r.n), 0);
      const total = count(() => true);
      const delivered = count((r) => r.status === 'delivered');
      const deferred = count((r) => r.status === 'deferred');
      const failed = count((r) => ['bounced', 'failed', 'expired'].includes(r.status));
      const tlsErrors = count((r) => num(r.tls) === 1);
      const problems = deferred + failed;
      const status: CheckStatus =
        total >= DELIVERY_PROBLEM_MIN && problems / total > DELIVERY_PROBLEM_RATIO
          ? 'warn'
          : 'pass';
      return checkResult('inbound.recent_deliveries', d.name, status, {
        total,
        delivered,
        deferred,
        failed,
        tlsErrors,
      });
    });
  }

  /** `outbound.relay_activity` (D11): accepted messages and proof failures of 24 h. */
  private async relayActivity(c: ConnectionView): Promise<CheckResult> {
    if (c.outboundMode !== 'active') {
      return checkResult('outbound.relay_activity', '', 'skipped', {
        outboundMode: c.outboundMode,
      });
    }
    const now = this.deps.now();
    const since = new Date(now.getTime() - 24 * 3_600_000);
    const sums = await this.deps.writer.providerRelayCounter.aggregate({
      where: { connectionId: c.id, organizationId: c.organizationId, hourStart: { gte: since } },
      _sum: { accepted: true, proofFailed: true, tempFailed: true, probes: true },
    });
    const accepted = sums._sum.accepted ?? 0;
    const proofFailed = sums._sum.proofFailed ?? 0;
    const evidence = {
      accepted24h: accepted,
      proofFailed24h: proofFailed,
      tempFailed24h: sums._sum.tempFailed ?? 0,
      lastAcceptedAt: c.lastRelayAcceptedAt?.toISOString() ?? null,
    };
    const total = accepted + proofFailed;
    if (total >= PROOF_FAILURE_MIN && proofFailed / total > PROOF_FAILURE_RATIO) {
      return checkResult('outbound.relay_activity', '', 'fail', {
        ...evidence,
        reason: 'proof_failures',
      });
    }
    const idleMs = this.deps.settings.relayIdleWarnHours * 3_600_000;
    const last = c.lastRelayAcceptedAt?.getTime() ?? null;
    if (
      (last === null && now.getTime() - c.createdAt.getTime() > idleMs) ||
      (last !== null && now.getTime() - last > idleMs)
    ) {
      return checkResult('outbound.relay_activity', '', 'warn', { ...evidence, reason: 'idle' });
    }
    return checkResult('outbound.relay_activity', '', 'pass', evidence);
  }

  /**
   * `routing.loops` / `routing.no_loops` (D9): deliveries to linked domains failed with
   * `loop_detected` in 24 h (reader).
   */
  private async loops(
    c: ConnectionView,
    code: 'routing.loops' | 'routing.no_loops',
  ): Promise<CheckResult> {
    if (c.domains.length === 0)
      return checkResult(code, '', 'skipped', { reason: 'no_linked_domains' });
    const since = new Date(this.deps.now().getTime() - 24 * 3_600_000);
    const keys = c.domains.map((d) => `tenant:${d.domainId.toString()}`);
    const [row] = await this.deps.reader().$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COUNT(*) AS n FROM email_deliveries
       WHERE organization_id = ${c.organizationId}
         AND received_at >= ${since}
         AND failure_reason = 'loop_detected'
         AND destination_key IN (${Prisma.join(keys)})`;
    const loops = num(row?.n);
    return checkResult(code, '', loops > 0 ? 'fail' : 'pass', { loopDeliveries24h: loops });
  }

  private lockdown(c: ConnectionView): CheckResult {
    const required = lockdownAttestations(c.provider);
    const missing = required.filter((code) => !c.attested.includes(code));
    return checkResult('lockdown.attested', '', missing.length === 0 ? 'pass' : 'warn', {
      attested: required.filter((code) => c.attested.includes(code)),
      missing,
      note: 'attestation by the administrator, not verified by the gateway',
    });
  }

  private credentialExpiry(c: ConnectionView): CheckResult[] {
    const now = this.deps.now();
    const grants = c.grants.filter(
      (g) => isCustomerCredentialMethod(g.authMethod) && g.status !== 'revoked',
    );
    if (grants.length === 0) {
      return [
        checkResult('credential.expiry', '', 'skipped', { reason: 'no_customer_credential' }),
      ];
    }
    return grants.map((g) => {
      const result = evaluateCredentialExpiry(g.credentialExpiresAt, now);
      return {
        ...checkResult('credential.expiry', g.profile, result.status, {
          daysLeft: result.daysLeft,
          expiresAt: g.credentialExpiresAt?.toISOString() ?? null,
        }),
        ...(result.status === 'fail' || result.status === 'warn'
          ? { severity: result.severity }
          : {}),
      };
    });
  }

  /**
   * Step 8.5 D11 `ato.identity_provider`: the health the ato-worker's probe stored on the
   * connection's ATO integration (by `connector_ref`), never a provider call or an ATO
   * credential (R2, R3). The previous result's `degradedSince` carries "degraded for > 1 h".
   */
  private async atoIdentityProvider(c: ConnectionView): Promise<CheckResult> {
    const [integrations, previous] = await Promise.all([
      readAtoIntegrationHealth(this.deps.writer, c.organizationId, c.publicId),
      this.deps.writer.providerHealthCheck.findFirst({
        where: {
          connectionId: c.id,
          organizationId: c.organizationId,
          checkCode: 'ato.identity_provider',
          subject: '',
        },
        select: { evidence: true },
      }),
    ]);
    const outcome = evaluateAtoIdentityProvider({
      integrations,
      previousDegradedSince: degradedSinceOf(previous?.evidence),
      now: this.deps.now(),
    });
    return checkResult('ato.identity_provider', '', outcome.status, outcome.evidence);
  }

  private async egressFresh(c: ConnectionView): Promise<CheckResult> {
    const set = await this.deps.writer.providerEgressRangeSet.findFirst({
      where: { provider: c.provider, status: 'active' },
      select: { version: true, publishedAt: true, importedAt: true, rangeCount: true },
      orderBy: { version: 'desc' },
    });
    if (!set || set.rangeCount === 0) {
      return checkResult('egress.ranges_fresh', '', 'fail', { reason: 'no_active_set' });
    }
    const reference = set.publishedAt ?? set.importedAt;
    const ageDays = Math.floor((this.deps.now().getTime() - reference.getTime()) / 86_400_000);
    const evidence = {
      version: set.version,
      publishedAt: reference.toISOString(),
      ageDays,
      ranges: set.rangeCount,
    };
    return checkResult(
      'egress.ranges_fresh',
      '',
      ageDays > this.deps.settings.egressMaxAgeDays ? 'fail' : 'pass',
      evidence,
    );
  }
}

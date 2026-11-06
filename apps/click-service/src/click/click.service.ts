import { performance } from 'node:perf_hooks';
import { uuidv7 } from '@email-gateway/common';
import { EventTypes, urlClickedV1 } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  resolveUrlSettings,
  type UrlEffectiveSettings,
  type UrlPlatformSettings,
} from '@email-gateway/security-contracts';
import {
  continueNonce,
  decideClick,
  verifyContinueNonce,
  verifyToken,
  type TokenClaims,
  type TokenKeys,
  type UrlVerdict,
} from '@email-gateway/url-security';
import {
  blockedPage,
  expiredPage,
  invalidPage,
  notFoundPage,
  rateLimitedPage,
  unavailablePage,
  warnPage,
} from '../http/pages';
import { clientNetwork } from './client-network';
import type { ClickMetrics, ClickRequestDecision } from './click-metrics';
import {
  InconsistentReadError,
  type ClickEventRecord,
  type ClickRepository,
  type UrlKey,
  type UrlRow,
} from './click-repository';
import type { ClickEventWriter } from './event-writer';
import type { RateLimiter } from './rate-limiter';
import { normalizeStored, type Evaluation, type Rechecker } from './recheck';

/** What the controller sends: a page with a status, or a redirect. */
export type ClickResponse =
  | { kind: 'page'; status: number; html: string; decision: ClickRequestDecision }
  | { kind: 'redirect'; location: string; decision: ClickRequestDecision };

export interface ClickRequest {
  token: string;
  /** The client address as Express derived it (CLICK_TRUST_PROXY hops). */
  clientIp: string | undefined;
  /** Continue nonce (`/c/:token/continue?n=`); undefined for the first click. */
  nonce?: string;
}

export interface ClickServiceOptions {
  tokenKeys: TokenKeys;
  platform: UrlPlatformSettings;
  continueTtlSeconds: number;
  storeClientNetwork: boolean;
  now?: () => number;
}

/** Longest token parameter looked at (the valid length is 62). */
const MAX_TOKEN_PARAM = 256;

/**
 * The time-of-click algorithm (step 4.3 U14, ADR-0031). Steps: rate limits → token verification
 * (no database access for an invalid token) → echo-checked lookup of `message_urls` (retry once,
 * then 503) → tenant settings (live) → re-evaluation within the budget (`Rechecker`) → click
 * policy → response, with one click event + outbox row written in the background.
 *
 * Invariants: the organization comes only from a token whose MAC was verified; the redirect
 * target is only the URL stored server side for that token, re-parsed as http(s) (never data
 * from the request: no open redirect); the database being down is a 503 page, never a blind
 * redirect; URLs and tokens are never logged.
 */
export class ClickService {
  private readonly now: () => number;

  constructor(
    private readonly repository: ClickRepository,
    private readonly limiter: RateLimiter,
    private readonly rechecker: Rechecker,
    private readonly writer: ClickEventWriter,
    private readonly metrics: ClickMetrics,
    private readonly logger: Logger,
    private readonly options: ClickServiceOptions,
  ) {
    this.now = options.now ?? Date.now;
  }

  async handle(request: ClickRequest): Promise<ClickResponse> {
    const started = performance.now();
    const response = await this.decide(request, started);
    this.metrics.request(response.decision, (performance.now() - started) / 1000);
    return response;
  }

  private async decide(request: ClickRequest, started: number): Promise<ClickResponse> {
    const token = request.token.slice(0, MAX_TOKEN_PARAM);
    const network = clientNetwork(request.clientIp);

    // 1. Rate limits (fail open on Redis errors, counted).
    const rate = await this.limiter.check(network, token);
    if (rate.limited) return page(429, rateLimitedPage(), 'rate_limited');
    if (rate.failedOpen) this.metrics.rateLimiterError();

    // 2. Token (U12 order). Invalid → 404 without any database access.
    const nowMs = this.now();
    const verification = verifyToken(token, this.options.tokenKeys, Math.floor(nowMs / 1000));
    if (verification.outcome !== 'ok' && verification.outcome !== 'expired') {
      this.metrics.invalidToken(verification.outcome);
      if (!(await this.limiter.recordInvalid(network))) this.metrics.rateLimiterError();
      return page(404, invalidPage(), 'invalid');
    }
    const claims = verification.claims;
    const key: UrlKey = {
      organizationId: claims.organizationId,
      messageId: claims.messageId,
      receivedAt: new Date(claims.receivedAtMs),
      urlSeq: claims.urlSeq,
    };
    const base = { key, claims, network, started };
    if (verification.outcome === 'expired') {
      await this.log(base, 'expired', null);
      return page(410, expiredPage(), 'expired');
    }

    // 3. The stored URL (echo-checked; one retry on a shifted read, then 503).
    const url = await this.readWithRetry('message_urls', () => this.repository.findUrl(key));
    if (url === 'unavailable') return page(503, unavailablePage(), 'unavailable');
    if (url === null) {
      await this.log(base, 'not_found', null);
      return page(404, notFoundPage(), 'not_found');
    }

    // Live tenant settings (U13: a change applies to the next click).
    const override = await this.readWithRetry('scan_engine_settings', () =>
      this.repository.tenantUrlSettings(key.organizationId),
    );
    if (override === 'unavailable') return page(503, unavailablePage(), 'unavailable');
    const settings = this.effectiveSettings(override, key.organizationId);

    // 4. Re-evaluation within the budget; a stored URL that does not re-parse as http(s) is
    // never followed.
    const destination = safeDestination(url);
    const normalized = destination === null ? null : normalizeStored(url.url);
    let evaluation: Evaluation;
    if (destination === null || normalized === null) {
      evaluation = {
        verdict: 'unknown',
        reasonCodes: ['url.fetch_not_performed'],
        recheck: { reputation: 'error', chain: 'skipped', dynamic: 'none' },
      };
    } else {
      evaluation = await this.rechecker.evaluate({ key, url, normalized, settings });
    }

    // 5. Click policy (clean → allow, malicious → block; allowedDomains never overrides M1/M2,
    // which the mapper guarantees).
    let action = decideClick(evaluation.verdict, settings.click);
    if (destination === null) action = 'block';

    // 6. Respond.
    const continuing = request.nonce !== undefined;
    if (action === 'allow') {
      const decision = continuing ? 'continued' : 'allowed';
      await this.log(base, decision, evaluation);
      return { kind: 'redirect', location: destination as string, decision };
    }
    if (action === 'warn') {
      const nowSeconds = Math.floor(nowMs / 1000);
      if (
        continuing &&
        settings.click.allowContinue &&
        verifyContinueNonce(
          token,
          request.nonce ?? '',
          this.options.tokenKeys.current,
          nowSeconds,
          this.options.continueTtlSeconds,
        )
      ) {
        await this.log(base, 'continued', evaluation);
        return { kind: 'redirect', location: destination as string, decision: 'continued' };
      }
      await this.log(base, 'warned', evaluation);
      const nonce = continueNonce(
        token,
        this.options.tokenKeys.current,
        nowSeconds,
        this.options.continueTtlSeconds,
      );
      return page(
        200,
        warnPage({
          domain: url.registrableDomain ?? url.host,
          unicodeDomain: url.unicodeHost ? unicodeRegistrable(url) : null,
          continuePath: settings.click.allowContinue
            ? `/c/${token}/continue?n=${encodeURIComponent(nonce)}`
            : null,
        }),
        'warned',
      );
    }
    const referenceId = await this.log(base, 'blocked', evaluation);
    return page(403, blockedPage(referenceId), 'blocked');
  }

  private effectiveSettings(override: unknown, organizationId: bigint): UrlEffectiveSettings {
    const resolved = resolveUrlSettings(this.options.platform, override);
    if (resolved.ok) return resolved.settings;
    // A stored override that no longer validates (e.g. the platform bounds changed): platform
    // settings apply, and the violation is logged (paths and codes only).
    this.logger.warn(
      {
        organizationId: organizationId.toString(),
        violations: resolved.violations.map((v) => `${v.path}:${v.code}`).slice(0, 10),
      },
      'invalid url settings override; platform settings apply',
    );
    const fallback = resolveUrlSettings(this.options.platform, null);
    if (!fallback.ok) throw new Error('platform url settings do not resolve');
    return fallback.settings;
  }

  private async readWithRetry<T>(read: string, fn: () => Promise<T>): Promise<T | 'unavailable'> {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        return await fn();
      } catch (error) {
        if (error instanceof InconsistentReadError && attempt === 0) {
          this.logger.warn({ read }, 'inconsistent read; retrying once');
          continue;
        }
        this.logger.error(
          {
            read,
            errName: error instanceof Error ? error.name : typeof error,
            errCode: (error as { code?: unknown } | null)?.code,
          },
          'click lookup failed',
        );
        return 'unavailable';
      }
    }
    return 'unavailable';
  }

  /**
   * Writes the click event and its `mail.url.clicked.v1` outbox row (bounded wait). Returns the
   * click's public id (the reference id of the block page).
   */
  private async log(
    base: { key: UrlKey; claims: TokenClaims; network: string; started: number },
    decision: ClickEventRecord['decision'],
    evaluation: Evaluation | null,
  ): Promise<string> {
    const clickedAt = new Date(this.now());
    const publicId = uuidv7(clickedAt.getTime());
    const verdict: UrlVerdict | null = evaluation?.verdict ?? null;
    const reasonCodes = evaluation ? evaluation.reasonCodes.slice(0, 16) : [];
    const payload = urlClickedV1.safeParse({
      clickId: publicId,
      messageId: base.key.messageId.toString(),
      receivedAt: base.key.receivedAt.toISOString(),
      urlSeq: base.key.urlSeq,
      decision,
      verdict,
      reasonCodes,
      clickedAt: clickedAt.toISOString(),
    });
    if (!payload.success) {
      this.metrics.event('error');
      this.logger.error(
        { clickId: publicId, decision, paths: payload.error.issues.map((i) => i.path.join('.')) },
        'click event payload invalid; not written',
      );
      return publicId;
    }
    const event: ClickEventRecord = {
      publicId,
      clickedAt,
      organizationId: base.key.organizationId,
      messageId: base.key.messageId,
      messageReceivedAt: base.key.receivedAt,
      urlSeq: base.key.urlSeq,
      decision,
      verdict,
      reasonCodes: evaluation ? reasonCodes : null,
      recheck: evaluation ? { ...evaluation.recheck } : null,
      tokenKid: base.claims.keyId,
      clientNetwork:
        this.options.storeClientNetwork && base.network !== 'unknown' ? base.network : null,
      durationMs: Math.max(0, Math.round(performance.now() - base.started)),
    };
    this.logger.info(
      {
        clickId: publicId,
        organizationId: base.key.organizationId.toString(),
        messageId: base.key.messageId.toString(),
        urlSeq: base.key.urlSeq,
        decision,
        verdict,
      },
      'click decided',
    );
    await this.writer.submit(event, {
      eventId: uuidv7(clickedAt.getTime()),
      organizationId: base.key.organizationId,
      eventType: EventTypes.UrlClicked,
      aggregateId: base.key.messageId.toString(),
      correlationId: `click-${publicId}`,
      payload: payload.data,
    });
    return publicId;
  }
}

const page = (status: number, html: string, decision: ClickRequestDecision): ClickResponse => ({
  kind: 'page',
  status,
  html,
  decision,
});

/**
 * The redirect target (U14 step 6): the stored URL re-parsed with WHATWG URL, http(s) only, no
 * userinfo, serialized; null for anything else (and for a truncated row, which is never a full
 * URL). Never built from request data.
 */
export function safeDestination(row: Pick<UrlRow, 'url' | 'truncated'>): string | null {
  if (row.truncated) return null;
  let parsed: URL;
  try {
    parsed = new URL(row.url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  if (parsed.username || parsed.password || !parsed.hostname) return null;
  return parsed.href;
}

/** Unicode form of the registrable domain of an IDN host (display only). */
function unicodeRegistrable(
  url: Pick<UrlRow, 'host' | 'unicodeHost' | 'registrableDomain'>,
): string | null {
  if (!url.unicodeHost) return null;
  if (!url.registrableDomain) return url.unicodeHost;
  const asciiLabels = url.host.split('.');
  const unicodeLabels = url.unicodeHost.split('.');
  const keep = url.registrableDomain.split('.').length;
  if (asciiLabels.length !== unicodeLabels.length) return url.unicodeHost;
  return unicodeLabels.slice(-keep).join('.');
}

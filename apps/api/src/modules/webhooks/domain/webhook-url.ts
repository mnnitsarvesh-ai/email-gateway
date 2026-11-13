import { createHash } from 'node:crypto';
import { type BlockedReason, SsrfGuard } from '@email-gateway/url-security';
import { hasControlCharacter } from './control-chars';

/** Longest endpoint URL (the `webhook_subscriptions.url` column, W6). */
export const WEBHOOK_URL_MAX_LENGTH = 2048;

export interface WebhookUrlRules {
  /** `WEBHOOK_ALLOWED_PORTS`. */
  allowedPorts: readonly number[];
  /** `WEBHOOK_ALLOW_HTTP` (TEST-ONLY; refused by the config outside APP_ENV local/ci). */
  allowHttp: boolean;
  /**
   * The platform's own hosts (the click-service host of `URL_CLICK_BASE_URL`, the portal host of
   * `PORTAL_PUBLIC_URL`): refused with their subdomains (`deny_list`).
   */
  denyHosts: readonly string[];
}

export type WebhookUrlDecision =
  | { allowed: true; url: string; host: string; sha256: string }
  | { allowed: false; reason: BlockedReason | 'format' };

/** Lower-case host without trailing dots (or null when the URL does not parse). */
export function hostOf(value: string | undefined | null): string | null {
  if (!value) return null;
  try {
    return new URL(value).hostname.toLowerCase().replace(/\.+$/, '') || null;
  } catch {
    return null;
  }
}

/** Hex SHA-256 of a URL (audit metadata names `urlHost` and `urlSha256`, never the URL). */
export const urlSha256 = (url: string): string =>
  createHash('sha256').update(url, 'utf8').digest('hex');

/**
 * The registration-time rules of a webhook endpoint (step 6.2 W6): an absolute URL of at most
 * 2048 characters without userinfo or fragment, scheme `https` (plain `http` only with the
 * TEST-ONLY `WEBHOOK_ALLOW_HTTP`), a port of `WEBHOOK_ALLOWED_PORTS`, and a host that passes the
 * SSRF guard's name checks (localhost, `.local`/`.internal`/… suffixes, single labels, the
 * platform's own hosts) or, for an IP literal, its address checks (loopback, private, link-local,
 * CGNAT, metadata, documentation, ULA, mapped …). The api's own host (the `Host` the request
 * reached) is refused too. DNS is NOT resolved here: the webhook-worker checks every resolved
 * address at every attempt (authoritative).
 */
export class WebhookUrlPolicy {
  private readonly guard: SsrfGuard;

  constructor(private readonly rules: WebhookUrlRules) {
    // Hosts the guard already refuses by name (`localhost` of a local portal URL) keep their
    // more precise reason; the others become deny-list entries.
    const plain = new SsrfGuard({ allowedPorts: rules.allowedPorts, testAllowCidrs: [] });
    this.guard = new SsrfGuard({
      allowedPorts: rules.allowedPorts,
      denyHosts: rules.denyHosts.filter(
        (h) => h.trim() !== '' && plain.checkHostName(h.trim()).allowed,
      ),
      // No test seams: documentation ranges stay blocked at registration.
      testAllowCidrs: [],
    });
  }

  check(raw: string, requestHost?: string | null): WebhookUrlDecision {
    if (raw.length === 0 || raw.length > WEBHOOK_URL_MAX_LENGTH || raw.trim() !== raw) {
      return { allowed: false, reason: 'format' };
    }
    if (hasControlCharacter(raw) || /\s/.test(raw) || raw.includes('#')) {
      return { allowed: false, reason: 'format' };
    }
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return { allowed: false, reason: 'format' };
    }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && this.rules.allowHttp)) {
      return { allowed: false, reason: 'scheme' };
    }
    if (url.username !== '' || url.password !== '' || url.hash !== '') {
      return { allowed: false, reason: 'format' };
    }
    const host = url.hostname.toLowerCase().replace(/\.+$/, '');
    if (host === '') return { allowed: false, reason: 'format' };
    const decision = this.guard.checkUrl(url);
    if (!decision.allowed) return { allowed: false, reason: decision.reason };
    const own = requestHost?.toLowerCase().replace(/\.+$/, '');
    if (own && (host === own || host.endsWith(`.${own}`))) {
      return { allowed: false, reason: 'deny_list' };
    }
    const normalized = url.href;
    if (normalized.length > WEBHOOK_URL_MAX_LENGTH) return { allowed: false, reason: 'format' };
    return { allowed: true, url: normalized, host, sha256: urlSha256(normalized) };
  }
}

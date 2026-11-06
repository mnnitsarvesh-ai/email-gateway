/**
 * The click-service pages (U14 "Pages"): constant server-side templates. No JavaScript, no
 * tenant name, subject, sender, recipient, scan details or reason codes — only the decision, the
 * destination's domain (warn page) and the reference id (block page). Every dynamic value is
 * HTML-escaped; the only link targets are this service's own continue path and stylesheet.
 */

export const STYLESHEET_PATH = '/static/click.css';

/** The stylesheet served at STYLESHEET_PATH (CSP `style-src 'self'`). */
export const STYLESHEET = `*{box-sizing:border-box}
body{margin:0;background:#f4f5f7;color:#1f2328;font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:560px;margin:12vh auto;padding:32px;background:#fff;border:1px solid #d0d7de;border-radius:8px}
h1{margin:0 0 12px;font-size:1.4rem}
p{margin:0 0 12px}
.domain{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:1.05rem;word-break:break-all;background:#f6f8fa;padding:8px 12px;border-radius:6px}
.ref{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9rem;color:#57606a}
.warn h1{color:#9a6700}.block h1{color:#cf222e}
a.button{display:inline-block;margin-top:8px;padding:8px 16px;border:1px solid #9a6700;border-radius:6px;color:#9a6700;text-decoration:none}
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}main{background:#161b22;border-color:#30363d}.domain{background:#0d1117}.ref{color:#8b949e}}
`;

const ESCAPES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;',
};

export const escapeHtml = (value: string): string =>
  value.replace(/[&<>"'`]/g, (c) => ESCAPES[c] ?? c);

function layout(kind: string, title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)}</title>
<link rel="stylesheet" href="${STYLESHEET_PATH}">
</head>
<body>
<main class="${kind}">
${body}
</main>
</body>
</html>
`;
}

export function invalidPage(): string {
  return layout(
    'invalid',
    'Link not valid',
    `<h1>This link is not valid</h1>
<p>The link you followed is not valid. It may have been copied incompletely.</p>`,
  );
}

export function notFoundPage(): string {
  return layout(
    'invalid',
    'Link not available',
    `<h1>This link is not available</h1>
<p>The destination of this protected link is no longer available.</p>`,
  );
}

export function expiredPage(): string {
  return layout(
    'expired',
    'Link expired',
    `<h1>This link has expired</h1>
<p>Protected links are valid for a limited time. Ask the sender for a new link if you still need it.</p>`,
  );
}

export function rateLimitedPage(): string {
  return layout(
    'limited',
    'Too many requests',
    `<h1>Too many requests</h1>
<p>Please wait a minute and try again.</p>`,
  );
}

export function unavailablePage(): string {
  return layout(
    'unavailable',
    'Temporarily unavailable',
    `<h1>Link check temporarily unavailable</h1>
<p>The link could not be checked right now. Please try again in a few minutes.</p>`,
  );
}

export function errorPage(): string {
  return layout(
    'unavailable',
    'Error',
    `<h1>Something went wrong</h1>
<p>Please try again in a few minutes.</p>`,
  );
}

export function blockedPage(referenceId: string): string {
  return layout(
    'block',
    'Link blocked',
    `<h1>This link has been blocked</h1>
<p>The destination was identified as dangerous and has been blocked by your organization's email security.</p>
<p>If you believe this is a mistake, contact your IT administrator with this reference:</p>
<p class="ref">${escapeHtml(referenceId)}</p>`,
  );
}

export interface WarnPageInput {
  /** Registrable domain (or host) of the destination, ASCII. */
  domain: string;
  /** Unicode form when the domain is an IDN, else null. */
  unicodeDomain: string | null;
  /** `/c/<token>/continue?n=<nonce>`, or null when continuing is not allowed. */
  continuePath: string | null;
}

export function warnPage(input: WarnPageInput): string {
  const unicode =
    input.unicodeDomain && input.unicodeDomain !== input.domain
      ? `\n<p>Displayed as: <span class="domain">${escapeHtml(input.unicodeDomain)}</span></p>`
      : '';
  const action = input.continuePath
    ? `\n<p>Continue only if you trust this destination.</p>
<p><a class="button" href="${escapeHtml(input.continuePath)}" rel="noreferrer noopener">Continue to the site</a></p>`
    : `\n<p>Your organization does not allow continuing to this destination.</p>`;
  return layout(
    'warn',
    'Caution',
    `<h1>Be careful with this link</h1>
<p>This link leads to a site that could not be confirmed as safe:</p>
<p class="domain">${escapeHtml(input.domain)}</p>${unicode}${action}`,
  );
}

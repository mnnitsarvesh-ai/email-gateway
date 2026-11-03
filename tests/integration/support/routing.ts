import { buildMessage } from './messages';
import type { DestinationServerFixture, FixtureDomain, SmtpFixtures } from './smtp-fixtures';
import { reply, swaks, type SwaksResult } from './smtp-tools';

/**
 * Shared pieces of the step 2.3 routing stack suites (docs/plan/steps/05-routing.md §9).
 *
 * Test-network names (dns-sink, docs/deployment/mail-routing.md "Test profile"):
 * - `mx.sink.test` (mail-sink, .25): a customer's own server; also the MX of every other
 *   `*.sink.test` domain ("the Internet");
 * - `<key>.mail.protection.outlook.com` (sink-m365, .26) with a test-CA certificate for
 *   `mail.protection.outlook.com` / `*.mail.protection.outlook.com`;
 * - `aspmx.l.google.com`, `alt2`–`alt4` (sink-google, .27) and `alt1` (sink-google-alt, .28)
 *   with `mx.google.com` / `aspmx.l.google.com` / `*.aspmx.l.google.com`;
 * - `relay.sink.test` (relay-sink, .29): relays everything back to the gateway MX;
 * - `*.gwtenant.sink.test`: MX `gw-mx.sink.test` = the gateway's inbound MX (postfix, .10).
 */
export const MAIL_SINK_HOST = 'mx.sink.test';
export const RELAY_SINK_HOST = 'relay.sink.test';

/** The Microsoft 365 preset's servers for one domain key (R2: the customer supplies the host). */
export function m365Servers(key: string): DestinationServerFixture[] {
  return [
    {
      host: `${key}.mail.protection.outlook.com`,
      tlsMode: 'verify',
      provider: 'microsoft_365',
      tlsVerifyNames: 'nexthop:mail.protection.outlook.com:.mail.protection.outlook.com',
      priority: 0,
    },
  ];
}

/** The Google Workspace preset's servers (R2 `default_servers`), in priority order. */
export function googleServers(): DestinationServerFixture[] {
  const names = 'nexthop:mx.google.com:.aspmx.l.google.com';
  return [
    ['aspmx.l.google.com', 1],
    ['alt1.aspmx.l.google.com', 5],
    ['alt2.aspmx.l.google.com', 5],
    ['alt3.aspmx.l.google.com', 10],
    ['alt4.aspmx.l.google.com', 10],
  ].map(([host, priority]) => ({
    host: host as string,
    priority: priority as number,
    tlsMode: 'verify' as const,
    provider: 'google_workspace' as const,
    tlsVerifyNames: names,
  }));
}

export interface SentMessage extends SwaksResult {
  messageId: string;
  text: string;
}

/** One message to the gateway's inbound MX (postfix:25) from smtp-tools. */
export async function sendInbound(options: {
  from: string;
  to: readonly string[];
  subject: string;
  headers?: readonly string[];
  /** Header lines placed BEFORE the generated ones (e.g. earlier `Received:` hops). */
  leadingHeaders?: readonly string[];
}): Promise<SentMessage> {
  const built = buildMessage({
    from: options.from === '' ? 'MAILER-DAEMON@example.org' : options.from,
    to: options.to,
    subject: options.subject,
    headers: options.headers,
  });
  const text = options.leadingHeaders?.length
    ? `${options.leadingHeaders.join('\r\n')}\r\n${built.text}`
    : built.text;
  const result = await swaks({
    server: 'postfix',
    port: 25,
    from: options.from,
    to: options.to,
    data: text,
  });
  if (reply(result, 'DATA-END').code !== 250) {
    throw new Error(`inbound MX did not accept the message:\n${result.transcript}`);
  }
  return { ...result, messageId: built.messageId, text };
}

/** One authenticated submission (postfix-outbound:587, STARTTLS + SASL). */
export async function submit(options: {
  credentials: { username: string; password: string };
  from: string;
  to: readonly string[];
  subject: string;
  headerFrom?: string;
}): Promise<SentMessage> {
  const built = buildMessage({
    from: options.headerFrom ?? options.from,
    to: options.to,
    subject: options.subject,
  });
  const result = await swaks({
    server: 'postfix-outbound',
    port: 587,
    tls: true,
    auth: options.credentials,
    from: options.from,
    to: options.to,
    data: built.text,
  });
  if (reply(result, 'DATA-END').code !== 250) {
    throw new Error(`submission was not accepted:\n${result.transcript}`);
  }
  return { ...result, messageId: built.messageId, text: built.text };
}

/** An outbound-capable sending domain: active, outbound enabled, DKIM key (published later). */
export async function sendingDomain(
  fx: SmtpFixtures,
  organizationId: bigint,
  label: string,
): Promise<FixtureDomain> {
  const domain = await fx.domain(organizationId, label, { outboundEnabled: true });
  // SMTP_OUTBOUND_REQUIRE_DKIM=true: every sending domain needs an active key (step 2.2 D12).
  await fx.dkimKey(domain);
  return domain;
}

/** LF line endings (Maildir files are stored with LF; the S3 EML keeps the wire CRLF). */
export const lf = (bytes: Buffer | string) =>
  (typeof bytes === 'string' ? bytes : bytes.toString('utf8')).replace(/\r\n/g, '\n');

/** Header block (unfolded lines kept as-is) of a message: everything before the first blank line. */
export function headerBlock(message: string): string {
  const text = lf(message);
  const end = text.indexOf('\n\n');
  return end === -1 ? text : text.slice(0, end + 1);
}

/** Header fields (folded continuation lines joined to their field) of a header block. */
export function headerFields(block: string): string[] {
  const fields: string[] = [];
  for (const line of lf(block).split('\n')) {
    if (line === '') continue;
    if (/^[ \t]/.test(line) && fields.length > 0) fields[fields.length - 1] += `\n${line}`;
    else fields.push(line);
  }
  return fields;
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Organization slug of a fixture organization (for api logins). */
export async function organizationRef(fx: SmtpFixtures, id: bigint) {
  return fx.prisma.organization.findUniqueOrThrow({
    where: { id },
    select: { id: true, slug: true, name: true, publicId: true },
  });
}

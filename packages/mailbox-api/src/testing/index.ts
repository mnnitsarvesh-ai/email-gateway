/**
 * Test-only entry `@email-gateway/mailbox-api/testing` (design D9 "Testing", D13): the mailbox
 * clients wired to the in-process provider simulators of `@email-gateway/idp-adapters/testing`
 * (Graph, Gmail, Google Directory on 127.0.0.1), simulator token sources for the two
 * `mailbox_remediation` grants, a recording budget and the in-memory throttle gate. Never imported
 * by production code; never contacts a real provider.
 */
import {
  ProviderHttpClient,
  type IdpMetricsSink,
  type RateBudget,
  type TokenSource,
} from '@email-gateway/idp-adapters';
import {
  CapturingLogger,
  GS_ADMIN_EMAIL,
  GS_CUSTOMER_ID,
  MS_TENANT_ID,
  TestClock,
  googleCustomer,
  immediateSleep,
  microsoftDirectory,
  startSimulators,
  type RunningSimulators,
  type SimDataset,
  type SimTokenRegistry,
} from '@email-gateway/idp-adapters/testing';
import {
  GOOGLE_MAILBOX_REMEDIATION_PROFILE,
  M365_MAILBOX_REMEDIATION_PROFILE,
} from '@email-gateway/provider-integrations';
import { InMemoryThrottleGate, type MailboxApiFamily } from '../budget';
import type { MailboxClientContext } from '../clients/context';
import { GmailClient } from '../clients/gmail-client';
import { GoogleDirectoryClient } from '../clients/google-directory-client';
import { GraphMailClient } from '../clients/graph-mail-client';

export const TEST_API_CONNECTION_ID = '0190dddd-0000-7000-8000-000000000001';

/** A token source minting simulator tokens (`EXAMPLE-sim-token-<n>`); `invalidate` drops it. */
export class SimTokenSource implements TokenSource {
  private current: string | null = null;
  issued = 0;
  invalidations = 0;

  constructor(
    private readonly tokens: SimTokenRegistry,
    private readonly info: {
      directoryId: string;
      resource: 'graph' | 'google';
      profile: string;
      subject?: string;
      now: () => number;
    },
  ) {}

  get(): Promise<string> {
    if (this.current === null) {
      this.issued += 1;
      this.current = this.tokens.issue({
        directoryId: this.info.directoryId,
        resource: this.info.resource,
        profile: this.info.profile,
        ...(this.info.subject !== undefined ? { subject: this.info.subject } : {}),
        expiresAt: this.info.now() + 3_600_000,
      });
    }
    return Promise.resolve(this.current);
  }

  invalidate(): void {
    this.invalidations += 1;
    this.current = null;
  }

  /** The token this source would send next (tests make it invalid at the simulator). */
  peek(): string | null {
    return this.current;
  }
}

/** A budget that records every take and can be exhausted per family. */
export class RecordingRateBudget implements RateBudget {
  readonly takes: { integrationId: string; family: string }[] = [];
  readonly exhausted = new Set<string>();

  take(integrationId: string, family: string): Promise<'ok' | 'exhausted'> {
    this.takes.push({ integrationId, family });
    return Promise.resolve(this.exhausted.has(family) ? 'exhausted' : 'ok');
  }
}

export interface MailboxTestbedOptions {
  now?: Date;
  dataset?: (now: Date) => SimDataset;
  apiConnectionPublicId?: string;
  metrics?: IdpMetricsSink;
  /** Grant permissions (default: the profiles' permissions). */
  microsoftPermissions?: readonly string[];
  googleScopes?: readonly string[];
  maxResponseBytes?: number;
}

export interface MailboxTestbed {
  clock: TestClock;
  sims: RunningSimulators;
  logger: CapturingLogger;
  http: ProviderHttpClient;
  budget: RecordingRateBudget;
  throttle: InMemoryThrottleGate;
  context: MailboxClientContext;
  graphToken: SimTokenSource;
  gmailTokens: Map<string, SimTokenSource>;
  directoryToken: SimTokenSource;
  graph: GraphMailClient;
  gmail: GmailClient;
  directory: GoogleDirectoryClient;
  /** Calls of one family at the simulators (for "no fetch" assertions). */
  stop(): Promise<void>;
}

const SIMULATOR_OF: Readonly<Record<MailboxApiFamily, string>> = {
  graph: 'graph',
  gmail: 'gmail',
  google_directory: 'google-admin',
};
export { SIMULATOR_OF as MAILBOX_SIMULATOR_OF_FAMILY };

/** Starts the simulators and wires the three clients for one API connection. */
export async function createMailboxTestbed(
  options: MailboxTestbedOptions = {},
): Promise<MailboxTestbed> {
  const clock = new TestClock(options.now ?? new Date('2026-11-10T12:00:00.000Z'));
  const dataset =
    options.dataset?.(clock.now()) ??
    ({
      microsoft: { directories: [microsoftDirectory(clock.now())] },
      google: { customers: [googleCustomer(clock.now())] },
    } satisfies SimDataset);
  const sims = await startSimulators({ dataset, now: clock.ms });
  const tokens = sims.tokens;
  tokens.setGrant(
    MS_TENANT_ID,
    M365_MAILBOX_REMEDIATION_PROFILE.key,
    options.microsoftPermissions ?? M365_MAILBOX_REMEDIATION_PROFILE.permissions,
  );
  tokens.setGrant(
    GS_CUSTOMER_ID,
    GOOGLE_MAILBOX_REMEDIATION_PROFILE.key,
    options.googleScopes ?? GOOGLE_MAILBOX_REMEDIATION_PROFILE.permissions,
  );
  const logger = new CapturingLogger();
  const http = new ProviderHttpClient({
    baseUrls: {
      graph: sims.baseUrl('graph'),
      o365: sims.baseUrl('o365'),
      google_admin: sims.baseUrl('google-admin'),
      gmail: sims.baseUrl('gmail'),
    },
    allowHttpEndpoints: true,
    timeoutMs: 5_000,
    maxResponseBytes: options.maxResponseBytes ?? 4 * 1024 * 1024,
    maxBackoffMs: 900_000,
    provider: 'mailbox_api',
    logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
    random: () => 0.5,
    now: clock.ms,
    env: {},
  });
  const budget = new RecordingRateBudget();
  const throttle = new InMemoryThrottleGate(clock.ms);
  const context: MailboxClientContext = {
    http,
    apiConnectionPublicId: options.apiConnectionPublicId ?? TEST_API_CONNECTION_ID,
    budget,
    throttle,
    sleep: immediateSleep,
    ...(options.metrics ? { metrics: options.metrics } : {}),
  };
  const graphToken = new SimTokenSource(tokens, {
    directoryId: MS_TENANT_ID,
    resource: 'graph',
    profile: M365_MAILBOX_REMEDIATION_PROFILE.key,
    now: clock.ms,
  });
  const gmailTokens = new Map<string, SimTokenSource>();
  const gmailToken = (mailbox: string): SimTokenSource => {
    let source = gmailTokens.get(mailbox);
    if (!source) {
      source = new SimTokenSource(tokens, {
        directoryId: GS_CUSTOMER_ID,
        resource: 'google',
        profile: GOOGLE_MAILBOX_REMEDIATION_PROFILE.key,
        subject: mailbox,
        now: clock.ms,
      });
      gmailTokens.set(mailbox, source);
    }
    return source;
  };
  const directoryToken = new SimTokenSource(tokens, {
    directoryId: GS_CUSTOMER_ID,
    resource: 'google',
    profile: GOOGLE_MAILBOX_REMEDIATION_PROFILE.key,
    subject: GS_ADMIN_EMAIL,
    now: clock.ms,
  });
  return {
    clock,
    sims,
    logger,
    http,
    budget,
    throttle,
    context,
    graphToken,
    gmailTokens,
    directoryToken,
    graph: new GraphMailClient(context, graphToken),
    gmail: new GmailClient(context, gmailToken),
    directory: new GoogleDirectoryClient(context, directoryToken),
    stop: () => sims.stop(),
  };
}

/** Collects a streamed body. */
export async function collectStream(body: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of body) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

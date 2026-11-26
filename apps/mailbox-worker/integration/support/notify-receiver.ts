import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { PrismaClient } from '@email-gateway/database';
import { clientStateMatches, graphNotificationSchema } from '@email-gateway/mailbox-api';

/**
 * TEST-ONLY stand-in for the api's public Graph callback (D12.4, built by WP5): answers the
 * validation handshake (`validationToken` echoed as `text/plain`) and, for change and lifecycle
 * notifications, only requests a sync of the mailbox whose stored subscription id and client-state
 * hash match — exactly what the api route does, so the feed path can be driven end to end by the
 * in-process Graph simulator's pushes.
 */
export class NotifyReceiver {
  private server: Server | null = null;
  readonly received: { subscriptionId: string; matched: boolean; lifecycleEvent?: string }[] = [];
  url = '';

  constructor(
    private readonly prisma: PrismaClient,
    private readonly now: () => Date,
  ) {}

  async start(): Promise<void> {
    this.server = createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      const token = url.searchParams.get('validationToken');
      if (token !== null) {
        res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        res.end(token);
        return;
      }
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        void this.handle(
          Buffer.concat(chunks).toString('utf8'),
          url.pathname.endsWith('/lifecycle'),
        )
          .catch(() => undefined)
          .finally(() => {
            res.writeHead(202);
            res.end();
          });
      });
    });
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    const { port } = this.server.address() as AddressInfo;
    this.url = `http://127.0.0.1:${port}/api/v1/provider-notifications/graph`;
  }

  private async handle(body: string, lifecycle: boolean): Promise<void> {
    const parsed = graphNotificationSchema.safeParse(JSON.parse(body));
    if (!parsed.success) return;
    for (const item of parsed.data.value) {
      const mailbox = await this.prisma.apiMailbox.findUnique({
        where: { subscriptionId: item.subscriptionId },
        select: { id: true, clientStateHash: true },
      });
      const matched =
        mailbox !== null && clientStateMatches(item.clientState, mailbox.clientStateHash);
      this.received.push({
        subscriptionId: item.subscriptionId,
        matched,
        ...(item.lifecycleEvent ? { lifecycleEvent: item.lifecycleEvent } : {}),
      });
      if (!matched || !mailbox) continue;
      const now = this.now();
      await this.prisma.$executeRaw`
        UPDATE api_mailboxes
        SET sync_requested_at = COALESCE(sync_requested_at, ${now}),
            subscription_id = IF(${lifecycle && item.lifecycleEvent === 'subscriptionRemoved'}, NULL, subscription_id),
            subscription_expires_at = IF(${lifecycle && item.lifecycleEvent === 'reauthorizationRequired'}, ${now}, subscription_expires_at)
        WHERE id = ${mailbox.id}`;
    }
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) =>
      this.server ? this.server.close(() => resolve()) : resolve(),
    );
  }
}

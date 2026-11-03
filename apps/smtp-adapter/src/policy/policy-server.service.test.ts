import { createConnection } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { silentLogger } from '../../integration/in-session-support/fakes';
import { parseNetworkList } from '../shared/internal-networks';
import type { PolicyDecisionService } from './policy-decision.service';
import { PolicyServerService } from './policy-server.service';

async function query(port: number, payload: string, expectedResponses: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ port, host: '127.0.0.1' });
    let data = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      data += chunk;
      if (data.split('\n\n').length - 1 >= expectedResponses) {
        socket.end();
        resolve(data);
      }
    });
    socket.on('close', () => resolve(data));
    // A refused peer sees a reset: resolve with what arrived (nothing).
    socket.on('error', (err: NodeJS.ErrnoException) =>
      err.code === 'ECONNRESET' ? resolve(data) : reject(err),
    );
    socket.write(payload);
  });
}

const rcpt = 'request=smtpd_access_policy\nprotocol_state=RCPT\nrecipient=a@example.test\n\n';

const decisions = (decide: PolicyDecisionService['decide']) =>
  ({ decide }) as unknown as PolicyDecisionService;

describe('PolicyServerService', () => {
  let server: PolicyServerService | undefined;

  afterEach(async () => {
    await server?.onModuleDestroy();
    server = undefined;
  });

  async function start(service: PolicyDecisionService, networks = '127.0.0.0/8'): Promise<number> {
    server = new PolicyServerService(
      { host: '127.0.0.1', port: 0, internalNetworks: parseNetworkList(networks) },
      service,
      silentLogger(),
    );
    await server.onModuleInit();
    return server.address();
  }

  it('answers each pipelined request in order, even when later ones finish first', async () => {
    let call = 0;
    const port = await start(
      decisions(async () => {
        call += 1;
        const mine = call;
        await new Promise((r) => setTimeout(r, mine === 1 ? 30 : 0));
        return mine === 1 ? 'DUNNO' : 'REJECT 5.7.1 Relay access denied';
      }),
    );
    // REJECT is encoded as Postfix's numeric 550 action on the wire.
    expect(await query(port, rcpt + rcpt, 2)).toBe(
      'action=DUNNO\n\naction=550 5.7.1 Relay access denied\n\n',
    );
    await expect(server?.checkHealth()).resolves.toBeUndefined();
  });

  it('tempfails (never accepts) when the decision throws', async () => {
    const port = await start(decisions(() => Promise.reject(new Error('db down'))));
    expect(await query(port, rcpt, 1)).toMatch(/^action=DEFER_IF_PERMIT 4\.3\.5/);
  });

  it('answers malformed input with a tempfail and closes the connection', async () => {
    const port = await start(decisions(() => Promise.resolve('DUNNO')));
    expect(await query(port, 'no-equals-sign\n\n', 5)).toBe(
      'action=DEFER_IF_PERMIT 4.3.5 Policy service temporarily unavailable\n\n',
    );
  });

  it('closes oversized requests (16 KiB cap) with a tempfail', async () => {
    const port = await start(decisions(() => Promise.resolve('DUNNO')));
    const huge = `request=smtpd_access_policy\nx=${'a'.repeat(17 * 1024)}\n\n`;
    expect(await query(port, huge, 5)).toMatch(/^action=DEFER_IF_PERMIT 4\.3\.5/);
  });

  it('refuses peers outside SMTP_INTERNAL_CLIENT_NETWORKS without answering', async () => {
    const port = await start(
      decisions(() => Promise.resolve('DUNNO')),
      '10.0.0.0/8',
    );
    expect(await query(port, rcpt, 1)).toBe('');
  });

  it('reports unhealthy after shutdown and closes idle client connections', async () => {
    const port = await start(decisions(() => Promise.resolve('DUNNO')));
    const socket = createConnection({ port, host: '127.0.0.1' });
    socket.on('error', () => undefined);
    await new Promise((r) => socket.once('connect', r));
    const closed = new Promise((r) => socket.once('close', r));
    await server?.onModuleDestroy();
    await closed;
    await expect(server?.checkHealth()).rejects.toThrow('not accepting');
    server = undefined;
  });
});

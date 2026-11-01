import { createConnection } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { PolicyDecisionService } from './policy-decision.service';
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
    socket.on('error', reject);
    socket.write(payload);
  });
}

const rcpt = 'request=smtpd_access_policy\nprotocol_state=RCPT\nrecipient=a@example.test\n\n';

describe('PolicyServerService', () => {
  let server: PolicyServerService | undefined;

  afterEach(async () => {
    await server?.onModuleDestroy();
  });

  async function start(decisions: PolicyDecisionService): Promise<number> {
    server = new PolicyServerService({ host: '127.0.0.1', port: 0, logLevel: 'silent' }, decisions);
    await server.onModuleInit();
    return server.address();
  }

  it('answers each pipelined request in order', async () => {
    const port = await start(new PolicyDecisionService());
    expect(await query(port, rcpt + rcpt, 2)).toBe('action=DUNNO\n\naction=DUNNO\n\n');
    await expect(server?.checkHealth()).resolves.toBeUndefined();
  });

  it('tempfails (never accepts) when the decision throws', async () => {
    const failing = {
      decide: () => Promise.reject(new Error('db down')),
    } as unknown as PolicyDecisionService;
    const port = await start(failing);
    expect(await query(port, rcpt, 1)).toMatch(/^action=DEFER_IF_PERMIT 4\.3\.5/);
  });
});

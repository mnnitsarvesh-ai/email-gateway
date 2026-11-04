import { afterEach, describe, expect, it, vi } from 'vitest';
import { MetricsService } from '../metrics/metrics.service';
import { AmqpConnection, type AmqpConnectionOptions, BrokerUnavailableError } from './connection';
import { createMessagingMetrics } from './metrics';
import { FakeBroker, memoryLogger, waitFor } from './testing/fake-amqp';

const URLS = ['amqp://u:secret-password@node1:5672/vh', 'amqp://u:secret-password@node2:5672/vh'];

function setup(overrides: Partial<AmqpConnectionOptions> = {}) {
  const broker = new FakeBroker();
  const { logger, raw } = memoryLogger();
  const sleeps: number[] = [];
  const connection = new AmqpConnection({
    urls: URLS,
    connectionName: 'test-conn',
    logger,
    connect: broker.connect,
    random: () => 0,
    reconnect: { baseMs: 100, maxMs: 1_000 },
    sleep: (ms) => {
      sleeps.push(ms);
      return Promise.resolve(true);
    },
    ...overrides,
  });
  return { broker, connection, sleeps, raw };
}

const opened: AmqpConnection[] = [];
afterEach(async () => {
  await Promise.all(opened.splice(0).map((c) => c.close()));
});

describe('AmqpConnection', () => {
  it('validates its options', () => {
    const { logger } = memoryLogger();
    expect(() => new AmqpConnection({ urls: [], connectionName: 'a', logger })).toThrow();
    expect(() => new AmqpConnection({ urls: ['http://x'], connectionName: 'a', logger })).toThrow();
    expect(() => new AmqpConnection({ urls: URLS, connectionName: 'has space', logger })).toThrow();
  });

  it('connects in the background with a heartbeat and the connection name', async () => {
    const { broker, connection } = setup();
    opened.push(connection);
    expect(connection.connected).toBe(false);
    connection.start();
    await connection.waitUntilConnected(1_000);
    expect(connection.connected).toBe(true);
    expect(broker.attempts[0]).toContain('heartbeat=30');
    expect(broker.attempts[0]).toMatch(/^amqp:\/\/u:secret-password@node1:5672\/vh/);
  });

  it('rotates through the URLs with equal-jitter backoff while connecting fails', async () => {
    const { broker, connection, sleeps, raw } = setup();
    opened.push(connection);
    broker.failures = 3;
    connection.start();
    await connection.waitUntilConnected(1_000);
    expect(broker.attempts.map((u) => new URL(u).hostname)).toEqual([
      'node1',
      'node2',
      'node1',
      'node2',
    ]);
    // random = 0 → half of min(max, base * 2^(n-1)).
    expect(sleeps).toEqual([50, 100, 200]);
    expect(raw()).not.toContain('secret-password');
    expect(raw()).toContain('ECONNREFUSED');
  });

  it('re-runs every onConnected setup in order after a loss, and never exits the process', async () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => undefined as never);
    const service = new MetricsService({ service: 'test' });
    const { broker, connection } = setup({ metrics: createMessagingMetrics(service) });
    opened.push(connection);
    const calls: string[] = [];
    connection.onConnected(() => {
      calls.push('a');
      return Promise.resolve();
    });
    connection.onConnected(() => {
      calls.push('b');
      return Promise.reject(new Error('setup failure is logged, not fatal'));
    });
    const unregister = connection.onConnected(() => {
      calls.push('c');
      return Promise.resolve();
    });
    connection.start();
    await waitFor(() => calls.length === 3, 1_000, 'first setups');
    expect(calls).toEqual(['a', 'b', 'c']);

    unregister();
    broker.current?.drop();
    expect(connection.connected).toBe(false);
    await waitFor(() => calls.length === 5, 1_000, 'setups after reconnect');
    expect(calls).toEqual(['a', 'b', 'c', 'a', 'b']);
    expect(connection.connected).toBe(true);
    expect(broker.models).toHaveLength(2);
    expect(exit).not.toHaveBeenCalled();
    const text = await service.metrics();
    expect(text).toContain('amqp_reconnects_total{connection="test-conn",service="test"} 1');
    expect(text).toContain('amqp_connection_up{connection="test-conn",service="test"} 1');
    exit.mockRestore();
  });

  it('runs a setup registered while connected at once', async () => {
    const { connection } = setup();
    opened.push(connection);
    connection.start();
    await connection.waitUntilConnected(1_000);
    let ran = false;
    connection.onConnected(() => {
      ran = true;
      return Promise.resolve();
    });
    await waitFor(() => ran);
  });

  it('createChannel fails with BrokerUnavailableError while disconnected', async () => {
    const { connection } = setup();
    opened.push(connection);
    await expect(connection.createConfirmChannel()).rejects.toBeInstanceOf(BrokerUnavailableError);
    await expect(connection.waitUntilConnected(5)).rejects.toBeInstanceOf(BrokerUnavailableError);
  });

  it('checkHealth: connected, not blocked, required topology verified passively', async () => {
    const { broker, connection } = setup();
    opened.push(connection);
    await expect(connection.checkHealth()).rejects.toThrow(/disconnected/);
    connection.requireTopology({ exchanges: ['email.events'], queues: ['email.received'] });
    broker.missing.add('email.received');
    connection.start();
    await connection.waitUntilConnected(1_000);
    await expect(connection.checkHealth()).rejects.toThrow(/queue email.received \(NOT_FOUND\)/);
    broker.missing.delete('email.received');
    await expect(connection.checkHealth()).resolves.toBeUndefined();

    const model = broker.current;
    model?.emit('blocked', 'memory');
    expect(connection.blocked).toBe(true);
    await expect(connection.checkHealth()).rejects.toThrow(/blocked/);
    const waiting = connection.waitUntilUnblocked(1_000);
    model?.emit('unblocked');
    await expect(waiting).resolves.toBe(true);
    await expect(connection.checkHealth()).resolves.toBeUndefined();
    // New requirements are verified again.
    connection.requireTopology({ exchanges: ['email.delivery'] });
    broker.missing.add('email.delivery');
    await expect(connection.checkHealth()).rejects.toThrow(/exchange email.delivery/);
  });

  it('waitUntilUnblocked times out while blocked', async () => {
    const { broker, connection } = setup();
    opened.push(connection);
    connection.start();
    await connection.waitUntilConnected(1_000);
    broker.current?.emit('blocked', 'disk');
    await expect(connection.waitUntilUnblocked(5)).resolves.toBe(false);
  });

  it('close() stops reconnecting and closes the model', async () => {
    const { broker, connection } = setup();
    connection.start();
    await connection.waitUntilConnected(1_000);
    const model = broker.current;
    await connection.close();
    expect(model?.closed).toBe(true);
    expect(connection.connected).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(broker.models).toHaveLength(1);
    await expect(connection.waitUntilConnected(5)).rejects.toBeInstanceOf(BrokerUnavailableError);
  });
});

import { randomUUID } from 'node:crypto';
import { connect } from 'amqplib';
import { Redis } from 'ioredis';
import { describe, expect, it } from 'vitest';
import { stack } from './support/env';

describe('RabbitMQ', () => {
  it('confirms a publish and delivers it to a quorum queue', async () => {
    const connection = await connect(stack.rabbitmqUrl());
    const channel = await connection.createConfirmChannel();
    const queue = `it.${randomUUID()}`;
    try {
      await channel.assertQueue(queue, { durable: true, arguments: { 'x-queue-type': 'quorum' } });
      const body = JSON.stringify({ eventId: randomUUID() });
      channel.sendToQueue(queue, Buffer.from(body), { persistent: true });
      await channel.waitForConfirms();

      const message = await new Promise<string>((resolve) => {
        void channel.consume(queue, (msg) => {
          if (!msg) return;
          channel.ack(msg);
          resolve(msg.content.toString());
        });
      });
      expect(message).toBe(body);
    } finally {
      await channel.deleteQueue(queue);
      await connection.close();
    }
  });

  it('rejects connections with wrong credentials', async () => {
    const url = new URL(stack.rabbitmqUrl());
    url.password = 'wrong-password';
    await expect(connect(url.toString())).rejects.toThrow();
  });
});

describe('Redis', () => {
  it('requires authentication', async () => {
    const url = new URL(stack.redisUrl());
    url.password = '';
    const anonymous = new Redis(url.toString(), { lazyConnect: true, maxRetriesPerRequest: 0 });
    anonymous.on('error', () => undefined);
    try {
      await expect(anonymous.set('it:anon', '1')).rejects.toThrow(/NOAUTH/);
    } finally {
      anonymous.disconnect();
    }
  });

  it('stores keys with a TTL', async () => {
    const redis = new Redis(stack.redisUrl());
    const key = `it:${randomUUID()}`;
    try {
      await redis.set(key, 'value', 'EX', 30);
      expect(await redis.get(key)).toBe('value');
      expect(await redis.ttl(key)).toBeGreaterThan(0);
    } finally {
      await redis.del(key);
      redis.disconnect();
    }
  });
});

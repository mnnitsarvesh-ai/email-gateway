import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { ConfigValidationError, loadConfig } from './load-config';
import { amqpUrlListSchema } from './schemas';

const schema = z.object({ RABBITMQ_RELAY_URL: amqpUrlListSchema });
const SECRET = 's3cr3t-Pa55word';

function issues(value: string): string[] {
  try {
    loadConfig(schema, { RABBITMQ_RELAY_URL: value });
  } catch (error) {
    if (error instanceof ConfigValidationError) return error.issues;
    throw error;
  }
  throw new Error('expected a validation error');
}

describe('amqpUrlListSchema', () => {
  it('accepts one URL as a one-element list', () => {
    expect(amqpUrlListSchema.parse('amqp://u:p@rabbitmq:5672/email-gateway')).toEqual([
      'amqp://u:p@rabbitmq:5672/email-gateway',
    ]);
  });

  it('splits, trims and keeps the order of cluster node URLs, amqp and amqps', () => {
    expect(
      amqpUrlListSchema.parse(
        ' amqp://u:p@127.0.0.1:5701/email-gateway , amqps://u:p@rmq2:5671/email-gateway,amqp://rmq3',
      ),
    ).toEqual([
      'amqp://u:p@127.0.0.1:5701/email-gateway',
      'amqps://u:p@rmq2:5671/email-gateway',
      'amqp://rmq3',
    ]);
  });

  it('refuses an empty list, empty entries, other schemes and malformed URLs', () => {
    expect(amqpUrlListSchema.safeParse('').success).toBe(false);
    expect(amqpUrlListSchema.safeParse('  ').success).toBe(false);
    expect(amqpUrlListSchema.safeParse('amqp://a,,amqp://b').success).toBe(false);
    expect(amqpUrlListSchema.safeParse('amqp://a,').success).toBe(false);
    expect(amqpUrlListSchema.safeParse('http://rabbitmq:15672').success).toBe(false);
    expect(amqpUrlListSchema.safeParse('rabbitmq:5672').success).toBe(false);
    expect(amqpUrlListSchema.safeParse('not a url').success).toBe(false);
    expect(amqpUrlListSchema.safeParse('amqp://').success).toBe(false);
  });

  it('names the failing entry by position and never echoes a value', () => {
    for (const value of [
      `amqp://user:${SECRET}@rabbitmq:5672/vhost,http://user:${SECRET}@x`,
      `amqp://user:${SECRET}@rabbitmq:5672/vhost,,`,
      `${SECRET}`,
      `amqp://user:${SECRET}@rabbitmq:5672, ://${SECRET}`,
    ]) {
      const messages = issues(value);
      expect(messages.length).toBeGreaterThan(0);
      for (const message of messages) {
        expect(message).toMatch(/^RABBITMQ_RELAY_URL: /);
        expect(message).not.toContain(SECRET);
        expect(message).not.toContain('user');
        expect(message).not.toContain('rabbitmq');
      }
    }
    expect(issues(`amqp://u:${SECRET}@a,http://b`)).toEqual([
      'RABBITMQ_RELAY_URL: entry 2 must be an amqp(s):// URL',
    ]);
  });

  it('composes into a service schema through loadConfig', () => {
    const cfg = loadConfig(schema, { RABBITMQ_RELAY_URL: 'amqp://a:b@n1/v,amqp://a:b@n2/v' });
    expect(cfg.RABBITMQ_RELAY_URL).toEqual(['amqp://a:b@n1/v', 'amqp://a:b@n2/v']);
  });
});

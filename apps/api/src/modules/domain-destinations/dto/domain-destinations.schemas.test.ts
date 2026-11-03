import { describe, expect, it } from 'vitest';
import { PutDestinationsSchema } from './domain-destinations.schemas';

const issues = (body: unknown): string[] => {
  const result = PutDestinationsSchema.safeParse(body);
  return result.success
    ? []
    : result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`);
};

describe('PutDestinationsSchema (step 2.3 R13)', () => {
  it('accepts the three providers', () => {
    expect(issues({ provider: 'microsoft_365', host: 'x.mail.protection.outlook.com' })).toEqual(
      [],
    );
    expect(issues({ provider: 'google_workspace' })).toEqual([]);
    expect(
      issues({
        provider: 'custom',
        servers: [
          {
            host: 'mx.example',
            port: 2525,
            priority: 0,
            tlsMode: 'verify',
            tlsVerifyNames: 'nexthop',
          },
        ],
      }),
    ).toEqual([]);
  });

  it.each([
    [{ provider: 'other' }, 'provider'],
    [{ provider: 'microsoft_365' }, 'host'],
    [{ provider: 'microsoft_365', host: 'x', port: 25 }, ''],
    [{ provider: 'google_workspace', servers: [] }, ''],
    [{ provider: 'custom', servers: [] }, 'servers'],
    [
      {
        provider: 'custom',
        servers: Array.from({ length: 11 }, (_, i) => ({ host: `m${i}.example` })),
      },
      'servers',
    ],
    [{ provider: 'custom', servers: [{ host: '' }] }, 'servers.0.host'],
    [{ provider: 'custom', servers: [{ host: 'a.example', port: 0 }] }, 'servers.0.port'],
    [{ provider: 'custom', servers: [{ host: 'a.example', port: 65536 }] }, 'servers.0.port'],
    [{ provider: 'custom', servers: [{ host: 'a.example', priority: -1 }] }, 'servers.0.priority'],
    [
      { provider: 'custom', servers: [{ host: 'a.example', tlsMode: 'strict' }] },
      'servers.0.tlsMode',
    ],
    [
      {
        provider: 'custom',
        servers: [{ host: 'a.example', tlsMode: 'verify', tlsVerifyNames: 'a b' }],
      },
      'servers.0.tlsVerifyNames',
    ],
    [
      {
        provider: 'custom',
        servers: [{ host: 'a.example', tlsMode: 'verify', tlsVerifyNames: 'x=y' }],
      },
      'servers.0.tlsVerifyNames',
    ],
    [
      { provider: 'custom', servers: [{ host: 'a.example', tlsVerifyNames: 'nexthop' }] },
      'servers.0.tlsVerifyNames',
    ],
    [{ provider: 'custom', servers: [{ host: 'a.example', organizationId: '9' }] }, 'servers.0'],
  ])('refuses %j at %s', (body, path) => {
    const found = issues(body);
    expect(found.length).toBeGreaterThan(0);
    expect(
      found.some((issue) => issue.startsWith(`${path}:`) || (path === '' && issue.startsWith(':'))),
    ).toBe(true);
  });
});

import { describe, expect, it } from 'vitest';
import { hostOf, urlSha256, WebhookUrlPolicy } from './webhook-url';

const policy = (patch: Partial<ConstructorParameters<typeof WebhookUrlPolicy>[0]> = {}) =>
  new WebhookUrlPolicy({
    allowedPorts: [443],
    allowHttp: false,
    denyHosts: ['click.gateway.example', 'localhost'],
    ...patch,
  });

describe('WebhookUrlPolicy (step 6.2 W6)', () => {
  it('accepts absolute https URLs and normalizes them; host and SHA-256 for the audit', () => {
    const decision = policy().check('https://Hooks.Example.com/in?x=1');
    expect(decision).toEqual({
      allowed: true,
      url: 'https://hooks.example.com/in?x=1',
      host: 'hooks.example.com',
      sha256: urlSha256('https://hooks.example.com/in?x=1'),
    });
    expect(policy().check('https://hooks.example.com:443/in')).toMatchObject({ allowed: true });
    expect(
      policy({ allowedPorts: [443, 8443] }).check('https://h.example.com:8443/'),
    ).toMatchObject({ allowed: true });
  });

  it.each([
    ['http://hooks.example.com/', 'scheme'],
    ['ftp://hooks.example.com/', 'scheme'],
    ['javascript:alert(1)', 'scheme'],
    ['https://hooks.example.com:8443/', 'port'],
    ['https://user@hooks.example.com/', 'format'],
    ['https://u:p@hooks.example.com/', 'format'],
    ['https://hooks.example.com/#x', 'format'],
    [' https://hooks.example.com/', 'format'],
    ['https://hooks.example.com/a b', 'format'],
    ['', 'format'],
    ['relative/path', 'format'],
    [`https://hooks.example.com/${'a'.repeat(2048)}`, 'format'],
    ['https://localhost/', 'name'],
    ['https://single/', 'name'],
    ['https://nas.local/', 'name'],
    ['https://svc.internal/', 'name'],
    ['https://127.0.0.1/', 'loopback'],
    ['https://10.0.0.8/', 'private'],
    ['https://172.16.0.1/', 'private'],
    ['https://192.168.0.1/', 'private'],
    ['https://100.64.0.1/', 'cgnat'],
    ['https://169.254.169.254/', 'metadata'],
    ['https://169.254.1.1/', 'link_local'],
    ['https://0.0.0.0/', 'unspecified'],
    ['https://203.0.113.20/', 'documentation'],
    ['https://[::1]/', 'loopback'],
    ['https://[fd00::1]/', 'ula'],
    ['https://[::ffff:10.0.0.1]/', 'private'],
    ['https://click.gateway.example/x', 'deny_list'],
    ['https://a.click.gateway.example/x', 'deny_list'],
  ])('refuses %s (%s)', (url, reason) => {
    expect(policy().check(url)).toEqual({ allowed: false, reason });
  });

  it('allows http only with the test seam', () => {
    expect(
      policy({ allowHttp: true, allowedPorts: [80, 443] }).check('http://h.example.com/'),
    ).toMatchObject({
      allowed: true,
    });
  });

  it('refuses the host the request reached and its subdomains', () => {
    expect(policy().check('https://api.gw.example/x', 'API.gw.example')).toEqual({
      allowed: false,
      reason: 'deny_list',
    });
    expect(policy().check('https://a.api.gw.example/x', 'api.gw.example')).toMatchObject({
      allowed: false,
    });
    expect(policy().check('https://other.example/x', 'api.gw.example')).toMatchObject({
      allowed: true,
    });
  });

  it('hostOf reads a host or null', () => {
    expect(hostOf('https://Click.Example.com:3080/x')).toBe('click.example.com');
    expect(hostOf('nope')).toBeNull();
    expect(hostOf(undefined)).toBeNull();
  });
});

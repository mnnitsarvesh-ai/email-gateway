import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Deployment check (step 4.6 X5, threat model "no route to tenant data"): the sandbox-controller
 * parses attacker-controlled files and holds SANDBOX_SAMPLE_KEY, so its NetworkPolicy must be
 * fail-closed — egress only to private CIDRs (broker subnet, S3 interface VPC endpoint subnet)
 * and cluster DNS, never a world or other public range, never a rule without destinations. The
 * base and every overlay file that touches the controller's NetworkPolicy are checked, so a
 * production overlay that re-opens the Internet fails `pnpm test`.
 */
const ROOT = resolve(__dirname, '../../../..');
const KUBE = join(ROOT, 'infrastructure/kubernetes');

function yamlFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return yamlFiles(path);
    return /\.ya?ml$/.test(name) ? [path] : [];
  });
}

/** YAML documents (`---`-separated) of the controller's NetworkPolicy, or patches of it. */
function controllerPolicies(): { file: string; doc: string }[] {
  return yamlFiles(KUBE).flatMap((file) =>
    readFileSync(file, 'utf8')
      .split(/^---\s*$/m)
      .filter(
        (doc) =>
          /^kind:\s*NetworkPolicy\s*$/m.test(doc) &&
          /^\s*name:\s*sandbox-controller\s*$/m.test(doc),
      )
      .map((doc) => ({ file: relative(ROOT, file), doc })),
  );
}

const ipv4 = (cidr: string): { base: number; bits: number } | null => {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr);
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  const bits = Number(match[5]);
  if (octets.some((o) => o > 255) || bits > 32) return null;
  return { base: octets.reduce((a, o) => a * 256 + o, 0), bits };
};

const PRIVATE_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].map((c) => ipv4(c)!);

/**
 * Whether `cidr` lies inside an RFC 1918 range (IPv4) or the IPv6 ULA range fc00::/7 — except
 * fd00:ec2::/32, the AWS instance-metadata range.
 */
function isPrivateCidr(cidr: string): boolean {
  const v4 = ipv4(cidr);
  if (v4) {
    return PRIVATE_V4.some((range) => {
      if (v4.bits < range.bits) return false;
      const size = 2 ** (32 - range.bits);
      return Math.floor(v4.base / size) === Math.floor(range.base / size);
    });
  }
  const v6 = /^([0-9a-f]{1,4}):[0-9a-f:]*\/(\d{1,3})$/i.exec(cidr);
  if (!v6) return false;
  if (
    /^fd00:0*ec2:/i.test(cidr) ||
    /^fd00::?\//i.test(cidr) ||
    cidr.toLowerCase().startsWith('fd00::')
  ) {
    return false;
  }
  return Number(v6[2]) >= 7 && (parseInt(v6[1]!, 16) & 0xfe00) === 0xfc00;
}

describe('sandbox-controller NetworkPolicy (fail-closed egress)', () => {
  const policies = controllerPolicies();

  it('exists in the base', () => {
    expect(policies.map((p) => p.file)).toContain(
      'infrastructure/kubernetes/base/sandbox-controller.yaml',
    );
  });

  it('allows egress only to private CIDRs: no 0.0.0.0/0, ::/0 or other public range anywhere', () => {
    for (const { file, doc } of policies) {
      const cidrs = [...doc.matchAll(/cidr:\s*([^\s,}]+)/g)].map((m) => m[1]!);
      expect(cidrs.length, file).toBeGreaterThan(0);
      for (const cidr of cidrs) {
        expect(isPrivateCidr(cidr), `${file}: ${cidr} is not a private CIDR`).toBe(true);
      }
      // `except` only makes sense under a broad (public) block: none is allowed.
      expect(doc, file).not.toMatch(/^\s*except:/m);
    }
  });

  it('every egress rule names its destinations (a rule without `to` allows every address)', () => {
    for (const { file, doc } of policies) {
      const egress = doc.split(/^\s{2}egress:\s*$/m)[1];
      if (egress === undefined) continue;
      const rules = egress.split('\n').filter((line) => /^\s{4}-\s/.test(line));
      expect(rules.length, file).toBeGreaterThan(0);
      for (const rule of rules) expect(rule, file).toMatch(/^\s{4}-\s+to:/);
    }
  });

  it('HTTPS (443) goes to a private endpoint subnet only', () => {
    const base = policies.find((p) => p.file.endsWith('base/sandbox-controller.yaml'))!;
    const https = base.doc.split(/^\s{4}-\s+/m).filter((rule) => /port:\s*443\b/.test(rule));
    expect(https).toHaveLength(1);
    expect(https[0]).toMatch(/ipBlock:\s*\{\s*cidr:\s*10\.\d+\.\d+\.\d+\/\d+\s*\}/);
  });

  it('the CIDR check refuses world and public ranges', () => {
    for (const bad of [
      '0.0.0.0/0',
      '::/0',
      '8.8.8.0/24',
      '10.0.0.0/7',
      '172.32.0.0/16',
      '169.254.169.254/32',
      '2001:db8::/32',
      'fd00:ec2::/32',
      'fd00::/8',
    ]) {
      expect(isPrivateCidr(bad), bad).toBe(false);
    }
    for (const ok of ['10.0.80.0/24', '172.16.5.0/24', '192.168.1.0/24', 'fd12:3456::/48']) {
      expect(isPrivateCidr(ok), ok).toBe(true);
    }
  });
});

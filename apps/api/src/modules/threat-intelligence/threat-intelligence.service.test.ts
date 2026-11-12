import { BadRequestException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../audit/audit.service';
import type { ApiKeyPrincipal } from '../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../auth-contracts/tenant-scope';
import type { ThreatIntelligenceRepository } from './threat-intelligence.repository';
import { ThreatIntelligenceService } from './threat-intelligence.service';

const principal: ApiKeyPrincipal = {
  kind: 'api_key',
  apiKeyId: 3n,
  apiKeyPublicId: 'key-public-id',
  organizationId: 21n,
  organizationPublicId: 'org-21',
  permissions: new Set(['threat_intel:read']),
};
const scope = scopeFromPrincipal(principal);
const seen = {
  firstSeenAt: new Date('2026-11-01T00:00:00Z'),
  lastSeenAt: new Date('2026-11-02T00:00:00Z'),
};

function setup(indicators: unknown[] = [], signature: unknown = null) {
  const repo = {
    indicators: vi.fn(() => Promise.resolve(indicators)),
    signature: vi.fn(() => Promise.resolve(signature)),
  };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: () => ({ type: 'api_key', id: principal.apiKeyPublicId }),
  };
  const service = new ThreatIntelligenceService(
    repo as unknown as ThreatIntelligenceRepository,
    audit as unknown as AuditService,
  );
  return { service, repo, audit };
}

describe('ThreatIntelligenceService', () => {
  it('matches sha256 against indicators and the hash catalogue, most severe first, and audits the hash only', async () => {
    const hex = 'cd'.repeat(32);
    const { service, repo, audit } = setup(
      [{ valueSha256: 'x', severity: 'medium', category: 'malware', expiresAt: null, ...seen }],
      { severity: 'critical', expiresAt: null, ...seen },
    );
    const res = await service.lookup(
      principal,
      scope,
      { type: 'sha256', value: hex },
      { ip: '203.0.113.9', userAgent: null },
    );
    expect(res.known).toBe(true);
    expect(res.matches.map((m) => [m.source, m.severity])).toEqual([
      ['hash_catalog', 'critical'],
      ['platform_indicator', 'medium'],
    ]);
    expect(repo.indicators).toHaveBeenCalledWith(
      'file_sha256',
      [res.valueSha256],
      expect.any(Date),
    );
    expect(repo.signature).toHaveBeenCalledWith(hex, expect.any(Date));
    const entry = (audit.record.mock.calls[0] as unknown[])[0] as Record<string, unknown>;
    expect(entry).toMatchObject({
      organizationId: 21n,
      action: 'threat_intel.looked_up',
      sourceIp: '203.0.113.9',
      metadata: { type: 'sha256', valueSha256: res.valueSha256, known: true, matchCount: 2 },
    });
    expect(JSON.stringify(entry.metadata)).not.toContain(hex);
  });

  it('answers known=false without matches and never queries the catalogue for non-hash types', async () => {
    const { service, repo } = setup();
    const res = await service.lookup(
      principal,
      scope,
      { type: 'domain', value: 'Evil.Example.com' },
      { ip: null, userAgent: null },
    );
    expect(res).toMatchObject({ type: 'domain', known: false, matches: [] });
    expect(repo.signature).not.toHaveBeenCalled();
    expect((repo.indicators.mock.calls[0] as unknown[])[0]).toBe('domain');
  });

  it('refuses an invalid value with 400 before any read or audit', async () => {
    const { service, repo, audit } = setup();
    await expect(
      service.lookup(
        principal,
        scope,
        { type: 'ip', value: 'not-an-ip' },
        { ip: null, userAgent: null },
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(repo.indicators).not.toHaveBeenCalled();
    expect(audit.record).not.toHaveBeenCalled();
  });
});

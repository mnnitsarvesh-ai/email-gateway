import { MetricsService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { UrlMetrics } from './url-metrics';

describe('url engine metrics (step 4.3 U18)', () => {
  it('registers the U18 series once per registry with zero series for the alert rules', async () => {
    const registry = new MetricsService({ service: 'url-metrics-test' });
    expect(UrlMetrics.for(registry)).toBe(UrlMetrics.for(registry));
    const text = await registry.metrics();
    for (const name of [
      'scan_url_urls_total',
      'scan_url_extracted_total',
      'scan_url_findings_total',
      'url_reputation_lookups_total',
      'url_reputation_duration_seconds',
      'url_provider_breaker_state',
      'url_fetch_total',
      'url_fetch_duration_seconds',
      'url_fetch_blocked_total',
      'url_cache_total',
      'scan_url_rewrites_total',
      'scan_url_rewritten_links_total',
      'scan_url_dynamic_inspections_total',
      'scan_url_inconsistent_reads_total',
    ]) {
      expect(text).toContain(`# TYPE ${name} `);
    }
    expect(text).toMatch(/scan_url_rewrites_total\{result="error"[^}]*\} 0/);
    expect(text).toMatch(/url_cache_total\{cache="chain",result="rejected"[^}]*\} 0/);
    expect(text).toMatch(/scan_url_dynamic_inspections_total\{status="expired"[^}]*\} 0/);
  });

  it('keeps labels bounded: unknown codes, sources and reasons become other; unknown providers are dropped', async () => {
    const registry = new MetricsService({ service: 'url-metrics-test' });
    const m = UrlMetrics.for(registry);
    m.url('suspicious', ['url.lookalike_homoglyph', 'http://evil.example/']);
    m.url('not-a-verdict', []);
    m.extractedFrom('html_href', 2);
    m.extractedFrom('evil.example', 1);
    m.lookup('dnsbl', 'listed', 0.01);
    m.lookup('evil.example', 'error', 0.01);
    m.breaker('dnsbl', 'open');
    m.breaker('evil.example', 'open');
    m.fetch('engine', 'blocked', 0.002);
    m.blocked('engine', 'loopback');
    m.blocked('engine', 'evil' as never);
    m.rewrite('signed_smime');
    m.rewrite('http://evil.example/');
    m.links('html', 3);
    m.links('text', 0);
    m.dynamic('dropped');
    m.inconsistent('feed');
    const text = await registry.metrics();
    expect(text).toMatch(/scan_url_findings_total\{code="url.lookalike_homoglyph"[^}]*\} 1/);
    expect(text).toMatch(/scan_url_findings_total\{code="other"[^}]*\} 1/);
    expect(text).toMatch(/scan_url_extracted_total\{source="other"[^}]*\} 1/);
    expect(text).toMatch(/url_provider_breaker_state\{provider="dnsbl"[^}]*\} 2/);
    expect(text).toMatch(/url_fetch_blocked_total\{reason="other",component="engine"[^}]*\} 1/);
    expect(text).toMatch(/scan_url_rewrites_total\{result="error"[^}]*\} 1/);
    expect(text).toMatch(/scan_url_rewritten_links_total\{part="html"[^}]*\} 3/);
    expect(text).not.toContain('evil.example');
    expect(text).not.toContain('not-a-verdict');
  });
});

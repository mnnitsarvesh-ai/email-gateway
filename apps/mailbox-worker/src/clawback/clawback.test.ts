import { describe, expect, it } from 'vitest';
import { CLAWBACK_HARD_BLOCKS } from '@email-gateway/mailbox-api';
import { clawbackEntryExplanation, clawbackEntryReason } from '../remediation/quarantine-entries';
import { automaticCriteria, automaticWindow } from './clawback-rows';
import { isAutomatic, storedFacts, type ClawbackRow } from './clawback-runner';
import { lateSignalFacts, verdictRank } from './late-signal.handler';
import { indicatorKeys } from './ti-sweep';

const NOW = new Date('2026-11-27T12:00:00.000Z');
const DAY = 86_400_000;
const H = 'a'.repeat(64);

describe('automatic clawback documents (C2.1, C2.2, C4.1)', () => {
  it('the window spans [anchor − lookback, now] and never precedes the copies retention', () => {
    expect(automaticWindow(new Date(NOW.getTime() - DAY), 14, NOW)).toEqual({
      from: new Date(NOW.getTime() - 15 * DAY).toISOString(),
      to: NOW.toISOString(),
    });
    const old = automaticWindow(new Date(NOW.getTime() - 400 * DAY), 14, NOW);
    expect(Date.parse(old.from)).toBeGreaterThan(NOW.getTime() - 186 * DAY);
    expect(old.to).toBe(NOW.toISOString());
  });

  it('criteria drop empty keys, validate strictly and are null without any key', () => {
    const window = automaticWindow(NOW, 14, NOW);
    expect(
      automaticCriteria({
        window,
        keys: { messageIdHashes: [H], urlSha256: [], attachmentSha256: [] },
      }),
    ).toMatchObject({
      v: 1,
      keys: { messageIdHashes: [H] },
      directions: ['inbound', 'internal'],
      includeReportMailboxes: false,
    });
    expect(automaticCriteria({ window, keys: { urlSha256: [] } })).toBeNull();
    expect(automaticCriteria({ window, keys: { attachmentSha256: ['not-hex'] } })).toBeNull();
  });
});

describe('late signal facts (C3.1) and verdict order (C3.3)', () => {
  const base = {
    messageId: '10',
    receivedAt: NOW.toISOString(),
    scanId: '5',
    attachmentSha256: [],
    signalAt: NOW.toISOString(),
  };

  it('sandbox revision: the revision verdict, level and hard blocks', () => {
    expect(
      lateSignalFacts({
        ...base,
        kind: 'sandbox_revision',
        revision: 1,
        verdict: 'malware',
        level: 'critical',
        hardBlocks: ['hb.malware_sandbox'],
        urlSha256: [],
      }),
    ).toEqual({ verdict: 'malware', level: 'critical', hardBlocks: ['hb.malware_sandbox'] });
  });

  it('URL dynamic: phishing/critical with the URL hard block, else suspicious/high', () => {
    const url = { ...base, kind: 'url_dynamic' as const, revision: null, urlSha256: [H] };
    expect(
      lateSignalFacts({ ...url, verdict: 'phishing', level: 'critical', hardBlocks: [] }),
    ).toEqual({ verdict: 'phishing', level: 'critical', hardBlocks: [CLAWBACK_HARD_BLOCKS.url] });
    expect(
      lateSignalFacts({
        ...url,
        verdict: 'phishing',
        level: 'critical',
        hardBlocks: [CLAWBACK_HARD_BLOCKS.url],
      }),
    ).toEqual({ verdict: 'phishing', level: 'critical', hardBlocks: [CLAWBACK_HARD_BLOCKS.url] });
    // A `suspicious` inspection with `url.dynamic_phishing`: phishing/high, no hard block (C3.1).
    expect(lateSignalFacts({ ...url, verdict: 'phishing', level: 'high', hardBlocks: [] })).toEqual(
      { verdict: 'suspicious', level: 'high', hardBlocks: [] },
    );
    expect(
      lateSignalFacts({ ...url, verdict: 'suspicious', level: 'high', hardBlocks: [] }),
    ).toEqual({
      verdict: 'suspicious',
      level: 'high',
      hardBlocks: [],
    });
  });

  it('ranks verdicts so a late signal only raises a stored verdict', () => {
    expect(verdictRank('malware')).toBeGreaterThan(verdictRank('phishing'));
    expect(verdictRank('phishing')).toBeGreaterThan(verdictRank('suspicious'));
    expect(verdictRank('suspicious')).toBeGreaterThan(verdictRank('spam'));
    expect(verdictRank('clean')).toBe(verdictRank('unknown'));
    expect(verdictRank(null)).toBeLessThan(verdictRank('clean'));
  });
});

describe('threat-intelligence keys (C2.2)', () => {
  it('maps indicator types to criteria keys; ip and malformed values have none', () => {
    expect(indicatorKeys('url', 'https://x.example/', H)).toEqual({ urlSha256: [H] });
    expect(indicatorKeys('domain', 'Phish.Example', H)).toEqual({
      urlDomains: ['phish.example'],
      senderDomains: ['phish.example'],
    });
    expect(indicatorKeys('file_sha256', H.toUpperCase(), 'b'.repeat(64))).toEqual({
      attachmentSha256: [H],
    });
    expect(indicatorKeys('email', 'Bad@Evil.Example', H)).toEqual({
      senders: ['bad@evil.example'],
    });
    expect(indicatorKeys('ip', '192.0.2.1', H)).toBeNull();
    expect(indicatorKeys('domain', 'localhost', H)).toBeNull();
    expect(indicatorKeys('email', 'no-at-sign', H)).toBeNull();
    expect(indicatorKeys('url', 'https://x.example/', 'short')).toBeNull();
  });
});

describe('clawback rows', () => {
  const row = (over: Partial<ClawbackRow>): ClawbackRow =>
    ({
      signalVerdict: 'phishing',
      signalLevel: 'critical',
      signalHardBlocks: ['hb.clawback.analyst'],
      ...over,
    }) as ClawbackRow;

  it('automatic triggers are late verdicts and threat intelligence', () => {
    expect(isAutomatic('late_verdict')).toBe(true);
    expect(isAutomatic('threat_intel')).toBe(true);
    expect(isAutomatic('admin')).toBe(false);
    expect(isAutomatic('report')).toBe(false);
    expect(isAutomatic('campaign')).toBe(false);
  });

  it('reads the stored policy facts, or none', () => {
    expect(storedFacts(row({}))).toEqual({
      verdict: 'phishing',
      level: 'critical',
      hardBlocks: ['hb.clawback.analyst'],
    });
    expect(storedFacts(row({ signalVerdict: null }))).toBeNull();
    expect(storedFacts(row({ signalHardBlocks: null }))).toMatchObject({ hardBlocks: [] });
    expect(storedFacts(row({ signalHardBlocks: ['NOT VALID'] }))).toBeNull();
  });
});

describe('mailbox entries of clawback actions (C5.5)', () => {
  const clawback = { publicId: '0193b000-0000-7000-8000-000000000001', trigger: 'admin' };

  it('reason: the signal verdict; an explicit purge of a non-threat copy → manual', () => {
    expect(clawbackEntryReason({ ...clawback, signalVerdict: 'malware' }, 'clean')).toBe('malware');
    expect(clawbackEntryReason({ ...clawback, signalVerdict: null }, 'clean')).toBe('manual');
    expect(clawbackEntryReason({ ...clawback, signalVerdict: null }, null)).toBe('manual');
    expect(clawbackEntryReason({ ...clawback, signalVerdict: null }, 'phishing')).toBe('phishing');
    expect(clawbackEntryReason({ ...clawback, signalVerdict: null }, 'dlp_violation')).toBe('dlp');
  });

  it('explanation names the clawback public id and trigger only', () => {
    expect(clawbackEntryExplanation({ ...clawback, signalVerdict: null })).toBe(
      'Removed from the mailbox by clawback 0193b000-0000-7000-8000-000000000001 (admin)',
    );
  });
});

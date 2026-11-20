import { describe, expect, it } from 'vitest';
import {
  FINANCE_KEYWORDS,
  MAILBOX_RULE_TRAITS,
  SECURITY_KEYWORDS,
  classifyRule,
  forwardingTraits,
  type RuleDefinition,
} from './traits';

const internal = { directoryDomains: ['contoso-it.example'] };

function rule(patch: Partial<RuleDefinition> = {}): RuleDefinition {
  return {
    forwardTo: [],
    redirectTo: [],
    forwardAsAttachmentTo: [],
    deletes: false,
    moveToFolder: null,
    marksRead: false,
    stopsProcessing: false,
    conditionWords: ['quarterly report'],
    hasNoConditions: false,
    ...patch,
  };
}

describe('classifyRule (D8.3)', () => {
  it('produces every trait', () => {
    const all = classifyRule(
      rule({
        forwardTo: ['collector@evil-mail.example'],
        redirectTo: ['someone@contoso-it.example'],
        forwardAsAttachmentTo: ['other@evil-mail.example'],
        deletes: true,
        moveToFolder: 'RSS Feeds',
        marksRead: true,
        stopsProcessing: true,
        conditionWords: ['Invoice due', 'password reset'],
        hasNoConditions: true,
      }),
      internal,
    );
    expect(all.traits).toEqual([...MAILBOX_RULE_TRAITS]);
    expect(all.targetDomain).toBe('evil-mail.example');
  });

  it('separates internal from external forwarding by directory domain', () => {
    const inside = classifyRule(rule({ forwardTo: ['Boss@Contoso-IT.example'] }), internal);
    expect(inside.traits).toEqual(['forwards']);
    expect(inside.targetDomain).toBe('contoso-it.example');
    const outside = forwardingTraits('smtp:collector@evil-mail.example', internal);
    expect(outside.traits).toEqual(['forwards', 'forwards_external', 'matches_all_messages']);
    expect(outside.targetDomain).toBe('evil-mail.example');
  });

  it('flags only rarely used folders and archive-like label removals', () => {
    expect(classifyRule(rule({ moveToFolder: 'Projects' }), internal).traits).toEqual([
      'moves_to_folder',
    ]);
    expect(classifyRule(rule({ moveToFolder: ' deleted items ' }), internal).traits).toEqual([
      'moves_to_folder',
      'moves_to_rarely_used_folder',
    ]);
    expect(classifyRule(rule({ skipsInbox: true }), internal).traits).toEqual([
      'moves_to_folder',
      'moves_to_rarely_used_folder',
    ]);
  });

  it('classifies finance and security keywords, short stems on word boundaries', () => {
    expect(classifyRule(rule({ conditionWords: ['Wire transfer'] }), internal).traits).toEqual([
      'matches_finance_keywords',
    ]);
    expect(classifyRule(rule({ conditionWords: ['MFA code'] }), internal).traits).toEqual([
      'matches_security_keywords',
    ]);
    // 'ach' must not match inside 'reach'; 'mfa' must not match inside 'comfab'
    expect(
      classifyRule(rule({ conditionWords: ['reach out', 'comfabric'] }), internal).traits,
    ).toEqual([]);
    expect(
      classifyRule(rule({ conditionWords: [], hasNoConditions: true }), internal).traits,
    ).toEqual(['matches_all_messages']);
  });

  it('never returns a keyword, folder name or address', () => {
    const words = ['Invoice 4711 secret-project', 'helpdesk password'];
    const result = classifyRule(
      rule({
        forwardTo: ['collector@evil-mail.example'],
        moveToFolder: 'Hidden stash',
        conditionWords: words,
      }),
      internal,
    );
    const dump = JSON.stringify(result);
    for (const value of [
      ...words,
      'collector',
      'Hidden stash',
      ...FINANCE_KEYWORDS,
      ...SECURITY_KEYWORDS,
    ]) {
      expect(dump.toLowerCase().includes(`"${value.toLowerCase()}"`)).toBe(false);
    }
    expect(dump).not.toContain('collector@');
    expect(
      result.traits.every((trait) => (MAILBOX_RULE_TRAITS as readonly string[]).includes(trait)),
    ).toBe(true);
  });

  it('includes the design keyword list', () => {
    for (const keyword of ['invoice', 'payment', 'wire', 'bank', 'payroll', 'remittance', 'iban']) {
      expect(FINANCE_KEYWORDS).toContain(keyword);
    }
    for (const keyword of [
      'password',
      'security',
      'phish',
      'hacked',
      'mfa',
      'verification',
      'helpdesk',
      'it support',
    ]) {
      expect(SECURITY_KEYWORDS).toContain(keyword);
    }
  });
});

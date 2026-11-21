import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { sanitizeText } from '../results/sanitize';

/**
 * The versioned system prompt `assistant-system/2` (design 28 D7, D10; step AI-2 D9: writes are
 * proposals confirmed in a card). `prompts/assistant-system-1.md` stays in the package because
 * stored turns reference their `prompt_version`. Layout, stable first for
 * prompt caching: the prompt text, then the catalogue index (stable per permission set and
 * registry version), then the volatile context block (organization, user, roles, current time,
 * time zone, registry version).
 */

export const PROMPT_VERSION = 'assistant-system/2';
export const PROMPT_FILE = 'assistant-system-2.md';
const PACKAGE_DIR = join(__dirname, '..', '..');

export interface PromptTemplate {
  version: string;
  text: string;
  sha256: string;
}

let cached: PromptTemplate | null = null;

export function loadSystemPromptTemplate(): PromptTemplate {
  if (cached) return cached;
  const text = readFileSync(join(PACKAGE_DIR, 'prompts', PROMPT_FILE), 'utf8').trim();
  cached = {
    version: PROMPT_VERSION,
    text,
    sha256: createHash('sha256').update(text).digest('hex'),
  };
  return cached;
}

export interface SystemPromptContext {
  organization: { name: string; publicId: string };
  user: { displayName: string };
  /** Role keys of the user. */
  roles: readonly string[];
  now: Date;
  /** The browser's IANA time zone from the turn body (validated by the api), or null. */
  timeZone: string | null;
  registryVersion: string;
  /** `renderCatalogueIndex(enabledTools(...))`. */
  catalogueIndex: string;
}

export interface SystemPrompt {
  version: string;
  text: string;
  /** SHA-256 of the template text (recorded per turn with the version). */
  templateSha256: string;
}

const line = (value: string, max = 120): string => sanitizeText(value.replace(/\s+/g, ' '), max);

/** Minute precision keeps the volatile block stable within a minute. */
function isoMinute(now: Date): string {
  return `${now.toISOString().slice(0, 16)}Z`;
}

export function buildSystemPrompt(context: SystemPromptContext): SystemPrompt {
  const template = loadSystemPromptTemplate();
  const catalogue = context.catalogueIndex.trim();
  const roles = context.roles.length > 0 ? context.roles.map((r) => line(r, 64)).join(', ') : '-';
  const text = [
    template.text,
    '',
    '# Catalogue index',
    '',
    catalogue.length > 0 ? catalogue : '(no tools are available to this user)',
    '',
    '# Context',
    '',
    `- Organization: ${line(context.organization.name)} (id ${line(context.organization.publicId, 64)})`,
    `- User: ${line(context.user.displayName)}`,
    `- Roles: ${roles}`,
    `- Current date-time (UTC): ${isoMinute(context.now)}`,
    `- User time zone: ${context.timeZone ? line(context.timeZone, 64) : 'unknown (use UTC)'}`,
    `- Tool registry version: ${line(context.registryVersion, 32)}`,
    '',
  ].join('\n');
  return { version: template.version, text, templateSha256: template.sha256 };
}

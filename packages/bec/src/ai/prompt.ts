import { readPackageFile, sha256Hex } from '../data';

/** LLM prompt template (B10): versioned file, its SHA-256 recorded with every LLM result. */
export const PROMPT_TEMPLATE_VERSION = 'bec-llm-prompt/1';
export const PROMPT_TEMPLATE_FILE = 'bec-llm-prompt-1.txt';

export interface PromptTemplate {
  version: string;
  text: string;
  sha256: string;
}

let cached: PromptTemplate | null = null;

export function loadPromptTemplate(): PromptTemplate {
  if (cached) return cached;
  const text = readPackageFile('prompts', PROMPT_TEMPLATE_FILE);
  cached = { version: PROMPT_TEMPLATE_VERSION, text, sha256: sha256Hex(text) };
  return cached;
}

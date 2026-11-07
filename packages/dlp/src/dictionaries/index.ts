import {
  DLP_DICTIONARY_CATEGORIES,
  DLP_TENANT_SEVERITIES,
  type DlpDictionaryCategory,
  type DlpTenantSeverity,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import { PhraseTrie, MAX_PHRASE_CHARS, phraseTokens } from '../context/trie';
import { DLP_DICTIONARY_FILES, canonicalJson, readDataFile, sha256Hex } from '../data';
import { CONTEXT_GROUPS, type ContextGroup } from '../detectors/types';

/**
 * Keyword dictionaries (step 4.5 D8): the packaged built-in dictionaries (`labels` CF1,
 * `business` CF2, `financial` FI1, positive `context` per detector family, `negative` and
 * disclaimer lexicons; languages en, hi, hi-Latn) and the tenant dictionaries (DC1) compiled
 * with the built-ins into one phrase trie per organization snapshot.
 */

export const DLP_DICTIONARY_LANGUAGES = ['en', 'hi', 'hi-Latn'] as const;
export type DlpDictionaryLanguage = (typeof DLP_DICTIONARY_LANGUAGES)[number];

export const FINANCIAL_KINDS = [
  'invoice',
  'salary',
  'balance_sheet',
  'bank_statement',
  'tax',
] as const;
export type FinancialKind = (typeof FINANCIAL_KINDS)[number];

export const NEGATIVE_GROUPS = ['negative', 'negative_phone', 'disclaimer'] as const;
export type NegativeGroup = (typeof NEGATIVE_GROUPS)[number];

export type DictionaryPayload =
  | { kind: 'label'; id: string }
  | { kind: 'business'; id: string }
  | { kind: 'financial'; id: string; finKind: FinancialKind }
  | { kind: 'context'; id: string; group: ContextGroup }
  | { kind: 'negative'; id: string; group: NegativeGroup }
  | { kind: 'tenant'; dictionary: number; termIndex: number };

const entryId = (name: string) =>
  z
    .string()
    .regex(new RegExp(`^(en|hi|hi-Latn)\\.${name}\\.\\d{3}$`), `Expected <lang>.${name}.<nnn>`);

const fileSchema = <T extends z.ZodRawShape>(name: string, extra: T) =>
  z.strictObject({
    version: z.number().int().min(1),
    dictionary: z.literal(name),
    description: z.string(),
    entries: z
      .array(
        z.strictObject({
          id: entryId(name),
          phrase: z.string().min(1).max(MAX_PHRASE_CHARS),
          ...extra,
        }),
      )
      .min(1)
      .max(2000),
  });

const SCHEMAS = {
  'labels.json': fileSchema('labels', {}),
  'business.json': fileSchema('business', {}),
  'financial.json': fileSchema('financial', { kind: z.enum(FINANCIAL_KINDS) }),
  'context.json': fileSchema('context', { group: z.enum(CONTEXT_GROUPS) }),
  'negative.json': fileSchema('negative', { group: z.enum(NEGATIVE_GROUPS) }),
};

export interface BuiltInEntry {
  id: string;
  phrase: string;
  tokens: string[];
  payload: DictionaryPayload;
}

export interface BuiltInDictionaries {
  entries: readonly BuiltInEntry[];
  /** First 8 hex of SHA-256 over the packaged dictionary files (`dict=` of the engine version). */
  version: string;
  byId: ReadonlyMap<string, BuiltInEntry>;
}

/** Parses the packaged dictionary files (given as text, so tests can feed variants). */
export function parseBuiltInDictionaries(
  files: Readonly<Record<(typeof DLP_DICTIONARY_FILES)[number], string>>,
): BuiltInDictionaries {
  const entries: BuiltInEntry[] = [];
  const byId = new Map<string, BuiltInEntry>();
  const add = (id: string, phrase: string, payload: DictionaryPayload) => {
    if (byId.has(id)) throw new Error(`duplicate dictionary id ${id}`);
    let tokens: string[];
    try {
      tokens = phraseTokens(phrase);
    } catch {
      throw new Error(`dictionary ${id}: phrase must have 1..8 tokens`);
    }
    const entry = { id, phrase, tokens, payload };
    byId.set(id, entry);
    entries.push(entry);
  };
  const labels = SCHEMAS['labels.json'].parse(JSON.parse(files['labels.json']));
  for (const e of labels.entries) add(e.id, e.phrase, { kind: 'label', id: e.id });
  const business = SCHEMAS['business.json'].parse(JSON.parse(files['business.json']));
  for (const e of business.entries) add(e.id, e.phrase, { kind: 'business', id: e.id });
  const financial = SCHEMAS['financial.json'].parse(JSON.parse(files['financial.json']));
  for (const e of financial.entries) {
    add(e.id, e.phrase, { kind: 'financial', id: e.id, finKind: e.kind });
  }
  const context = SCHEMAS['context.json'].parse(JSON.parse(files['context.json']));
  for (const e of context.entries)
    add(e.id, e.phrase, { kind: 'context', id: e.id, group: e.group });
  const negative = SCHEMAS['negative.json'].parse(JSON.parse(files['negative.json']));
  for (const e of negative.entries) {
    add(e.id, e.phrase, { kind: 'negative', id: e.id, group: e.group });
  }
  const version = sha256Hex(
    DLP_DICTIONARY_FILES.map((name) => `${name}\0${files[name]}`).join('\0'),
  ).slice(0, 8);
  return { entries, version, byId };
}

let builtIns: BuiltInDictionaries | null = null;

/** The packaged built-in dictionaries (loaded once). */
export function builtInDictionaries(): BuiltInDictionaries {
  if (!builtIns) {
    const files = Object.fromEntries(
      DLP_DICTIONARY_FILES.map((name) => [name, readDataFile('dictionaries', name)]),
    ) as Record<(typeof DLP_DICTIONARY_FILES)[number], string>;
    builtIns = parseBuiltInDictionaries(files);
  }
  return builtIns;
}

// ---------------------------------------------------------------------------------------------
// Tenant dictionaries (DC1)
// ---------------------------------------------------------------------------------------------

export const DLP_DICTIONARY_TERM_MAX_CHARS = 64;

/** A tenant dictionary as loaded by the worker (public id; terms are tenant configuration). */
export interface TenantDictionaryInput {
  id: string;
  version: number;
  category: DlpDictionaryCategory;
  terms: readonly string[];
  severity: DlpTenantSeverity;
  baseConfidence: number;
  minMatches: number;
}

export type DictionaryTermsCheck =
  | { ok: true; tokens: string[][] }
  | { ok: false; code: 'dictionary_terms_count' | 'dictionary_term_invalid'; index?: number };

/**
 * Validates tenant dictionary terms (D8; the api at create/update and the worker at load):
 * 1..`maxTerms` terms, each 1..64 characters and 1..8 tokens after normalization, no
 * duplicate after normalization. Returns the token lists; never echoes a term.
 */
export function checkDictionaryTerms(
  terms: readonly string[],
  maxTerms: number,
): DictionaryTermsCheck {
  if (terms.length < 1 || terms.length > maxTerms)
    return { ok: false, code: 'dictionary_terms_count' };
  const tokens: string[][] = [];
  const seen = new Set<string>();
  for (let index = 0; index < terms.length; index += 1) {
    const term = terms[index]!;
    if (term.length < 1 || term.length > DLP_DICTIONARY_TERM_MAX_CHARS) {
      return { ok: false, code: 'dictionary_term_invalid', index };
    }
    let list: string[];
    try {
      list = phraseTokens(term);
    } catch {
      return { ok: false, code: 'dictionary_term_invalid', index };
    }
    const key = list.join(' ');
    if (seen.has(key)) return { ok: false, code: 'dictionary_term_invalid', index };
    seen.add(key);
    tokens.push(list);
  }
  return { ok: true, tokens };
}

export const tenantDictionarySchema = z.strictObject({
  id: z.uuid(),
  version: z.number().int().min(1),
  category: z.enum(DLP_DICTIONARY_CATEGORIES),
  terms: z.array(z.string()).min(1),
  severity: z.enum(DLP_TENANT_SEVERITIES),
  baseConfidence: z.number().min(0.5).max(1),
  minMatches: z.number().int().min(1).max(100),
});

/**
 * One organization's compiled dictionaries: the built-ins plus its enabled tenant dictionaries
 * in one phrase trie (D8). `tenantVersion` hashes the tenant dictionary ids and versions.
 */
export class DlpDictionarySet {
  readonly trie: PhraseTrie<DictionaryPayload>;
  readonly builtIn: BuiltInDictionaries;
  readonly tenant: readonly TenantDictionaryInput[];
  /** Tenant dictionaries that failed validation at load (skipped; their ids only). */
  readonly invalid: readonly string[];
  readonly tenantVersion: string;

  private constructor(
    builtIn: BuiltInDictionaries,
    tenant: readonly TenantDictionaryInput[],
    maxTerms: number,
  ) {
    this.builtIn = builtIn;
    this.trie = new PhraseTrie<DictionaryPayload>();
    for (const entry of builtIn.entries) this.trie.add(entry.tokens, entry.payload);
    const accepted: TenantDictionaryInput[] = [];
    const invalid: string[] = [];
    const sorted = [...tenant].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    for (const dictionary of sorted) {
      const parsed = tenantDictionarySchema.safeParse(dictionary);
      const check = parsed.success ? checkDictionaryTerms(dictionary.terms, maxTerms) : null;
      if (!check?.ok) {
        invalid.push(dictionary.id);
        continue;
      }
      const index = accepted.length;
      accepted.push(dictionary);
      check.tokens.forEach((tokens, termIndex) =>
        this.trie.add(tokens, { kind: 'tenant', dictionary: index, termIndex }),
      );
    }
    this.tenant = accepted;
    this.invalid = invalid;
    this.tenantVersion = sha256Hex(
      canonicalJson(accepted.map((d) => ({ id: d.id, version: d.version }))),
    ).slice(0, 8);
  }

  static create(
    tenant: readonly TenantDictionaryInput[] = [],
    options: { maxTerms?: number; builtIn?: BuiltInDictionaries } = {},
  ): DlpDictionarySet {
    return new DlpDictionarySet(
      options.builtIn ?? builtInDictionaries(),
      tenant,
      options.maxTerms ?? 1000,
    );
  }
}

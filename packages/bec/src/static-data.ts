import { loadBrands, lookalikeVersion, type Brand } from '@email-gateway/url-security';
import { loadFreemail, type FreemailList } from './identity/freemail';
import { Lexicon } from './text/lexicon';

/**
 * Process-wide data of the bec engine, loaded once at start (B5, B8, B16): protected brands
 * (url-security's packaged list or URL_PROTECTED_BRANDS_FILE), the free-mail list and the
 * lexicons. `engineVersion` = `bec/1;lex=<8 hex>;fm=<8 hex>;br=<8 hex>` (≤ 64 characters).
 */
export interface BecStaticData {
  brands: readonly Brand[];
  freemail: FreemailList;
  lexicon: Lexicon;
  brandsVersion: string;
  engineVersion: string;
}

export const BEC_ENGINE_VERSION_PREFIX = 'bec/1';

/** The brands hash of url-security's `lookalikeVersion` (`…;brands=<8 hex>`), reused as is. */
export function brandsHash(brands: readonly Brand[]): string {
  const match = /;brands=([0-9a-f]{8})$/.exec(lookalikeVersion(brands));
  if (!match) throw new Error('unexpected url-security lookalikeVersion format');
  return match[1]!;
}

export function becEngineVersion(
  lexiconVersion: string,
  freemailVersion: string,
  brandsVersion: string,
): string {
  const version = `${BEC_ENGINE_VERSION_PREFIX};lex=${lexiconVersion};fm=${freemailVersion};br=${brandsVersion}`;
  if (version.length > 64) throw new Error('bec engine version exceeds 64 characters');
  return version;
}

export function loadBecStaticData(options: { brandsFile?: string | null } = {}): BecStaticData {
  const brands = loadBrands(options.brandsFile ?? null);
  const freemail = loadFreemail();
  const lexicon = Lexicon.load();
  const brandsVersion = brandsHash(brands);
  return {
    brands,
    freemail,
    lexicon,
    brandsVersion,
    engineVersion: becEngineVersion(lexicon.version, freemail.version, brandsVersion),
  };
}

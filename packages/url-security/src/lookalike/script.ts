/**
 * UTS #39 §5.2 "Highly Restrictive" restriction level via `\p{Script_Extensions=…}` (U7 L4):
 * a label passes when it is single-script, or every character is covered by one of
 * Latin+Han+Hiragana+Katakana, Latin+Han+Bopomofo, Latin+Han+Hangul. Common and Inherited
 * characters (digits, hyphen, combining marks) are ignored.
 */

const SCRIPTS = [
  'Adlam',
  'Ahom',
  'Anatolian_Hieroglyphs',
  'Arabic',
  'Armenian',
  'Avestan',
  'Balinese',
  'Bamum',
  'Bassa_Vah',
  'Batak',
  'Bengali',
  'Bhaiksuki',
  'Bopomofo',
  'Brahmi',
  'Braille',
  'Buginese',
  'Buhid',
  'Canadian_Aboriginal',
  'Carian',
  'Caucasian_Albanian',
  'Chakma',
  'Cham',
  'Cherokee',
  'Chorasmian',
  'Coptic',
  'Cuneiform',
  'Cypriot',
  'Cypro_Minoan',
  'Cyrillic',
  'Deseret',
  'Devanagari',
  'Dives_Akuru',
  'Dogra',
  'Duployan',
  'Egyptian_Hieroglyphs',
  'Elbasan',
  'Elymaic',
  'Ethiopic',
  'Garay',
  'Georgian',
  'Glagolitic',
  'Gothic',
  'Grantha',
  'Greek',
  'Gujarati',
  'Gunjala_Gondi',
  'Gurmukhi',
  'Gurung_Khema',
  'Han',
  'Hangul',
  'Hanifi_Rohingya',
  'Hanunoo',
  'Hatran',
  'Hebrew',
  'Hiragana',
  'Imperial_Aramaic',
  'Inscriptional_Pahlavi',
  'Inscriptional_Parthian',
  'Javanese',
  'Kaithi',
  'Kannada',
  'Katakana',
  'Kawi',
  'Kayah_Li',
  'Kharoshthi',
  'Khitan_Small_Script',
  'Khmer',
  'Khojki',
  'Khudawadi',
  'Kirat_Rai',
  'Lao',
  'Latin',
  'Lepcha',
  'Limbu',
  'Linear_A',
  'Linear_B',
  'Lisu',
  'Lycian',
  'Lydian',
  'Mahajani',
  'Makasar',
  'Malayalam',
  'Mandaic',
  'Manichaean',
  'Marchen',
  'Masaram_Gondi',
  'Medefaidrin',
  'Meetei_Mayek',
  'Mende_Kikakui',
  'Meroitic_Cursive',
  'Meroitic_Hieroglyphs',
  'Miao',
  'Modi',
  'Mongolian',
  'Mro',
  'Multani',
  'Myanmar',
  'Nabataean',
  'Nag_Mundari',
  'Nandinagari',
  'New_Tai_Lue',
  'Newa',
  'Nko',
  'Nushu',
  'Nyiakeng_Puachue_Hmong',
  'Ogham',
  'Ol_Chiki',
  'Ol_Onal',
  'Old_Hungarian',
  'Old_Italic',
  'Old_North_Arabian',
  'Old_Permic',
  'Old_Persian',
  'Old_Sogdian',
  'Old_South_Arabian',
  'Old_Turkic',
  'Old_Uyghur',
  'Oriya',
  'Osage',
  'Osmanya',
  'Pahawh_Hmong',
  'Palmyrene',
  'Pau_Cin_Hau',
  'Phags_Pa',
  'Phoenician',
  'Psalter_Pahlavi',
  'Rejang',
  'Runic',
  'Samaritan',
  'Saurashtra',
  'Sharada',
  'Shavian',
  'Siddham',
  'SignWriting',
  'Sinhala',
  'Sogdian',
  'Sora_Sompeng',
  'Soyombo',
  'Sundanese',
  'Sunuwar',
  'Syloti_Nagri',
  'Syriac',
  'Tagalog',
  'Tagbanwa',
  'Tai_Le',
  'Tai_Tham',
  'Tai_Viet',
  'Takri',
  'Tamil',
  'Tangsa',
  'Tangut',
  'Telugu',
  'Thaana',
  'Thai',
  'Tibetan',
  'Tifinagh',
  'Tirhuta',
  'Todhri',
  'Toto',
  'Tulu_Tigalari',
  'Ugaritic',
  'Vai',
  'Vithkuqi',
  'Wancho',
  'Warang_Citi',
  'Yezidi',
  'Yi',
  'Zanabazar_Square',
] as const;

/** Script tests the running V8/ICU supports (a newer name on an older Node is skipped). */
const TESTS: ReadonlyArray<readonly [string, RegExp]> = SCRIPTS.flatMap((script) => {
  try {
    return [[script, new RegExp(`^\\p{Script_Extensions=${script}}$`, 'u')] as const];
  } catch {
    return [];
  }
});
const COMMON_OR_INHERITED = /^[\p{Script=Common}\p{Script=Inherited}]$/u;

const ALLOWED_COMBINATIONS: ReadonlyArray<ReadonlySet<string>> = [
  new Set(['Latin', 'Han', 'Hiragana', 'Katakana']),
  new Set(['Latin', 'Han', 'Bopomofo']),
  new Set(['Latin', 'Han', 'Hangul']),
];

/** Script_Extensions of one code point (Common/Inherited → empty: ignored). 'Unknown' if none. */
export function scriptExtensions(char: string): ReadonlySet<string> {
  if (COMMON_OR_INHERITED.test(char)) return new Set();
  const scripts = new Set<string>();
  for (const [script, test] of TESTS) if (test.test(char)) scripts.add(script);
  if (scripts.size === 0) scripts.add('Unknown');
  return scripts;
}

/** UTS #39 resolved script set is non-empty (single script), Common/Inherited ignored. */
export function isSingleScript(label: string): boolean {
  let resolved: Set<string> | null = null;
  for (const char of label) {
    const scx = scriptExtensions(char);
    if (scx.size === 0) continue;
    if (resolved === null) {
      resolved = new Set(scx);
      continue;
    }
    for (const script of [...resolved]) if (!scx.has(script)) resolved.delete(script);
    if (resolved.size === 0) return false;
  }
  return true;
}

/** UTS #39 §5.2 Highly Restrictive. */
export function isHighlyRestrictive(label: string): boolean {
  if (isSingleScript(label)) return true;
  const sets = [...label].map(scriptExtensions).filter((scx) => scx.size > 0);
  return ALLOWED_COMBINATIONS.some((combination) =>
    sets.every((scx) => [...scx].some((script) => combination.has(script))),
  );
}

/** C0 control characters and DEL (U+0000–U+001F, U+007F): never part of tenant text or URLs. */
const isControl = (char: string): boolean => {
  const code = char.charCodeAt(0);
  return code < 0x20 || code === 0x7f;
};

export const hasControlCharacter = (value: string): boolean => [...value].some(isControl);

/** `value` without control characters (§9: subscription names are sanitized). */
export const stripControlCharacters = (value: string): string =>
  [...value].filter((char) => !isControl(char)).join('');

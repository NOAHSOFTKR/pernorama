/**
 * `Character.isWhitespace` for one UTF-16 code unit — what Java's
 * `String.isBlank` and `String.strip` use. Not the same set as
 * `String.prototype.trim`: Java does not count the non-breaking spaces
 * (U+00A0, U+2007, U+202F) or U+FEFF, and does count the separators
 * U+001C to U+001F. Values have to validate identically in both
 * languages, so this follows Java.
 */
export function isWhitespace(char: string): boolean {
  const code = char.charCodeAt(0);
  return (
    (code >= 0x0009 && code <= 0x000d) || // tab, line feed, vertical tab, form feed, carriage return
    (code >= 0x001c && code <= 0x001f) || // file, group, record and unit separators
    code === 0x0020 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x2006) ||
    (code >= 0x2008 && code <= 0x200a) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x205f ||
    code === 0x3000
  );
}

/** `String.isBlank`: empty, or nothing but whitespace. */
export function isBlank(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    if (!isWhitespace(value.charAt(i))) {
      return false;
    }
  }
  return true;
}

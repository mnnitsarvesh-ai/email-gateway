/**
 * Detects the closing delimiters (`--boundary--`) of the multiparts of a message from the `data`
 * chunks mailsplit emits (preambles, delimiter lines, epilogues). mailsplit does not report a
 * missing closing delimiter itself, and it groups consecutive `data` lines under the node of the
 * first one, so the lines are matched against every open multipart rather than the chunk's node.
 * Defect detection only (design M6); it never splits. Memory: one line of at most the longest
 * delimiter plus mailsplit's trailing-whitespace allowance.
 */
export class ClosingDelimiterScanner {
  /** Delimiter line → ids of the multiparts using it that are not closed yet (innermost last). */
  private readonly open = new Map<string, number[]>();
  private readonly closedIds = new Set<number>();
  private parts: Buffer[] = [];
  private length = 0;
  private overflow = false;
  private maxLine = 0;

  /** Registers a multipart (in document order, so a nested reuse of a boundary is innermost). */
  register(id: number, boundary: Buffer): void {
    const delimiter = `--${boundary.toString('latin1')}--`;
    const ids = this.open.get(delimiter);
    if (ids) ids.push(id);
    else this.open.set(delimiter, [id]);
    // mailsplit accepts up to 998 SP/HTAB and the line ending after the delimiter.
    this.maxLine = Math.max(this.maxLine, delimiter.length + 1010);
  }

  isClosed(id: number): boolean {
    return this.closedIds.has(id);
  }

  push(chunk: Buffer): void {
    let start = 0;
    for (;;) {
      const lineFeed = chunk.indexOf(0x0a, start);
      if (lineFeed < 0) {
        this.append(chunk.subarray(start));
        return;
      }
      this.append(chunk.subarray(start, lineFeed));
      this.evaluate();
      start = lineFeed + 1;
    }
  }

  /** End of input: the closing delimiter may be the last line, without a line ending. */
  finish(): void {
    this.evaluate();
  }

  private append(part: Buffer): void {
    if (this.overflow || part.length === 0) return;
    if (this.length + part.length > this.maxLine) {
      this.overflow = true;
      this.parts = [];
      this.length = 0;
      return;
    }
    this.parts.push(Buffer.from(part));
    this.length += part.length;
  }

  private evaluate(): void {
    if (!this.overflow && this.length > 0) {
      const line = Buffer.concat(this.parts, this.length)
        .toString('latin1')
        .replace(/^\r+/, '')
        .replace(/\r+$/, '')
        .replace(/[ \t]+$/, '');
      const id = this.open.get(line)?.pop();
      if (id !== undefined) this.closedIds.add(id);
    }
    this.parts = [];
    this.length = 0;
    this.overflow = false;
  }
}

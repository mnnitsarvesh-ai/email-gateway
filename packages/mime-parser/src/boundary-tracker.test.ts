import { describe, expect, it } from 'vitest';
import { ClosingDelimiterScanner } from './boundary-tracker';

function scan(chunks: string[], boundaries: string[]): boolean[] {
  const scanner = new ClosingDelimiterScanner();
  boundaries.forEach((boundary, id) => scanner.register(id, Buffer.from(boundary)));
  for (const chunk of chunks) scanner.push(Buffer.from(chunk, 'latin1'));
  scanner.finish();
  return boundaries.map((_, id) => scanner.isClosed(id));
}

describe('ClosingDelimiterScanner', () => {
  it('finds a closing delimiter with a leading line ending and trailing whitespace', () => {
    expect(scan(['preamble\r\n', '\r\n--b--  \t\r\n', 'epilogue'], ['b'])).toEqual([true]);
  });

  it('joins a delimiter split across chunks and accepts one at EOF without a line ending', () => {
    expect(scan(['\r\n--lo', 'ng-bou', 'ndary--'], ['long-boundary'])).toEqual([true]);
  });

  it('does not take a child delimiter, a prefix or a longer line for a closing one', () => {
    expect(scan(['--b\r\n', '--b-\r\n', '--b--x\r\n', 'x--b--\r\n'], ['b'])).toEqual([false]);
  });

  it('closes the innermost open multipart that reuses a boundary', () => {
    expect(scan(['--b--\r\n'], ['b', 'b'])).toEqual([false, true]);
    expect(scan(['--b--\r\n', '--b--\r\n'], ['b', 'b'])).toEqual([true, true]);
  });

  it('matches every open multipart, whatever chunk carries the line', () => {
    expect(scan(['--inner--\r\n\r\n--outer--\r\n'], ['outer', 'inner'])).toEqual([true, true]);
  });

  it('ignores over-long lines', () => {
    expect(scan([`${'x'.repeat(5000)}--b--\r\n`], ['b'])).toEqual([false]);
  });
});

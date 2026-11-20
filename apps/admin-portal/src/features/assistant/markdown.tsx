'use client';

import Link from 'next/link';
import { Fragment, type ReactNode } from 'react';
import { sanitizeDisplay } from '@/components/domain/untrusted-text';
import { cn } from '@/lib/utils';
import { safePortalHref } from './portal-routes';

/**
 * Restricted Markdown for assistant text (step AI-1 D9): builds React elements, never HTML.
 * Blocks: paragraphs (single line breaks kept), headings (rendered as strong paragraphs so the
 * page outline stays the page's own), bullet and numbered lists (one level), fenced code blocks
 * (text), simple pipe tables. Inline: `code`, **bold**, *italic*, and `[text](/portal/route)`
 * links to allow-listed internal routes only. External links, images, autolinks and raw HTML stay
 * literal text: nothing the model writes can load a resource or open another origin.
 */

const MAX_SOURCE = 32_000;
const MAX_INLINE_DEPTH = 4;
const MAX_TABLE_COLUMNS = 20;
const MAX_TABLE_ROWS = 200;

type Block =
  | { kind: 'paragraph'; lines: string[] }
  | { kind: 'heading'; text: string }
  | { kind: 'code'; text: string; language: string }
  | { kind: 'list'; ordered: boolean; start: number; items: string[] }
  | { kind: 'table'; header: string[]; rows: string[][] };

const FENCE = /^\s{0,3}(`{3,}|~{3,})\s*([A-Za-z0-9_+-]{0,32})\s*$/;
const HEADING = /^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$/;
const BULLET = /^\s{0,6}[-*+]\s+(.*)$/;
const ORDERED = /^\s{0,6}(\d{1,9})[.)]\s+(.*)$/;
const TABLE_SEPARATOR = /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/;
const RULE = /^\s{0,3}([-*_])(\s*\1){2,}\s*$/;

function splitRow(line: string): string[] {
  let text = line.trim();
  if (text.startsWith('|')) text = text.slice(1);
  if (text.endsWith('|') && !text.endsWith('\\|')) text = text.slice(0, -1);
  const cells: string[] = [];
  let current = '';
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (char === '\\' && text[i + 1] === '|') {
      current += '|';
      i += 1;
    } else if (char === '|') {
      cells.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  cells.push(current.trim());
  return cells;
}

function isTableStart(lines: readonly string[], index: number): boolean {
  const line = lines[index] ?? '';
  const next = lines[index + 1] ?? '';
  return line.includes('|') && TABLE_SEPARATOR.test(next) && next.includes('-');
}

/** Splits the source into blocks (pure; exported for tests). */
export function parseBlocks(source: string): Block[] {
  const lines = sanitizeDisplay(source.slice(0, MAX_SOURCE).replace(/\r\n?/g, '\n')).split('\n');
  const blocks: Block[] = [];
  let paragraph: string[] = [];
  const flush = () => {
    if (paragraph.length > 0) blocks.push({ kind: 'paragraph', lines: paragraph });
    paragraph = [];
  };
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    const fence = FENCE.exec(line);
    if (fence) {
      flush();
      const marker = fence[1] ?? '```';
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !(lines[i] ?? '').trim().startsWith(marker)) {
        body.push(lines[i] ?? '');
        i += 1;
      }
      blocks.push({ kind: 'code', text: body.join('\n'), language: fence[2] ?? '' });
      continue;
    }
    if (line.trim() === '') {
      flush();
      continue;
    }
    if (RULE.test(line)) {
      flush();
      continue;
    }
    const heading = HEADING.exec(line);
    if (heading) {
      flush();
      blocks.push({ kind: 'heading', text: heading[1] ?? '' });
      continue;
    }
    if (isTableStart(lines, i)) {
      flush();
      const header = splitRow(line).slice(0, MAX_TABLE_COLUMNS);
      const rows: string[][] = [];
      i += 2;
      while (i < lines.length && (lines[i] ?? '').includes('|') && (lines[i] ?? '').trim() !== '') {
        if (rows.length < MAX_TABLE_ROWS)
          rows.push(splitRow(lines[i] ?? '').slice(0, header.length));
        i += 1;
      }
      i -= 1;
      blocks.push({ kind: 'table', header, rows });
      continue;
    }
    const bullet = BULLET.exec(line);
    const ordered = bullet ? null : ORDERED.exec(line);
    if (bullet || ordered) {
      flush();
      const isOrdered = Boolean(ordered);
      const items: string[] = [];
      const start = ordered ? Number(ordered[1]) : 1;
      while (i < lines.length) {
        const current = lines[i] ?? '';
        const item = isOrdered ? ORDERED.exec(current) : BULLET.exec(current);
        if (item) {
          items.push((isOrdered ? item[2] : item[1]) ?? '');
        } else if (current.trim() !== '' && /^\s{2,}\S/.test(current) && items.length > 0) {
          // A continuation (or a nested item, flattened into its parent).
          items[items.length - 1] += ` ${current.trim().replace(/^([-*+]|\d{1,9}[.)])\s+/, '')}`;
        } else {
          break;
        }
        i += 1;
      }
      i -= 1;
      blocks.push({ kind: 'list', ordered: isOrdered, start, items });
      continue;
    }
    paragraph.push(line.trim());
  }
  flush();
  return blocks;
}

function isWordChar(char: string | undefined): boolean {
  return char !== undefined && /[\p{L}\p{N}]/u.test(char);
}

/** `[text](target)` at `index` (also `![…](…)`): the parts and the end index, else null. */
function readLink(
  text: string,
  index: number,
): { label: string; target: string; end: number } | null {
  if (text[index] !== '[') return null;
  const close = text.indexOf(']', index + 1);
  if (close < 0 || close - index > 500 || text[close + 1] !== '(') return null;
  const end = text.indexOf(')', close + 2);
  if (end < 0 || end - close > 2100) return null;
  const inner = text.slice(close + 2, end).trim();
  const target = inner.split(/\s+/)[0] ?? '';
  return { label: text.slice(index + 1, close), target, end: end + 1 };
}

interface InlineOptions {
  readonly onNavigate?: () => void;
}

/** Inline Markdown to React nodes (pure; exported for tests). */
export function renderInline(
  text: string,
  options: InlineOptions = {},
  depth = 0,
  keyPrefix = 'i',
): ReactNode[] {
  const out: ReactNode[] = [];
  let buffer = '';
  let key = 0;
  const pushText = () => {
    if (buffer) out.push(buffer);
    buffer = '';
  };
  const nextKey = () => `${keyPrefix}-${key++}`;
  for (let i = 0; i < text.length;) {
    const char = text[i];
    // Inline code: a run of backticks closed by the same run.
    if (char === '`') {
      let run = 1;
      while (text[i + run] === '`') run += 1;
      const fence = '`'.repeat(run);
      const close = text.indexOf(fence, i + run);
      if (close > i + run - 1) {
        pushText();
        out.push(
          <code key={nextKey()} className="rounded-sm bg-muted px-1 py-0.5 font-mono text-[0.85em]">
            {text.slice(i + run, close).trim() || text.slice(i + run, close)}
          </code>,
        );
        i = close + run;
        continue;
      }
      buffer += fence;
      i += run;
      continue;
    }
    // Images are never loaded: the whole source stays text.
    if (char === '!' && text[i + 1] === '[') {
      const image = readLink(text, i + 1);
      if (image) {
        buffer += text.slice(i, image.end);
        i = image.end;
        continue;
      }
    }
    if (char === '[') {
      const link = readLink(text, i);
      if (link) {
        const href = safePortalHref(link.target);
        if (href && depth < MAX_INLINE_DEPTH) {
          pushText();
          out.push(
            <Link
              key={nextKey()}
              href={href}
              onClick={options.onNavigate}
              className="text-primary underline underline-offset-2 hover:no-underline"
            >
              {renderInline(link.label, {}, depth + 1, nextKey())}
            </Link>,
          );
        } else {
          // Not an internal portal route: shown as the literal Markdown, never clickable.
          buffer += text.slice(i, link.end);
        }
        i = link.end;
        continue;
      }
    }
    if ((char === '*' || char === '_') && depth < MAX_INLINE_DEPTH) {
      const double = text[i + 1] === char;
      const marker = double ? char + char : char;
      const opensAfterWord = char === '_' && isWordChar(text[i - 1]);
      const startsWithSpace = /\s/.test(text[i + marker.length] ?? ' ');
      if (!opensAfterWord && !startsWithSpace) {
        let close = text.indexOf(marker, i + marker.length);
        while (close > 0) {
          const before = text[close - 1];
          const after = text[close + marker.length];
          const singleOk = double || after !== char;
          const underscoreOk = char !== '_' || !isWordChar(after);
          if (before && !/\s/.test(before) && singleOk && underscoreOk) break;
          close = text.indexOf(marker, close + 1);
        }
        if (close > i + marker.length) {
          pushText();
          const inner = renderInline(
            text.slice(i + marker.length, close),
            options,
            depth + 1,
            nextKey(),
          );
          out.push(
            double ? (
              <strong key={nextKey()} className="font-semibold">
                {inner}
              </strong>
            ) : (
              <em key={nextKey()}>{inner}</em>
            ),
          );
          i = close + marker.length;
          continue;
        }
      }
    }
    buffer += char;
    i += 1;
  }
  pushText();
  return out;
}

/** Assistant text as restricted Markdown (see the module comment). */
export function AssistantMarkdown({
  source,
  className,
  onNavigate,
}: {
  source: string;
  className?: string;
  /** Called when an internal link is followed (the panel closes itself). */
  onNavigate?: () => void;
}) {
  const blocks = parseBlocks(source);
  const options: InlineOptions = { onNavigate };
  return (
    <div className={cn('grid gap-2 text-sm leading-relaxed break-words', className)}>
      {blocks.map((block, index) => {
        const key = `b${index}`;
        switch (block.kind) {
          case 'paragraph':
            return (
              <p key={key}>
                {block.lines.map((line, lineIndex) => (
                  <Fragment key={lineIndex}>
                    {lineIndex > 0 ? <br /> : null}
                    {renderInline(line, options, 0, `${key}-${lineIndex}`)}
                  </Fragment>
                ))}
              </p>
            );
          case 'heading':
            return (
              <p key={key} className="font-semibold">
                {renderInline(block.text, options, 0, key)}
              </p>
            );
          case 'code':
            return (
              <pre
                key={key}
                className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs"
                // A wide block scrolls; keyboard users must be able to scroll it (WCAG 2.1.1).
                // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- scrollable region
                tabIndex={0}
                aria-label={block.language ? `Code (${block.language})` : 'Code'}
              >
                <code>{block.text}</code>
              </pre>
            );
          case 'list': {
            const items = block.items.map((item, itemIndex) => (
              <li key={itemIndex}>{renderInline(item, options, 0, `${key}-${itemIndex}`)}</li>
            ));
            return block.ordered ? (
              <ol key={key} start={block.start} className="ml-5 list-decimal space-y-1">
                {items}
              </ol>
            ) : (
              <ul key={key} className="ml-5 list-disc space-y-1">
                {items}
              </ul>
            );
          }
          case 'table':
            return (
              <div
                key={key}
                className="overflow-x-auto rounded-md border"
                role="group"
                aria-label="Table in the answer"
                // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- scrollable region
                tabIndex={0}
              >
                <table className="w-full border-collapse text-xs">
                  <thead className="bg-muted/50">
                    <tr>
                      {block.header.map((cell, cellIndex) => (
                        <th
                          key={cellIndex}
                          scope="col"
                          className="border-b px-2 py-1.5 text-left font-semibold"
                        >
                          {renderInline(cell, options, 0, `${key}-h${cellIndex}`)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {block.rows.map((row, rowIndex) => (
                      <tr key={rowIndex} className="border-b last:border-0">
                        {block.header.map((_, cellIndex) => (
                          <td key={cellIndex} className="px-2 py-1.5 align-top">
                            {renderInline(
                              row[cellIndex] ?? '',
                              options,
                              0,
                              `${key}-${rowIndex}-${cellIndex}`,
                            )}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          default:
            return null;
        }
      })}
    </div>
  );
}

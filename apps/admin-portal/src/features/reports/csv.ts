/**
 * Client-side CSV of the aggregates a report tab displays (design §1.3 row 18): numbers and
 * labels only, never message data. Cells that a spreadsheet would read as a formula are
 * prefixed with an apostrophe (CSV injection); every cell is quoted when needed.
 */
export type CsvCell = string | number | boolean | null | undefined;

export function csvCell(value: CsvCell): string {
  if (value === null || value === undefined) return '';
  let text = String(value);
  if (typeof value === 'string' && /^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function toCsv(header: readonly string[], rows: readonly (readonly CsvCell[])[]): string {
  return [header, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

/** Saves a CSV file in the browser (no server round trip). */
export function downloadCsv(filename: string, csv: string): void {
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** `traffic-2026-11-06_2026-11-13.csv` */
export function csvFilename(report: string, from: string, to: string): string {
  return `${report}-${from.slice(0, 10)}_${to.slice(0, 10)}.csv`;
}

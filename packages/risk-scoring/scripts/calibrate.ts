/* eslint-disable no-console -- command-line tool output */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { formattedReport, REPORT_PATH, scoreDataset } from './calibration';
import { DATASET_PATH, parseDatasetJsonl } from './dataset';

// pnpm --filter @email-gateway/risk-scoring calibrate | calibrate:check (step 5.1 §9.2).
const PACKAGE_ROOT = join(__dirname, '..');

/** The report regenerated from the committed dataset. */
export async function regenerateReport(root: string = PACKAGE_ROOT): Promise<string> {
  const fixtures = parseDatasetJsonl(readFileSync(join(root, DATASET_PATH), 'utf8'));
  return formattedReport(scoreDataset(fixtures), join(root, REPORT_PATH));
}

/** Regenerates the report and compares it with the committed file. */
export async function checkReport(
  root: string = PACKAGE_ROOT,
): Promise<{ ok: boolean; path: string }> {
  const path = join(root, REPORT_PATH);
  let committed = '';
  try {
    committed = readFileSync(path, 'utf8');
  } catch {
    return { ok: false, path };
  }
  return { ok: committed === (await regenerateReport(root)), path };
}

async function main(command: string | undefined): Promise<number> {
  if (command === 'write') {
    writeFileSync(join(PACKAGE_ROOT, REPORT_PATH), await regenerateReport());
    console.log(`${REPORT_PATH} written`);
    return 0;
  }
  if (command === 'check') {
    const result = await checkReport();
    console.log(
      result.ok
        ? 'calibration report is up to date'
        : 'calibration report differs: run pnpm calibrate',
    );
    return result.ok ? 0 : 1;
  }
  console.error('usage: calibrate.ts write|check');
  return 2;
}

if (require.main === module) {
  main(process.argv[2]).then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      console.error(error);
      process.exitCode = 1;
    },
  );
}

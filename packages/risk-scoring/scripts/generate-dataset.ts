/* eslint-disable no-console -- command-line tool output */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DATASET_PATH, datasetJsonl } from './dataset';

// pnpm --filter @email-gateway/risk-scoring dataset | dataset:check (step 5.1 §9.2).
const PACKAGE_ROOT = join(__dirname, '..');

/** Regenerates the dataset and compares it with the committed file byte for byte. */
export function checkDataset(root: string = PACKAGE_ROOT): { ok: boolean; path: string } {
  const path = join(root, DATASET_PATH);
  let committed = '';
  try {
    committed = readFileSync(path, 'utf8');
  } catch {
    return { ok: false, path };
  }
  return { ok: committed === datasetJsonl(), path };
}

function main(command: string | undefined): number {
  if (command === 'write') {
    const text = datasetJsonl();
    writeFileSync(join(PACKAGE_ROOT, DATASET_PATH), text);
    console.log(`${DATASET_PATH}: ${text.trim().split('\n').length} fixtures`);
    return 0;
  }
  if (command === 'check') {
    const result = checkDataset();
    console.log(
      result.ok ? `${DATASET_PATH} is up to date` : `${DATASET_PATH} differs: run pnpm dataset`,
    );
    return result.ok ? 0 : 1;
  }
  console.error('usage: generate-dataset.ts write|check');
  return 2;
}

if (require.main === module) process.exitCode = main(process.argv[2]);

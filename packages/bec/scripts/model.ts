/* eslint-disable no-console -- command-line tool output */
import { checkModel, generateTrainingFile, trainAndWrite } from '../src/training/model-files';

// pnpm --filter @email-gateway/bec model:generate | model:train | model:check (B9, B16).
async function main(command: string | undefined): Promise<number> {
  if (command === 'generate') {
    const text = generateTrainingFile();
    console.log(`training/bec-train-1.jsonl: ${text.trim().split('\n').length} records`);
    return 0;
  }
  if (command === 'train') {
    generateTrainingFile();
    const model = await trainAndWrite();
    console.log(`models/bec-lr-1.json written; held-out metrics ${JSON.stringify(model.metrics)}`);
    return 0;
  }
  if (command === 'check') {
    const result = checkModel();
    console.log(JSON.stringify(result, null, 2));
    return result.ok ? 0 : 1;
  }
  console.error('usage: model.ts generate|train|check');
  return 2;
}

main(process.argv[2]).then(
  (code) => process.exit(code),
  (error: unknown) => {
    console.error(error);
    process.exit(1);
  },
);

/**
 * Generates `data/probe-corpus.txt` (step 4.5 D9 steps 5–6): ≈ 64 KiB of ordinary
 * multilingual prose (en, hi, hi-Latn), small numbers, prices, times, URLs and code — no
 * sensitive value of any built-in detector (asserted by `probe-corpus.test.ts`). Deterministic
 * (seeded PRNG), so the file and the engine version's data hash are reproducible.
 *
 *   tsx scripts/probe-corpus.ts          # rewrite the file
 *   tsx scripts/probe-corpus.ts --check  # exit 1 when the file differs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const TARGET_BYTES = 64 * 1024;

function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const EN = [
  'The team met on Tuesday to review the plan for the new office in Pune.',
  'Please bring the printed agenda and a notebook to the workshop.',
  'Our cafeteria now serves lunch from noon until half past two.',
  'The train to Mumbai leaves at 7:45 and arrives a little after eleven.',
  'We planted twelve trees near the parking area last weekend.',
  'Thank you for the feedback on the onboarding guide; we will update it.',
  'The weather report says light rain is likely in the evening.',
  'She finished the marathon in just under four hours.',
  'The library will be closed on Friday for maintenance.',
  'Remember to switch off the lights when you leave the meeting room.',
  'The new version of the app adds a dark theme and faster search.',
  'Our football club won three matches in a row this season.',
  'He prefers tea with ginger and a little honey in the morning.',
  'The museum opens a photography exhibition next month.',
  'Kindly share your travel dates so we can book the hotel.',
  'The quarterly town hall moves to the larger auditorium.',
  'Water the plants on the balcony twice a week during summer.',
  'The bakery on the corner sells fresh bread every morning.',
  'A short survey about the canteen menu is open until Monday.',
  'The cricket match was stopped for a while because of rain.',
];
const HI = [
  'आज मौसम बहुत सुहावना है और हल्की हवा चल रही है।',
  'कृपया बैठक के लिए समय पर पहुँचें।',
  'हमने पिछले सप्ताह बगीचे में नए पौधे लगाए।',
  'बच्चों ने विद्यालय के वार्षिक उत्सव में नृत्य प्रस्तुत किया।',
  'शाम को बाज़ार में बहुत भीड़ होती है।',
  'नई पुस्तकें पुस्तकालय में आ गई हैं।',
  'हम रविवार को परिवार के साथ पिकनिक पर जाएँगे।',
  'रेलगाड़ी समय से थोड़ी देर से पहुँची।',
];
const HI_LATN = [
  'Aaj mausam bahut accha hai, chalo bahar chai peete hain.',
  'Kal subah ki meeting thodi der se shuru hogi.',
  'Mujhe naya phone pasand aaya, camera bahut badhiya hai.',
  'Shaam ko hum park mein cricket khelenge.',
  'Yeh kitaab bahut rochak hai, zaroor padhna.',
  'Office ke paas ek naya cafe khula hai.',
];
const URLS = [
  'https://www.wikipedia.org/wiki/Monsoon',
  'https://developer.mozilla.org/en-US/docs/Web/HTML',
  'https://nodejs.org/en/learn/getting-started/introduction-to-nodejs',
  'https://www.python.org/doc/',
  'http://localhost:8080/health',
  'https://github.com/nodejs/node/blob/main/README.md',
  'https://www.india.gov.in/topics/agriculture',
];
const CODE = [
  'function add(a, b) {\n  return a + b;\n}',
  'for (let i = 0; i < items.length; i += 1) {\n  total += items[i].price;\n}',
  'def greet(name):\n    return f"Hello, {name}!"',
  'SELECT title, year FROM books WHERE year > 1990 ORDER BY title;',
  'const colors = ["red", "green", "blue"];',
  'if __name__ == "__main__":\n    main()',
  'git log --oneline -n 5',
  'docker compose up -d web',
];
const ITEMS = ['apples', 'notebooks', 'chairs', 'lamps', 'pens', 'tickets', 'mangoes', 'books'];
const DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

export function generateProbeCorpus(): string {
  const random = prng(20261107);
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
  const lines: string[] = [];
  let bytes = 0;
  while (bytes < TARGET_BYTES) {
    const roll = random();
    let line: string;
    if (roll < 0.45) line = `${pick(EN)} ${pick(EN)}`;
    else if (roll < 0.58) line = pick(HI);
    else if (roll < 0.68) line = pick(HI_LATN);
    else if (roll < 0.76) line = `See ${pick(URLS)} for details.`;
    else if (roll < 0.86) line = pick(CODE);
    else if (roll < 0.93) {
      const n = 2 + Math.floor(random() * 40);
      const price = 10 + Math.floor(random() * 900);
      line = `We bought ${n} ${pick(ITEMS)} for Rs. ${price} on ${pick(DAYS)} at ${1 + Math.floor(random() * 11)}:${String(Math.floor(random() * 60)).padStart(2, '0')}.`;
    } else {
      line = `Room ${100 + Math.floor(random() * 400)}, floor ${1 + Math.floor(random() * 9)}, seats ${4 + Math.floor(random() * 30)}; version ${1 + Math.floor(random() * 5)}.${Math.floor(random() * 10)}.`;
    }
    lines.push(line);
    bytes += Buffer.byteLength(line, 'utf8') + 1;
  }
  return `${lines.join('\n')}\n`;
}

if (require.main === module) {
  const file = join(__dirname, '..', 'data', 'probe-corpus.txt');
  const text = generateProbeCorpus();
  if (process.argv.includes('--check')) {
    if (readFileSync(file, 'utf8') !== text) {
      process.stderr.write(
        'data/probe-corpus.txt is out of date: run tsx scripts/probe-corpus.ts\n',
      );
      process.exit(1);
    }
  } else {
    writeFileSync(file, text);
  }
}

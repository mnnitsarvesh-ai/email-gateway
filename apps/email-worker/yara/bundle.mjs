#!/usr/bin/env node
// YARA rules bundle tool (step 4.2 A9, docs/plan/steps/10-attachment-scanning.md; algorithm in
// ./README.md). The email-worker computes the same bundle id in TypeScript at start and refuses
// an inspector child that reports another one.
//
//   node yara/bundle.mjs                 print the bundle id of ./ (no compilation)
//   node yara/bundle.mjs --check         validate and compile every rule, run the self-test of
//                                        the platform rules, print the bundle id
//   node yara/bundle.mjs --check --json  the same, as one JSON line
//   node yara/bundle.mjs --dir <path>    another bundle directory (ATTACHMENT_YARA_RULES_DIR)
//
// Exit code 0 = valid, 1 = invalid (every problem is printed), 2 = usage error.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));

export const SEVERITIES = ['high', 'medium', 'low'];
export const RULE_FILE_PATTERN = /^[a-z][a-z0-9._-]{0,63}\.yar$/;
const BUNDLE_NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
const META_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const RULE_HEADER = /^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]{0,127})\b/gm;

/** Version string of the YARA-X binding in use (the `version` of @litko/yara-x/package.json). */
export function yaraXVersion() {
  return require('@litko/yara-x/package.json').version;
}

/**
 * Bundle id (A9): `yara-<version>-<first 12 hex of SHA-256>` over the YARA-X version string,
 * then for each rule file in ascending name order: name, NUL, file bytes, NUL.
 */
export function bundleId(version, files, yaraX) {
  const hash = createHash('sha256');
  hash.update(Buffer.from(yaraX, 'utf8'));
  for (const file of [...files].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    hash.update(Buffer.from(file.name, 'utf8'));
    hash.update(Buffer.from([0]));
    hash.update(file.bytes);
    hash.update(Buffer.from([0]));
  }
  return `yara-${version}-${hash.digest('hex').slice(0, 12)}`;
}

/** Reads and validates bundle.json and the rule files of `dir`; returns problems instead of throwing. */
export function loadBundle(dir) {
  const problems = [];
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(join(dir, 'bundle.json'), 'utf8'));
  } catch (error) {
    return { problems: [`bundle.json: ${error.message}`], files: [], manifest: null };
  }
  const keys = Object.keys(manifest ?? {})
    .sort()
    .join(',');
  if (keys !== 'name,rules,version')
    problems.push(`bundle.json: keys must be name, version, rules (got ${keys})`);
  if (typeof manifest.name !== 'string' || !BUNDLE_NAME_PATTERN.test(manifest.name)) {
    problems.push('bundle.json: name must match ^[a-z0-9][a-z0-9-]{0,31}$');
  }
  if (!Number.isSafeInteger(manifest.version) || manifest.version < 1) {
    problems.push('bundle.json: version must be a positive integer');
  }
  const listed = Array.isArray(manifest.rules) ? manifest.rules : [];
  if (!Array.isArray(manifest.rules) || listed.length === 0)
    problems.push('bundle.json: rules must be a non-empty array');
  for (const name of listed) {
    if (typeof name !== 'string' || !RULE_FILE_PATTERN.test(name))
      problems.push(`bundle.json: invalid rule file name ${JSON.stringify(name)}`);
  }
  if (new Set(listed).size !== listed.length)
    problems.push('bundle.json: rules lists a file twice');
  let present = [];
  try {
    present = readdirSync(join(dir, 'rules')).filter((name) => name.endsWith('.yar'));
  } catch (error) {
    problems.push(`rules/: ${error.message}`);
  }
  for (const name of present)
    if (!listed.includes(name)) problems.push(`rules/${name} is not listed in bundle.json`);
  for (const name of listed)
    if (!present.includes(name))
      problems.push(`bundle.json lists ${name}, which is missing from rules/`);
  const files = listed
    .filter((name) => present.includes(name))
    .map((name) => ({ name, bytes: readFileSync(join(dir, 'rules', name)) }));
  return { problems, files, manifest };
}

/**
 * The rules of one file with their `meta:` key/values. Convention for bundle files: comments are
 * full-line `//` comments only (a regex may contain `//`), one `key = value` per meta line.
 */
export function parseRules(source) {
  const text = source
    .split('\n')
    .map((line) => (/^\s*\/\//.test(line) ? '' : line))
    .join('\n')
    .replace(/\/\*[\s\S]*?\*\//g, '');
  const headers = [...text.matchAll(RULE_HEADER)];
  return headers.map((match, index) => {
    const body = text.slice(match.index, headers[index + 1]?.index ?? text.length);
    const metaBlock = /\bmeta\s*:([\s\S]*?)(?:\bstrings\s*:|\bcondition\s*:)/.exec(body)?.[1] ?? '';
    const meta = {};
    for (const line of metaBlock.split('\n')) {
      const kv = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$/.exec(line);
      if (!kv) continue;
      const raw = kv[2];
      meta[kv[1]] = raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw;
    }
    return { name: match[1], meta };
  });
}

// Self-test of the platform rules: rule name → samples that must match it, plus samples no rule
// may match. Built here (not imported from the TypeScript corpus) so the check runs without a
// build. The YARA test markers are synthetic strings, the other samples inert text.
function selfTestSamples() {
  const b64 = (n) =>
    Buffer.alloc(n, 0x5a)
      .map((v, i) => (v ^ (i * 7)) & 0xff)
      .toString('base64');
  const lnk = (target) => {
    const header = Buffer.alloc(0x4c);
    header.writeUInt32LE(0x4c, 0);
    Buffer.from('0114020000000000c000000000000046', 'hex').copy(header, 4);
    return Buffer.concat([header, Buffer.from(`${target}\0/c echo test\0`, 'utf16le')]);
  };
  const rels = (target) =>
    Buffer.from(
      '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="${target}" TargetMode="External"/></Relationships>`,
    );
  const smuggle = (save) =>
    Buffer.from(
      `<html><body><script>var d = "${b64(9000)}"; var b = atob(d); var f = new Blob([b]);\n${save}\n</script></body></html>`,
    );
  return {
    positive: {
      EG_Test_Marker_High: [
        Buffer.from('report\nEG-YARA-TEST-HIGH-5f0c2e7a\n'),
        Buffer.from('EG-YARA-TEST-HIGH-5f0c2e7a', 'utf16le'),
      ],
      EG_Test_Marker_Medium: [Buffer.from('notes EG-YARA-TEST-MEDIUM-8d41b9c3')],
      EG_Heuristic_HTML_Smuggling: [
        smuggle('window.navigator.msSaveOrOpenBlob(f, "a.iso");'),
        smuggle(
          'var a = document.createElement("a"); a.href = URL.createObjectURL(f); a.download = "a.iso"; a.click();',
        ),
      ],
      EG_Heuristic_PowerShell_EncodedCommand: [
        Buffer.from(
          `powershell.exe -NoP -W Hidden -EncodedCommand ${Buffer.from('Write-Output test', 'utf16le').toString('base64')}\r\n`,
        ),
        Buffer.from(
          `PowerShell -enc ${Buffer.from('Get-Date; Get-Date', 'utf16le').toString('base64')}`,
        ),
        Buffer.from(
          `pwsh /e ${Buffer.from('Get-Date; Get-Date', 'utf16le').toString('base64')}`,
          'utf16le',
        ),
      ],
      EG_Heuristic_LNK_Command_Interpreter: [
        lnk('C:\\Windows\\System32\\cmd.exe'),
        lnk('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'),
      ],
      EG_Heuristic_OOXML_External_Template: [
        rels('https://evil.example.test/t.dotm'),
        rels('http://10.0.0.1/x.dotm'),
      ],
    },
    negative: [
      Buffer.from('Quarterly report. EG-YARA-TEST-LOW-00000000 is not a marker.\n'),
      Buffer.from('<html><body><script>console.log(new Blob(["x"]))</script></body></html>'),
      smuggle('console.log(f.size);'),
      Buffer.from('powershell.exe -ExecutionPolicy Bypass -File update.ps1\r\n'),
      Buffer.from(`-EncodedCommand ${'QQBB'.repeat(20)} without the interpreter name`),
      lnk('C:\\Program Files\\App\\app.exe'),
      Buffer.from('cmd.exe /c echo not a shortcut'),
      // An internal (package-relative) template relationship.
      Buffer.from(rels('../template.dotx').toString().replace(' TargetMode="External"', '')),
      Buffer.alloc(4096),
    ],
  };
}

/** Compiles and validates the bundle in `dir`; returns { problems, summary }. */
export function checkBundle(dir) {
  const { problems, files, manifest } = loadBundle(dir);
  const yara = require('@litko/yara-x');
  const yaraX = yaraXVersion();
  const rules = [];
  for (const file of files) {
    const source = file.bytes.toString('utf8');
    if (!file.bytes.equals(Buffer.from(source, 'utf8')))
      problems.push(`${file.name}: not valid UTF-8`);
    const result = yara.validate(source);
    for (const error of result.errors)
      problems.push(`${file.name}: compile error ${error.code}: ${error.message.split('\n')[0]}`);
    for (const warning of result.warnings)
      problems.push(`${file.name}: warning ${warning.code}: ${warning.message.split('\n')[0]}`);
    const parsed = parseRules(source);
    if (parsed.length === 0) problems.push(`${file.name}: no rule`);
    for (const rule of parsed) rules.push({ ...rule, file: file.name });
  }
  const names = new Map();
  const ids = new Map();
  for (const rule of rules) {
    if (names.has(rule.name))
      problems.push(`rule ${rule.name} is defined in ${names.get(rule.name)} and ${rule.file}`);
    names.set(rule.name, rule.file);
    const { id, severity } = rule.meta;
    if (typeof id !== 'string' || !META_ID_PATTERN.test(id))
      problems.push(`rule ${rule.name}: meta id missing or not ^[a-z0-9][a-z0-9._-]{0,63}$`);
    else if (ids.has(id))
      problems.push(`rule ${rule.name}: meta id ${id} also used by ${ids.get(id)}`);
    else ids.set(id, rule.name);
    if (!SEVERITIES.includes(severity))
      problems.push(`rule ${rule.name}: meta severity must be one of ${SEVERITIES.join(', ')}`);
  }

  let compiled = null;
  if (problems.length === 0) {
    // The inspector compiles the bundle the same way: every file in ascending name order.
    const sorted = [...files].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    try {
      compiled = yara.compile(sorted.map((file) => file.bytes.toString('utf8')).join('\n'));
      for (const warning of compiled.getWarnings())
        problems.push(`bundle: warning ${warning.code}: ${warning.message.split('\n')[0]}`);
    } catch (error) {
      problems.push(`bundle: compile failed: ${String(error.message).split('\n')[0]}`);
    }
  }

  if (compiled && manifest?.name === 'eg-platform') {
    const { positive, negative } = selfTestSamples();
    for (const rule of rules)
      if (!positive[rule.name])
        problems.push(`self-test: no sample for platform rule ${rule.name}`);
    for (const [ruleName, samples] of Object.entries(positive)) {
      if (!names.has(ruleName)) problems.push(`self-test: sample for unknown rule ${ruleName}`);
      samples.forEach((sample, index) => {
        const matches = compiled.scan(sample);
        const hit = matches.find((m) => m.ruleIdentifier === ruleName);
        if (!hit) problems.push(`self-test: ${ruleName} does not match its sample ${index}`);
        else {
          // Meta as YARA-X reports it (what the inspector reads).
          const expected = rules.find((r) => r.name === ruleName)?.meta ?? {};
          if (hit.meta.id !== expected.id || hit.meta.severity !== expected.severity) {
            problems.push(`self-test: ${ruleName} reports meta ${JSON.stringify(hit.meta)}`);
          }
        }
        const others = matches.map((m) => m.ruleIdentifier).filter((n) => n !== ruleName);
        if (others.length > 0)
          problems.push(
            `self-test: sample ${index} of ${ruleName} also matches ${others.join(', ')}`,
          );
      });
    }
    negative.forEach((sample, index) => {
      const matches = compiled.scan(sample).map((m) => m.ruleIdentifier);
      if (matches.length > 0)
        problems.push(`self-test: negative sample ${index} matches ${matches.join(', ')}`);
    });
  }

  return {
    problems,
    summary: {
      name: manifest?.name ?? null,
      version: manifest?.version ?? null,
      bundleId:
        manifest && Number.isSafeInteger(manifest.version)
          ? bundleId(manifest.version, files, yaraX)
          : null,
      yaraXVersion: yaraX,
      ruleCount: rules.length,
      files: files.map((file) => file.name).sort(),
    },
  };
}

function main(argv) {
  const args = argv.slice(2);
  const known = new Set(['--check', '--json', '--dir']);
  const dirIndex = args.indexOf('--dir');
  const dir = resolve(dirIndex >= 0 ? (args[dirIndex + 1] ?? '') : here);
  if (
    (dirIndex >= 0 && !args[dirIndex + 1]) ||
    args.some((a, i) => a.startsWith('--') && !known.has(a) && i !== dirIndex + 1)
  ) {
    process.stderr.write('usage: node yara/bundle.mjs [--check] [--json] [--dir <bundle dir>]\n');
    return 2;
  }
  const json = args.includes('--json');
  if (!args.includes('--check')) {
    const { problems, files, manifest } = loadBundle(dir);
    if (problems.length > 0 || !manifest) {
      for (const problem of problems) process.stderr.write(`invalid: ${problem}\n`);
      return 1;
    }
    const id = bundleId(manifest.version, files, yaraXVersion());
    process.stdout.write(json ? `${JSON.stringify({ bundleId: id })}\n` : `${id}\n`);
    return 0;
  }
  const { problems, summary } = checkBundle(dir);
  if (problems.length > 0) {
    for (const problem of problems) process.stderr.write(`invalid: ${problem}\n`);
    return 1;
  }
  if (json) process.stdout.write(`${JSON.stringify(summary)}\n`);
  else {
    process.stdout.write(
      `${summary.name} v${summary.version}: ${summary.ruleCount} rules in ${summary.files.length} files, YARA-X binding ${summary.yaraXVersion}\n${summary.bundleId}\n`,
    );
  }
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv);
}

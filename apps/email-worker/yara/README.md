# YARA rules bundle (`eg-platform`)

The platform YARA rules of the attachment engine (step 4.2 A4/A9, [design](../../../docs/plan/steps/10-attachment-scanning.md)). The inspector child compiles this bundle once at start with **YARA-X** through `@litko/yara-x` (exact pin in `../package.json`) and reports its bundle id in the startup handshake; the worker computes the same id and refuses a child that reports another one. `ATTACHMENT_YARA_RULES_DIR` points at another directory with the same layout (the production rule feed); empty = this directory.

## Layout

- `bundle.json`: `{ "name": "eg-platform", "version": <positive integer>, "rules": [<file names>] }`. `rules` lists **exactly** the `rules/*.yar` files (no missing, no extra, no duplicates). Raise `version` whenever a rule changes meaningfully (the id changes with any byte anyway).
- `rules/*.yar`: file names match `^[a-z][a-z0-9._-]{0,63}\.yar$`. Every rule has `meta: id` (stable, unique in the bundle, `^[a-z0-9][a-z0-9._-]{0,63}$`) and `meta: severity` = `"high"` | `"medium"` | `"low"` (A6: high → `yara.high` malicious, medium → `yara.medium` suspicious, low → `yara.low` informational). Comments are full-line `//` comments only (regexes may contain `//`); one `key = value` per meta line. No compiler warnings are allowed.
- `bundle.mjs`: the reference implementation of the id and the validation.

## Rules

| Rule                                     | File                              | Severity | Matches                                                                                                                                                                                                      |
| ---------------------------------------- | --------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `EG_Test_Marker_High` (`test = true`)    | `eg-test-markers.yar`             | high     | the synthetic marker `EG-YARA-TEST-HIGH-5f0c2e7a` (`yaraHigh()` of `tests/fixtures/attachment-corpus`)                                                                                                       |
| `EG_Test_Marker_Medium` (`test = true`)  | `eg-test-markers.yar`             | medium   | the synthetic marker `EG-YARA-TEST-MEDIUM-8d41b9c3` (`yaraMedium()`)                                                                                                                                         |
| `EG_Heuristic_HTML_Smuggling`            | `eg-html-smuggling.yar`           | medium   | HTML (2 KB–30 MB) with a script that builds a `Blob` from a decoded (`atob(` / `;base64,`) quoted base64 run of ≥ 256 characters and saves it (`msSaveOrOpenBlob`, or `createObjectURL` + `.download`)       |
| `EG_Heuristic_PowerShell_EncodedCommand` | `eg-powershell-encoded.yar`       | medium   | `powershell`/`pwsh` and an `-e…`/`/e…` flag (any prefix of `-EncodedCommand`, `-ec`) followed by ≥ 40 base64 characters (ASCII or UTF-16LE)                                                                  |
| `EG_Heuristic_LNK_Command_Interpreter`   | `eg-lnk-command.yar`              | medium   | a Windows shortcut (header size `0x4C` + LinkCLSID `00021401-0000-0000-C000-000000000046`, < 4 MB) naming `cmd.exe`, `powershell.exe`, `pwsh.exe`, `mshta.exe`, `wscript.exe` or `cscript.exe`               |
| `EG_Heuristic_OOXML_External_Template`   | `eg-ooxml-template-injection.yar` | medium   | an OOXML relationships part (< 1 MB) with an `attachedTemplate` relationship, `TargetMode="External"` and an `http(s)://` target (the inspector scans the decompressed `word/_rels/settings.xml.rels` entry) |

The heuristics are deliberately narrow (several independent indicators per rule) to keep false positives low; they raise `suspicious`, never `malicious`.

## Bundle id (the algorithm WP3 implements in TypeScript)

```
bundleId = "yara-" + <bundle.json version> + "-" + hex(SHA-256(M))[0..12)
M        = utf8(yaraXVersion)
           ‖ for each file of bundle.json "rules", in ascending order of the file name
             (byte order of the UTF-8 name; names are ASCII):
               utf8(name) ‖ 0x00 ‖ <file bytes, exactly as on disk> ‖ 0x00
```

- `yaraXVersion` is the `version` field of `@litko/yara-x/package.json` as installed (`0.10.0`). The binding pins exactly one YARA-X engine (0.10.0 ships YARA-X 1.21.0) and 0.10.0 exposes no engine-version API, so the binding version stands for the engine version. Upgrading the binding therefore changes every bundle id (and, through the content version of A9, every cache key), which is intended.
- No separator between `yaraXVersion` and the first file name; one NUL after each name and after each file's bytes. No normalization of line endings or encodings (the bytes are hashed as stored; `.gitattributes` keeps them stable).
- Example: this bundle with binding `0.10.0` → `yara-1-462fab6e5cc4` (same on macOS arm64 and in `node:22-bookworm-slim` linux/arm64).

The inspector compiles the bundle as **one source**: the files' UTF-8 text in the same ascending name order, joined with `\n` (`compile(source)` of `@litko/yara-x`); rule names are unique across the bundle.

## Commands

```bash
pnpm --filter @email-gateway/email-worker yara:bundle      # node yara/bundle.mjs --check
node apps/email-worker/yara/bundle.mjs                     # print the id only (no compilation)
node apps/email-worker/yara/bundle.mjs --check --json      # {"name","version","bundleId","yaraXVersion","ruleCount","files"}
node apps/email-worker/yara/bundle.mjs --check --dir <dir> # another bundle (ATTACHMENT_YARA_RULES_DIR)
```

`--check` fails (exit 1, every problem printed) when `bundle.json` is malformed or does not list exactly the files, a file is not UTF-8, a rule does not compile or produces a compiler warning, a rule lacks `meta: id`/`meta: severity` or reuses a name or id, the bundle does not compile as one source, or — for the `eg-platform` bundle — the **self-test** fails: every platform rule must match its built-in positive samples (and only its own rule must match them; `id`/`severity` are read back from YARA-X's match metadata) and no rule may match the negative samples (clean HTML, a plain `-ExecutionPolicy` PowerShell line, the interpreter flag without `powershell`, a shortcut to an ordinary program, an internal template relationship, zeros). A new platform rule needs a sample in `bundle.mjs`.

## Runtime notes for the inspector (recorded by WP2)

- `@litko/yara-x@0.10.0` has `compile`, `validate`, `scan`/`scanAsync`, `setTimeout(ms)`, `getWarnings()`, `serialize`/`deserialize`, but **not** `setMaxScanSize` or `ruleCount` (both arrive in 0.11.0, which was younger than the 14-day rule when this step pinned the binding; deviation recorded in the design §12). The inspector therefore enforces `ATTACHMENT_MAX_ENTRY_BYTES` itself before calling `scan` (it never passes a larger buffer) and takes the rule count from the bundle's rule declarations (`bundle.mjs` `parseRules`: 6 rules).
- The binding's loader detects musl by reading `/usr/bin/ldd` first and only falls back to `child_process.execSync('ldd --version')` when that file cannot be read; `node:22-bookworm-slim` has `/usr/bin/ldd`, so the child never spawns a process through the loader. The inspector's "no child_process in the child's module graph" test must account for this transitive `require('child_process')` in the loader code path.

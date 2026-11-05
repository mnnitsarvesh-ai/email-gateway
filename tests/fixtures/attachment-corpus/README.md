# @email-gateway/attachment-corpus

Attachment test files for step 4.2 (§9 of the [design](../../../docs/plan/steps/10-attachment-scanning.md)), **generated at test time**: no binary is committed, no real malware is used, and the EICAR test string is assembled from fragments (the 68-byte string never appears verbatim in the repository or in `dist/`). Every generator is deterministic (fixed timestamps and seeds), so SHA-256 values are stable between runs.

Unlike `tests/fixtures/scan-corpus` (committed `.eml` files read by path), this corpus is a TypeScript workspace package (listed in `pnpm-workspace.yaml`, built to `dist/` like every package), because its files are produced by code. Consumers declare it as a dev dependency and import it by name:

```ts
import { eicar, nestedZip, zipBomb } from '@email-gateway/attachment-corpus';
```

Current consumers: `packages/clamav` (integration), `apps/email-worker` (dev dependency for unit/integration tests and the benchmark, WP3) and `tests` (stack suites, WP5). Turbo builds it through `^build` of each consumer; the root `pnpm test:integration` builds it for `tests` and `packages/clamav`.

## Generators

| Function                                                                                  | Produces                                                                                                                                        |
| ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `eicar()`, `EICAR_SHA256`, `EICAR_CLAMAV_SIGNATURE`                                       | the 68-byte EICAR file (SHA-256 `275a021b…51fd0f`); clamd 1.4 reports `Eicar-Test-Signature`                                                    |
| `zip(entries)`                                                                            | a valid zip (yazl), deflated or stored per entry                                                                                                |
| `nestedZip(depth, inner)`                                                                 | `depth` zips around `inner` (depth 1 = a zip containing `inner`; depth 4 is past `ATTACHMENT_ARCHIVE_MAX_DEPTH` 3)                              |
| `gzip(data)`, `multiMemberGzip(a, b)`, `tar(entries)` (tar-stream, ustar), `tgz(entries)` | compressed and archived files                                                                                                                   |
| `fake7z()`, `fakeRar()`, `fakeXz()`, `fakeBzip2()`, `fakeCab()`                           | the format's magic header + padding (unsupported formats for the inspector: `archive.unsupported_format`)                                       |
| `zipBomb(bytes = 64 MiB)`                                                                 | one entry of ≥ 50 MiB zeros deflated to ~64 KiB (streamed into yazl, never one buffer)                                                          |
| `highRatioFile(bytes = 4 MiB)`                                                            | a zip entry with a ratio ≫ 100 but a small decompressed size (`limit.compression_ratio` only)                                                   |
| `encryptedZip()`, `aesEncryptedZip()`                                                     | general purpose bit 0 (PKWARE); method 99 + extra field `0x9901` (WinZip AES)                                                                   |
| `malformedZip()`, `truncatedZip()`, `truncatedGzip()`, `badTarChecksum()`                 | central directory shorter than the end record claims; a zip cut inside its first header; gzip without trailer; wrong tar checksum               |
| `pathTraversalZip()`, `absolutePathZip()`, `overlappingZip()`, `manyEntriesZip(n)`        | `../../etc/evil.txt` and `/tmp/evil.txt` entry names (raw writer, yazl refuses them); two central entries sharing one local header; `n` entries |
| `peStub()`, `mzWithoutPe()`                                                               | a harmless PE header (`MZ`, `e_lfanew` → `PE\0\0`, i386 COFF, no sections, no code) for "exe renamed to pdf"; `MZ` without a PE target          |
| `yaraHigh()`, `yaraMedium()`, `YARA_TEST_MARKERS`                                         | files with the markers of the bundled YARA test rules (`EG_Test_Marker_High` / `_Medium`, apps/email-worker/yara)                               |
| `pdfLike(size)`, `truncatedPdf(size)`, `largeFile(size)`, `pseudoRandom(size, seed)`      | a PDF-looking file of exactly `size` bytes; its first half; incompressible data of exactly `size` bytes (near/above the size limits)            |
| `docxLike()`, `docmLike()`, `docxTemplateInjection()`, `ooxmlTemplateInjectionRels()`     | OOXML-like zips: a docx, a macro-enabled docm with `word/vbaProject.bin` (OLE header stub), a remote `attachedTemplate`                         |
| `htmlSmuggling()`, `cleanHtml()`, `powershellEncoded()`, `lnkWithCommandTarget()`         | inert samples of the bundled YARA heuristics (and a clean HTML counterpart)                                                                     |
| `buildRawZip(entries)`, `rawEntry(...)`, `zipLayout(buffer)`, `FIXED_MTIME`               | the low-level zip writer (every header field settable) and a central-directory locator for further variants                                     |

Sizes worth knowing: `ATTACHMENT_MAX_BYTES` = 26 214 400 (`pdfLike(26_214_399)` is scanned, `largeFile(26_214_401)` is above), clamd `StreamMaxLength` = 30M (`largeFile(31 * 1024 * 1024)` is refused by clamd).

## Tests

`pnpm --filter @email-gateway/attachment-corpus test`: shape and size of every generator (EICAR SHA-256, central directories, nesting, bomb ratio, encryption markers, malformed layouts, tar/gzip round trips, magic headers, PE stub, exact sizes) and that `eicar.ts` does not contain the EICAR string.

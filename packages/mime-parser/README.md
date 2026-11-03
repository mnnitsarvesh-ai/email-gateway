# @email-gateway/mime-parser

Streaming, limit-enforcing MIME parser for post-queue ingestion (step 3.1, design
[06-mime-ingestion.md](../../docs/plan/steps/06-mime-ingestion.md) M4–M10, M13;
[ADR-0022](../../docs/architecture/adr/0022-mime-parsing-and-post-queue-ingestion.md)).

It is a **pure library**: there is no Nest, Prisma, AWS SDK or logger, and it does no logging at all. It
reads one message from a `Readable`, splits it with `@zone-eu/mailsplit` and decodes every leaf
on the fly. Each text body, HTML body and attachment goes to a caller-supplied `PartSink`. The
result is a plain object with codes, counts, hashes, sizes and keys, never an exception for
hostile content. email-worker (WP4) supplies the S3 sink and stores the result. Step 4.x can reuse
`sniffContentType`, `inspectZip` and `inspectGzip`.

## API

```ts
import {
  parseMessage,
  DEFAULT_MIME_LIMITS,
  PARSER_VERSION, // 'mime-1'
  MIME_LIMIT_NAMES,
  MIME_DEFECT_CODES,
  ATTACHMENT_FLAGS,
  type PartSink,
} from '@email-gateway/mime-parser';

const sink: PartSink = {
  async open(part) {
    // part = { partIndex, partPath, depth, kind: 'text' | 'html' | 'attachment' }
    return {
      write: async (chunk) => {}, // awaited by the parser: backpressure reaches the input
      finish: async () => ({ key, readRange: (start, endInclusive, signal) => fetchRange() }),
      abort: async () => {}, // no object may remain
    };
  },
};

const result = await parseMessage(emlStream, { limits: DEFAULT_MIME_LIMITS, sink, signal });
```

| Export                                                      | Purpose                                                                                                 |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `parseMessage(input, { limits, sink, signal })`             | Parses one message. Resolves to a `MimeParseResult`. It rejects only with infrastructure errors (below) |
| `PARSER_VERSION`                                            | `'mime-1'`. Bump it on any change that alters the output for the same input                             |
| `MIME_LIMIT_NAMES`, `MIME_DEFECT_CODES`, `ATTACHMENT_FLAGS` | The code lists, in order                                                                                |
| `MimeLimits`, `DEFAULT_MIME_LIMITS`, `assertMimeLimits`     | Limits (design §5 defaults). `assertMimeLimits` refuses values the parser cannot use                    |
| `sanitizeFilename(raw, maxChars)`                           | M9 filename rules. Returns `{ filename, originalFilename, flags }`                                      |
| `sniffContentType(head)`                                    | M9 magic-byte table over the first 4 KiB                                                                |
| `inspectZip(part, sizeBytes, limits, signal)`               | M10 central-directory inspection over `StoredPart.readRange`                                            |
| `inspectGzip(head, tail, sizeBytes, limits)`                | M10 gzip header and ISIZE from the streamed head (4 KiB) and tail (8 bytes)                             |
| `STORED_HEADER_NAMES`                                       | The M7 allow-list, canonical spelling                                                                   |

`MimeParseResult`:

- `status`: `parsed`, `parsed_with_defects`, `parse_limit_exceeded` or `parse_failed`, with
  `failureReason: 'parser_error'` for the last.
- `limitsExceeded` and `defects`: unique codes in the order they were first seen.
- `stats`: `bytesRead`, `sha256` (all input bytes), `inputComplete`, `partCount`, `maxDepth`,
  `headerCount` (every field of the top-level block), `attachmentCount`, `decodedBytes` and
  `durationMs`.
- `subject`: decoded, at most 998 code points. `headers`: `{ seq, name, value }` rows.
- `textBody` and `htmlBody`: `{ key | null, sha256, sizeBytes, charset, partIndex, flags }`.
- `attachments`: `{ partIndex, partPath, depth, disposition, declaredContentType, detectedContentType, sizeBytes, encodedSizeBytes, sha256, key | null, filename | null, originalFilename | null, flags, archiveInfo | null }`.
- `structure`: one node per MIME node in document order (M13). It holds no filenames and no
  header values.

`partIndex` is the node's index in `structure`. `path` is `0` for the root, `<parent>.<n>` for
the n-th child of a multipart (n starts at 1) and `<container>.0` for the root of an embedded
`message/rfc822`. Depth is 0 for the root and grows by 1 for every multipart child and for every
embedded message root.

### Status rules

1. An unexpected library exception gives `parse_failed`, `failureReason: 'parser_error'`. The
   limits, defects and parts collected up to that point are kept.
2. Otherwise, any limit hit gives `parse_limit_exceeded`. That includes the per-part limits, which
   let the parse continue.
3. Otherwise, any defect gives `parsed_with_defects`.
4. Otherwise the status is `parsed`.

### Error mapping

| Source                                                                   | Outcome                                                                                                                                       |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `PartSink.open`, `PartWriter.write/finish/abort`, `StoredPart.readRange` | **Rethrown unchanged** (same error object). The worker treats it as infrastructure and retries. The in-flight writer is aborted (best effort) |
| Input stream error                                                       | **Rethrown unchanged**                                                                                                                        |
| `signal` fires, or `limits.parseTimeoutMs` elapses                       | Limit `parse_timeout`. Reading stops and the in-flight writer is aborted. Any error caused by the abort counts as the timeout                 |
| mailsplit `EMAXLEN`                                                      | `part_count` if its node counter passed `maxChildNodes`, otherwise `header_block_size`                                                        |
| yauzl rejects an archive                                                 | Flag `archive_malformed`                                                                                                                      |
| A throwing RFC 2047 decoder                                              | Defect `invalid_encoded_word`; the value is kept raw                                                                                          |
| Any other exception of mailsplit, libmime, the decoders or iconv-lite    | `parse_failed / parser_error`                                                                                                                 |

Errors are classified by class or `code`, **never by their message**. No message text ends up in
the result.

## Limits (design M5)

| Name                 | `MimeLimits` field (config key, default)                             | Enforced                                                                                              | On breach                                                                                                                    |
| -------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `message_size`       | `maxMessageBytes` (`MIME_MAX_MESSAGE_BYTES`, 53 477 376)             | Byte counter on the input                                                                             | Parse stops and reading stops (`inputComplete: false`)                                                                       |
| `nesting_depth`      | `maxDepth` (`MIME_MAX_DEPTH`, 10)                                    | When a node is emitted (also when its `partPath` would exceed `MAX_PART_PATH_CHARS` = 128, note 6)    | Parse stops                                                                                                                  |
| `part_count`         | `maxParts` (`MIME_MAX_PARTS`, 250)                                   | Every node. mailsplit `maxChildNodes = maxParts + 1` is the backstop                                  | Parse stops                                                                                                                  |
| `header_count`       | `maxHeaders` (`MIME_MAX_HEADERS`, 1 000)                             | Fields of any one node's header block                                                                 | Parse stops                                                                                                                  |
| `header_line_length` | `maxHeaderLineBytes` (`MIME_MAX_HEADER_LINE_BYTES`, 32 768)          | Bytes of one unfolded field                                                                           | Parse stops                                                                                                                  |
| `header_block_size`  | `maxHeaderBlockBytes` (`MIME_MAX_HEADER_BLOCK_BYTES`, 262 144)       | mailsplit `maxHeadSize`, which counts every header line as **at least 64 bytes**, plus the blank line | Parse stops                                                                                                                  |
| `attachment_count`   | `maxAttachments` (`MIME_MAX_ATTACHMENTS`, 100)                       | Leaves classified as attachments                                                                      | Parse stops                                                                                                                  |
| `attachment_size`    | `maxAttachmentBytes` (`MIME_MAX_ATTACHMENT_BYTES`, 26 214 400)       | Decoded bytes of one attachment                                                                       | The writer is aborted. The part is still hashed and measured: `key: null`, flag `not_stored_size_limit`. The parse continues |
| `body_size`          | `maxBodyBytes` (`MIME_MAX_BODY_BYTES`, 10 485 760)                   | Decoded and UTF-8 converted bytes of a body                                                           | As `attachment_size`                                                                                                         |
| `decoded_ratio`      | `maxDecodedRatio` (`MIME_MAX_DECODED_RATIO`, 1.1)                    | decoded ÷ max(encoded, 1) per leaf, once at least 64 KiB are decoded                                  | Parse stops                                                                                                                  |
| `total_decoded_size` | `maxTotalDecodedBytes` (`MIME_MAX_TOTAL_DECODED_BYTES`, 104 857 600) | Decoded bytes over all leaves                                                                         | Parse stops                                                                                                                  |
| `parse_timeout`      | `parseTimeoutMs` (`MIME_PARSE_TIMEOUT_MS`, 120 000) and `signal`     | Wall clock                                                                                            | Parse stops and reading stops                                                                                                |

"Parse stops" means three things. The in-flight part's writer is aborted, and that node stays in
`structure` with `truncated: true` but gets no body or attachment row. Everything completed before
the stop is kept. After any stop except `message_size`, `parse_timeout` and an infrastructure
error, the **rest of the input is still read and hashed** without being parsed, so `stats.sha256`
and `bytesRead` cover the whole object and the worker's integrity check (M3.8) stays meaningful.

The other caps are `maxStoredHeaders` (`MIME_MAX_STORED_HEADERS`, 200) and `filenameMaxChars`
(`MIME_FILENAME_MAX_CHARS`, 200). The archive thresholds are `archiveMaxEntries` (1 000),
`archiveMaxRatio` (100), `archiveMaxTotalUncompressedBytes` (1 GiB) and
`archiveMaxCentralDirectoryBytes` (8 MiB).

## Defect codes (design M6)

| Code                                          | Meaning                                                                                                                |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `no_headers`                                  | No header block: the message starts with a blank line, or its first line is no header                                  |
| `invalid_header_line`                         | A header-block line without `name:` or with an invalid field name                                                      |
| `missing_boundary_parameter`                  | `multipart/*` without a usable `boundary=`. The body becomes one attachment leaf                                       |
| `boundary_not_found`                          | A multipart whose boundary never occurs                                                                                |
| `missing_closing_boundary`                    | A multipart that reaches EOF, or its ancestor's delimiter, without `--boundary--`                                      |
| `invalid_base64`                              | Characters outside the alphabet, or a length that is not a multiple of 4                                               |
| `invalid_quoted_printable`                    | `=` not followed by two hex digits or by a soft line break                                                             |
| `unknown_transfer_encoding`                   | A CTE other than 7bit/8bit/binary/base64/quoted-printable. The part is decoded as binary                               |
| `unknown_charset`                             | A body or encoded-word charset that cannot be decoded, or raw 8-bit header bytes that are not UTF-8 (read as latin1)   |
| `invalid_encoded_word`                        | A malformed RFC 2047 word, left raw                                                                                    |
| `duplicate_singleton_header`                  | More than one `From`, `Sender`, `Subject`, `Date`, `Message-ID`, `To`, `Cc`, `Reply-To`, `In-Reply-To` or `References` |
| `header_control_chars`                        | C0 (except HT), DEL or C1 in a stored value, each replaced with U+FFFD                                                 |
| `header_bidi_control`                         | A bidi control in a stored value. It is kept                                                                           |
| `header_value_truncated`, `subject_truncated` | Values cut at 2 048 and 998 code points                                                                                |
| `stored_headers_truncated`                    | More than `maxStoredHeaders` allow-listed rows                                                                         |
| `nul_bytes`                                   | NUL in a header block                                                                                                  |
| `empty_message`                               | Zero bytes. `no_headers` is set as well                                                                                |

Stored headers (M7) are `From`, `Sender`, `Reply-To`, `To`, `Cc`, `Subject`, `Message-ID`, `Date`,
`In-Reply-To`, `References`, `Return-Path` and `Authentication-Results`, from the top-level block
only. Every occurrence is a row. Each value goes through these steps in order: unfold, keep raw
UTF-8 (else read it as latin1), decode RFC 2047 with `libmime.decodeWords`, normalize to NFC and
make it well-formed, replace control characters, flag bidi controls, then truncate at a code-point
boundary. Address lists are **not** parsed.

## Attachment flags (design M9, M10)

| Flag                            | Set when                                                                                                                                                                                                                               |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `filename_path_stripped`        | The name had `/` or `\` components or a drive prefix (`C:`)                                                                                                                                                                            |
| `filename_control_chars`        | C0, C1 or DEL removed                                                                                                                                                                                                                  |
| `filename_bidi_control`         | U+061C, U+200E, U+200F, U+202A–U+202E or U+2066–U+2069 removed                                                                                                                                                                         |
| `filename_zero_width`           | U+200B–U+200D or U+FEFF removed (**added** to M9's list, so the removal is never silent)                                                                                                                                               |
| `filename_whitespace_padding`   | 3 or more whitespace characters before the final extension                                                                                                                                                                             |
| `filename_reserved_name`        | `CON`, `PRN`, `AUX`, `NUL`, `COM1-9` or `LPT1-9` (any extension); the name gets a `_` prefix                                                                                                                                           |
| `filename_truncated`            | Cut to `filenameMaxChars` code points, keeping a final extension of up to 16 characters                                                                                                                                                |
| `filename_missing`              | No name, or nothing left after sanitizing (`filename: null`)                                                                                                                                                                           |
| `filename_executable_extension` | The final extension is in the M9 executable set                                                                                                                                                                                        |
| `filename_double_extension`     | An executable extension after a document or media extension (`report.pdf.exe`)                                                                                                                                                         |
| `filename_extension_mismatch`   | The sniffed type is an executable or archive and the (present) extension does not belong to it                                                                                                                                         |
| `original_filename_truncated`   | The escaped original was cut at 1 024 characters                                                                                                                                                                                       |
| `content_type_mismatch`         | Declared and sniffed types differ and the sniffed type is not `application/octet-stream`. Container aliases count as equal: OOXML/ODF/JAR/APK as zip, Word/Excel/PowerPoint/MSI as OLE, `image/jpg`, `application/x-zip-compressed`, … |
| `executable`                    | Sniffed PE, ELF, Mach-O, Windows shortcut or `#!` script                                                                                                                                                                               |
| `archive`                       | Sniffed zip, gzip, bzip2, xz, 7z, rar, tar or cab                                                                                                                                                                                      |
| `nested_message_part`           | The leaf is inside an embedded message                                                                                                                                                                                                 |
| `not_stored_size_limit`         | Over `attachment_size` or `body_size`; `key: null`. Bodies carry it too                                                                                                                                                                |
| `archive_entry_count`           | More than `archiveMaxEntries` entries (declared or iterated); iteration stops at max + 1                                                                                                                                               |
| `archive_compression_ratio`     | An entry's (or gzip's) uncompressed ÷ max(compressed, 1) is above `archiveMaxRatio`                                                                                                                                                    |
| `archive_total_size`            | Declared uncompressed total above `archiveMaxTotalUncompressedBytes`                                                                                                                                                                   |
| `archive_encrypted`             | General-purpose bit 0 set                                                                                                                                                                                                              |
| `archive_nested`                | An entry name (or gzip FNAME) ends in `zip rar 7z gz tgz tar bz2 xz cab iso jar arj lzh z ace img`                                                                                                                                     |
| `archive_overlapping_entries`   | Sorted by local-header offset, an entry's header (30 bytes minimum) plus its compressed data reaches the next one (Fifield bomb)                                                                                                       |
| `archive_path_traversal`        | An entry name with `..` components, a leading `/` or a drive letter                                                                                                                                                                    |
| `archive_malformed`             | yauzl (or the EOCD pre-check) rejected the archive                                                                                                                                                                                     |
| `archive_not_inspected`         | Central directory above the limit, zip not stored, or an archive type without an inspector                                                                                                                                             |

`archiveInfo` is `{ type, inspected, entries, declaredUncompressedBytes, maxRatio, encryptedEntries, nestedArchives }`.
It holds numbers only and no entry names. Its `maxRatio` is rounded to two decimals.

## Security notes

- **Untrusted content.** Nothing is executed, rendered or converted. There is no HTML↔text
  conversion, no linkification and no address parsing. HTML bodies are stored as decoded bytes.
  `format=flowed` is not applied.
- **Bounded memory.** The parser holds mailsplit's line buffer, which flushes a line without line
  breaks every 64 KiB, and mailsplit's header block, which is bounded by `maxHeadSize`. Each open
  part adds at most 4 KiB plus 8 bytes, the base64 remainder (≤ 3 characters) and a QP pending
  line of ≤ 64 KiB. Sink writes are awaited, so the input is read only as fast as the sink stores.
  A test parses 20 MiB of single-line base64 with heap growth below 64 MiB.
- **Hashing.** `stats.sha256` covers every input byte. Each part's `sha256` covers exactly the
  bytes handed to the sink: decoded attachment bytes, or UTF-8 converted body bytes.
- **Filenames** are metadata only. They are never part of a key, never a path and never in
  `structure`. `originalFilename` escapes every invisible, unassigned, private-use, bidi and
  zero-width code point and `\` as `\u{XXXX}`.
- **Archives.** Only the zip central directory is read. Reads go through at most two bounded
  ranges (the last min(size, 65 557) bytes, then the central directory), plus the 56-byte zip64
  record if it lies before the tail. Entry data is never fetched or decompressed. Declared sizes
  can lie, so the flags are hints and step 4.2 enforces real limits while it decompresses.
- **No logging.** The library logs nothing and puts no error message into its result.

### CVE and advisory notes (ADR-0022)

- `mailparser` is **not** used. GHSA-7gmj-h9xc-mcxc / CVE-2026-3455 is an XSS in its `textToHtml`.
  `html-to-text` and `linkify-it` are not used either.
- nodemailer's address parser is not used. GHSA-prgh-xp8r-p3m5 was a ReDoS, fixed in nodemailer
  10.0.5, and GHSA-46j5-6fg5-4gv3 was an infinite-recursion DoS.
- `yauzl` must be ≥ 3.2.1 because of CVE-2026-31988, an out-of-bounds read in the NTFS extra-field
  date parser. The pin is 3.4.0, and `getLastModDate()` is never called anyway.
- `file-type` is not used: it is ESM-only under this repository's CommonJS/`node10` build.
- All parser dependencies are pinned **exactly**. Bumps are security-relevant: check GitHub
  advisories for mailsplit, libmime, libqp, libbase64, iconv-lite and yauzl, rerun the corpus, and
  bump `PARSER_VERSION` if the output changes.

| Dependency           | Pinned | Note                                          |
| -------------------- | ------ | --------------------------------------------- |
| `@zone-eu/mailsplit` | 5.4.29 | Newest release older than 7 days              |
| `libmime`            | 5.6.3  | mailsplit 5.4.29's pin; ships its own types   |
| `libqp`              | 3.0.1  | mailsplit's pin; ships its own types          |
| `libbase64`          | 1.4.1  | mailsplit's pin; ships its own types          |
| `iconv-lite`         | 0.7.3  |                                               |
| `yauzl`              | 3.4.0  | `@types/yauzl` 3.4.0                          |
| `yazl` (dev)         | 3.3.1  | Test-time zip generation; `@types/yazl` 3.3.1 |

## Deviations from the design (documented as required by §0)

1. **Quoted-printable is not decoded with `libqp.Decoder`.** In libqp 3.0.1 that stream
   concatenates the whole part and decodes it on flush, which would hold a full attachment in
   memory. The parser applies `libqp.decode` to line-aligned batches instead. A line over 64 KiB is
   cut outside any escape or soft break. The output is byte-identical to libqp's (tested at every
   split point). Base64 uses `libbase64.decode` over quartet-aligned input, the same segmentation as
   `libbase64.Decoder`, so invalid input can be counted. Bodies are converted with iconv-lite's
   incremental decoder (`getDecoder`, which is what `decodeStream` wraps) so the parser can await
   the sink between chunks.
2. **Embedded messages:** mailsplit parses a `message/rfc822` part as a nested message only when
   its disposition is `inline`. The parser sets `defaultInlineEmbedded: true`, so a message without
   a disposition is parsed too. A `message/rfc822` with `Content-Disposition: attachment`, or with a
   base64/QP transfer encoding, stays a single attachment leaf (`declaredContentType` `message/rfc822`).
3. **Zip names:** yauzl runs with `decodeStrings: false`. With `decodeStrings: true` it rejects the
   whole archive on the first `..` or absolute entry name, which would turn `archive_path_traversal`
   into `archive_malformed`. Names are judged from the raw bytes, and `\` counts as `/`. An entry
   with strong encryption (bit 6) still makes yauzl reject the archive (`archive_malformed`).
4. **Closing delimiters:** mailsplit groups consecutive `data` lines under the node of the first
   line, so a delimiter line cannot be attributed by its chunk's node. One scanner matches every
   `data` line against all open multiparts (innermost first) for `missing_closing_boundary`.
5. `filename_zero_width` and `original_filename_truncated` are additional flags, and
   `stats.inputComplete` is an additional stat. ISO-2022-JP bodies are not supported by
   iconv-lite: they get `unknown_charset` and are stored as read as UTF-8, which is lossless for
   that 7-bit encoding. Encoded words in ISO-2022-JP are decoded by libmime.
6. `part_path` values grow by up to 4 characters per level. A node whose path would be longer
   than `MAX_PART_PATH_CHARS` (128, the `email_attachments.part_path` column) stops the parse as
   `nesting_depth`, like a node below `maxDepth`. The email-worker also refuses a
   `MIME_MAX_DEPTH` / `MIME_MAX_PARTS` pair whose longest path could exceed it. At the default of
   10 a path stays below 45 characters.

## Tests

```sh
pnpm --filter @email-gateway/mime-parser test               # unit + corpus + stress
pnpm --filter @email-gateway/mime-parser fixtures:generate  # rewrite the committed corpus
```

- `src/**/*.test.ts` hold the unit tests: decoders, headers, filenames, sniffer, zip and gzip
  inspectors, the delimiter scanner and the limits.
- `test/corpus.test.ts` regenerates every fixture in memory and asserts byte equality with the
  committed `.eml` files. Each file is marked `-text` in `/.gitattributes`, so CRLF and 8-bit
  bytes survive, and it is excluded from Prettier. The test then checks each fixture's status,
  defects and limits, and that every stored object matches its hash.
- `test/limits.test.ts` checks every M5 limit at the limit and at limit + 1.
- `test/defects.test.ts` checks every M6 code, and `test/errors.test.ts` the error mapping.
- `test/structure.test.ts` checks the tree, body selection, charsets and backpressure, and
  `test/archives.test.ts` the archives inside messages.
- `test/large.test.ts` streams messages from generators, so they are never built in memory: a
  20 MiB single-line base64 body with bounded heap, a ~50 MiB message near
  `MIME_MAX_MESSAGE_BYTES` with a 20 MiB attachment, a message over the body and attachment
  limits, and one over the message size.
- Zip bombs (200 MiB of zeros deflated, 1 001 entries, the encrypted flag, overlapping entries,
  path traversal, zip64) and gzip files with a large ISIZE are generated at test time and never
  committed.

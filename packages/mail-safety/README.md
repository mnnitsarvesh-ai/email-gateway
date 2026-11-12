# @email-gateway/mail-safety

Content safety for quarantined and delivered mail of step 5.3 ([design](../../docs/plan/steps/17-quarantine.md) Q1, Q11, Q22; [ADR-0048](../../docs/architecture/adr/0048-quarantine-preview-and-download-controls.md), [ADR-0049](../../docs/architecture/adr/0049-policy-copy-body-edits-banners-and-url-rewrite.md)): the sanitized quarantine preview, DLP masking, link defanging, signed/encrypted detection and the streaming WARN body banner. Used by the api (preview) and the policy-engine (banner in the policy copy).

## Invariants

- **The preview is JSON text, never HTML.** HTML parts are reduced to text with parse5 (scripts, styles, frames, objects, forms, SVG, MathML, templates and the head dropped; images and media become placeholders; no attribute is ever copied); comments disappear; entities are decoded; control, bidi and zero-width characters are removed; Unicode NFC; bounded length with a `truncated` flag. The api never parses the raw EML: it passes the decoded parts of step 3.1.
- **Links are never clickable.** Every URL is listed defanged (`hxxps://host[.]example/…`, no userinfo, other schemes `<scheme>:[removed]`) with a number and its stored verdict; the body shows `text [link N]`.
- **DLP values are masked** with every built-in value detector of `@email-gateway/dlp`, independent of tenant DLP settings: cards keep the first 6 and last 4 digits, everything else becomes `•`.
- **A banner never breaks a signature.** Signed (S/MIME, PGP) and encrypted messages are passed through and recorded (`skipped_signed`, `skipped_encrypted`); the edit mirrors the 4.3 URL rewriter (mailsplit, original transfer encoding, lossless charset round trip, untouched parts byte-identical).
- **Pure.** No I/O except the caller's streams, no clock (`now` is a parameter), no logger.

## API

| Export                                                                                          | Purpose                                                                                       |
| ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `renderPreview(input): QuarantinePreview`, `quarantinePreviewSchema`, `DEFAULT_PREVIEW_LIMITS`  | Q11 preview from header rows, decoded text/HTML parts, attachment and URL facts               |
| `maskDlp(text, { now }): { text, masked, categories }`, `dlpCandidates`                         | Q11 DLP masking                                                                               |
| `defangUrl(url): { displayUrl, host, identitySha256 }`                                          | Q11 link display; `identitySha256` matches `message_urls.url_sha256`                          |
| `htmlToPreviewText(html, limits, onLink)`                                                       | the HTML → text converter used by the preview                                                 |
| `detectSignedOrEncrypted(structure, headBytes)`                                                 | Q22 pre-check on `email_message_parses.structure` and the first 64 KiB of the candidate parts |
| `insertWarningBanner({ source, sink, level, text, limits, structure? }): Promise<BannerResult>` | Q22 streaming banner; a skip destroys the sink (the caller delivers its input unchanged)      |
| `insertWarningBannerBuffer(input, options): { result, output }`                                 | buffer form: `output` is the input when skipped                                               |
| `bannerText`, `textBanner`, `htmlBanner`, `BANNER_TEMPLATES`, `BANNER_STATUSES`                 | fixed templates per level                                                                     |

Precisions and the contract for WP3/WP4: [step 5.3 §12.2](../../docs/plan/steps/17-quarantine.md#122-wp2-pure-libraries) (the merged WP2 note).

## Tests

`pnpm --filter @email-gateway/mail-safety test` (no infrastructure): the sanitization corpus (scripts, event handlers, `javascript:` links, remote images, data URIs, CSS, `<base>`, iframes, forms, SVG, MathML, comments, entities, bidi and zero-width characters, malformed and 20 000-level nested HTML, huge input), link defanging and verdicts, DLP masking (cards, IBAN, Aadhaar, PAN, AWS keys, tokens, private keys, e-mail addresses) in the subject, body and headers, attachment listing; banners on text, HTML with and without `<body>`, multipart/alternative (QP + base64), mixed with attachments, 7bit/8bit, CRLF/LF, the 998-octet rule, a UTF-16 part, S/MIME signed and enveloped, PGP/MIME and inline PGP, nested `message/rfc822`, `multipart/related`, size limits, byte identity of untouched parts, the stream contract.

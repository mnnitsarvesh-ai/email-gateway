# DLP engine performance (step 4.5)

Benchmark of the `dlp` engine (design [13-dlp.md](../plan/steps/13-dlp.md) §9 "Benchmark"), run by
WP3 on 2026-11-07.

## How it was measured

```sh
pnpm --filter @email-gateway/email-worker build
pnpm --filter @email-gateway/email-worker bench:dlp                      # concurrency 4, 10 s per run
pnpm --filter @email-gateway/email-worker bench:dlp -- --concurrency=1 \
  --classes=typical,large_text,pdf20,xlsx10k --tenant=plain
```

`apps/email-worker/bench/dlp-bench.ts` drives the real `DlpEngine` adapter (text budget,
extraction routing, `detect()`, classification, policy evaluation, evidence build and seal,
metrics) with the **real extractor pool** (2 children of the compiled `dist` child, under Node's
permission model; no `prlimit` on macOS, so CPU/RSS were enforced by the sampler only). Part reads
(with the SHA-256 check of a full read), the tenant store and the evidence bucket are in memory:
S3 and MySQL latency is not part of these numbers. Each class runs 10 s at a fixed concurrency, one
message per call; `rich` adds 20 tenant custom patterns (re2js) and 3 dictionaries of 100 terms.

**Machine:** Apple M5 Pro (15 cores), 24 GiB, macOS (Darwin 25.3), Node v22.23.4, on the host
(not in the 8 GB Docker VM), with the local Compose infrastructure idle.

| Class        | Input                                                      | Size / message |
| ------------ | ---------------------------------------------------------- | -------------- |
| `typical`    | 8 KiB text body + 20 KiB HTML body, 2 findings (card, PAN) | 28 KiB         |
| `large_text` | 4 MiB text body (a card at the start)                      | 4 MiB          |
| `pdf20`      | 20-page PDF (Flate, repeated prose; one card on page 4)    | 9 KiB          |
| `docx200k`   | DOCX of 3 000 random-word paragraphs + one card            | 166 KiB        |
| `xlsx10k`    | XLSX with 10 000 rows (PAN every 500 rows)                 | 243 KiB        |
| `zip20`      | ZIP of 20 DOCX (60 random-word paragraphs each; one card)  | 89 KiB         |

## Results (p50 / p95 in ms; concurrency 4 unless noted)

| Class        | Tenant | msg/s | MiB/s | extract       | detect        | policy*     | seal        | total         |
| ------------ | ------ | ----- | ----- | ------------- | ------------- | ----------- | ----------- | ------------- |
| `typical`    | plain  | 97.1  | 2.60  | —             | 40.1 / 44.6   | 0.04 / 0.08 | 0.04 / 0.07 | 40.3 / 45.2   |
| `typical`    | rich   | 99.1  | 2.65  | —             | 39.5 / 44.4   | 0.03 / 0.08 | 0.02 / 0.06 | 39.7 / 44.6   |
| `large_text` | plain  | 0.66  | 2.63  | —             | 6 066 / 6 078 | 0.03 / 0.11 | 0.03 / 0.08 | 6 073 / 6 081 |
| `large_text` | rich   | 0.66  | 2.65  | —             | 6 039 / 6 052 | 0.03 / 0.13 | 0.03 / 0.08 | 6 042 / 6 055 |
| `pdf20`      | plain  | 36.2  | 0.32  | 65.6 / 92.9   | 47.3 / 79.9   | 0.07 / 0.11 | 0.07 / 0.11 | 104.7 / 142.4 |
| `pdf20`      | rich   | 38.0  | 0.34  | 63.0 / 90.6   | 46.3 / 73.1   | 0.06 / 0.08 | 0.06 / 0.08 | 101.5 / 125.5 |
| `docx200k`   | plain  | 7.23  | 1.17  | 177.3 / 258.8 | 372.8 / 440.0 | 0.07 / 0.09 | 0.07 / 0.09 | 554.8 / 617.0 |
| `docx200k`   | rich   | 7.22  | 1.17  | 168.5 / 236.5 | 380.9 / 470.3 | 0.06 / 0.08 | 0.06 / 0.08 | 553.0 / 637.2 |
| `xlsx10k`    | plain  | 5.90  | 1.40  | 260.6 / 339.1 | 432.8 / 505.9 | 0.08 / 0.12 | 0.08 / 0.09 | 680.7 / 761.2 |
| `xlsx10k`    | rich   | 5.80  | 1.37  | 254.1 / 339.0 | 437.1 / 513.1 | 0.08 / 0.09 | 0.07 / 0.08 | 684.7 / 788.1 |
| `zip20`      | plain  | 20.0  | 1.75  | 29.9 / 40.0   | 168.1 / 179.8 | 0.07 / 0.10 | 0.06 / 0.09 | 197.4 / 216.3 |
| `zip20`      | rich   | 19.7  | 1.72  | 30.5 / 51.6   | 171.6 / 179.7 | 0.08 / 0.09 | 0.06 / 0.10 | 201.9 / 218.7 |

\* `policy` = classification + coverage composition + `evaluateDlpPolicy` (no tenant policy: the
platform default). `read` (in-memory, hash check) was ≤ 2.1 ms in every class (4 MiB body).

Concurrency 1 (one message at a time, plain tenant):

| Class        | msg/s | extract     | detect        | total         |
| ------------ | ----- | ----------- | ------------- | ------------- |
| `typical`    | 96.8  | —           | 9.8 / 11.2    | 10.1 / 11.6   |
| `large_text` | 0.64  | —           | 1 544 / 1 647 | 1 547 / 1 650 |
| `pdf20`      | 23.9  | 15.8 / 25.1 | 23.7 / 26.0   | 40.0 / 50.4   |
| `xlsx10k`    | 4.75  | 34.6 / 52.1 | 168.1 / 186.4 | 205.5 / 225.6 |

## Against the targets (§9, not gates)

| Target                                    | Result                                                                                                                                                                    |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| typical p95 < 50 ms detect                | **met**: 44.6 ms at concurrency 4, 11.2 ms at concurrency 1                                                                                                               |
| 4 MiB text p95 < 2 s                      | **met at concurrency 1** (1.65 s); **missed at concurrency 4** (6.08 s): detection is CPU-bound on the worker's event loop, so 4 concurrent 4 MiB messages share one core |
| extraction p95 < 1 s for office documents | **met**: DOCX 259 ms, XLSX 339 ms, ZIP of 20 DOCX 52 ms (p95, concurrency 4)                                                                                              |
| extraction p95 < 3 s for the 20-page PDF  | **met**: 93 ms (this PDF is small and text-only; complex PDFs with CID fonts will be slower)                                                                              |

## Observations

- **Detection dominates** every class except the PDF; it runs on the worker's main thread
  (chunked with event-loop yields, D3), so its latency grows with `SCAN_DLP_CONCURRENCY` when the
  messages are large. Throughput is bounded by one core per replica for text: ≈ 2.6 MiB/s of text
  per replica on this machine. Scale replicas (not `SCAN_DLP_CONCURRENCY`) for text-heavy load.
  Since the closer review (2026-11-08) the 15 s `DLP_DETECT_TIMEOUT_MS` is measured on each
  message's own detection work (a `WorkClock` paused while detection yields the loop), so the
  wall time other concurrent messages take no longer counts against it; the latency above is
  unchanged (it is wall time) and still misses the 2 s target for 4 MiB at concurrency 4.
- Extraction runs in the 2 children in parallel with the main thread; it is not the bottleneck at
  these sizes. Since the closer review the attachments of one message are extracted up to
  `DLP_EXTRACTOR_POOL_SIZE` at a time (results consumed in part order, so the result does not
  depend on completion order); this benchmark was not rerun after that change.
- 20 custom patterns and 3 dictionaries add no measurable cost at these sizes (re2js scans stop at
  `DLP_CUSTOM_SCAN_MAX_CHARS`; dictionaries share the one phrase trie).
- Policy evaluation and evidence sealing are below 0.3 ms p95 in every class.
- WP2 measured `detect()` alone on 4 MiB of probe text at ≈ 2.1 s; the engine run here (≈ 1.5 s at
  concurrency 1) scans mostly ASCII filler, which normalizes faster.

Raw JSON lines of these runs are reproduced by the commands above; they were not committed.

# Attachment scanning: local benchmark (step 4.2 A20)

**These are local single-VM numbers, not capacity figures.** They were measured on one developer machine with clamd, MySQL, RabbitMQ, Redis, MinIO and the rest of the local stack sharing an 8 GB Docker VM; production sizing follows [docs/deployment/attachment-scanning.md](../deployment/attachment-scanning.md) and must be measured on production-like clamd pods.

## Setup

- Host: Apple M5 Pro (15 cores), 24 GiB, macOS; Node 22.23.4. Docker Desktop VM: linux/arm64, 15 CPUs, **8 GB** (≈ 7.7 GiB usable), every infrastructure service of `docker compose` running, apps idle.
- clamd: `clamav/clamav-debian:1.4`, `ClamAV 1.4.6/28174`, `infrastructure/clamav/clamd.conf` (**`MaxThreads 4`**, `ConcurrentDatabaseReload no`, `mem_limit 2048m`), reached over TCP on 127.0.0.1:3310 (Docker Desktop port forwarding adds latency to every INSTREAM byte).
- Worker side on the host: the real `AttachmentEngine` (mapping, byte budget, cache, metrics), the real `InspectorPool` (**pool 2**, compiled `dist` child under Node's permission model, `best_effort` rlimits on macOS: no prlimit), the real `ClamdClient` (4 connections); `--cache=on` uses the real Redis. S3 part reads and the MySQL catalog lookups are in-memory fakes (not measured).
- Workload: one attachment per message, **concurrency 4**, 10 s per run, generated files (`tests/fixtures/attachment-corpus`): `plain` = a PDF-like file of incompressible filler, `zip` = that PDF deflated in a zip, `nested3` = zip in zip in zip, `gzip`; sizes 10 KiB, 100 KiB, 1 MiB, 5 MiB, 25 MiB (archive payloads 16 KiB below the class). Cache off: every call scans a distinct but valid file (also defeating clamd's internal clean-file cache); cache on: each worker repeats one file (hits after its first scan).
- Command: `pnpm --filter @email-gateway/email-worker build && pnpm --filter @email-gateway/email-worker bench:attachments -- --duration=10` (equivalently `npx tsx bench/attachment-bench.ts --duration=10` in `apps/email-worker`). Stages: `clamav` = one INSTREAM call, `inspect` = one inspector job (IPC transfer included), `total` = one engine call (cache, both stages in parallel, mapping). MiB/s counts attachment bytes.

## Results (2026-11-05)

| Cache | Size | Kind    | Files | Files/s |   MiB/s | clamd p50 / p95 (ms) | inspect p50 / p95 (ms) | total p50 / p95 (ms) | Verdicts    |
| ----- | ---- | ------- | ----: | ------: | ------: | -------------------: | ---------------------: | -------------------: | ----------- |
| off   | 10k  | plain   |  2786 |  278.36 |    2.72 |            13 / 22.9 |                3 / 6.7 |          13.1 / 23.2 | clean 2786  |
| off   | 10k  | zip     |  3789 |  378.74 |    0.42 |           8.7 / 16.1 |             5.5 / 16.5 |           9.3 / 18.8 | clean 3789  |
| off   | 10k  | nested3 |  3648 |  364.67 |    0.49 |             9.1 / 17 |             5.6 / 14.4 |            10 / 18.1 | clean 3648  |
| off   | 10k  | gzip    |  3493 |  349.08 |    0.36 |            10 / 19.3 |             4.2 / 10.9 |          10.1 / 19.8 | clean 3493  |
| off   | 100k | plain   |  1246 |  124.18 |   12.13 |          27.6 / 55.6 |              5.2 / 9.3 |            27.7 / 56 | clean 1246  |
| off   | 100k | zip     |   636 |   63.33 |     5.2 |          59.1 / 83.4 |              4.3 / 8.3 |          59.2 / 83.6 | clean 636   |
| off   | 100k | nested3 |   483 |   48.01 |    3.96 |         68.4 / 161.4 |               6.6 / 27 |           68.6 / 162 | clean 483   |
| off   | 100k | gzip    |  2037 |  203.29 |   16.69 |          17.9 / 29.9 |              5.7 / 9.3 |            18 / 30.1 | clean 2037  |
| off   | 1m   | plain   |   246 |   24.31 |   24.31 |        139.3 / 335.2 |              4.1 / 9.4 |        139.6 / 335.5 | clean 246   |
| off   | 1m   | zip     |    60 |    5.69 |     5.6 |        648.2 / 879.5 |             9.6 / 24.8 |        648.4 / 879.8 | clean 60    |
| off   | 1m   | nested3 |    49 |    4.71 |    4.64 |       612.8 / 1705.1 |            16.2 / 29.1 |         613 / 1707.9 | clean 49    |
| off   | 1m   | gzip    |   362 |   35.98 |   35.43 |        103.7 / 159.7 |              10.3 / 22 |        103.9 / 159.9 | clean 362   |
| off   | 5m   | plain   |    60 |    5.92 |   29.58 |       594.8 / 1243.1 |            17.2 / 34.2 |       595.4 / 1243.3 | clean 60    |
| off   | 5m   | zip     |    16 |    1.24 |    6.19 |        3210.8 / 3516 |            55.4 / 98.7 |        3211 / 3516.3 | clean 16    |
| off   | 5m   | nested3 |     8 |    0.46 |    2.29 |      8643.9 / 8697.9 |           81.2 / 126.5 |      8651.3 / 8698.5 | clean 8     |
| off   | 5m   | gzip    |    86 |    8.43 |   42.04 |        416.7 / 730.8 |            31.2 / 48.8 |          417 / 738.2 | clean 86    |
| off   | 25m  | plain   |    17 |    1.38 |   34.38 |      2702.5 / 3743.4 |             47 / 142.5 |      2740.3 / 3768.2 | clean 17    |
| off   | 25m  | zip     |     4 |    0.22 |    5.43 |    18221.9 / 18326.7 |          362.2 / 363.1 |    18272.1 / 18364.6 | clean 4     |
| off   | 25m  | nested3 |     4 |    0.09 |    2.17 |    46052.3 / 46061.7 |            532.8 / 566 |    46061.5 / 46084.2 | clean 4     |
| off   | 25m  | gzip    |    14 |    1.19 |   29.81 |      3078.4 / 4143.6 |          159.1 / 361.6 |        3094 / 4144.1 | clean 14    |
| on    | 10k  | plain   | 83300 | 8329.89 |   81.35 |          21.2 / 21.6 |                7.4 / 8 |            0.4 / 0.8 | clean 83300 |
| on    | 10k  | zip     | 85692 | 8569.04 |    9.45 |          56.5 / 57.5 |              5.5 / 6.4 |            0.4 / 0.7 | clean 85692 |
| on    | 10k  | nested3 | 84766 | 8476.46 |   11.43 |          16.2 / 18.4 |              5.3 / 5.5 |            0.4 / 0.7 | clean 84766 |
| on    | 10k  | gzip    | 85802 | 8580.12 |    8.57 |          13.3 / 14.4 |              3.8 / 4.1 |            0.4 / 0.7 | clean 85802 |
| on    | 100k | plain   | 65823 |    6582 |  642.77 |            63.7 / 64 |              5.1 / 5.3 |            0.5 / 0.8 | clean 65823 |
| on    | 100k | zip     | 64713 | 6471.16 |  531.81 |          119 / 125.5 |            10.5 / 12.8 |            0.5 / 0.9 | clean 64713 |
| on    | 100k | nested3 | 61029 | 6102.78 |  503.03 |        269.1 / 271.3 |            54.4 / 55.5 |            0.5 / 0.9 | clean 61029 |
| on    | 100k | gzip    | 65529 | 6552.61 |  537.82 |          34.3 / 35.7 |              5.2 / 6.7 |            0.5 / 0.8 | clean 65529 |
| on    | 1m   | plain   | 17624 | 1762.29 | 1762.29 |            212 / 214 |              8.9 / 9.3 |            1.6 / 2.1 | clean 17624 |
| on    | 1m   | zip     | 16715 | 1671.38 | 1645.97 |        644.4 / 646.6 |              30.8 / 40 |            1.6 / 2.2 | clean 16715 |
| on    | 1m   | nested3 | 13973 | 1397.14 | 1376.25 |        2121 / 2126.2 |            206.9 / 213 |            1.6 / 2.2 | clean 13973 |
| on    | 1m   | gzip    | 17523 |  1752.2 | 1725.38 |        211.6 / 221.3 |              18 / 18.5 |            1.6 / 2.1 | clean 17523 |
| on    | 5m   | plain   |  3554 |  355.34 | 1776.68 |        934.5 / 937.9 |            192 / 194.4 |            7.6 / 8.5 | clean 3554  |
| on    | 5m   | zip     |  2530 |  252.96 | 1261.25 |        3579 / 3628.6 |          313.4 / 313.5 |            7.6 / 8.4 | clean 2530  |
| on    | 5m   | nested3 |   299 |   29.89 |  149.06 |      9206.4 / 9227.8 |          176.6 / 180.1 |           7.6 / 12.5 | clean 299   |
| on    | 5m   | gzip    |  3443 |   344.2 | 1716.17 |      1280.7 / 1288.7 |          202.3 / 210.1 |            7.5 / 8.4 | clean 3443  |
| on    | 25m  | plain   |   531 |   53.09 | 1327.17 |      3112.3 / 3953.7 |          330.5 / 332.5 |          37.2 / 46.4 | clean 531   |
| on    | 25m  | zip     |     4 |    0.23 |    5.63 |    16749.5 / 17643.3 |          446.8 / 447.5 |      16843 / 17722.6 | clean 4     |
| on    | 25m  | nested3 |     4 |    0.09 |    2.21 |    43902.4 / 45087.1 |            630 / 630.8 |      43957.9 / 45128 | clean 4     |
| on    | 25m  | gzip    |   398 |   39.31 |  982.38 |      3479.5 / 4987.8 |         685.6 / 4663.4 |          25.8 / 31.3 | clean 398   |

## Reading the numbers

- **clamd dominates** every uncached run: the inspector (type detection, archive walk, YARA-X) takes 3–50 ms up to 5 MiB and ~0.5 s for 25 MiB archives, while clamd takes 13 ms (10 KiB) to 2.7 s (25 MiB plain) and much longer for archives of incompressible PDF-like content (it unpacks and parses every member: 18 s for a 25 MiB zip, 46 s for the depth-3 nesting). With `MaxThreads 4` and 4 concurrent calls, these are per-thread costs; throughput scales with clamd threads/pods (`CLAMAV_MAX_CONNECTIONS × workers ≤ MaxThreads × clamd pods`). The worst case (25 MiB nested zip, 46 s) stays below `CLAMAV_TIMEOUT_MS` (60 s) but would need more clamd capacity under load; uncommon real attachments of that shape are the reason for the per-call timeout and the attempt budget.
- **The content cache removes both stages**: hits cost 0.4–2 ms up to 1 MiB and 7–37 ms for 5–25 MiB (the S3 read is faked here; in production a hit still saves the S3 read, clamd and the inspector — only the cache GET and the catalog lookup remain). The cache-on 25 MiB zip and nested3 rows show **no hits** within the 10 s window because each worker's first (uncached) scan took longer than the run; they measure the uncached path again.
- Inspector p95 for 25 MiB gzip with the cache on (4.6 s) is one outlier while clamd's 25 MiB scans saturated the VM; the median is 0.7 s.
- Not measured: S3 and MySQL latency, the round orchestration (ledger, finalize transaction, outbox), Linux `/proc` sampling vs macOS `ps` (the host sampler spawns `ps` every 100 ms per busy child), prlimit, concurrent clamd reloads, more than one clamd.

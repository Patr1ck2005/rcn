# Storage algorithms: implementation and measured boundary

2026-10-24, isolated branch `codex/storage-algorithms`, based on c910ec4 plus
the parent-supplied live dispatcher/repository/SSH hotfixes. No production state,
scientific parameters, priorities, slots, owner pause, or 10 GiB reserve changed.
Interface and adapter contracts are in [storage-algorithm-interfaces.md](storage-algorithm-interfaces.md).

## Delivery and integration

- Member collection uses an event-driven FIFO and one earliest-deadline timer for
  real fault backoff. Same actor/center/job/destination requests attach to one
  canonical writer and reuse its durable partials. Completed reuse revalidates
  current producer/authorization. Alias pause and original pause remain separate.
- Dispatch policy lookup is once per unique user, preserving the exact ordering.
- Inventory GET uses derived metadata only. Incremental manifests, custody events
  and deletion outcomes update logical bytes, pending custody, eligible and
  confirmed retired categories; bounded backfill and hourly growth are rebuildable.
  Registered volumes and claim samples run in the existing maintenance tick.
  Forecast uses confirmed normal file-event buckets, not whole-volume free-space
  changes. Baseline/backfill/registered migration copies are excluded; estimates
  explicitly describe managed logical growth, with no estimate when events are absent.
- Actual occupancy uses exact registered paths, a persistent cursor, 32-file and
  25 ms limits. Windows native allocation/file identity deduplicates registered
  hardlinks. Missing, stale, compressed/sparse or unregistered allocations remain
  unknown. No recursive scanner, payload hashing, remote probing or volume probe
  occurs on the dashboard GET. A single OS call cannot be forcibly time-bounded.
- Registered WKR and requester-local sources provide actual bytes through the
  existing verified handle/Range/collection path. Scientific custody retains the
  original acceptance/manifest identity, excludes supplemental files from original
  downloads and preserves intentionally retired MPH 410. Revocation is rechecked.
  Atomic source closure/drain and lifecycle writer permits protect retirement.
- Member, durable SDK and CLI collection discover existing requester-local
  registrations on explicit runs. Browser browsing performs no restore. WKR's
  formal Workbench adapter and installed cross-product verification belong to the
  parent integration; they are not claimed here.

No new dependency, database file, daemon or autonomous discovery service was added.
The parent owns web changes in the same worktree; this commit excludes them.

## Verification

All commands used the existing QA Python with explicit `PYTHONPATH=src`, cleared
inherited `RCN_*`, and isolated RCN_HOME/TEMP beneath `.scratch/algorithm-tests`.
The machine-readable JUnit receipts remain there:

| Receipt | Result | Scope |
| --- | --- | --- |
| final-storage.xml | 235 passed, 1 skipped | Lifecycle, HTTP, scientific retention, preparation, member recovery, collection/CLI/SDK/capacity and new source/inventory boundaries |
| final-dispatch.xml | 87 passed | Priority, fairness, refill, reap latency, recovery evidence and new algorithms/inventory |
| final-boundaries.xml | 18 passed | Latest inventory cursor, foreground arrival and locator invalidation; queue, projection, policy lookup |
| final-source-index.xml | 7 passed | Latest source registration, scientific revocation/MPH and actual local SDK/CLI path |
| final-forecast-events.xml | 19 passed | Latest forecast attribution, migration/backfill exclusion and unchanged algorithm/occupancy boundaries |

These suites overlap; the counts are not additive. The broad storage run emitted
existing deprecation warnings and one non-failing subprocess stderr reader
UnicodeDecodeError from a PowerShell capacity probe. Later focused runs emitted
only the existing TestClient deprecation warning. The one skip was retained.

Behavioral assertions include FIFO/no idle timer, one canonical writer,
same-target frozen binding, current authorization, source close/drain versus
unlink admission, preserved original Attempt, native hardlink dedup, cursor/time
limits, no data-path/history-table access from snapshot, and capacity wait leaving
GC eligible. All three supplied hotfix files are preserved, with projection hooks
added only to repository manifest writes.

## Paired measurements and unresolved performance gate

Raw samples, including failures, are committed in
[evidence/storage-algorithms-20261024](evidence/storage-algorithms-20261024).
The reproducible entrypoint is `tools/benchmark_storage_algorithms.py`.

The final run used 50 valid samples per variant, alternating pair order, 256 Jobs
from 8 users, 8,192 manifest files and a 32 MiB warm-cache read. Scheduling before
is the same function with only the previous per-Job lookup restored; inventory
before is an explicitly labeled full-metadata reduction reference. These are
isolated Windows fixtures, not production full-load or natural-load acceptance.
The subsequent forecast-only correction replaces free-space deltas with existing
hourly file-event data; the timing receipt predates that correction. It is not a
fresh timing claim for the revised forecast aggregation.

| Case | Before/alone p50 ms | After/background p50 ms | Before/alone P95 ms | After/background P95 ms |
| --- | ---: | ---: | ---: | ---: |
| Dispatch sort | 54.327 | 5.248 | 116.944 | 14.706 |
| Inventory query | 15.379 | 2.661 | 21.934 | 4.501 |
| Foreground read, SHA background | 63.376 | 61.898 | 102.812 | 109.491 |
| Dispatch, SHA background | 4.938 | 6.623 | 8.388 | 9.404 |
| Foreground read, native inventory background | 50.032 | 51.635 | 86.591 | 76.055 |
| Dispatch, native inventory background | 7.315 | 9.136 | 12.561 | 14.532 |

The final controlled overlap admits one real background chunk or native probe
immediately before foreground arrival. Every background-enabled sample records
actual work; none passes merely because the dispatch quiet period prevented any
background work from starting. The configured chunk is 16 KiB and dispatch quiet
period is 250 ms. The SHA/read P95 ratio is 1.065; dispatch/SHA is **1.121** and
dispatch/inventory is **1.157**. Therefore the <=10% background degradation gate
is **not passed**. Lower read latency in one pair is not evidence of a speedup.
Do not label this as production throughput acceptance or promote it on that basis.
There was no repeated identical-run search for a passing sample.

Earlier receipts remain unchanged: run-1 (30 samples, 64 KiB) and run-3 (50 samples,
64 KiB) failed the dispatch gate. Run-2 failed setup with a missing namespace name
before collecting samples and has no raw sample file. Run-4 (50 samples, 16 KiB,
250 ms quiet) passed its weaker enabled-worker fixture (read ratio 1.096), but the
worker was not guaranteed to have begun bytes before foreground admission. The
final stronger overlap receipt supersedes that performance conclusion.

The demonstrated complexity changes do not depend on noisy wall time: dispatch
policy database reads are 256 -> 8 for the same order; ordinary storage queries
have zero data traversal/read/hash/remote probes; 256 idle waiters over 120 logical
seconds have 30,720 modeled polling callbacks -> 0 idle callbacks, with FIFO work
only on queue/completion/retry events. Queue fault-deadline sorting remains
O(R log R) per event, rather than introducing another scheduling framework.
Registration builds one file index per receipt, O(F+P), instead of repeated scans.

Remaining acceptance is explicit: parent Workbench/installed two-product adapter
verification, and meeting or explicitly revisiting the foreground performance
gate using meaningful evidence. Functional tests do not discharge either gate.

## Follow-up: real archive priority and bounded native work

The preceding section remains the original `ba31e7d` receipt. The follow-up fixes
actual archive verification and legacy/prepared Range bodies, not just synthetic
background SHA. Normal verification declares demand before waiting for its volume
permit; archives yield at 4 KiB boundaries, close handles/pins and release active
preparation and destination reservations. Deferred/offline tickets retain their
immutable identity without consuming active limits. The existing retry event
re-POSTs the original operation and resumes its durable prefix. Local registered
archives use the same budget, excluding only their own destination claim.

Explicit retrieval tries up to eight registered copies. Missing/offline copies
fall through; bad SHA, permission, changed volume identity and observed revocation
do not. Missing local copies may use the normal remote transfer. All registered
copies offline returns retryable 503; no registered source remains conflict 409.
Prepared-handle expiry/restart races are retryable; the urllib client now retains
bounded structured reason codes, including older servers' exact 409 expiry codes.
Unregistered or intentionally retired scientific files are not resurrected.

The measured investigation found two avoidable costs: SQLite connection context
managers committed but did not close the budget connections, and each Windows
probe rebuilt ctypes types/loaded its DLL wrapper. Budget connections now close
on admission and deferral. Immutable FFI definitions are cached, while handles,
native identity and allocations stay fresh. The 200-probe microprofile reduced
class builds 846 -> 50 and DLL loads 201 -> 2 (the residual includes initial
imports). Median probe time was 0.176 -> 0.117 ms; P95 was noisy, 0.293 -> 0.336 ms,
so this is evidence of removed setup work, not an end-to-end latency guarantee.
See `native-profile-comparison.json` for every sample and function counts.

The intermediate 4 KiB / 8-file / 10 ms run still failed dispatch/inventory P95:
1.1185. It remains in `followup-bounded-preflight.json` with 50 samples per variant
and all 14 preflight deferrals. An earlier incomplete attempt is recorded in
`followup-incomplete.json`; its old harness lost partial timing arrays, and no
acceptance is claimed for it. The harness now writes each sample immediately and
saves partial reports on failure. Windows Python's coarse monotonic clock also
produced 15–16 ms budget jumps; inventory now uses `perf_counter` for its 10 ms
budget. No production clock or lease/fence logic changed.

The final meaningful change checks foreground demand between Windows OS calls,
rather than only between whole probes. A started handle is always closed. The
cursor and projection remain unchanged on deferral. A probe therefore need not
complete its three information calls after foreground arrival.

`followup-native-boundaries.json` retains 50 alternating pairs per variant on the
same 256-Job/8-user, 8,192-file and 32 MiB warm-cache fixtures. Background is
admitted before foreground; the instrumented real OS open executes, then later
native calls can yield. All 100 inventory-background samples record a native call,
and all SHA-background samples record actual bytes. Two preflights expired before
work and are separately retained; neither counts as a valid timed overlap sample.
This matches the smaller production work boundary rather than silently counting
an idle worker as overlap. There was one run of this changed configuration, with
no repeated identical-run search for a pass.

| Case | Alone p50 ms | Background p50 ms | Alone P95 ms | Background P95 ms | P95 ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| Foreground read, SHA | 88.248 | 95.854 | 228.594 | 213.767 | 0.935 |
| Dispatch, SHA | 7.797 | 9.672 | 21.430 | 18.665 | 0.871 |
| Foreground read, native inventory | 119.966 | 128.852 | 216.624 | 202.293 | 0.934 |
| Dispatch, native inventory | 7.504 | 9.397 | 14.441 | 14.295 | 0.990 |

For equal foreground byte counts the aggregate throughput ratios are 0.9869
(SHA, 1.31% lower) and 1.0146 (native inventory). The specified foreground
throughput and scheduling P95 point-estimate gates pass this isolated receipt.
Dispatch-sort P95 is 94.200 -> 17.037 ms; inventory-reference P95 is 35.472 ->
7.401 ms. Raw observations, including CPU clocks and ranges, are preserved.

Variance limits the claim: foreground read times ranged 51–321 ms, and Windows
thread CPU clocks advanced in 15.625 ms increments. Dispatch medians still rose
about 1.9 ms (24–25%); their aggregate rates also fell 12–15%, although the stated
scheduling P95 gate passed. Thus ratios below 1 are not evidence of a speedup or
of improved typical dispatch latency. `variance-and-throughput.json` records these
unfavorable statistics as well. We cannot attribute all tail changes to the native
boundary improvement or promise a production <=10% bound from these samples.
Natural-load/installed validation belongs to the parent release gate.

Release interpretation remains unresolved: the raw `background_target_passed`
field describes its declared P95 point-estimate predicate, not a blanket <=10%
dispatch cost claim. The extra median ~1.9 ms is real in this experiment. The
enabled branch wakes another thread inside the measured interval; the alone
branch has no waiting thread. Event/GIL/OS handoff and production work are not
separated by a null-work control, so assigning all overhead to the benchmark would
be unsupported. The removed FFI setup is much smaller than this residual; OS and
thread scheduling are plausible contributors, not established causes.

A concrete user tradeoff, **not approved or applied**, is to retain the simple
cooperative implementation and permit up to about 2 ms additional median latency
per 256-Job scan, while retaining the existing foreground byte-throughput and
dispatch P95 10% limits and checking natural-load evidence later. If a blanket
10% bound must include median/aggregate dispatch, this receipt does not meet it.
Do not relabel the unfavorable ratios or deploy on a broader performance claim.

Functional coverage includes two registered copies with first missing/second valid
for both custody types; bad SHA never falls through; local missing -> remote;
real archive verification yields its volume slot to a normal read; actual prepared
Range yields after one chunk; original ticket and Range continue after yield,
offline/online and expiry; a three-byte durable partial survives deferral; native
probe deferral closes its handle and leaves accounting unchanged. These checks
also retain 410 retired-model behavior and conflict on revocation/integrity.

Final follow-up suite: **231 passed, 1 skipped**, 141.18 seconds, in
`.scratch/algorithm-tests/followup-final.xml`. It covers archive priority,
registered restore boundaries, storage algorithms, preparation/maintenance,
occupancy, lifecycle/scientific retention, durable/HTTP collection recovery,
member recovery, original transfer and custody clock-skew behavior. Only existing
FastAPI/Starlette deprecation warnings remain. Earlier 227-pass/2-failure receipt
is retained locally; the two failures exposed missing-unregistered-source
classification and were corrected and rerun in this final suite. `git diff
--check` passed. No production probe, deployment or natural full-load claim was
made by this worker. The timing fixture covers real normal verification/reads and
dispatch sorting against lifecycle SHA/native inventory work; real archive HTTP
concurrency is covered by functional tests, not a separate 50-pair HTTP throughput
measurement.

## Confirmed release decision — 2026-10-24

The user accepted approximately 2 ms additional typical latency per 256-Job scan,
while retaining the 10% foreground byte-throughput and dispatch P95 limits. The
50-pair follow-up above satisfies this revised isolated gate: dispatch medians
increase by 1.875/1.893 ms, collection aggregate throughput falls at most 1.31%,
and all four P95 ratios are at most 0.990. This decision does not erase the earlier
failed receipts, establish a blanket <=10% dispatch-cost claim, or constitute
natural production full-load acceptance. No additional component or dynamic
slot/priority rule was introduced to pursue sub-millisecond differences.

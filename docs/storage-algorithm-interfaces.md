# Storage algorithm integration

This branch starts at c910ec4 and preserves the three newer live backend hotfix
files supplied by the parent (dispatcher, repository, schedulers/ssh). The first
member-client delivery is integrated separately.

## Registered restore sources

`RegisteredResultSources(lifecycle, allowed_kind="wkr_archive")` uses the existing
metadata database. No new server or byte cache is created. Trusted origin adapters
register a store with `register_store(root, location, kind, actor_id=...)`, where
`location` is the exact `CustodyLocation` already used in custody receipts. The
store must be local to this host and its physical volume must match. The adapter
then calls `register_receipt_files(receipt_id, paths, actor_id=...)`; `paths` maps
manifest relative paths to relative paths inside that registered root. Opaque
restore references are never parsed as filesystem paths, URLs or commands.

The existing result-preparation factory selects a registered archive only for a
file unavailable from ordinary staging. It keeps the original producer identity,
verifies the opened file, and serves the same handle through existing Range
responses. The client writes directly to its selected registered destination.
Browser metadata reads do not restore anything. Repeated Range admissions recheck
authorization, manifest, store generation and non-revoked custody evidence.

Explicit downloads try at most eight registered candidates with the same exact
manifest/file identity. Missing or offline copies may fall through to another
registered copy; permission errors, changed volume identity, bad SHA and observed
revocation are conflicts. All missing/offline registered copies yield
`restore_source_unavailable` (503). No registration yields
`restore_source_unregistered` (409); intentionally retired MPH remains 410.
`open_verified(..., opener=...)` returns `(source, pin, path, stream, stat)` and
closes/releases each failed candidate before trying the next. Browsing only reads
metadata and never invokes this method.

For requester-local copies, construct the same resolver with
`allowed_kind="requester_local"` and pass it to
`CollectionRunner(..., local_sources=resolver)`. Only a local registered copy is
eligible. Missing local copies fall through to the existing remote transport.
Unavailable remote sources defer the original collection; they do not create
new Jobs or Attempts. The trusted adapter is responsible for its existing
archive-retirement read guard; registry pins and native open handles protect
the registered transfer and can be inspected before archive retirement.

Archive verification and both legacy/prepared Range streams are background work.
Normal verification announces demand before waiting for a volume permit. Archive
verification/body checks the existing budget at 4 KiB boundaries, closes its
handle and pin on deferral, and releases preparation/destination admission.
Dormant `restore_pending` tickets have `storage_background_deferred` or
`restore_source_unavailable`, HTTP 503 and no scarce resource. They do not consume
active preparation limits. Re-POST of the same immutable operation reuses its
ticket; CollectionRunner keeps its durable prefix and original Attempt. Ready
handle expiry/process restart also returns 503; clients recognize these exact
typed reasons from older 409 responses. Revocation/integrity remains paused.

Member, SDK durable download and `origin collect start/resume` also discover an
already registered `requester_local` source in the existing local
`RCN_HOME/control-plane.db` when a download runs. No database is created just for
this discovery. Metadata/status/finalize do not discover or open sources. A resumed
local request revalidates the current authenticated result index once for all its
files before copying; its final SHA and atomic publication remain unchanged.

The same `register_receipt_files` method accepts `custody-*` UnitCustodyReceipt
IDs and `science-custody-*` ScientificCustodyReceipt IDs already in this lifecycle
database. Scientific receipts are joined to their original acceptance to retain
Job/Unit/Attempt and original manifest SHA. Both revocations are rechecked. Only
the exact intersection with the original manifest can use original-result
downloads; supplemental exports do not impersonate original results. Intentionally
retired MPH retains its existing 410 behavior. No new full-inventory attestation
is invented when an old model is absent.

Before an adapter's independently authorized archive unlink, call
`sources.begin_retirement(receipt_id, actor_id=...)`. It durably closes new source
admissions and returns `{closed: true, active_readers: N, drained: bool}`. Wait for
`drained` before deletion; `active_readers()` by itself is not a deletion permit.
Replay registration never reopens a closed source. Keep the origin's native file
guard through the destructive stage as well. This is a read guard, not custody or
scientific-retirement authorization.

The RCN registry is transport metadata. Registration does not attest bytes or
scientific acceptance. A genuine, current custody receipt remains necessary.

## Metadata-only storage inventory API (UI contract)

`GET /v1/admin/storage/inventory` is admin-only and does not rebuild, enumerate,
hash, read a data file, probe a data volume or contact another host. Response:

```json
{
  "schema": 1,
  "generated_at": "ISO UTC",
  "basis": "registered_manifest_bytes",
  "projects": [{"project_id":"p","role":"origin_spool","location":"center","bytes":123,"logical_registered_bytes":123,"physical_bytes":null,"pending_custody_bytes":123,"eligible_bytes":0,"confirmed_retired_bytes":0,"classification_pending":false}],
  "growth_24h": [{"project_id":"p","role":"origin_spool","location":"center","added_bytes":123,"removed_bytes":0,"net_bytes":123,"first_observed_hour":"ISO UTC"}],
  "locations": {"center":{"host_id":"host","store_id":"store","generation":"1","volume_id":"volume","physical_device_id":"disk"}},
  "volumes": [{"host_id":"host","volume_id":"volume","physical_device_id":"disk","location":"center","free_bytes":123,"total_bytes":456,"reserved_bytes":0,"hard_reserve_bytes":10737418240,"usable_bytes":0,"sampled_at":"ISO UTC","growth_bytes_per_day":null,"days_to_reserve":null,"forecast_reason":"insufficient_or_stale_samples","sample_count":1,"stale":false}],
  "backfill_complete": false,
  "unattributed_device_bytes": null,
  "data_reads": 0,
  "coverage": "manifest outputs and registered custody copies; other device usage is unattributed"
}
```

`generated_at` is the metadata response time, not the device sample time. Use
`sampled_at/stale` on each volume. Null growth/ETA is unknown; never display zero
days for it. Forecast requires at least three hourly samples spanning six complete
hour buckets, complete backfill and a volume sample at most 120 seconds old.
`forecast_basis="registered_logical_file_events"` means the rate uses confirmed
normal file additions/deletions mapped to that volume. Initial/backfill/registered
copy imports do not emit growth; unrelated volume free-space changes cannot become
growth. `forecast_reason="no_confirmed_natural_growth"` leaves growth/ETA null when
no eligible events exist. Positive estimates use `registered_file_growth_estimate`;
nonpositive growth has no exhaustion date. This is an estimate of managed logical
file growth, not a whole-device or measured allocated-byte forecast; unregistered
usage remains excluded. Admission and the 10 GiB reserve are unchanged.

Project bytes are attributed managed copies, not total device occupancy. Distinct
physical copies count separately; role paths do not create extra free capacity.
Use location host/volume identity for grouping. The first increment covers result
manifests and registered custody copies; unregistered data and input caches remain
explicitly unattributed. Existing `/v1/admin/storage/status` is unchanged.

`pending_custody_bytes`, `eligible_bytes`, and `confirmed_retired_bytes` describe
the center copy. Pending/eligible become null while a receipt/policy event awaits
bounded recomputation. Eligibility is metadata custody eligibility; live-reader,
source-byte and current-policy guards are still mandatory before deletion.
Confirmed retirement comes only from the durable exact-file deletion result.
Other locations remain null where no local retirement evidence exists.

Registered archive volumes are sampled round-robin by the existing maintenance
callback. Unsampled/offline volumes appear with null bytes and `stale: true`.
Ordinary dashboard loading must use inventory only: the older status endpoint
intentionally performs live validation and is not a zero-probe read. No new
recursive actual-occupancy scanner is included. Exact registered paths are
inventoried by the same maintenance callback with a durable cursor, at most 8
files and a 10 ms high-resolution elapsed budget per tick. A single native
filesystem call cannot be interrupted; foreground demand is checked between
Windows native calls and no additional file starts after the budget expires.

Windows uses one native attributes handle with FileStandardInfo and FileIdInfo;
POSIX uses `st_blocks` and native device/inode. No payload is read or hashed.
Unknown, inaccessible, reparse, and unsupported compressed/sparse files stay
unknown. Each row exposes `registered_files`, `measured_files`,
`observed_allocated_bytes`, `physical_bytes`, `occupancy_oldest_observed_at` and
`occupancy_stale`. `physical_bytes` is null until all its registered resident
paths are measured and the oldest measurement is under 24 hours old. The
`occupancy_inventory` object gives cursor and last completed pass time.

Hardlinks to the same native physical object count once across registered paths.
For deterministic additive project/role totals its allocation is attributed to
the first registered path (`physical_attribution=unique_object_first_registered_path`),
while each path retains its logical byte count. These are observed allocations,
not reclaimable bytes: unregistered hardlinks, unrelated files and other device
usage remain outside coverage. No delete decision consumes this estimate.

Background source SHA chunks are 4 KiB. An active foreground collection/read or
admitted write defers background bytes; dispatch sorting also reserves 250 ms of
quiet time after each scan to avoid immediately restarting background work between
refill passes. This changes no slot, priority, policy or machine-owner pause.
Volume/claim metadata sampling is separate so it can report active reservations.

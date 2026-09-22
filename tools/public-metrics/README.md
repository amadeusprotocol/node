# Amadeus public activity metrics

## DefiLlama submission bundle

`dimension-adapters.patch` contains the activity adapter against DefiLlama commit
`55ac76d33912afa294a22b3838b22e8f4041d92d`. Apply it in a clean checkout with
`git apply /path/to/dimension-adapters.patch`. The adapter remains pending
upstream review and the live-data prerequisites below; it is not a listing.

For a cross-repository test, arrange sibling checkouts named `node`, `sdk`, and
`dimension-adapters`, install their documented dependencies and build the SDK.
Run `node --test tools/public-metrics/verify-integration.cjs` from the node repo.
`AMADEUS_INTEGRATION_ROOT` can override the parent directory of these checkouts.
Only synthetic local data is used; the test exercises the real HTTP service,
built SDK and DefiLlama runner. Publishing the node/SDK source does not publish
an npm release or deploy the analytics service.

Read-only node evidence, a resumable SQLite index, a public daily API, and a
hash-pinned external block-time importer. Requires Node.js 24+. No npm
dependencies. Analytics runs separately from consensus and never writes the
node's RocksDB database.

## Release constraint

Amadeus entry headers have **no UTC timestamp**. `DB.Entry.seentime` is local
receipt time and changes when a node downloads history. Transaction nonces and
an assumed 500 ms block interval are not block timestamps. The node export
therefore returns `timestamp: null`. Indexing works without timestamps, but
daily metrics remain incomplete until a reviewed archive supplies UTC seconds
keyed by canonical block hash and height. SHA-256 pins the archive bytes; it
does not make its time assertions consensus-authenticated.

Do not submit this as a live DefiLlama source until archive provenance and
methodology are reviewed, a public deployment exists, and real historical days
have been compared. No historical traction figures are manufactured.

## Node API

Block exports also include nullable `node_seen_time_ms` (Unix milliseconds)
and `node_seen_time_basis: "local_database_insertion"`. This exposes the
existing DB.Entry.seentime value for historical provenance audits. It is local
node insertion time, including blocks inserted during sync; it is not a
consensus timestamp or proof of original reception. Missing values stay null.
The collector does not use it for daily attribution. `timestamp` stays null
until an independently reviewed time source supports the existing import flow.

Deploy the accompanying API.Metrics module and HTTP routes on an archival node:

- `GET /api/chain/metrics/status`: chain ID, rooted height, pruning boundary.
- `GET /api/chain/metrics/block/123`: one canonical rooted block, parent hash,
  transaction hashes, signers, and explicit execution success.

The block route selects the canonical hash, checks rooted height and receipt
identity, and rechecks the canonical hash/root after reading. Pruned/missing
history and unknown receipts are errors. It does not use the ordinary RPC
pruning proxy, which could mix sources. Source identity is the Base58 genesis
hash. Mainnet: `HsFp8cZeFuPxBmJcjvfwYu9MqXZi8fW6XxecLfyHEqEY`.

## Run

From the repository root, create a persistent data directory and use an actual
archival RPC deployment. The example loopback node is not a live service claim.

```sh
node tools/public-metrics/cli.mjs sync --db /srv/ama-metrics/activity.sqlite --chain-id HsFp8cZeFuPxBmJcjvfwYu9MqXZi8fW6XxecLfyHEqEY --rpc http://127.0.0.1:8000 --limit 100
node tools/public-metrics/cli.mjs status --db /srv/ama-metrics/activity.sqlite --chain-id HsFp8cZeFuPxBmJcjvfwYu9MqXZi8fW6XxecLfyHEqEY
node tools/public-metrics/cli.mjs serve --db /srv/ama-metrics/activity.sqlite --chain-id HsFp8cZeFuPxBmJcjvfwYu9MqXZi8fW6XxecLfyHEqEY
```

`sync` processes a bounded batch (1..10,000 blocks), then exits. Repeat it serially
under the deployment supervisor, checking exit codes. Every batch verifies the
saved checkpoint. Blocks and signers commit atomically. Exact replays have no
effect; gaps, duplicate transactions, wrong networks and conflicting receipts
fail. Changed finalized history or parents quarantine the index: public counts
become null until the source is reconciled and the database rebuilt. No
automatic fork rewrite or quarantine reset.

Default indexing begins at height 0. Deliberate `--start-height N` creates a
partial index; pass it consistently for all commands using that database.
Globally new addresses remain null for partial indices. Never infer first-ever
activity from a pruned archive or the current balance list.

## Unattended deployment

The container runs the public reader and one serial collector. It retries RPC
outages with capped exponential backoff, resumes the durable checkpoint, aborts
in-flight requests on shutdown, and exits on quarantined history. Retries never
skip blocks. The container is unprivileged, its root filesystem is read-only,
and the database lives on a persistent volume. Docker health does not imply
that historical dates have complete time coverage.

From this directory, after deploying the node exporter on an archival RPC:

```sh
export AMA_METRICS_RPC=https://YOUR-ARCHIVAL-RPC
docker compose up -d --build
docker compose logs --tail=50 metrics
curl --fail http://127.0.0.1:8788/healthz
```

The host port is loopback-only. Configure the existing HTTPS reverse proxy to
forward the metrics paths and health check to port 8788. No production hostname
is assumed. `compose down` preserves the volume; do not use `down --volumes`.
Pin the tested image digest in the production deployment after building it.
Rollback code with the previous image while retaining the volume. Never reset
quarantine to restore a green health check; reconcile the source first.

Without containers, set `AMA_METRICS_DB`, `AMA_METRICS_CHAIN_ID`, and
`AMA_METRICS_RPC`, then run `node tools/public-metrics/daemon.mjs` under the host
supervisor. Optional variables: `AMA_METRICS_HOST` (default 127.0.0.1),
`AMA_METRICS_PORT` (8788), `AMA_METRICS_START_HEIGHT` (0), `AMA_METRICS_BATCH`
(100, maximum 10000), and `AMA_METRICS_POLL_MS` (10000). Health returns HTTP 503
until the first successful batch, during source failures, when stale, or when
quarantined. Full backfill batches yield immediately; caught-up polling waits.

After importing reviewed time evidence, run the release check with independent
replay enabled. Any failed check exits nonzero:

```sh
node tools/public-metrics/preflight.mjs --rpc https://YOUR-ARCHIVAL-RPC --public https://YOUR-METRICS-ORIGIN --day 2026-01-02 --day 2026-01-03 --day 2026-01-04 --replay --max-blocks 10000
```

Replace the example dates with actual reviewed coverage. This checks exporter
availability, genesis coverage, service health and complete daily responses,
then recomputes counts from the canonical RPC and published timestamp files.
Omitting `--replay` cannot produce `ready: true`. Readiness remains conditional
on human review of the external UTC methodology and DefiLlama acceptance.

The standalone replayer can check one or more days and emit a JSON evidence
report, without reading the collector database or using its SQL aggregation:

```sh
node tools/public-metrics/verify-days.mjs --rpc https://YOUR-ARCHIVAL-RPC --public https://YOUR-METRICS-ORIGIN --day 2026-01-02 --max-blocks 10000 > replay-report.json
```

Replay reads canonical blocks **from genesis**, once for all selected days, to
verify first-ever successful signers. It checks block continuity, receipt
completeness, archive SHA-256, timestamp-to-block mappings, daily boundaries,
per-day provenance, all five counts, and the final checkpoint. It includes
failed transactions in transaction totals but excludes failed-only signers
from active/new addresses. It trusts the archival RPC for canonical execution
evidence; it does not implement independent consensus or signature validation.

The default 10,000-block budget prevents accidental full-history scans. For
real history, deliberately set it to at least the final boundary height plus
one and use a dedicated archive. First-signer membership uses a disposable
SQLite index in the system temp directory; daily active signer sets use memory.
Ensure sufficient temp disk and memory. Progress goes to stderr, the report to
stdout. An interrupted replay restarts from genesis; no partial success report
is emitted. Published timestamp files must be at most 64 MiB each, with at most
128 distinct files per invocation; split/review large archives accordingly.
SHA pinning verifies bytes, not the truth of a publisher's UTC assertions.

## Import reviewed time evidence

Each JSONL line contains `chain_id`, `height`, `hash`, and `timestamp` (UTC Unix
seconds). Blocks must already be indexed. Review the publisher's methodology,
publish the source file at a stable HTTPS URL and compute its SHA-256:

```sh
node tools/public-metrics/cli.mjs import-times --db /srv/ama-metrics/activity.sqlite --chain-id HsFp8cZeFuPxBmJcjvfwYu9MqXZi8fW6XxecLfyHEqEY --file /srv/ama-metrics/reviewed-times.jsonl --source https://YOUR-PUBLIC-ARCHIVE/reviewed-times.jsonl --sha256 REVIEWED_SHA256
```

Wrong chains/hashes, future/decreasing times and changes to previously imported
times are rejected. Any bad row or file digest rolls back the entire import.
Split large archives into bounded files. Preserve published source files for
independent replay. The service does not fetch user-supplied URLs.

## Public contract and methodology

Expose the loopback service through the existing HTTPS reverse proxy. Apply
edge request limits/timeouts; never expose SQLite files. Routes are GET-only:

- `/v1/metrics/daily?start=2026-01-02&end=2026-01-03`
- `/v1/metrics/status`
- `/v1/metrics/methodology`

Dates are UTC; end is exclusive; maximum range is 31 days. Each day has `blocks`,
`transactions`, `successful_transactions`, `unique_active_addresses`,
`new_addresses`, completeness statuses, height/hash anchors and archive
URLs/digests. Current days, missing boundaries/times and quarantined indices
return explicit reasons and null counts. Zero is reported only with complete
boundary evidence. Genesis can bound the first day of the chain.

Active addresses are distinct successful transaction signers, not people, Hub
logins, holders or validator keys. Includes automated signers. Transactions
include failed executions. New addresses means first successful signing
activity with genesis coverage. No fees, USD values, TVL, agent counts or token
price assumptions are added.

The index retains transaction hashes and signers for exact deduplication.
Mainnet history needs persistent disk capacity planning and measured backfill
and query throughput. Fixture tests are not a 350M-row load test. Use a
dedicated archive for bulk indexing; requests are sequential. Back up SQLite
with online backup tooling, not by copying an active main file without its WAL.

## Verify

```sh
node --test tools/public-metrics/metrics.test.mjs tools/public-metrics/runtime.test.mjs tools/public-metrics/replay.test.mjs
cd ex
elixir -r lib/api/api_metrics.ex -r test/test_helper.exs test/api_metrics_test.exs
```

The isolated Elixir tests use a source double; they do not start RocksDB or
consensus. Before release run the native build/test suite and an archival-node
GET-only smoke test. Independently replay at least three real historical days:
fetch the returned height ranges, join the pinned timestamp archive, recompute
transaction totals and distinct successful signers. First-time signers require
preceding history as well. Verify zero and incomplete cases before listing.

After a full native `mix compile`, run the real-storage smoke check from `ex`
with a **new** disposable directory ending in `/metrics-native-smoke`:

```sh
OFFLINE=true AUTOUPDATE=false AMA_METRICS_NATIVE_SMOKE=1 WORKFOLDER=/tmp/ama-metrics-check/metrics-native-smoke mix run --no-start test/api_metrics_native_smoke.exs
```

It refuses an existing database and starts no node services. It checks empty
root handling, canonical genesis export, finality and pruning against actual
RocksDB. Its explicit fixture finality marker does not validate live consensus
or replace the archival-node smoke test.

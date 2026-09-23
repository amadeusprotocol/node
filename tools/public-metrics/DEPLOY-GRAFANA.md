# Start the DefiLlama collector on the Grafana host

Ivan designated the existing Grafana host for this service. The archival node
exporter is already live at https://mainnet-rpc.ama.one. This service is a
separate Node.js/SQLite container; installing a Grafana dashboard does not run it.

## Operator startup

Use a checkout of this repository on the Grafana host. Check available disk and
memory for retained transaction history, Docker Compose availability, and that
127.0.0.1:8788 is free. Full history capacity/throughput has not been load-tested.
The commands below start collection immediately from genesis, with serial RPC
requests. Do not start multiple writers against the same database.

```sh
cd tools/public-metrics
export AMA_METRICS_RPC=https://mainnet-rpc.ama.one
docker compose -p amadeus-metrics config --quiet
docker compose -p amadeus-metrics up -d --build
docker compose -p amadeus-metrics logs --tail=50 metrics
curl --fail http://127.0.0.1:8788/healthz
curl --fail http://127.0.0.1:8788/v1/metrics/status
```

The health endpoint can initially return 503 before the first batch completes.
Verify that `indexed_tip.height` advances across two status reads and that
`integrity` is `ok`. Capture the running image ID and retain it for rollback:

```sh
docker inspect --format '{{.Image}}' "$(docker compose -p amadeus-metrics ps -q metrics)"
```

The named volume persists through restarts. Stop collection without deleting it:

```sh
docker compose -p amadeus-metrics stop metrics
```

Resume with `docker compose -p amadeus-metrics start metrics`. Never use
`down --volumes`. Use SQLite online backups rather than copying a live database
without its WAL. Restore previous code/image with the same volume for rollback;
do not clear an integrity quarantine just to restore a green health check.

## Public access

Assign a dedicated public HTTPS origin using the host's existing reverse proxy.
Proxy only `/healthz`, `/v1/metrics/status`, `/v1/metrics/methodology`, and
`/v1/metrics/daily` to 127.0.0.1:8788. Apply edge request limits and timeouts.
Keep Grafana's existing login intact. If the proxy is itself containerized,
its loopback is not the host loopback: use the operator's existing private
proxy network rather than exposing port8788 on all public interfaces.

Return the assigned origin, image ID, health output and two status outputs to
the integration owner. No hostname has been provisioned by this repository.

## Time evidence and DefiLlama acceptance

Start indexing transaction evidence now; reviewed time evidence can be imported
later using README.md. Without it, daily counts correctly remain incomplete.
Do not feed `node_seen_time_ms` directly into the timestamp importer. A live
September23 audit found these stored insertion times:

| Height | Stored UTC time |
| --- | --- |
| 39,200,000 | 2025-11-11 09:25:58.584 |
| 39,400,000 | 2025-11-11 06:59:30.974 |

These cannot be chronological block timestamps as-is. They may reflect sync or
restore history. Exact affected boundaries are not established. A separate
31-point sample at heights80M..84.5M had no reversals; sparse sampling does not
verify every block or establish provenance. Recover original times from older
archive backups/logs where needed. Do not interpolate or reorder observations.

After approved canonical block/time evidence is published and imported, run
`preflight.mjs --replay` for three complete days as documented in README.md.
Only then configure the DefiLlama adapter's public origin and submit its patch.
Source publication, healthy collection, and approved DefiLlama listing are
separate milestones. This runbook does not claim a service deployment or listing.

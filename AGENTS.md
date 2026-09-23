# Repository Instructions

- Never run `mix format` in this repository, including on individual files.
- Preserve the existing formatting and make only targeted edits.

## Sync verification

- Changes to bootstrap, peer heads, catchup, quorum or synced status require a live local multi-node check. Unit tests or simulated request counts alone are not sufficient.
- Reproduce an older state bundle with its RPC thousands of blocks ahead. Use separate node processes, databases and identities, real HTTP bundle download/import, and real P2P catchup on loopback only.
- Record both nodes' actual temporal/rooted heights, the learner's reported network head, sync status and progress over time. A learner must not report synced while it remains behind a verified network head, even when its local rooted and temporal tips agree.
- Include a non-validator RPC carrying hidden validators' quorum proofs, a rooted-only advertisement, discovery before quorum, and a validator-set change after the snapshot. Check the catchup opcode budget and compare canonical hashes after convergence.
- Preserve fake-head protections: arbitrary peer claims must not gain consensus authority. Document actual runtime evidence and any untested cases; do not describe helper-only tests as end-to-end validation.
- Validate every block again immediately before native apply against its committed parent and the validator set reached by replay. Membership can change mid-epoch, and the ahead node may already use a different set. An RPC discovery hint is never permission to execute a block or grant quorum.
- Queue blocks that pass admission under an old snapshot's validator set, then replay a real validator removal. Confirm those stale candidates cannot mutate state, attest, or occupy the producer's slot, and that valid alternatives still advance. Include removed signers, stale validator roots/masks, invalid block/transaction signatures, wrong parent/MMR commitments, reused nonces and insufficient funds.
- Use `ex/scripts/sync_audit/README.md` for the live harness and record its runtime results. Keep failing baselines observable, but require convergence, matching canonical block/mutation hashes, no false synced status, no opcode flood drops, and no execution of queued invalid candidates for acceptance.
- Peer discovery is part of sync correctness: a node may advertise a much newer head without appearing in `API.Peer.all` until its ANR is known and handshaked. Test both the handshaked table and the unverified ANR pool; do not treat a stale four-peer `API.Peer.all` result as evidence that the network head is low. Discovery batches must stay within the existing per-peer wire quotas.

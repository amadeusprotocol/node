defmodule NodeOps do
  @moduledoc """
  Single source of truth for P2P message ops.

  Defines the canonical set of accepted ops and their per-peer rate-limit quota
  (max messages per 6 seconds). Everything else is derived from this one table:

    * `NodeGenNetguard` uses `quota/1` to rate-limit / drop unknown ops.
    * `NodeProto` uses `op_atoms/0` as the string->atom allowlist when decoding
      an untrusted `op` field (so it can't create atoms or smuggle in an
      arbitrary already-loaded atom).

  To add an op, add it here once.
  """

  # uint32 max: effectively unlimited — for ops we accept but do not throttle.
  @unlimited 4_294_967_295

  # op atom => max messages per 6 seconds, per peer IP.
  @quotas %{
    new_phone_who_dis: 20,
    new_phone_who_dis_reply: 20,
    new_phone_who_dis_reply_ns: @unlimited,
    get_peer_anrs: 10,
    get_peer_anrs_reply: 10,
    get_peer_anrs_reply_ns: @unlimited,
    ping: 30,
    ping_reply: 30,
    ping_reply_ns: @unlimited,
    special_business: 200,
    special_business_reply: 200,
    catchup: 50,
    catchup_reply: 50,
    event_tip: 60,
    event_entry: 60,
    event_tx: 8000,
    event_attestation: 8000,
    solicit_entry: 2,
    sell_sol: 10_000
  }

  # string form => atom, computed once at compile time.
  @op_atoms Map.new(@quotas, fn {op, _quota} -> {Atom.to_string(op), op} end)

  @doc "Per-op rate-limit quota map (op atom => max per 6s)."
  def quotas(), do: @quotas

  @doc "Rate-limit quota for `op`, or nil if the op is not an accepted op."
  def quota(op), do: Map.get(@quotas, op)

  @doc "String -> atom allowlist of accepted ops (for decoding untrusted input)."
  def op_atoms(), do: @op_atoms
end

defmodule DB.MMR do
  @moduledoc """
  RocksDB persistence for the MMR accumulator.

  - Live peaks + size live in `sysconf` under `mmr:peaks` / `mmr:size`.
  - Per-block pre-apply snapshots live in `entry_meta` under
    `entry:<hash>:mmr_peaks_before`, used for reorg rewind.

  All functions accept an optional `db_opts` map that flows through
  `DB.API.db_handle/3`, so they participate in an open `rtx` transaction
  (e.g. from `apply_into_main_chain`) or fall back to the persistent_term
  db handle when called standalone.
  """
  import DB.API

  @sysconf_peaks "mmr:peaks"
  @sysconf_size  "mmr:size"
  @rooted_safety_window 3

  def load(db_opts \\ %{}) do
    raw_peaks = RocksDB.get(@sysconf_peaks, db_handle(db_opts, :sysconf, %{}))
    raw_size  = RocksDB.get(@sysconf_size,  db_handle(db_opts, :sysconf, %{}))
    case {raw_peaks, raw_size} do
      {nil, _} -> nil
      {_, nil} -> nil
      {p, s}   -> %{peaks: RDB.vecpak_decode(p), size: :erlang.binary_to_integer(s)}
    end
  end

  def load_or_empty(db_opts \\ %{}), do: load(db_opts) || MMR.empty()

  def save(%{peaks: peaks, size: size}, db_opts) do
    RocksDB.put(@sysconf_peaks, RDB.vecpak_encode(peaks), db_handle(db_opts, :sysconf, %{}))
    RocksDB.put(@sysconf_size,  Integer.to_string(size),  db_handle(db_opts, :sysconf, %{}))
  end

  @doc """
  Persist the pre-apply peaks snapshot for `entry_hash`. Called from
  `apply_into_main_chain` before advancing the MMR with this entry.
  """
  def snapshot_before(entry_hash, prev_state, db_opts) do
    payload = RDB.vecpak_encode(%{peaks: prev_state.peaks, size: prev_state.size})
    RocksDB.put("entry:#{entry_hash}:mmr_peaks_before", payload, db_handle(db_opts, :entry_meta, %{}))
  end

  @doc """
  Load the pre-apply peaks snapshot for `entry_hash`. Used during reorg rewind.
  """
  def snapshot_for(entry_hash, db_opts \\ %{}) do
    case RocksDB.get("entry:#{entry_hash}:mmr_peaks_before", db_handle(db_opts, :entry_meta, %{})) do
      nil -> nil
      bin ->
        m = RDB.vecpak_decode(bin)
        %{peaks: m.peaks, size: m.size}
    end
  end

  @doc """
  Drop the snapshot for `entry_hash`. Called during reorg cleanup and as
  rooted advances past the safety window.
  """
  def drop_snapshot(entry_hash, db_opts) do
    RocksDB.delete("entry:#{entry_hash}:mmr_peaks_before", db_handle(db_opts, :entry_meta, %{}))
  end

  @doc """
  Keep snapshots for the temporal range (rooted..tip) plus a small safety
  window behind rooted; drop everything older.
  """
  def prune_below(rooted_height, db_opts) do
    cutoff = rooted_height - @rooted_safety_window
    if cutoff > 0 do
      case DB.Entry.by_height_in_main_chain(cutoff - 1, db_opts) do
        hash when is_binary(hash) -> drop_snapshot(hash, db_opts)
        _ -> :ok
      end
    end
  end

  def export_snapshot(entry_hash, db_opts \\ %{}) do
    state = snapshot_for(entry_hash, db_opts)
    %{
      @sysconf_peaks => RDB.vecpak_encode(state.peaks),
      @sysconf_size  => Integer.to_string(state.size)
    }
  end

  @doc """
  Stable chain identifier. Currently the genesis hash — unique per network.
  """
  def chain_id() do
    EntryGenesis.get().hash
  end

  @doc """
  Current root_chain if the MMR is populated, else nil. Used for shadow
  validation (and by the proposer once Phase 2 ships).
  """
  def current_root_chain(db_opts \\ %{}) do
    case load(db_opts) do
      nil   -> nil
      state -> MMR.root_chain(chain_id(), state)
    end
  end
end

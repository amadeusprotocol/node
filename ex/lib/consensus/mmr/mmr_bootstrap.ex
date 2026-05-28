defmodule MMR.Bootstrap do
  @moduledoc """
  MMR rebuild entry points.

  - `rebuild_from_genesis/0` — walk the full main chain from height 0.
    Run this once on an offline archival node to generate the values you
    bake into `@checkpoint_*` below.

  - `rebuild_from_checkpoint/0` — restore peaks from the compiled-in
    checkpoint, then catch up by appending blocks from `size` (= last
    appended block height + 1) to the local tip. Falls back to
    `rebuild_from_genesis/0` if no checkpoint is compiled in.

  Both are safe to re-run — they overwrite whatever's in sysconf. Progress
  is logged every 100k blocks. Both print the final `peaks`, `size`, and
  `root_chain` at the end — paste the values into `@checkpoint_*` to bake
  in a fresh checkpoint for the next release.
  """

  @progress_every 100_000

  # ----- compile-time checkpoint -----
  # Replace with values printed by an offline `rebuild_from_genesis/0`.
  # Defaults are "no checkpoint" — bootstrap falls back to a full rebuild
  # whenever @checkpoint_size is 0.
  @checkpoint_size  0
  @checkpoint_peaks []

  defp checkpoint_present?(), do: @checkpoint_size > 0
  defp checkpoint_state(),    do: %{peaks: @checkpoint_peaks, size: @checkpoint_size}
  defp checkpoint_height(),   do: @checkpoint_size - 1

  # ----- entry points -----

  def rebuild_from_genesis() do
    # Refuse if the node doesn't actually hold the full chain — pruning or
    # bundle-bootstrapped nodes would silently skip missing blocks here and
    # produce a wrong MMR with no error. Bake values in and use
    # rebuild_from_checkpoint/0 instead.
    pruned = DB.Chain.pruned_below_height()
    cond do
      pruned > 0 ->
        IO.puts "MMR bootstrap: chain is pruned below height #{pruned} — full genesis rebuild is impossible. Bake values in and use rebuild_from_checkpoint/0 instead."
        {:error, :chain_pruned}

      is_nil(DB.Entry.by_height_in_main_chain(0)) ->
        IO.puts "MMR bootstrap: genesis (height 0) is not in main chain — node does not hold full history. Bake values in and use rebuild_from_checkpoint/0 instead."
        {:error, :genesis_missing}

      true ->
        tip_height = DB.Chain.height()
        IO.puts "MMR bootstrap: full scan from height 0..#{tip_height}"
        do_rebuild(MMR.empty(), 0, tip_height)
    end
  end

  def rebuild_from_checkpoint() do
    if !checkpoint_present?() do
      IO.puts "MMR bootstrap: no checkpoint compiled in — falling back to full genesis rebuild"
      rebuild_from_genesis()
    else
      cp_height = checkpoint_height()
      cp_state  = checkpoint_state()

      cp_block = DB.Entry.by_height_in_main_chain(cp_height)
      if is_nil(cp_block) do
        IO.puts "MMR bootstrap: checkpoint height #{cp_height} not present in local main chain — refusing"
        {:error, :checkpoint_height_missing}
      else
        tip_height = DB.Chain.height() || 0
        cond do
          tip_height < cp_height ->
            IO.puts "MMR bootstrap: local tip (#{tip_height}) is below checkpoint (#{cp_height}) — refusing"
            {:error, :tip_below_checkpoint}

          tip_height == cp_height ->
            IO.puts "MMR bootstrap: local tip matches checkpoint exactly (#{cp_height}) — committing checkpoint as-is"
            commit(cp_state, 0.0)

          true ->
            IO.puts "MMR bootstrap: checkpoint at height #{cp_height}, catching up to #{tip_height} (#{tip_height - cp_height} blocks)"
            do_rebuild(cp_state, cp_height + 1, tip_height)
        end
      end
    end
  end

  # ----- internal -----

  defp do_rebuild(start_state, from_h, tip_height) do
    t0 = :os.system_time(1000)

    try do
      final_state =
        Enum.reduce(from_h..tip_height, start_state, fn h, acc ->
          if rem(h, @progress_every) == 0 and h > from_h do
            elapsed_s = (:os.system_time(1000) - t0) / 1000
            rate = if elapsed_s > 0, do: (h - from_h) / elapsed_s, else: 0
            IO.puts "MMR bootstrap: height #{h} / #{tip_height} (#{Float.round(rate, 0)} blocks/s)"
          end

          case DB.Entry.by_height_in_main_chain(h) do
            nil  -> throw({:missing_block, h})
            hash -> MMR.append(acc, hash)
          end
        end)

      elapsed_s = (:os.system_time(1000) - t0) / 1000
      commit(final_state, elapsed_s)
    catch
      :throw, {:missing_block, h} ->
        IO.puts "MMR bootstrap: missing block at height #{h} — refusing to commit a partial MMR"
        {:error, {:missing_block, h}}
    end
  end

  defp commit(state, elapsed_s) do
    %{db: db, cf: _cf} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)
    DB.MMR.save(state, %{rtx: rtx})
    RocksDB.transaction_commit(rtx)

    cid = DB.MMR.chain_id()
    root = MMR.root_chain(cid, state)

    IO.puts "MMR bootstrap complete in #{Float.round(elapsed_s, 1)}s"
    IO.puts "  @checkpoint_size  = #{state.size}"
    IO.puts "  @checkpoint_peaks = #{inspect(state.peaks, limit: :infinity, printable_limit: :infinity)}"
    IO.puts "  chain_id          = #{Base.encode16(cid, case: :lower)}"
    IO.puts "  root_chain        = #{Base.encode16(root, case: :lower)}"

    state
  end
end

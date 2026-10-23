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
  @checkpoint_size  88109745
  @checkpoint_peaks [
    <<141, 217, 175, 185, 66, 254, 192, 68, 236, 229, 97, 196, 239, 3, 100, 196, 211, 123, 103, 115, 113, 21, 33, 73, 235, 120, 42, 227, 3, 211, 1, 88>>,
    <<179, 54, 100, 90, 148, 147, 11, 254, 37, 238, 170, 55, 58, 247, 146, 13, 215, 113, 54, 155, 106, 39, 49, 203, 93, 173, 33, 14, 248, 167, 90, 106>>,
    <<88, 230, 33, 51, 67, 218, 153, 201, 240, 206, 183, 20, 218, 94, 97, 149, 228, 106, 34, 214, 89, 95, 165, 208, 189, 36, 218, 152, 210, 202, 61, 67>>,
    <<165, 122, 153, 242, 83, 8, 91, 70, 180, 184, 95, 214, 113, 202, 175, 74, 162, 204, 82, 4, 226, 189, 157, 250, 135, 66, 219, 244, 234, 104, 131, 174>>,
    <<36, 81, 243, 144, 81, 115, 121, 169, 40, 121, 222, 41, 63, 160, 229, 127, 168, 87, 150, 255, 181, 101, 162, 80, 164, 215, 142, 159, 208, 95, 123, 49>>,
    <<180, 112, 149, 18, 62, 61, 7, 4, 11, 6, 76, 67, 40, 73, 97, 36, 131, 15, 185, 13, 243, 17, 231, 167, 26, 229, 227, 152, 204, 33, 155, 29>>,
    <<226, 208, 139, 109, 125, 191, 167, 122, 104, 177, 231, 232, 31, 106, 6, 11, 147, 124, 87, 57, 103, 128, 80, 82, 226, 158, 255, 88, 105, 163, 27, 15>>,
    <<125, 252, 164, 43, 45, 158, 189, 40, 87, 49, 124, 97, 65, 78, 1, 251, 50, 62, 82, 84, 225, 176, 155, 67, 205, 17, 54, 226, 135, 149, 198, 100>>,
    <<92, 110, 156, 171, 159, 62, 56, 16, 193, 102, 5, 108, 202, 149, 187, 32, 23, 4, 168, 21, 245, 191, 164, 80, 45, 211, 130, 192, 147, 64, 85, 227>>,
    <<10, 148, 235, 164, 109, 193, 48, 117, 161, 158, 212, 5, 37, 199, 45, 180, 114, 209, 174, 164, 188, 99, 226, 127, 133, 14, 252, 61, 250, 247, 14, 101>>,
    <<177, 117, 213, 252, 173, 202, 39, 220, 201, 123, 126, 24, 234, 191, 243, 57, 59, 124, 123, 234, 67, 18, 29, 19, 167, 201, 119, 34, 194, 249, 82, 28>>
  ]

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
    total = tip_height - from_h + 1

    try do
      final_state =
        Enum.reduce(from_h..tip_height, start_state, fn h, acc ->
          if rem(h, @progress_every) == 0 and h > from_h do
            elapsed_s = (:os.system_time(1000) - t0) / 1000
            rate = if elapsed_s > 0, do: (h - from_h) / elapsed_s, else: 0
            pct = (h - from_h) * 100.0 / max(total, 1)
            IO.puts "MMR bootstrap: height #{h} / #{tip_height}  #{Float.round(pct, 2)}%  (#{Float.round(rate, 0)} blocks/s)"
          end

          case DB.Entry.mmr_leaf(h) do
            nil  -> throw({:missing_block, h})
            leaf -> MMR.append(acc, leaf)
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

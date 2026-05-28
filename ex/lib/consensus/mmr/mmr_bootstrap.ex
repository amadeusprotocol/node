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
  @checkpoint_size  68131588
  @checkpoint_peaks [
    <<141, 217, 175, 185, 66, 254, 192, 68, 236, 229, 97, 196, 239, 3, 100, 196, 211, 123, 103, 115, 113, 21, 33, 73, 235, 120, 42, 227, 3, 211, 1, 88>>,
    <<240, 11, 162, 200, 41, 141, 245, 162, 114, 120, 192, 17, 118, 104, 195, 180, 103, 184, 108, 177, 177, 103, 23, 197, 237, 139, 115, 178, 183, 207, 116, 131>>,
    <<155, 200, 198, 13, 204, 68, 174, 204, 121, 191, 126, 114, 85, 39, 231, 121, 149, 232, 54, 83, 211, 147, 12, 128, 58, 79, 78, 106, 200, 21, 62, 40>>,
    <<151, 39, 169, 160, 242, 223, 101, 225, 26, 106, 39, 25, 238, 214, 231, 173, 130, 39, 233, 239, 10, 132, 247, 177, 123, 226, 54, 41, 7, 48, 92, 82>>,
    <<82, 124, 150, 5, 164, 27, 184, 95, 104, 229, 242, 45, 171, 209, 82, 35, 212, 152, 71, 228, 205, 224, 242, 245, 101, 220, 99, 24, 176, 83, 59, 73>>,
    <<240, 200, 17, 67, 195, 229, 67, 183, 168, 255, 115, 85, 156, 131, 8, 137, 196, 95, 60, 60, 154, 106, 53, 120, 217, 215, 42, 73, 20, 16, 102, 16>>,
    <<187, 41, 253, 18, 19, 37, 130, 176, 119, 200, 250, 50, 199, 82, 254, 89, 231, 53, 158, 130, 190, 36, 154, 128, 159, 173, 131, 94, 123, 76, 38, 121>>,
    <<177, 66, 49, 123, 181, 179, 216, 10, 159, 158, 242, 34, 156, 189, 50, 108, 165, 152, 67, 78, 141, 98, 53, 205, 205, 133, 213, 252, 47, 207, 72, 235>>,
    <<210, 184, 72, 111, 121, 145, 172, 128, 90, 107, 133, 251, 85, 133, 129, 114, 203, 8, 153, 76, 39, 141, 37, 195, 181, 66, 221, 54, 107, 114, 147, 64>>,
    <<64, 244, 69, 101, 3, 234, 165, 151, 127, 203, 87, 159, 50, 171, 217, 229, 67, 197, 221, 78, 228, 159, 9, 102, 104, 124, 29, 193, 194, 36, 188, 75>>,
    <<34, 65, 97, 20, 255, 231, 201, 227, 58, 101, 154, 71, 236, 91, 101, 101, 187, 28, 84, 229, 196, 99, 75, 214, 172, 92, 145, 153, 84, 165, 243, 108>>
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
